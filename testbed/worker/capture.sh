#!/usr/bin/env bash
# capture.sh — packet capture harness for proxy experiments
#
# Sets up network emulation, disables segmentation offloading at every layer, 
# captures traffic via tcpdump inside a Docker container's network namespace, 
# then runs the Playwright script.
#
# Usage:
#   ./capture.sh <proxy-name> <socks-url> <sniff-container> <delay-container> <bpf-filter> [tls-version] [post-quantum]
#
# Arguments:
#   proxy-name       Label for output files (e.g. "gost", "trojan")
#   socks-url        SOCKS5 proxy URL (e.g. "socks5://127.0.0.1:1088")
#   sniff-container  Docker container where tcpdump runs (client side)
#   delay-container  Docker container where netem is applied (server side)
#   bpf-filter       tcpdump BPF filter expression (e.g. "tcp port 8443")
#   tls-version      "1.2" or "1.3" (default: 1.3)
#   post-quantum     "on" or "off" (default: on, only used with TLS 1.3)
#
# Environment:
#   HOST_NIC         Host network interface for offloading control (default: enp1s0)
#
# Examples:
#   ./capture.sh gost   "socks5://127.0.0.1:1088" gost-client gost-server "tcp port 8443"
#   ./capture.sh trojan "socks5://127.0.0.1:1084" xray-client xray-server "tcp port 10003" 1.2 off

set -euo pipefail

PROXY_NAME="${1:-}"
SOCKS_URL="${2:-}"
SNIFF_CONTAINER="${3:-}"
DELAY_CONTAINER="${4:-}"
BPF_FILTER="${5:-}"
TLS_VERSION="${6:-1.3}"
POST_QUANTUM="${7:-on}"

if [[ -z "$PROXY_NAME" || -z "$SOCKS_URL" || -z "$SNIFF_CONTAINER" || -z "$DELAY_CONTAINER" || -z "$BPF_FILTER" ]]; then
  echo "Usage: $0 <proxy-name> <socks-url> <sniff-container> <delay-container> <bpf-filter> [tls-version] [post-quantum]" >&2
  echo "Example: $0 gost \"socks5://127.0.0.1:1088\" gost-client gost-server \"tcp port 8443\" 1.3 on" >&2
  exit 1
fi

if [[ "$TLS_VERSION" != "1.2" && "$TLS_VERSION" != "1.3" ]]; then
  echo "Error: tls-version must be '1.2' or '1.3' (got: $TLS_VERSION)" >&2
  exit 1
fi

if [[ "$POST_QUANTUM" != "on" && "$POST_QUANTUM" != "off" ]]; then
  echo "Error: post-quantum must be 'on' or 'off' (got: $POST_QUANTUM)" >&2
  exit 1
fi

MAIN_PID=$$
trap "exit 1" TERM INT

HOST_NIC="${HOST_NIC:-enp1s0}"

OUTDIR="captures_${PROXY_NAME}"
mkdir -p "$OUTDIR"

# Netem parameters
NETEM_DELAY_MS="36"
NETEM_JITTER_MS="63"
NETEM_DIST="lab"

echo "[*] Configuration: proxy=${PROXY_NAME} tls=${TLS_VERSION} pq=${POST_QUANTUM}"
echo "[*] Containers: sniff=${SNIFF_CONTAINER} delay=${DELAY_CONTAINER}"
echo "[*] BPF filter: ${BPF_FILTER}"

disable_offloading() {
  local CONTAINER="$1"
  local PID
  PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"
  sudo nsenter -t "$PID" -n ethtool -K eth0 tx off rx off sg off tso off gso off gro off lro off 2>/dev/null || true
}

disable_host_offloading() {
  echo "[*] Disabling offloading on host NIC: $HOST_NIC"
  sudo ethtool -K "$HOST_NIC" tx off rx off sg off tso off gso off gro off lro off 2>/dev/null || true
}

disable_veth_offloading() {
  local CONTAINER="$1"
  local PID
  PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"
  local IFINDEX
  IFINDEX=$(sudo nsenter -t "$PID" -n ip -o link show eth0 2>/dev/null | grep -oP '@if\K[0-9]+')
  if [[ -z "$IFINDEX" ]]; then
    echo "Warning: Could not find host-side ifindex for $CONTAINER" >&2
    return
  fi

  local VETH
  VETH=$(ip -o link | awk -F': ' -v idx="$IFINDEX" '$1 == idx {print $2}' | cut -d'@' -f1)
  if [[ -n "$VETH" ]]; then
    echo "[*] Disabling offloading on veth: $VETH (host side of $CONTAINER)"
    sudo ethtool -K "$VETH" tx off rx off sg off tso off gso off gro off lro off 2>/dev/null || true
  fi
}

apply_network_delay() {
  local CONTAINER="$1"
  local PID
  PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"

  sudo nsenter -t "$PID" -n tc qdisc del dev eth0 root 2>/dev/null || true

  if ! sudo nsenter -t "$PID" -n tc qdisc add dev eth0 root netem \
        delay "${NETEM_DELAY_MS}ms" "${NETEM_JITTER_MS}ms" distribution "${NETEM_DIST}"; then
    echo "FATAL: Failed to apply netem qdisc on $CONTAINER." >&2
    echo "   Is /usr/lib/tc/${NETEM_DIST}.dist installed?" >&2
    exit 1
  fi
}

verify_delay() {
  local SERVER_CONTAINER="$1"
  local TARGET_IP="$2"

  echo "[*] Verifying netem delay is active..."

  local PID
  PID="$(docker inspect -f '{{.State.Pid}}' "$SERVER_CONTAINER")"

  local qdisc_output
  qdisc_output="$(sudo nsenter -t "$PID" -n tc qdisc show dev eth0)"

  if ! echo "$qdisc_output" | grep -q "netem"; then
    echo "FATAL: netem qdisc not loaded on $SERVER_CONTAINER" >&2
    echo "   tc output: $qdisc_output" >&2
    exit 1
  fi

  if ! echo "$qdisc_output" | grep -q "delay ${NETEM_DELAY_MS}ms"; then
    echo "FATAL: netem loaded but delay parameter wrong" >&2
    echo "   tc output: $qdisc_output" >&2
    exit 1
  fi

  echo "    Qdisc verified: $qdisc_output"


  local avg_rtt
  avg_rtt="$(sudo nsenter -t "$PID" -n ping -c 20 -W 2 "$TARGET_IP" 2>/dev/null \
             | tail -1 | awk -F'/' '{print $5}')"

  if [[ -z "$avg_rtt" ]]; then
    echo "Warning: Ping verification failed (no route?). Continuing on qdisc check." >&2
  else
    if awk -v rtt="$avg_rtt" 'BEGIN { exit !(rtt >= 5) }'; then
      echo "    Measured avg RTT (20 pings): ${avg_rtt}ms — netem is shaping traffic."
    else
      echo "FATAL: qdisc is loaded but measured RTT (${avg_rtt}ms) is suspiciously low." >&2
      exit 1
    fi
  fi
}

start_tcpdump_in_netns() {
  local CONTAINER="$1"
  local PCAP="$2"
  local IFACE="$3"
  local FILTER="$4"

  local TARGET_PID
  TARGET_PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"

  sudo nsenter -t "$TARGET_PID" -n sh -lc \
    "tcpdump -i '$IFACE' -nn '$FILTER' -w '$PCAP' >/dev/null 2>&1 & echo \$!"
}

stop_tcpdump_in_netns() {
  local CONTAINER="$1"
  local TD_PID="$2"

  local TARGET_PID
  TARGET_PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"

  sudo nsenter -t "$TARGET_PID" -n sh -lc "kill -2 '$TD_PID' 2>/dev/null || true"
}

run_capture() {
  local PCAP="${OUTDIR}/traffic.${PROXY_NAME}.pcap"
  local IFACE="any"

  echo "=== ${PROXY_NAME} ==="

  # 1. Disable offloading at every layer (host NIC, host-side veths, container interfaces)
  disable_host_offloading
  disable_veth_offloading "$SNIFF_CONTAINER"
  disable_veth_offloading "$DELAY_CONTAINER"
  disable_offloading "$SNIFF_CONTAINER"
  disable_offloading "$DELAY_CONTAINER"

  # 2. Inject the RTT distribution onto the server container's egress
  apply_network_delay "$DELAY_CONTAINER"

  # 3. Verify the delay is active (ping target is the sniff container's IP)
  local CLIENT_IP
  CLIENT_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SNIFF_CONTAINER")"
  verify_delay "$DELAY_CONTAINER" "$CLIENT_IP"

  # 4. Start PCAP capture in the sniff container's network namespace
  local TD_PID=""
  TD_PID="$(start_tcpdump_in_netns "$SNIFF_CONTAINER" "$PCAP" "$IFACE" "$BPF_FILTER")"

  cleanup() {
    set +e
    echo "[*] Cleaning up background processes..."
    if [[ -n "${TD_PID:-}" ]]; then
      stop_tcpdump_in_netns "$SNIFF_CONTAINER" "$TD_PID"
      sudo nsenter -t "$(docker inspect -f '{{.State.Pid}}' "$SNIFF_CONTAINER")" \
        -n sh -lc "while kill -0 '$TD_PID' 2>/dev/null; do sleep 0.1; done" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT

  # 5. Run the Playwright script
  node runner.mjs "$PROXY_NAME" "$SOCKS_URL" "$TLS_VERSION" "$POST_QUANTUM" || echo "Runner failed rc=$?"

  trap - EXIT
  cleanup

  echo "Saved ${PCAP}"
}

run_capture
