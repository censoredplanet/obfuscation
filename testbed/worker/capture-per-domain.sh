#!/usr/bin/env bash
# capture-per-domain.sh — per-domain packet capture with proxy restart between domains
#
# Like capture.sh, but iterates through a domain list itself, restarting the
# proxy process inside the client container between each domain. This is needed
# for protocols whose client process must be recycled per connection (e.g.
# NaiveProxy, WebTunnel/Tor, VLESS-gRPC).
#
# Usage:
#   ./capture-per-domain.sh <proxy-name> <socks-url> <sniff-container> <delay-container> \
#                           <client-container> <process-name> <bpf-filter> [tls-version] [post-quantum]
#
# Arguments:
#   proxy-name        Label for output files (e.g. "naive", "webtunnel")
#   socks-url         SOCKS5 proxy URL (e.g. "socks5://127.0.0.1:1081")
#   sniff-container   Docker container where tcpdump runs
#   delay-container   Docker container where netem is applied (often the same as sniff-container)
#   client-container  Docker container running the proxy client (restarted between domains)
#   process-name      Process to kill inside client-container between domains (e.g. "naive", "tor", "xray")
#   bpf-filter        tcpdump BPF filter expression (e.g. "tcp port 443")
#   tls-version       "1.2" or "1.3" (default: 1.3)
#   post-quantum      "on" or "off" (default: on, only used with TLS 1.3)
#
# Environment:
#   HOST_NIC          Host network interface for offloading control (default: enp1s0)
#   DOMAINS_FILE      Path to newline-separated domain list (default: ./domains.txt)
#   RESTART_DELAY     If set, sleep this many seconds after killing the proxy instead of
#                     waiting for the SOCKS port. Useful for slow-starting proxies like Tor.
#
# Examples:
#   # NaiveProxy — auto-waits for SOCKS port
#   ./capture-per-domain.sh naive "socks5://127.0.0.1:1081" \
#       naiveproxy-server naiveproxy-server naiveproxy-client-1 naive "tcp port 443"
#
#   # WebTunnel/Tor — needs a fixed delay for Tor bootstrap
#   RESTART_DELAY=4 ./capture-per-domain.sh webtunnel "socks5://127.0.0.1:1091" \
#       webtunnel-nginx webtunnel-nginx webtunnel-client-1 tor \
#       "tcp and host 172.28.0.20 and port 443"
#
#   # VLESS-gRPC
#   ./capture-per-domain.sh xray-grpc "socks5://127.0.0.1:3001" \
#       xray-server-grpc xray-server-grpc xray-client-grpc-1 xray \
#       "tcp and host 172.28.0.30"

set -euo pipefail

PROXY_NAME="${1:-}"
SOCKS_URL="${2:-}"
SNIFF_CONTAINER="${3:-}"
DELAY_CONTAINER="${4:-}"
CLIENT_CONTAINER="${5:-}"
PROCESS_NAME="${6:-}"
BPF_FILTER="${7:-}"
TLS_VERSION="${8:-1.3}"
POST_QUANTUM="${9:-on}"

if [[ -z "$PROXY_NAME" || -z "$SOCKS_URL" || -z "$SNIFF_CONTAINER" || -z "$DELAY_CONTAINER" \
   || -z "$CLIENT_CONTAINER" || -z "$PROCESS_NAME" || -z "$BPF_FILTER" ]]; then
  echo "Usage: $0 <proxy-name> <socks-url> <sniff-container> <delay-container> <client-container> <process-name> <bpf-filter> [tls-version] [post-quantum]" >&2
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
DOMAINS_FILE="${DOMAINS_FILE:-./domains.txt}"

OUTDIR="captures_${PROXY_NAME}"
mkdir -p "$OUTDIR"

# Netem parameters
NETEM_DELAY_MS="36"
NETEM_JITTER_MS="63"
NETEM_DIST="lab"

# Extract the SOCKS port from the URL for wait_for_port (e.g. "socks5://127.0.0.1:1081" → "1081")
SOCKS_PORT="${SOCKS_URL##*:}"

echo "[*] Configuration: proxy=${PROXY_NAME} tls=${TLS_VERSION} pq=${POST_QUANTUM}"
echo "[*] Containers: sniff=${SNIFF_CONTAINER} delay=${DELAY_CONTAINER} client=${CLIENT_CONTAINER}"
echo "[*] BPF filter: ${BPF_FILTER}"
echo "[*] Restart strategy: kill ${PROCESS_NAME}, then ${RESTART_DELAY:+sleep ${RESTART_DELAY}s}${RESTART_DELAY:-wait for port ${SOCKS_PORT}}"

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
  IFINDEX=$(sudo nsenter -t "$PID" -n ip -o link show eth0 2>/dev/null | grep -oP '@if\K[0-9]+' || true)
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

  echo "[*] Verifying artificial delay is active..."

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

  # Informational ping check
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

# Waits for a TCP port on localhost to accept connections, with timeout.
wait_for_port() {
  local port="$1"
  local max_retries=20  # up to 10 seconds (20 × 0.5s)
  local count=0

  while ! bash -c "echo > /dev/tcp/127.0.0.1/${port}" 2>/dev/null; do
    sleep 0.5
    ((count++))
    if (( count >= max_retries )); then
      echo "Timeout: proxy port ${port} failed to open." >&2
      return 1
    fi
  done
}

# Kills the proxy process inside the client container and waits for it to
# come back up. The wait strategy depends on RESTART_DELAY:
#   - If set:   fixed sleep (for slow-starting proxies like Tor)
#   - If unset: poll the SOCKS port, then sleep 1s for stability
restart_proxy() {
  docker exec "$CLIENT_CONTAINER" sh -c "kill \$(pidof $PROCESS_NAME)" 2>/dev/null || true

  if [[ -n "${RESTART_DELAY:-}" ]]; then
    sleep "$RESTART_DELAY"
  else
    if ! wait_for_port "$SOCKS_PORT"; then
      return 1
    fi
    sleep 1
  fi
}

run_capture() {
  local PCAP="${OUTDIR}/traffic.${PROXY_NAME}.pcap"
  local IFACE="eth0"

  echo "=== ${PROXY_NAME} ==="

  # 1. Disable offloading at every layer
  disable_host_offloading
  disable_veth_offloading "$SNIFF_CONTAINER"
  disable_veth_offloading "$DELAY_CONTAINER"
  disable_veth_offloading "$CLIENT_CONTAINER"
  disable_offloading "$SNIFF_CONTAINER"
  disable_offloading "$DELAY_CONTAINER"
  disable_offloading "$CLIENT_CONTAINER"

  # 2. Inject the RTT distribution onto the server container's egress
  apply_network_delay "$DELAY_CONTAINER"

  # 3. Verify the delay is active
  local CLIENT_IP
  CLIENT_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLIENT_CONTAINER")"
  verify_delay "$DELAY_CONTAINER" "$CLIENT_IP"

  # 4. Start PCAP capture
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

  # 5. Iterate domains, restarting the proxy between each
  local count=0
  local total
  total=$(grep -cve '^\s*#' -e '^\s*$' "$DOMAINS_FILE")

  while IFS= read -r domain || [[ -n "$domain" ]]; do
    [[ "$domain" =~ ^#.*$ ]] && continue
    [[ -z "$domain" ]] && continue

    ((++count))
    echo "======================================================"
    echo "[$count/$total] $domain"

    if ! restart_proxy; then
      echo "Skipping $domain — proxy failed to restart."
      continue
    fi

    node runner-per-domain.mjs "$PROXY_NAME" "$SOCKS_URL" "$TLS_VERSION" "$POST_QUANTUM" --domain "$domain" || echo "Runner failed"
  done < "$DOMAINS_FILE"

  trap - EXIT
  cleanup

  echo "Saved ${PCAP}"
}

run_capture
