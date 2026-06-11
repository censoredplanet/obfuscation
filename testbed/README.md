# Testbed

For each domain in a configurable list, the testbed opens an HTTPS connection through a SOCKS proxy, records the HTTP status, and captures the resulting traffic as a PCAP file. Network delay is injected via `netem` using a custom RTT distribution derived from empirical measurements, and segmentation offloading is disabled at every layer to ensure PCAP fidelity.

## Proxy protocols

The testbed includes client–server pairs for the following protocols, all defined in `testbed.yaml`:

| Protocol | Client container | Server container | Host SOCKS port |
|---|---|---|---|
| NaiveProxy | `naiveproxy-client` | `naiveproxy-server` | 1081 |
| VMess (Xray) | `xray-client` | `xray-server` | 1082 |
| VLESS (Xray) | `xray-client` | `xray-server` | 1083 |
| Trojan (Xray) | `xray-client` | `xray-server` | 1084 |
| VLESS-WebSocket (Xray) | `xray-client` | `xray-server` | 1085 |
| VLESS-Vision (Xray) | `xray-client` | `xray-server` | 1087 |
| VLESS-gRPC (Xray) | `xray-client-grpc` | `xray-server-grpc` | 1086 |
| WebTunnel (Tor) | `webtunnel-client` | `webtunnel-nginx` | 1090 |
| GOST | `gost-client` | `gost-server` | 1088 |

## Prerequisites

**Docker and Docker Compose.** The testbed is orchestrated with Docker Compose.
**Node.js and npm.** The Playwright probe scripts require Node.js (v18 or later recommended).
**System tools.** The capture scripts use `tcpdump`, `ethtool`, `nsenter`, and `tc` (from `iproute2`), all invoked via `sudo`. On a typical Ubuntu server these are pre-installed.

## Setup

### 1. Generate certificates and install the netem distribution

Run the setup script to create a self-signed CA and server certificate for the `proxy.lab` domain, distribute the root CA to the proxy clients that need it, and install the custom netem delay distribution file:

```bash
./generate-certs.sh
```

This produces `certs/rootCA.pem`, `certs/server.crt`, and `certs/server.key`, copies `rootCA.pem` into `naiveproxy/client/` and `webtunnel/client/`, and installs `worker/lab.dist` to `/usr/lib/tc/lab.dist` (requires `sudo`).

### 2. Start the testbed

```bash
docker compose -f testbed.yaml up -d
```

### 3. WebTunnel bridge fingerprint

The WebTunnel setup requires the Tor client to know the bridge's relay fingerprint. After the `webtunnel-server` container has started and generated its keys, retrieve the fingerprint from the logs, copy the fingerprint and update the `Bridge` line in `webtunnel/client/torrc`:

```
Bridge webtunnel 172.28.0.20:443 <FINGERPRINT> url=https://webtunnel-bridge/Sup3rS3cr3tPath
```

Then restart the client container to pick up the change:

```bash
docker compose -f testbed.yaml up -d --build webtunnel-client
```

### 4. Install Playwright dependencies

```bash
cd worker
npm ci
npx playwright install --with-deps firefox
```

`npm ci` installs the exact dependency versions from `package-lock.json`. The second command downloads the Firefox browser binary that Playwright drives.

## Running experiments

The `worker/` directory contains two capture harnesses and two Playwright probe scripts. Which combination you use depends on the protocol.

### Batch mode (`capture.sh` + `runner.mjs`)

For protocols where the proxy client handles the full domain list in a single browser session. The Playwright script iterates through `domains.txt` internally, recycling browser instances every 250 domains.

```bash
cd worker

# GOST — TLS 1.3 with post-quantum key exchange
./capture.sh gost "socks5://127.0.0.1:1088" gost-client gost-server "tcp port 8443"

# Trojan — TLS 1.2, no post-quantum
./capture.sh trojan "socks5://127.0.0.1:1084" xray-client xray-server "tcp port 10003" 1.2 off

# VLESS
./capture.sh vless "socks5://127.0.0.1:1083" xray-client xray-server "tcp port 10002"
```

### Per-domain mode (`capture-per-domain.sh` + `runner-per-domain.mjs`)

For protocols whose client process must be restarted between domains (NaiveProxy, WebTunnel, VLESS-gRPC). The capture script iterates the domain list itself, killing and restarting the proxy client process between each domain.

```bash
cd worker

# NaiveProxy — waits for SOCKS port to come back up
./capture-per-domain.sh naive "socks5://127.0.0.1:1081" \
    naiveproxy-server naiveproxy-server naiveproxy-client naive "tcp port 443"

# WebTunnel — Tor needs a fixed bootstrap delay
RESTART_DELAY=4 ./capture-per-domain.sh webtunnel "socks5://127.0.0.1:1090" \
    webtunnel-nginx webtunnel-nginx webtunnel-client tor \
    "tcp and host 172.28.0.20 and port 443"

# VLESS-gRPC
./capture-per-domain.sh xray-grpc "socks5://127.0.0.1:1086" \
    xray-server-grpc xray-server-grpc xray-client-grpc xray \
    "tcp and host 172.28.0.31"
```

### Arguments and environment variables

Both capture scripts accept:

| Positional arg | Description |
|---|---|
| `proxy-name` | Label for output files |
| `socks-url` | SOCKS5 proxy URL |
| `sniff-container` | Container where tcpdump runs |
| `delay-container` | Container where netem is applied |
| `bpf-filter` | tcpdump BPF filter expression |
| `tls-version` | `1.2` or `1.3` (default: `1.3`) |
| `post-quantum` | `on` or `off` (default: `on`) |

`capture-per-domain.sh` additionally takes `client-container` and `process-name` (inserted between `delay-container` and `bpf-filter`).

| Environment variable | Description | Default |
|---|---|---|
| `HOST_NIC` | Host network interface for offloading control | `enp1s0` |
| `DOMAINS_FILE` | Path to the domain list (per-domain mode only) | `./domains.txt` |
| `RESTART_DELAY` | Fixed sleep in seconds after proxy restart (per-domain mode only) | unset (poll SOCKS port) |

## Output

Each run produces:

- **PCAP file** in `captures_<proxy-name>/traffic.<proxy-name>.pcap` — the raw packet capture from the sniff container's network namespace.
- **JSON results** in `worker/results/results.<proxy-name>.json` (batch mode) or `worker/results/results.<proxy-name>.jsonl` (per-domain mode) — one record per domain with HTTP status, timing, error messages, and the TLS/PQ configuration used.
