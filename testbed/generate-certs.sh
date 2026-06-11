#!/usr/bin/env bash
# generate-certs.sh — generates a self-signed PKI for the testbed and distributes artefacts
#
# Produces:
#   certs/rootCA.pem  — root CA certificate (distributed to proxy clients)
#   certs/server.key  — server private key
#   certs/server.crt  — server certificate signed by the root CA (SAN: proxy.lab)
#
# Also installs the netem delay distribution used by the capture scripts:
#   lab.dist → /usr/lib/tc/lab.dist

set -euo pipefail

DOMAIN="proxy.lab"
VALIDITY_DAYS=825
CERT_DIR="certs"

DIST_SRC="./worker/lab.dist"
if [[ -d "/usr/lib/x86_64-linux-gnu/tc" ]]; then
  DIST_DST="/usr/lib/x86_64-linux-gnu/tc/lab.dist"
else
  DIST_DST="/usr/lib/tc/lab.dist"
  sudo mkdir -p /usr/lib/tc
fi

mkdir -p "$CERT_DIR"
echo "[*] Output directory: ./$CERT_DIR/"

echo "[*] Generating Root CA key..."
openssl genrsa -out "$CERT_DIR/rootCA.key" 4096

echo "[*] Generating Root CA certificate..."
openssl req -x509 -new -nodes \
  -key "$CERT_DIR/rootCA.key" \
  -sha256 -days 3650 \
  -out "$CERT_DIR/rootCA.pem" \
  -subj "/C=XX/ST=State/L=City/O=Testbed/CN=Testbed Root CA"

echo "[*] Generating server key..."
openssl genrsa -out "$CERT_DIR/server.key" 2048

echo "[*] Generating server CSR..."
openssl req -new \
  -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -subj "/C=XX/ST=State/L=City/O=Testbed/CN=$DOMAIN"

cat > "$CERT_DIR/server.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $DOMAIN
DNS.2 = webtunnel-bridge
EOF

echo "[*] Signing server certificate (SAN: $DOMAIN)..."
openssl x509 -req \
  -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/rootCA.pem" \
  -CAkey "$CERT_DIR/rootCA.key" \
  -CAcreateserial \
  -out "$CERT_DIR/server.crt" \
  -days "$VALIDITY_DAYS" \
  -sha256 \
  -extfile "$CERT_DIR/server.ext"

echo "[*] Setting certificate permissions..."
chmod 644 "$CERT_DIR/server.crt"
chmod 644 "$CERT_DIR/server.key"

echo "[*] Cleaning up intermediate files..."
rm "$CERT_DIR/server.csr" "$CERT_DIR/server.ext" "$CERT_DIR/rootCA.srl" "$CERT_DIR/rootCA.key"

echo "[*] Distributing root CA to proxy clients..."
for dest in naiveproxy/client webtunnel/client; do
  if [[ ! -d "$dest" ]]; then
    echo "Error: target directory '$dest' does not exist — is the testbed checked out?" >&2
    exit 1
  fi
  cp "$CERT_DIR/rootCA.pem" "$dest/"
  echo "    → $dest/rootCA.pem"
done

echo "[*] Installing netem delay distribution..."
if [[ ! -f "$DIST_SRC" ]]; then
  echo "Error: $DIST_SRC not found — expected alongside this script." >&2
  exit 1
fi
sudo cp "$DIST_SRC" "$DIST_DST"
echo "    → $DIST_DST"

echo "[*] Done."
