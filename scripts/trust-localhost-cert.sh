#!/usr/bin/env bash
#
# trust-localhost-cert.sh — provision a locally-TRUSTED TLS certificate for the
# Sieve admin UI so the browser shows NO warning.
#
# Sieve serves the admin UI (port 19816) over HTTPS by default, using a
# self-signed cert it auto-generates — which works, but makes the browser warn
# once ("your connection is not private"). Run this script ONCE to replace that
# with a cert signed by mkcert's locally-trusted CA. It:
#
#   1. installs mkcert if it's missing,
#   2. registers mkcert's local CA in your system trust store (needs sudo/admin
#      — mkcert prompts for it),
#   3. writes a localhost cert to ./data/tls/admin-{cert,key}.pem — the SAME
#      paths Sieve's built-in auto-cert uses.
#
# On the next start Sieve finds the cert, sees it is CA-signed, and serves it
# with HSTS and no browser warning. Nothing else to configure.
#
# Usage:
#   ./scripts/trust-localhost-cert.sh          # uses ./data
#   SIEVE_DATA_DIR=/srv/sieve/data ./scripts/trust-localhost-cert.sh
#
set -euo pipefail

DATA_DIR="${SIEVE_DATA_DIR:-./data}"
TLS_DIR="$DATA_DIR/tls"
CERT="$TLS_DIR/admin-cert.pem"
KEY="$TLS_DIR/admin-key.pem"

echo "==> Sieve trusted-cert setup (data dir: $DATA_DIR)"

# 1. Ensure mkcert is available.
if ! command -v mkcert >/dev/null 2>&1; then
  echo "==> mkcert not found — installing..."
  if [[ "$(uname)" == "Darwin" ]]; then
    if command -v brew >/dev/null 2>&1; then
      brew install mkcert nss
    else
      echo "ERROR: Homebrew not found. Install it (https://brew.sh) then re-run," >&2
      echo "       or install mkcert manually: https://github.com/FiloSottile/mkcert#installation" >&2
      exit 1
    fi
  elif command -v apt-get >/dev/null 2>&1; then
    echo "    (installing libnss3-tools + mkcert via apt; needs sudo)"
    sudo apt-get update
    if ! sudo apt-get install -y libnss3-tools mkcert; then
      echo "ERROR: apt could not install mkcert (not in all repos)." >&2
      echo "       Install it manually: https://github.com/FiloSottile/mkcert#installation" >&2
      exit 1
    fi
  else
    echo "ERROR: no supported package manager detected. Install mkcert manually:" >&2
    echo "       https://github.com/FiloSottile/mkcert#installation" >&2
    exit 1
  fi
fi

# 2. Register mkcert's local CA in the system trust store (idempotent).
echo "==> Registering mkcert local CA (may prompt for your password)..."
mkcert -install

# 3. Issue the localhost cert into Sieve's conventional TLS path.
mkdir -p "$TLS_DIR"
echo "==> Issuing certificate for localhost / 127.0.0.1 / ::1 ..."
mkcert -cert-file "$CERT" -key-file "$KEY" localhost 127.0.0.1 ::1
chmod 600 "$KEY"
chmod 644 "$CERT"

echo
echo "==> Done. Trusted certificate written:"
echo "      cert: $CERT"
echo "      key:  $KEY"
echo
echo "Restart Sieve. The admin UI will serve HTTPS at https://localhost:19816"
echo "with no browser warning."
