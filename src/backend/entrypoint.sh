#!/bin/sh

set -eu

CERT_DIR="/app/certs"
CERT_FILE="$CERT_DIR/tls.crt"
KEY_FILE="$CERT_DIR/tls.key"

# --------------------------------------------------
# Check permissions
# --------------------------------------------------

echo "[INIT] Running as UID $(id -u)..."

mkdir -p "$CERT_DIR" /app/data

if [ ! -w "$CERT_DIR" ] || [ ! -w /app/data ]; then
    echo "[ERROR] Required directories are not writable."
    exit 1
fi

# --------------------------------------------------
# Generate individual TLS certificate if necessary
# --------------------------------------------------

echo "[TLS] Checking certificates..."

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then

    echo "[TLS] Generating new self-signed certificate..."

    TEMP_KEY="$CERT_DIR/tls.key.tmp"
    TEMP_CERT="$CERT_DIR/tls.crt.tmp"

    trap 'rm -f "$TEMP_KEY" "$TEMP_CERT"' EXIT HUP INT TERM

    umask 077

    openssl req -x509 \
        -newkey rsa:2048 \
        -sha256 \
        -days 365 \
        -noenc \
        -keyout "$TEMP_KEY" \
        -out "$TEMP_CERT" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

    chmod 600 "$TEMP_KEY"
    chmod 644 "$TEMP_CERT"

    mv "$TEMP_KEY" "$KEY_FILE"
    mv "$TEMP_CERT" "$CERT_FILE"

    trap - EXIT HUP INT TERM

    echo "[TLS] Certificate generated successfully."

else
    echo "[TLS] Existing certificate found."
fi

# --------------------------------------------------
# Start application
# --------------------------------------------------

echo "[APP] Starting Pontifex backend..."

exec "$@"
