#!/bin/sh

set -eu

CERT_DIR="/app/certs"
CERT_FILE="$CERT_DIR/tls.crt"
KEY_FILE="$CERT_DIR/tls.key"

# Subject alternative names of the generated certificate. Containers that are
# reached by another container under a service name add that name here.
TLS_SAN="${TLS_SAN:-DNS:localhost,IP:127.0.0.1}"

# --------------------------------------------------
# Check permissions
# --------------------------------------------------

echo "[INIT] Running as UID $(id -u)..."

mkdir -p "$CERT_DIR"

if [ ! -w "$CERT_DIR" ]; then
    echo "[ERROR] $CERT_DIR is not writable."
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
        -addext "subjectAltName=$TLS_SAN"

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
# Publish the PUBLIC certificate so that other containers
# can pin it, e.g. the backend verifying the database.
# --------------------------------------------------

if [ -n "${TLS_PUBLISH_DIR:-}" ]; then
    if [ ! -w "$TLS_PUBLISH_DIR" ]; then
        echo "[ERROR] $TLS_PUBLISH_DIR is not writable."
        exit 1
    fi
    cp "$CERT_FILE" "$TLS_PUBLISH_DIR/tls.crt"
    chmod 644 "$TLS_PUBLISH_DIR/tls.crt"
    echo "[TLS] Public certificate published to $TLS_PUBLISH_DIR."
fi

# --------------------------------------------------
# Start application
# --------------------------------------------------

echo "[APP] Starting Pontifex..."

exec "$@"
