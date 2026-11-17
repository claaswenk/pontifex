#!/bin/sh
# Entrypoint of every Pontifex container: creates the self-signed TLS certificate
# on the first start (it lives in a named volume), then starts the app.
#
# TLS_EXTRA_SANS  extra names for the certificate, e.g. "DNS:pontifex.local,IP:192.168.1.10".
#                 Only read when the certificate is created.

set -eu

CERT_DIR="/app/certs"
CERT_FILE="$CERT_DIR/tls.crt"
KEY_FILE="$CERT_DIR/tls.key"

echo "[INIT] Running as UID $(id -u)"

if [ ! -w "$CERT_DIR" ]; then
    echo "[ERROR] $CERT_DIR is not writable."
    exit 1
fi

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[TLS] Existing certificate found."
else
    echo "[TLS] Generating a self-signed certificate..."

    # Allow-list: only DNS:<name> and IP:<address> entries, comma separated.
    SAN="DNS:localhost,IP:127.0.0.1"
    EXTRA_SANS="${TLS_EXTRA_SANS:-}"
    if [ -n "$EXTRA_SANS" ]; then
        ENTRY='(DNS:[A-Za-z0-9.-]+|IP:[0-9A-Fa-f:.]+)'
        if ! printf '%s' "$EXTRA_SANS" | grep -Eq "^${ENTRY}(,${ENTRY})*\$"; then
            echo "[ERROR] TLS_EXTRA_SANS is invalid. Expected e.g. DNS:pontifex.local,IP:192.168.1.10"
            exit 1
        fi
        SAN="$SAN,$EXTRA_SANS"
    fi

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
        -addext "subjectAltName=$SAN"

    chmod 600 "$TEMP_KEY"
    chmod 644 "$TEMP_CERT"
    mv "$TEMP_KEY" "$KEY_FILE"
    mv "$TEMP_CERT" "$CERT_FILE"
    trap - EXIT HUP INT TERM

    echo "[TLS] Certificate created."
fi

exec "$@"
