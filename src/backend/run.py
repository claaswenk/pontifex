"""
run.py HTTPS entry point for the Pontifex backend

TLS configuration (mandatory)
-----------------------------
    TLS_CERT_PATH   path to the PEM certificate file
    TLS_KEY_PATH    path to the PEM private key file

The server refuses to start without a readable certificate and key, so it can
never silently fall back to plain HTTP.
"""

import os
import ssl
import sys
import logging

from app import create_app

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = create_app()


def _build_tls_context() -> ssl.SSLContext:
    cert_path = os.environ.get("TLS_CERT_PATH", "")
    key_path = os.environ.get("TLS_KEY_PATH", "")

    if not cert_path or not key_path:
        log.error("TLS_CERT_PATH and TLS_KEY_PATH must be set (HTTPS is mandatory)")
        sys.exit(1)

    for name, path in (("TLS_CERT_PATH", cert_path), ("TLS_KEY_PATH", key_path)):
        if not os.path.isfile(path):
            parent = os.path.dirname(path) or "."
            listing = sorted(os.listdir(parent)) if os.path.isdir(parent) else "directory missing"
            log.error(
                "%s=%s does not exist or is not a file (contents of %s: %s). "
                "Paths must be valid INSIDE the container; certificates "
                "are stored in the persistent /app/certs volume.",
                name, path, parent, listing,
            )
            sys.exit(1)
        if not os.access(path, os.R_OK):
            log.error("%s=%s is not readable by uid %d", name, path, os.getuid())
            sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    except (ssl.SSLError, OSError) as exc:
        log.error("Could not load TLS certificate/key: %s", exc)
        sys.exit(1)
    return ctx


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7337))
    tls_context = _build_tls_context()
    log.info("Starting Pontifex backend on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)
