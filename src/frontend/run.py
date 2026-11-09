"""
run.py HTTPS entry point for the Pontifex frontend

TLS configuration (mandatory)
-----------------------------
    TLS_CERT_PATH   path to the PEM certificate file
    TLS_KEY_PATH    path to the PEM private key file

The server refuses to start without a readable certificate and key, so it can
never silently fall back to plain HTTP.
"""

import logging
import os
import ssl
import sys

from app import create_app
from shared.container_auth import start_peer_monitors

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
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            log.error("%s=%s does not exist or is not readable", name, path)
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
    port = int(os.environ.get("PORT", 8443))
    tls_context = _build_tls_context()
    # Frontend -> backend: signs its requests and checks the backend's proof.
    start_peer_monitors(app.extensions["auth"].container, {
        "backend": ("BACKEND_URL", "/api/internal/ping"),
    })
    log.info("Starting Pontifex frontend on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)
