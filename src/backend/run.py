"""
run.py HTTPS entry point for the Pontifex backend

TLS configuration
-----------------
    TLS_CERT_PATH   path to the PEM certificate file (required for HTTPS)
    TLS_KEY_PATH    path to the PEM private key file (required for HTTPS)
"""

import os
import ssl
import logging

from app import create_app

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = create_app()

if __name__ == "__main__":
    cert_path = os.environ.get("TLS_CERT_PATH", "")
    key_path = os.environ.get("TLS_KEY_PATH", "")

    port = int(os.environ.get("PORT", 7337))

    if cert_path and key_path:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        log.info("Starting Pontifex backend on HTTPS port %d", port)
        app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ctx)
    else:
        log.warning(
            "TLS_CERT_PATH / TLS_KEY_PATH not set starting on plain HTTP"
        )
        app.run(host="0.0.0.0", port=port, debug=False)
