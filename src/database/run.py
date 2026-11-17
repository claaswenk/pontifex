"""HTTPS entry point of the Pontifex database (TLS is mandatory, see shared/tls.py)."""

import logging
import os

from app import create_app
from shared.container_auth import start_peer_monitors
from shared.tls import build_tls_context

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 13110))
    tls_context = build_tls_context()
    # Database -> backend: signs its requests and checks the backend's proof.
    start_peer_monitors(app.extensions["auth"].container, {
        "backend": ("BACKEND_URL", "/api/internal/ping"),
    })
    log.info("Starting Pontifex database on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)
