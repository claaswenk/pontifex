"""HTTPS entry point of the Pontifex backend (TLS is mandatory, see shared/tls.py)."""

import logging
import os

from app import create_app
from shared.container_auth import start_peer_monitors
from shared.tls import build_tls_context

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7337))
    tls_context = build_tls_context()
    # Backend -> frontend and database: signs its requests and checks the
    # peer's proof.
    start_peer_monitors(app.extensions["auth"].container, {
        "frontend": ("FRONTEND_URL", "/internal/ping"),
        "database": ("DATABASE_URL", "/api/internal/ping"),
    })
    log.info("Starting Pontifex backend on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)
