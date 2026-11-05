"""
run.py HTTPS entry point for the Pontifex backend

TLS is mandatory (see shared/tls.py): the server refuses to start without a
readable certificate and key, so it can never fall back to plain HTTP.
"""

import os
import logging

from app import create_app
from shared.tls import build_tls_context

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7337))
    tls_context = build_tls_context()
    log.info("Starting Pontifex backend on HTTPS port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=tls_context)
