"""
TLS server context shared by every container.

    TLS_CERT_PATH   path to the PEM certificate file
    TLS_KEY_PATH    path to the PEM private key file

A container refuses to start without a readable certificate and key, so it can
never silently fall back to plain HTTP.
"""

import logging
import os
import ssl
import sys

log = logging.getLogger(__name__)


def build_tls_context() -> ssl.SSLContext:
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
