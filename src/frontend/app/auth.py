"""
Frontend container authentication.

The frontend talks to the backend only. Both prove to each other that they hold
BACKEND_FRONTEND_SECRET, bound to the TLS certificate they actually present
(see shared/container_auth.py). The frontend does not hold the JWT secret:
a compromised frontend must not be able to forge user access tokens.
"""

from shared.auth import BaseAuth


class FrontendAuth(BaseAuth):
    CONTAINER_ID = "frontend"
    PEERS = ("backend",)
