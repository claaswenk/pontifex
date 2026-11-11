"""
Database container authentication.

The database only accepts requests from the backend container via
container-to-container authentication (see shared/container_auth.py).
"""

from shared.auth import BaseAuth


class DatabaseAuth(BaseAuth):
    CONTAINER_ID = "database"
    PEERS = ("backend",)
    REQUIRED_ENV = (BaseAuth.JWT_SECRET_ENV,)

    def init_app(self, app) -> None:
        """Attach container-level response signing to a Flask app."""
        self.container.init_app(app)

    def require_backend(self, f):
        """Only the backend container may call the route."""
        return self.require_container("backend")(f)
