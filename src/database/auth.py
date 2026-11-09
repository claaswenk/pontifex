"""
Database container authentication.

Only the backend may call the database, proving BACKEND_DATABASE_SECRET bound
to the TLS certificate (see shared/container_auth.py). The database knows no
users and no JWT secret.
"""

from shared.auth import BaseAuth


class DatabaseAuth(BaseAuth):
    CONTAINER_ID = "database"
    PEERS = ("backend",)

    def check_access_token(self, roles):
        """The database does not accept user tokens, only authenticated containers."""
        raise NotImplementedError("DatabaseAuth authenticates containers only.")
