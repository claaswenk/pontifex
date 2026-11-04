"""
Database container authentication.
"""

from shared.auth import BaseAuth


class DatabaseAuth(BaseAuth):
    REQUIRED_ENV = (BaseAuth.CONTAINER_KEY_ENV,)

    def check_access_token(self, roles):
        """The database does not accept user tokens, only container keys."""
        raise NotImplementedError("DatabaseAuth authenticates by container key only.")
