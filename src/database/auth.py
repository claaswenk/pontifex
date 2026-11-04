"""
Database container authentication.

The database is internal infrastructure: it is reachable only by other
Pontifex containers, so the container key is its sole credential. It has
no users and no JWT handling, which is why it requires nothing else.
"""

from shared.auth import BaseAuth


class DatabaseAuth(BaseAuth):
    REQUIRED_ENV = (BaseAuth.CONTAINER_KEY_ENV,)

    def check_access_token(self, roles):
        """The database does not accept user tokens, only container keys."""
        raise NotImplementedError("DatabaseAuth authenticates by container key only.")
