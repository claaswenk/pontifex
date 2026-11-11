"""
Interface to the database container.

The backend owns no data: users, hashed refresh tokens and the bootstrap flag
belong to the database container. Until that container exists, every operation
raises NotImplementedError, so nothing that needs the database can succeed
(fail closed).
"""


class DatabaseUnavailableError(Exception):
    """The database container is unreachable. The backend answers 503."""


class DatabaseClient:
    def validate_config(self) -> None:
        pass

    def create_bootstrap_admin(self, username: str, pw_hash: str) -> str:
        """Create the first admin and consume the bootstrap atomically. Returns the refresh token."""
        raise NotImplementedError

    def create_user(self, username: str, pw_hash: str, role: str, *, replacing: str | None = None) -> str:
        """Create a user, optionally deleting ``replacing`` in the same transaction."""
        raise NotImplementedError

    def bootstrap_consumed(self) -> bool:
        raise NotImplementedError

    def get_by_refresh_token(self, refresh_token: str) -> tuple[str, str] | None:
        """Return (username, role) for a refresh token, or None if unknown."""
        raise NotImplementedError

    def exists(self, username: str) -> bool:
        raise NotImplementedError
