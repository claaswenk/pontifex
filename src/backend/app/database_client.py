"""
Interface to the database container.

The backend owns no data: users, hashed refresh tokens and the bootstrap flag
belong to the database container. Until that container exists, every operation
raises NotImplementedError, so nothing that needs the database can succeed
(fail closed).

Devices are always addressed together with their owner. A device that belongs
to someone else is indistinguishable from one that does not exist.
"""


class DatabaseUnavailableError(Exception):
    """The database container is unreachable. The backend answers 503."""


class DatabaseClient:
    def validate_config(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_bootstrap_admin(self, username: str, pw_hash: str) -> str:
        """Create the first admin and consume the bootstrap atomically. Returns the refresh token."""
        raise NotImplementedError

    def create_user(self, username: str, pw_hash: str, role: str) -> None:
        """Create a user. Raises ValueError if the name is taken."""
        raise NotImplementedError

    def bootstrap_consumed(self) -> bool:
        raise NotImplementedError

    def exists(self, username: str) -> bool:
        raise NotImplementedError

    def get_credentials(self, username: str) -> dict | None:
        """``{"username": ..., "pw_hash": ..., "role": ...}`` for a login, or None if unknown."""
        raise NotImplementedError

    def list_users(self) -> list[dict]:
        """All accounts as ``[{"username": ..., "role": ...}, ...]``. Never includes hashes."""
        raise NotImplementedError

    def set_password(self, username: str, pw_hash: str) -> bool:
        """Replace the password hash and revoke every refresh token of the user. False if unknown."""
        raise NotImplementedError

    def rename_user(self, username: str, new_username: str) -> bool:
        """
        Change the name of an account. Its identity, role, password, devices stay
        as they are; every refresh token of the user is revoked.
        Raises ValueError if ``new_username`` is taken. False if ``username`` is unknown.
        """
        raise NotImplementedError

    def delete_user(self, username: str) -> bool:
        """Delete the user together with their devices and refresh tokens. False if unknown."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Refresh tokens
    # ------------------------------------------------------------------

    def get_by_refresh_token(self, refresh_token: str) -> tuple[str, str] | None:
        """Return (username, role) for a refresh token, or None if unknown."""
        raise NotImplementedError

    def create_refresh_token(self, username: str) -> str:
        """Issue a new refresh token for an existing user. Only its hash is stored."""
        raise NotImplementedError

    def revoke_refresh_token(self, refresh_token: str) -> None:
        """Forget a refresh token. Unknown tokens are ignored."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Devices (per owner)
    # ------------------------------------------------------------------

    def list_devices(self, username: str) -> list[dict]:
        """Devices owned by ``username`` as ``[{"id", "name", "address", "mac"}, ...]``."""
        raise NotImplementedError

    def get_device(self, username: str, device_id: int) -> dict | None:
        raise NotImplementedError

    def create_device(self, username: str, name: str, address: str, mac: str) -> dict:
        """Store a device for ``username``. Raises ValueError if the owner already has that name."""
        raise NotImplementedError

    def delete_device(self, username: str, device_id: int) -> bool:
        """Delete one of ``username``'s devices. False if there is no such device for that owner."""
        raise NotImplementedError
