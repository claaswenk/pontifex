"""
Interface to the database container.

The backend owns no data: users, hashed refresh tokens and the bootstrap flag
belong to the database container. Every operation is one signed request to it
(see shared/container_auth.py). The client creates and hashes the tokens, so the
container only ever sees hashes, and it never sees a password, only its Argon2 hash.

Fail closed: when the database cannot be reached, does not prove who it is, or
answers with something unexpected, the operation raises DatabaseUnavailableError
(HTTP 503) and nobody is let in.

Devices are always addressed together with their owner. A device that belongs
to someone else is indistinguishable from one that does not exist.
"""

import hashlib
import logging
import os
import secrets
import time
from urllib.parse import quote

from shared.container_auth import ContainerAuthError, ContainerClient, ContainerUnavailableError
from shared.errors import BootstrapConsumedError

log = logging.getLogger(__name__)

# How long a refresh token stays valid.
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60


class DatabaseUnavailableError(Exception):
    """The database container is unreachable. The backend answers 503."""


def _hash_token(token: str) -> str:
    """Refresh tokens are 256 bits of randomness, so a fast hash is enough."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _owner(username: str) -> str:
    return quote(username, safe="")


class DatabaseClient:
    def __init__(self, client: ContainerClient | None = None) -> None:
        self._client = client

    def validate_config(self) -> None:
        pass

    def connect(self, container_auth) -> None:
        """Reach the database container with the backend's container identity."""
        url = os.environ.get("DATABASE_URL", "")
        if not url:
            log.warning("DATABASE_URL is not set: every operation that needs the database is refused")
            return
        self._client = container_auth.client("database", url)

    # ------------------------------------------------------------------
    # One round trip
    # ------------------------------------------------------------------

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        if self._client is None:
            raise DatabaseUnavailableError()
        try:
            status, data = self._client.request(method, path, body)
        except ContainerAuthError as exc:
            log.error("Database could not be verified: %s", exc)
            raise DatabaseUnavailableError() from exc
        except ContainerUnavailableError as exc:
            log.error("Database unavailable: %s", exc)
            raise DatabaseUnavailableError() from exc
        if status >= 500:
            log.error("Database answered %s for %s %s", status, method, path)
            raise DatabaseUnavailableError()
        return status, data

    def _expect(self, status: int, wanted: tuple[int, ...], method: str, path: str) -> None:
        """Anything the contract does not name is a fault of the database, not a result."""
        if status not in wanted:
            log.error("Database answered unexpected status %s for %s %s", status, method, path)
            raise DatabaseUnavailableError()

    @staticmethod
    def _fault(what: str):
        log.error("Database sent an unusable answer: %s", what)
        raise DatabaseUnavailableError()

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_bootstrap_admin(self, username: str, pw_hash: str) -> str:
        """Create the first admin and consume the bootstrap atomically. Returns the refresh token."""
        token = secrets.token_urlsafe(32)
        status, _ = self._call("POST", "/api/bootstrap", {
            "username": username, "pw_hash": pw_hash, "token_hash": _hash_token(token),
            "expires_at": int(time.time()) + REFRESH_TOKEN_TTL_SECONDS,
        })
        if status == 410:
            raise BootstrapConsumedError()
        if status == 409:
            raise ValueError("username taken")
        self._expect(status, (201,), "POST", "/api/bootstrap")
        return token

    def create_user(self, username: str, pw_hash: str, role: str, must_change: bool = False) -> None:
        """Create a user. Raises ValueError if the name is taken."""
        status, _ = self._call("POST", "/api/accounts", {
            "username": username, "pw_hash": pw_hash, "role": role, "must_change": must_change,
        })
        if status == 409:
            raise ValueError("username taken")
        self._expect(status, (201,), "POST", "/api/accounts")

    def bootstrap_consumed(self) -> bool:
        status, data = self._call("GET", "/api/bootstrap")
        self._expect(status, (200,), "GET", "/api/bootstrap")
        if not isinstance(data.get("consumed"), bool):
            self._fault("bootstrap state")
        return data["consumed"]

    def exists(self, username: str) -> bool:
        return self.get_credentials(username) is not None

    def get_credentials(self, username: str) -> dict | None:
        """
        ``{"username", "pw_hash", "role", "must_change"}`` for a login, or None if unknown.
        ``must_change`` is True while the password was chosen by somebody else.
        """
        status, data = self._call("POST", "/api/accounts/lookup", {"username": username})
        if status == 404:
            return None
        self._expect(status, (200,), "POST", "/api/accounts/lookup")
        name, pw_hash, role = data.get("username"), data.get("pw_hash"), data.get("role")
        must_change = data.get("must_change")
        if not (isinstance(name, str) and isinstance(pw_hash, str) and role in ("admin", "user")
                and isinstance(must_change, bool)):
            self._fault("credentials")
        return {"username": name, "pw_hash": pw_hash, "role": role, "must_change": must_change}

    def list_users(self) -> list[dict]:
        """All accounts as ``[{"username": ..., "role": ...}, ...]``. Never includes hashes."""
        status, data = self._call("GET", "/api/accounts")
        self._expect(status, (200,), "GET", "/api/accounts")
        users = data.get("users")
        if not isinstance(users, list) or not all(
            isinstance(u, dict) and isinstance(u.get("username"), str) and u.get("role") in ("admin", "user")
            for u in users
        ):
            self._fault("user list")
        return [{"username": u["username"], "role": u["role"]} for u in users]

    def set_password(self, username: str, pw_hash: str, must_change: bool = False) -> bool:
        """Replace the password hash and revoke every refresh token of the user. False if unknown."""
        status, _ = self._call("POST", "/api/accounts/password",
                               {"username": username, "pw_hash": pw_hash, "must_change": must_change})
        if status == 404:
            return False
        self._expect(status, (200,), "POST", "/api/accounts/password")
        return True

    def create_reset_token(self, username: str, token_hash: str, expires_at: int) -> bool:
        """
        Store the hash of a one-time password reset token (valid until the unix
        time ``expires_at``), replacing any earlier unused one of the user.
        False if the user is unknown.
        """
        status, _ = self._call("POST", "/api/reset-tokens", {
            "username": username, "token_hash": token_hash, "expires_at": expires_at,
        })
        if status == 404:
            return False
        self._expect(status, (201,), "POST", "/api/reset-tokens")
        return True

    def reset_password_with_token(self, token_hash: str, pw_hash: str) -> bool:
        """
        Atomically: if the token is known and not expired, replace the owner's
        password hash, revoke all their refresh tokens and forget the token
        (single use). False for an unknown, used or expired token.
        set_password, rename_user and delete_user also forget the user's reset token.
        """
        status, _ = self._call("POST", "/api/reset-tokens/use",
                               {"token_hash": token_hash, "pw_hash": pw_hash})
        if status == 404:
            return False
        self._expect(status, (200,), "POST", "/api/reset-tokens/use")
        return True

    def rename_user(self, username: str, new_username: str) -> bool:
        """
        Change the name of an account. Its identity, role, password, devices stay
        as they are; every refresh token of the user is revoked.
        Raises ValueError if ``new_username`` is taken. False if ``username`` is unknown.
        """
        status, _ = self._call("POST", "/api/accounts/rename",
                               {"username": username, "new_username": new_username})
        if status == 409:
            raise ValueError("username taken")
        if status == 404:
            return False
        self._expect(status, (200,), "POST", "/api/accounts/rename")
        return True

    def delete_user(self, username: str) -> bool:
        """Delete the user together with their devices and refresh tokens. False if unknown."""
        path = f"/api/accounts/{_owner(username)}"
        status, _ = self._call("DELETE", path)
        if status == 404:
            return False
        self._expect(status, (200,), "DELETE", path)
        return True

    # ------------------------------------------------------------------
    # Refresh tokens
    # ------------------------------------------------------------------

    def get_by_refresh_token(self, refresh_token: str) -> tuple[str, str] | None:
        """Return (username, role) for a refresh token, or None if unknown."""
        status, data = self._call("POST", "/api/tokens/lookup", {"token_hash": _hash_token(refresh_token)})
        if status == 404:
            return None
        self._expect(status, (200,), "POST", "/api/tokens/lookup")
        name, role = data.get("username"), data.get("role")
        if not (isinstance(name, str) and role in ("admin", "user")):
            self._fault("token owner")
        return name, role

    def create_refresh_token(self, username: str) -> str:
        """Issue a new refresh token for an existing user. Only its hash is stored."""
        token = secrets.token_urlsafe(32)
        status, _ = self._call("POST", "/api/tokens", {
            "username": username, "token_hash": _hash_token(token),
            "expires_at": int(time.time()) + REFRESH_TOKEN_TTL_SECONDS,
        })
        if status == 404:
            raise ValueError("unknown user")
        self._expect(status, (201,), "POST", "/api/tokens")
        return token

    def revoke_refresh_token(self, refresh_token: str) -> None:
        """Forget a refresh token. Unknown tokens are ignored."""
        status, _ = self._call("POST", "/api/tokens/revoke", {"token_hash": _hash_token(refresh_token)})
        self._expect(status, (200,), "POST", "/api/tokens/revoke")

    # ------------------------------------------------------------------
    # Devices (per owner)
    # ------------------------------------------------------------------

    def _device(self, data) -> dict:
        """``picture`` is the version of the device's picture, None if it has none."""
        if not (isinstance(data, dict) and isinstance(data.get("id"), int)
                and all(isinstance(data.get(k), str) for k in ("name", "address", "mac"))
                and (data.get("picture") is None or isinstance(data["picture"], int))):
            self._fault("device")
        return {k: data[k] for k in ("id", "name", "address", "mac", "picture")}

    def list_devices(self, username: str) -> list[dict]:
        """Devices owned by ``username`` as ``[{"id", "name", "address", "mac"}, ...]``."""
        path = f"/api/owners/{_owner(username)}/devices"
        status, data = self._call("GET", path)
        self._expect(status, (200,), "GET", path)
        devices = data.get("devices")
        if not isinstance(devices, list):
            self._fault("device list")
        return [self._device(d) for d in devices]

    def get_device(self, username: str, device_id: int) -> dict | None:
        path = f"/api/owners/{_owner(username)}/devices/{int(device_id)}"
        status, data = self._call("GET", path)
        if status == 404:
            return None
        self._expect(status, (200,), "GET", path)
        return self._device(data.get("device"))

    def create_device(self, username: str, name: str, address: str, mac: str,
                      image: str | None = None) -> dict:
        """
        Store a device for ``username``, with its picture (base64) if there is one.
        Raises ValueError if the owner already has that name.
        """
        path = f"/api/owners/{_owner(username)}/devices"
        body = {"name": name, "address": address, "mac": mac}
        if image is not None:
            body["image"] = image
        status, data = self._call("POST", path, body)
        if status in (404, 409):
            raise ValueError("name taken" if status == 409 else "unknown user")
        self._expect(status, (201,), "POST", path)
        return self._device(data.get("device"))

    def update_device(self, username: str, device_id: int, name: str, address: str,
                      mac: str) -> dict | None:
        """
        Change name, address and MAC of one of ``username``'s devices (the picture stays).
        None if there is no such device for that owner, ValueError if the name is taken.
        """
        path = f"/api/owners/{_owner(username)}/devices/{int(device_id)}"
        status, data = self._call("PUT", path, {"name": name, "address": address, "mac": mac})
        if status == 404:
            return None
        if status == 409:
            raise ValueError("name taken")
        self._expect(status, (200,), "PUT", path)
        return self._device(data.get("device"))

    def delete_device(self, username: str, device_id: int) -> bool:
        """Delete one of ``username``'s devices. False if there is no such device for that owner."""
        path = f"/api/owners/{_owner(username)}/devices/{int(device_id)}"
        status, _ = self._call("DELETE", path)
        if status == 404:
            return False
        self._expect(status, (200,), "DELETE", path)
        return True

    # ------------------------------------------------------------------
    # Pictures. ``image`` is base64 text; the database checks the bytes.
    # ------------------------------------------------------------------

    def _picture_in(self, path: str) -> dict | None:
        status, data = self._call("GET", path)
        if status == 404:
            return None
        self._expect(status, (200,), "GET", path)
        media, image, version = data.get("media_type"), data.get("image"), data.get("version")
        if not (isinstance(media, str) and isinstance(image, str) and isinstance(version, int)):
            self._fault("picture")
        return {"media_type": media, "image": image, "version": version}

    def _picture_out(self, path: str, image: str) -> int | None:
        """The new version, None if the target is unknown. ValueError if the image is refused."""
        status, data = self._call("PUT", path, {"image": image})
        if status == 404:
            return None
        if status == 400:
            raise ValueError(data.get("error") if isinstance(data.get("error"), str) else "bad image")
        self._expect(status, (200,), "PUT", path)
        if not isinstance(data.get("version"), int):
            self._fault("picture version")
        return data["version"]

    def _picture_gone(self, path: str) -> bool:
        status, _ = self._call("DELETE", path)
        if status == 404:
            return False
        self._expect(status, (200,), "DELETE", path)
        return True

    def get_device_picture(self, username: str, device_id: int) -> dict | None:
        return self._picture_in(f"/api/owners/{_owner(username)}/devices/{int(device_id)}/picture")

    def set_device_picture(self, username: str, device_id: int, image: str) -> int | None:
        return self._picture_out(f"/api/owners/{_owner(username)}/devices/{int(device_id)}/picture", image)

    def delete_device_picture(self, username: str, device_id: int) -> bool:
        return self._picture_gone(f"/api/owners/{_owner(username)}/devices/{int(device_id)}/picture")

    def get_user_picture(self, username: str) -> dict | None:
        return self._picture_in(f"/api/accounts/{_owner(username)}/picture")

    def get_user_picture_version(self, username: str) -> int | None:
        path = f"/api/accounts/{_owner(username)}/picture/version"
        status, data = self._call("GET", path)
        self._expect(status, (200,), "GET", path)
        version = data.get("version")
        if version is not None and not isinstance(version, int):
            self._fault("picture version")
        return version

    def set_user_picture(self, username: str, image: str) -> int | None:
        return self._picture_out(f"/api/accounts/{_owner(username)}/picture", image)

    def delete_user_picture(self, username: str) -> bool:
        return self._picture_gone(f"/api/accounts/{_owner(username)}/picture")
