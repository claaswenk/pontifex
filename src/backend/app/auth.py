"""Backend authentication: user accounts, refresh tokens and the admin bootstrap."""

import hashlib
import os
import secrets
import time
from functools import wraps

from flask import jsonify

from shared.auth import BaseAuth
from shared.errors import BootstrapConsumedError
from app.database_client import DatabaseClient
from app.services import LoginThrottle, LoginThrottled, WakeThrottle

__all__ = ["BackendAuth", "BootstrapConsumedError"]


class BackendAuth(BaseAuth):
    INITIAL_KEY_ENV = "INITIAL_API_KEY"
    MIN_INITIAL_KEY_LENGTH = 8

    # A reset token is valid once, for this long. It is never stored in clear:
    # only its SHA-256 goes to the database (it is 256 bits of randomness, so a
    # fast hash is enough).
    RESET_TOKEN_TTL_SECONDS = 900
    # Not a valid username, so it cannot collide with a real account's counter.
    _RESET_THROTTLE_KEY = "<password-reset>"

    CONTAINER_ID = "backend"
    PEERS = ("frontend", "database")
    REQUIRED_ENV = (
        BaseAuth.JWT_SECRET_ENV,
        INITIAL_KEY_ENV,
    )

    def __init__(self, database: DatabaseClient) -> None:
        super().__init__()
        self.database = database
        self.throttle = LoginThrottle()
        self.wake_throttle = WakeThrottle()
        # Verified against when the username is unknown, so that an unknown
        # name costs the same time as a wrong password.
        self._dummy_hash = self.hash_password(secrets.token_urlsafe(16))

    def validate_config(self) -> None:
        super().validate_config()
        self.database.validate_config()
        initial_key = os.environ.get(self.INITIAL_KEY_ENV, "")
        if len(initial_key) < self.MIN_INITIAL_KEY_LENGTH:
            raise RuntimeError(
                f"{self.INITIAL_KEY_ENV} must be at least {self.MIN_INITIAL_KEY_LENGTH} characters"
            )

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_bootstrap_admin(self, username: str, password: str) -> tuple[str, str]:
        """First and only admin. Returns (refresh_token, access_token)."""
        refresh_token = self.database.create_bootstrap_admin(username, self.hash_password(password))
        return refresh_token, self.issue_access_token(username, "admin")

    def create_user(self, username: str, password: str) -> None:
        """
        Add a regular user. The only admin is the bootstrap admin. The admin chose
        the password, so the user has to replace it at the first sign-in.
        """
        self.database.create_user(username, self.hash_password(password), "user", must_change=True)

    def set_password(self, username: str, password: str) -> bool:
        """The admin sets a password for somebody else: the user has to replace it."""
        return self.database.set_password(username, self.hash_password(password), must_change=True)

    def change_own_password(
        self, username: str, current: str, new: str, address: str, is_trusted_peer: bool = False
    ) -> tuple[str, str] | None:
        """
        Change a password after proving the current one. Returns a fresh
        (refresh_token, access_token), or None if the current password is wrong.

        Wrong guesses count against the same limit as the login, so a stolen
        access token cannot be used to guess the password.
        Raises ValueError if the account must change its password and the new
        one is the old one again.
        """
        self.throttle.check(username, address, is_trusted_peer)

        credentials = self.database.get_credentials(username)
        if credentials is None or not self.verify_password(current, credentials["pw_hash"]):
            self.throttle.failure(username, address, is_trusted_peer)
            return None

        self.throttle.success(username, address, is_trusted_peer)
        if credentials["must_change"] and new == current:
            raise ValueError("same password")
        # Revokes every refresh token of the user, on all devices.
        self.database.set_password(username, self.hash_password(new))
        refresh_token = self.database.create_refresh_token(username)
        return refresh_token, self.issue_access_token(username, credentials["role"])

    @staticmethod
    def _hash_reset_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_reset_token(self, username: str) -> str | None:
        """
        Issue a one-time password reset token for ``username`` (replacing any
        earlier one). Returns the token, shown only once, or None if the user
        is unknown.
        """
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + self.RESET_TOKEN_TTL_SECONDS
        if not self.database.create_reset_token(username, self._hash_reset_token(token), expires_at):
            return None
        return token

    def reset_password_with_token(
        self, token: str, new_password: str, address: str, is_trusted_peer: bool = False
    ) -> bool:
        """
        Set a new password with a reset token and end every session of the user.
        False for an unknown, used or expired token. Wrong tokens count against
        a per-address limit, so tokens cannot be guessed.
        """
        self.throttle.check(self._RESET_THROTTLE_KEY, address, is_trusted_peer)

        # Hashed before the token is looked up, so a bad token costs the same time.
        pw_hash = self.hash_password(new_password)
        if not self.database.reset_password_with_token(self._hash_reset_token(token), pw_hash):
            self.throttle.failure(self._RESET_THROTTLE_KEY, address, is_trusted_peer)
            return False
        return True

    def change_own_username(
        self, username: str, current: str, new_username: str, address: str, is_trusted_peer: bool = False
    ) -> tuple[str, str] | None:
        """
        Rename the caller's account after proving the current password. Returns a
        fresh (refresh_token, access_token) for the new name, or None if the
        current password is wrong. Raises ValueError if the new name is not
        available (taken, or the caller's own name).

        The role is never touched. Wrong guesses count against the login limit.
        """
        self.throttle.check(username, address, is_trusted_peer)

        credentials = self.database.get_credentials(username)
        if credentials is None or not self.verify_password(current, credentials["pw_hash"]):
            self.throttle.failure(username, address, is_trusted_peer)
            return None

        self.throttle.success(username, address, is_trusted_peer)
        if new_username == username:
            raise ValueError("same name")
        if not self.database.rename_user(username, new_username):
            return None
        # Revokes every old session; the old access token stops working because
        # its subject no longer exists.
        refresh_token = self.database.create_refresh_token(new_username)
        return refresh_token, self.issue_access_token(new_username, credentials["role"])

    def delete_own_account(
        self, username: str, current: str, address: str, is_trusted_peer: bool = False
    ) -> bool:
        """
        Delete the caller's account (with devices and sessions) after proving
        the current password. False if the password is wrong.

        Wrong guesses count against the same limit as the login, so a stolen
        access token cannot be used to delete an account.
        """
        self.throttle.check(username, address, is_trusted_peer)

        credentials = self.database.get_credentials(username)
        if credentials is None or not self.verify_password(current, credentials["pw_hash"]):
            self.throttle.failure(username, address, is_trusted_peer)
            return False

        self.throttle.success(username, address, is_trusted_peer)
        return self.database.delete_user(username)

    def login(
        self, username: str, password: str, address: str, is_trusted_peer: bool = False
    ) -> tuple[str, str, str, bool] | None:
        """
        Check a username and password. Returns (refresh_token, access_token, role,
        must_change), or None for every kind of failure (unknown user, wrong password).

        Raises LoginThrottled when too many attempts failed recently.
        """
        self.throttle.check(username, address, is_trusted_peer)

        credentials = self.database.get_credentials(username)
        stored_hash = credentials["pw_hash"] if credentials else self._dummy_hash
        password_ok = self.verify_password(password, stored_hash)

        if credentials is None or not password_ok:
            self.throttle.failure(username, address, is_trusted_peer)
            return None

        self.throttle.success(username, address, is_trusted_peer)
        refresh_token = self.database.create_refresh_token(credentials["username"])
        access_token = self.issue_access_token(credentials["username"], credentials["role"])
        return refresh_token, access_token, credentials["role"], credentials["must_change"]

    def logout(self, refresh_token: str) -> None:
        self.database.revoke_refresh_token(refresh_token)

    def exchange_refresh_token(self, refresh_token: str) -> str | None:
        found = self.database.get_by_refresh_token(refresh_token)
        if found is None:
            return None
        username, role = found
        return self.issue_access_token(username, role)

    def subject_state(self, payload: dict) -> str | None:
        """
        Asked on every request, so a deleted account loses access immediately and a
        password set by the admin keeps the user out of everything but the password change.
        """
        credentials = self.database.get_credentials(payload.get("sub", ""))
        if credentials is None:
            return None
        return self.SUBJECT_PASSWORD_CHANGE if credentials["must_change"] else self.SUBJECT_ACTIVE

    # ------------------------------------------------------------------
    # One-time bootstrap protection
    # ------------------------------------------------------------------

    def require_initial_api_key(self, f):
        """
        Protects create-user/admin. Callable until the first admin exists;
        afterwards 410 Gone, whatever key is presented.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if self.database.bootstrap_consumed():
                return jsonify({"error": "Bootstrap already consumed. Admin account was already created."}), 410

            expected = os.environ.get(self.INITIAL_KEY_ENV, "")
            if not expected:
                return jsonify({"error": f"Bootstrap disabled: {self.INITIAL_KEY_ENV} not set."}), 503

            token = self.bearer_token()
            if not token or not self.keys_match(token, expected):
                return jsonify({"error": "Unauthorized."}), 401

            return f(*args, **kwargs)
        return decorated
