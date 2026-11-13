"""Backend authentication: user accounts, refresh tokens and the admin bootstrap."""

import os
import secrets
from functools import wraps

from flask import jsonify

from shared.auth import BaseAuth
from shared.errors import BootstrapConsumedError
from app.database_client import DatabaseClient
from app.services import LoginThrottle, LoginThrottled

__all__ = ["BackendAuth", "BootstrapConsumedError"]


class BackendAuth(BaseAuth):
    INITIAL_KEY_ENV = "INITIAL_API_KEY"

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
        # Verified against when the username is unknown, so that an unknown
        # name costs the same time as a wrong password.
        self._dummy_hash = self.hash_password(secrets.token_urlsafe(16))

    def validate_config(self) -> None:
        super().validate_config()
        self.database.validate_config()

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_bootstrap_admin(self, username: str, password: str) -> tuple[str, str]:
        """First and only admin. Returns (refresh_token, access_token)."""
        refresh_token = self.database.create_bootstrap_admin(username, self.hash_password(password))
        return refresh_token, self.issue_access_token(username, "admin")

    def create_user(self, username: str, password: str) -> None:
        """Add a regular user. The only admin is the bootstrap admin."""
        self.database.create_user(username, self.hash_password(password), "user")

    def set_password(self, username: str, password: str) -> bool:
        return self.database.set_password(username, self.hash_password(password))

    def change_own_password(
        self, username: str, current: str, new: str, address: str
    ) -> tuple[str, str] | None:
        """
        Change a password after proving the current one. Returns a fresh
        (refresh_token, access_token), or None if the current password is wrong.

        Wrong guesses count against the same limit as the login, so a stolen
        access token cannot be used to guess the password.
        """
        self.throttle.check(username, address)

        credentials = self.database.get_credentials(username)
        if credentials is None or not self.verify_password(current, credentials["pw_hash"]):
            self.throttle.failure(username, address)
            return None

        self.throttle.success(username, address)
        # Revokes every refresh token of the user, on all devices.
        self.database.set_password(username, self.hash_password(new))
        refresh_token = self.database.create_refresh_token(username)
        return refresh_token, self.issue_access_token(username, credentials["role"])

    def delete_own_account(self, username: str, current: str, address: str) -> bool:
        """
        Delete the caller's account (with devices and sessions) after proving
        the current password. False if the password is wrong.

        Wrong guesses count against the same limit as the login, so a stolen
        access token cannot be used to delete an account.
        """
        self.throttle.check(username, address)

        credentials = self.database.get_credentials(username)
        if credentials is None or not self.verify_password(current, credentials["pw_hash"]):
            self.throttle.failure(username, address)
            return False

        self.throttle.success(username, address)
        return self.database.delete_user(username)

    def login(self, username: str, password: str, address: str) -> tuple[str, str, str] | None:
        """
        Check a username and password. Returns (refresh_token, access_token, role),
        or None for every kind of failure (unknown user, wrong password).

        Raises LoginThrottled when too many attempts failed recently.
        """
        self.throttle.check(username, address)

        credentials = self.database.get_credentials(username)
        stored_hash = credentials["pw_hash"] if credentials else self._dummy_hash
        password_ok = self.verify_password(password, stored_hash)

        if credentials is None or not password_ok:
            self.throttle.failure(username, address)
            return None

        self.throttle.success(username, address)
        refresh_token = self.database.create_refresh_token(credentials["username"])
        access_token = self.issue_access_token(credentials["username"], credentials["role"])
        return refresh_token, access_token, credentials["role"]

    def logout(self, refresh_token: str) -> None:
        self.database.revoke_refresh_token(refresh_token)

    def exchange_refresh_token(self, refresh_token: str) -> str | None:
        found = self.database.get_by_refresh_token(refresh_token)
        if found is None:
            return None
        username, role = found
        return self.issue_access_token(username, role)

    def is_subject_active(self, payload: dict) -> bool:
        """A revoked admin loses access immediately, not after the token expires."""
        return self.database.exists(payload.get("sub", ""))

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
