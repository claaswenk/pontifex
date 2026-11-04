"""Backend authentication: user accounts, refresh tokens and the admin bootstrap."""

import os
from functools import wraps

from flask import jsonify

from shared.auth import BaseAuth
from app.user_store import BootstrapConsumedError, UserStore

__all__ = ["BackendAuth", "BootstrapConsumedError"]


class BackendAuth(BaseAuth):
    INITIAL_KEY_ENV = "INITIAL_API_KEY"
    REQUIRED_ENV = (
        BaseAuth.CONTAINER_KEY_ENV,
        BaseAuth.JWT_SECRET_ENV,
        INITIAL_KEY_ENV,
    )

    def __init__(self, store: UserStore) -> None:
        super().__init__()
        self.store = store

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def create_bootstrap_admin(self, username: str, password: str) -> tuple[str, str]:
        """First and only admin. Returns (refresh_token, access_token)."""
        refresh_token = self.store.create_bootstrap_admin(username, self.hash_password(password))
        return refresh_token, self.issue_access_token(username, "admin")

    def create_user(self, username: str, password: str, *, replacing_admin: str) -> tuple[str, str]:
        """Create the service user and delete the calling admin in one transaction."""
        refresh_token = self.store.create_user(
            username, self.hash_password(password), "user", replacing=replacing_admin
        )
        return refresh_token, self.issue_access_token(username, "user")

    def exchange_refresh_token(self, refresh_token: str) -> str | None:
        found = self.store.get_by_refresh_token(refresh_token)
        if found is None:
            return None
        username, role = found
        return self.issue_access_token(username, role)

    def is_subject_active(self, payload: dict) -> bool:
        """A revoked admin loses access immediately, not after the token expires."""
        return self.store.exists(payload.get("sub", ""))

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
            if self.store.bootstrap_consumed():
                return jsonify({"error": "Bootstrap already consumed. Admin account was already created."}), 410

            expected = os.environ.get(self.INITIAL_KEY_ENV, "")
            if not expected:
                return jsonify({"error": f"Bootstrap disabled: {self.INITIAL_KEY_ENV} not set."}), 503

            token = self.bearer_token()
            if not token or not self.keys_match(token, expected):
                return jsonify({"error": "Unauthorized."}), 401

            return f(*args, **kwargs)
        return decorated
