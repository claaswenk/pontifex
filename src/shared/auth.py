"""
Shared authentication primitives for every Pontifex container

``BaseAuth`` holds the mechanisms that are identical everywhere:

* user access tokens   - 5-minute HS256 JWTs, ``require_role``
* password hashing     - Argon2id
* container identity   - secret bound to the TLS certificate, ``require_container``
                         (see ``shared/container_auth.py``)

Each container (backend, frontend, database) subclasses it, names itself and
its peers, and adds only the authentication its own endpoints need.

Two separate trust paths exist on purpose:

* Anyone (external callers, the frontend's users) -> public API: user access
  token only. No container secret is involved, so the backend is usable
  independently of the frontend.
* Container -> container: signed requests and signed responses. These routes
  are never reachable with a user token and vice versa.
"""

import datetime
import os
from functools import wraps
from typing import Any, List

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import g, jsonify, request

from shared.container_auth import ContainerAuth


class BaseAuth:
    JWT_SECRET_ENV = "JWT_SECRET"
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_TTL = datetime.timedelta(minutes=5)

    # Overridden by every container.
    CONTAINER_ID = ""
    PEERS: tuple[str, ...] = ()
    REQUIRED_ENV: tuple[str, ...] = ()

    def __init__(self) -> None:
        self._hasher = PasswordHasher()
        self.container = ContainerAuth(self.CONTAINER_ID, self.PEERS)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def validate_config(self) -> None:
        """Fail fast at startup if a required env variable is missing."""
        missing: List[str] = [name for name in self.REQUIRED_ENV if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                "Missing required environment variables: " + ", ".join(missing)
            )
        self.container.validate_config()

    def init_app(self, app) -> None:
        """Attach container-level response signing to a Flask app."""
        self.container.init_app(app)

    def _jwt_secret(self) -> str:
        secret = os.environ.get(self.JWT_SECRET_ENV, "")
        if not secret:
            raise RuntimeError(f"{self.JWT_SECRET_ENV} environment variable is not set")
        return secret

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def hash_password(self, plain: str) -> str:
        """Argon2id hash with a securely generated random salt."""
        return self._hasher.hash(plain)

    def verify_password(self, plain: str, hashed: str) -> bool:
        try:
            return self._hasher.verify(hashed, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    # ------------------------------------------------------------------
    # Access tokens
    # ------------------------------------------------------------------

    def issue_access_token(self, username: str, role: str) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        payload: dict[str, Any] = {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + self.ACCESS_TOKEN_TTL,
        }
        return jwt.encode(payload, self._jwt_secret(), algorithm=self.JWT_ALGORITHM)

    def verify_access_token(self, token: str) -> dict | None:
        try:
            return jwt.decode(token, self._jwt_secret(), algorithms=[self.JWT_ALGORITHM])
        except jwt.PyJWTError:
            return None

    def is_subject_active(self, payload: dict) -> bool:
        """
        Hook: may a validly signed token still be used?
        """
        return True

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    @staticmethod
    def bearer_token() -> str | None:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[len("Bearer "):]
        return None

    @staticmethod
    def keys_match(provided: str, expected: str) -> bool:
        """Constant-time comparison that is also safe for non-ASCII input."""
        import secrets
        return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

    # ------------------------------------------------------------------
    # Checks: each returns None on success or a ready-made error response
    # ------------------------------------------------------------------

    def check_access_token(self, roles: tuple[str, ...]):
        token = self.bearer_token()
        if not token:
            return jsonify({"error": "Authorization header missing or malformed."}), 401

        payload = self.verify_access_token(token)
        if payload is None or not self.is_subject_active(payload):
            return jsonify({"error": "Unauthorized: invalid or expired access token."}), 401

        if payload.get("role") not in roles:
            return jsonify({"error": "Forbidden: insufficient role."}), 403

        g.current_user = payload
        return None

    # ------------------------------------------------------------------
    # Decorators
    # ------------------------------------------------------------------

    def require_container(self, *peers: str):
        """Only the named peer containers, proving the pair secret, may call the route."""
        return self.container.require(*peers)

    def require_role(self, *roles: str):
        """Valid user access token whose role is in ``roles``."""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                denied = self.check_access_token(roles)
                if denied is not None:
                    return denied
                return f(*args, **kwargs)
            return decorated
        return decorator
