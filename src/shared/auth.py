"""
Shared authentication primitives for every Pontifex container

``BaseAuth`` holds the mechanisms that are identical everywhere:

* container identity  - ``X-Container-Key`` header vs. ``CONTAINER_API_KEY`` env
* password hashing    - Argon2id
* access tokens       - 5-minute HS256 JWTs
* request decorators  - ``require_container_key`` and ``require_role``

Each container (backend, frontend, database) subclasses it and adds only the
authentication its own endpoints need.
"""

import datetime
import os
import secrets
from functools import wraps
from typing import Any, List

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import g, jsonify, request


class BaseAuth:
    CONTAINER_KEY_ENV = "CONTAINER_API_KEY"
    CONTAINER_KEY_HEADER = "X-Container-Key"
    JWT_SECRET_ENV = "JWT_SECRET"
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_TTL = datetime.timedelta(minutes=5)

    REQUIRED_ENV: tuple[str, ...] = (CONTAINER_KEY_ENV,)

    def __init__(self) -> None:
        self._hasher = PasswordHasher()

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
        return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

    # ------------------------------------------------------------------
    # Checks: each returns None on success or a ready-made error response
    # ------------------------------------------------------------------

    def check_container_key(self):
        """Fail-closed: a container without a configured key rejects everything."""
        expected = os.environ.get(self.CONTAINER_KEY_ENV, "")
        if not expected:
            return jsonify({"error": f"{self.CONTAINER_KEY_ENV} not configured."}), 503

        provided = request.headers.get(self.CONTAINER_KEY_HEADER, "")
        if not provided or not self.keys_match(provided, expected):
            return jsonify({"error": "Unauthorized: invalid container key."}), 401
        return None

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

    def require_container_key(self, f):
        """Only requests carrying this container's key may pass."""
        @wraps(f)
        def decorated(*args, **kwargs):
            denied = self.check_container_key()
            if denied is not None:
                return denied
            return f(*args, **kwargs)
        return decorated

    def require_role(self, *roles: str):
        """Container key + valid access token whose role is in ``roles``."""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                denied = self.check_container_key()
                if denied is None:
                    denied = self.check_access_token(roles)
                if denied is not None:
                    return denied
                return f(*args, **kwargs)
            return decorated
        return decorator
