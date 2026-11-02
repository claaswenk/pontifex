from typing import Any


import os
import secrets
import datetime
from functools import wraps

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import request, jsonify, g

_ACCESS_TOKEN_TTL = datetime.timedelta(minutes=5) # 5 minutes JWT Tokens
_JWT_ALGORITHM = "HS256"
_password_hasher = PasswordHasher()
_users: dict[str, dict] = dict()

def _jwt_secret() -> str:
    """
    The HMAC secret used to sign access tokens
    """
    secret = os.environ.get("JWT_SECRET", "")
    if not secret:
        raise RuntimeError("JWT_SECRET environment variable is not set")
    return secret


def hash_password(plain: str) -> str:
    """
    Hashes a given password via Argon2. Salt is created securly by setting salt = None
    """
    return _password_hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Validates a given password hash against the database stored credentials
    """
    try:
        return _password_hasher.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _generate_token() -> str:
    """Return a cryptographically random 256-bit hex token."""
    return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# Access-token helpers
# ---------------------------------------------------------------------------

def issue_access_token(username: str, role: str) -> str:
    """
    Mint a new signed JWT access token for username / role.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    payload: dict[str, Any] = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + _ACCESS_TOKEN_TTL,
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=_JWT_ALGORITHM)


def verify_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT access token.
    """
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=[_JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

def create_user(username: str, password: str, role: str) -> tuple[str, str]:
    """
    Persist a new user and return (refresh_token, access_token).
    """
    if _username_exists(username):
        raise ValueError(f"Username '{username}' is already taken.")

    refresh_token = _generate_token()
    _users[refresh_token] = {
        "username": username,
        "pw_hash":  hash_password(password),
        "role":     role,
    }
    access_token = issue_access_token(username, role)
    return refresh_token, access_token


def exchange_refresh_token(refresh_token: str) -> str | None:
    """
    Exchange a valid refresh_token for a new 5-minute access_token.
    """
    user = _users.get(refresh_token)
    if user is None:
        return None
    return issue_access_token(user["username"], user["role"])


def _username_exists(username: str) -> bool:
    return any(u["username"] == username for u in _users.values())


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def _get_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[len("Bearer "):]
    return None


# ---------------------------------------------------------------------------
# Container-to-container identity check
# ---------------------------------------------------------------------------

def require_container_key(f):
    """
    Verify the ``X-Container-Key`` header against the CONTAINER_API_KEY env
    variable.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        expected = os.environ.get("CONTAINER_API_KEY", "")
        if not expected:
            return jsonify({"error": "CONTAINER_API_KEY not configured."}), 503

        provided = request.headers.get("X-Container-Key", "")
        if not provided or not secrets.compare_digest(provided, expected):
            return jsonify({"error": "Unauthorized: invalid container key."}), 401

        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Admin-bootstrap key (one-time, from ENV)
# ---------------------------------------------------------------------------

def require_initial_api_key(f):
    """
    Protects the admin-bootstrap endpoint.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        initial_key = os.environ.get("INITIAL_API_KEY", "")
        if not initial_key:
            return jsonify({"error": "Bootstrap disabled: INITIAL_API_KEY not set."}), 503

        token = _get_bearer_token()
        if not token or not secrets.compare_digest(token, initial_key):
            return jsonify({"error": "Unauthorized."}), 401

        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Access-token + role enforcement
# ---------------------------------------------------------------------------

def require_role(*roles: str):
    """
    Verify the JWT access token and enforce role membership.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # --- 1. Container identity ---
            expected_ck = os.environ.get("CONTAINER_API_KEY", "")
            if expected_ck:
                provided_ck = request.headers.get("X-Container-Key", "")
                if not provided_ck or not secrets.compare_digest(provided_ck, expected_ck):
                    return jsonify({"error": "Unauthorized: invalid container key."}), 401

            # --- 2. Access token ---
            token = _get_bearer_token()
            if not token:
                return jsonify({"error": "Authorization header missing or malformed."}), 401

            payload = verify_access_token(token)
            if payload is None:
                return jsonify({"error": "Unauthorized: invalid or expired access token."}), 401

            # --- 3. Role ---
            if payload.get("role") not in roles:
                return jsonify({"error": "Forbidden: insufficient role."}), 403

            g.current_user = payload
            return f(*args, **kwargs)
        return decorated
    return decorator
