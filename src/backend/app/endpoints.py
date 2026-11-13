import logging
import re

from flask import Blueprint, jsonify, request, g
from app.auth import BackendAuth, BootstrapConsumedError
from app.services import (
    ADDRESS_RULE,
    MAC_RULE,
    MAX_DEVICES_PER_USER,
    NAME_RULE,
    LoginThrottled,
    WakeUnavailableError,
    check_devices,
    normalize_mac,
    process_pontifex_logic,
    request_wake,
    system_stats,
    valid_address,
    valid_name,
)

logger = logging.getLogger(__name__)

MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 1024
MIN_PASSWORD_LENGTH = 12

# Lower case only, so "Anna" and "anna" cannot be two accounts; the character
# set also keeps the name safe to use as a URL path segment.
USERNAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
USERNAME_RULE = "Username must be 3-64 characters: lower case letters, digits, '.', '_' or '-'."
PASSWORD_RULE = f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters."


def _normalized_username(value) -> str | None:
    """The canonical form of a username, or None if it is not a valid one."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    return name if USERNAME_PATTERN.fullmatch(name) else None


def _valid_new_password(value) -> bool:
    return isinstance(value, str) and MIN_PASSWORD_LENGTH <= len(value) <= MAX_PASSWORD_LENGTH


def create_api_blueprint(auth: BackendAuth) -> Blueprint:
    api_bp = Blueprint("api", __name__)

    # -----------------------------------------------------------------------
    # Health  (public, no auth required)
    # -----------------------------------------------------------------------

    @api_bp.route("/health", methods=["GET"])
    def health_check():
        return jsonify({"status": "healthy", "service": "pontifex-backend"}), 200

    # -----------------------------------------------------------------------
    # GET /api/internal/ping  (frontend only: mutual container authentication)
    # Not part of the public API. Outsiders get a bare 401 without any proof.
    # -----------------------------------------------------------------------

    @api_bp.route("/internal/ping", methods=["GET"])
    @auth.require_container("frontend")
    def internal_ping():
        return jsonify({"status": "ok", "service": "pontifex-backend"}), 200

    # -----------------------------------------------------------------------
    # GET /api/monitoring  (resource usage of the host running the backend)
    # Needs a token: CPU/RAM/disk figures are reconnaissance data.
    # -----------------------------------------------------------------------

    @api_bp.route("/monitoring", methods=["GET"])
    @auth.require_role("admin", "user")
    def monitoring():
        return jsonify({"status": "ok", "service": "pontifex-backend", "stats": system_stats()}), 200

    # -----------------------------------------------------------------------
    # GET /api/metrics  (online/offline state of the caller's own devices)
    # The device list comes from the database, never from the request, so
    # callers cannot make the backend probe arbitrary addresses.
    # -----------------------------------------------------------------------

    @api_bp.route("/metrics", methods=["GET"])
    @auth.require_role("admin", "user")
    def metrics():
        devices = auth.database.list_devices(g.current_user["sub"])
        results = check_devices(devices)
        online = sum(1 for d in results if d["status"] == "online")
        return jsonify({
            "devices": results,
            "summary": {"total": len(results), "online": online, "offline": len(results) - online},
        }), 200

    # -----------------------------------------------------------------------
    # POST /api/login  (username + password -> refresh and access token)
    # Every failure answers the same 401, so nobody learns which names exist.
    # -----------------------------------------------------------------------

    @api_bp.route("/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username")
        password = data.get("password")

        if (
            not isinstance(username, str) or not isinstance(password, str)
            or not username.strip() or not password
            or len(username) > MAX_USERNAME_LENGTH or len(password) > MAX_PASSWORD_LENGTH
        ):
            return jsonify({"error": "Invalid username or password."}), 401

        try:
            result = auth.login(username.strip().lower(), password, request.remote_addr or "unknown")
        except LoginThrottled as exc:
            logger.warning("Login throttled")
            response = jsonify({"error": "Too many failed attempts. Try again later."})
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429

        if result is None:
            return jsonify({"error": "Invalid username or password."}), 401

        refresh_token, access_token, role = result
        return jsonify({
            "refresh_token": refresh_token,
            "access_token":  access_token,
            "expires_in":    300,
            "role":          role,
        }), 200

    # -----------------------------------------------------------------------
    # POST /api/logout  (revokes the refresh token; unknown tokens are ignored)
    # -----------------------------------------------------------------------

    @api_bp.route("/logout", methods=["POST"])
    def logout():
        data = request.get_json(silent=True) or {}
        refresh_token = data.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            return jsonify({"error": "Field 'refresh_token' is required."}), 400
        auth.logout(refresh_token)
        return jsonify({"status": "ok"}), 200

    # -----------------------------------------------------------------------
    # GET /api/me
    # -----------------------------------------------------------------------

    @api_bp.route("/me", methods=["GET"])
    @auth.require_role("admin", "user")
    def me():
        return jsonify({
            "username": g.current_user["sub"],
            "role":     g.current_user["role"],
            "token_expires_at": g.current_user["exp"],
        }), 200

    # -----------------------------------------------------------------------
    # POST /api/token
    # -----------------------------------------------------------------------

    @api_bp.route("/token", methods=["POST"])
    def get_access_token():
        data = request.get_json(silent=True) or {}
        refresh_token = data.get("refresh_token", "")

        if not refresh_token:
            return jsonify({"error": "Field 'refresh_token' is required."}), 400

        access_token = auth.exchange_refresh_token(refresh_token)
        if access_token is None:
            return jsonify({"error": "Unauthorized: unknown refresh token."}), 401

        return jsonify({"access_token": access_token, "expires_in": 300}), 200

    # -----------------------------------------------------------------------
    # Process (existing stub - requires a valid access token)
    # -----------------------------------------------------------------------

    @api_bp.route("/process", methods=["POST"])
    @auth.require_role("admin", "user")
    def process_data():
        result = process_pontifex_logic()
        return jsonify({"success": True, "data": result}), 200

    # -----------------------------------------------------------------------
    # POST /api/create-user/admin
    # -----------------------------------------------------------------------

    @api_bp.route("/create-user/admin", methods=["POST"])
    @auth.require_initial_api_key
    def create_admin_user():
        data = request.get_json(silent=True) or {}

        username = _normalized_username(data.get("username"))
        password = data.get("password")

        if username is None:
            return jsonify({"error": USERNAME_RULE}), 400
        if not _valid_new_password(password):
            return jsonify({"error": PASSWORD_RULE}), 400

        try:
            refresh_token, access_token = auth.create_bootstrap_admin(username, password)
        except BootstrapConsumedError:
            return jsonify({"error": "Bootstrap already consumed. Admin account was already created."}), 410
        except ValueError:
            logger.exception("Failed to create admin user")
            return jsonify({"error": "Unable to create admin user."}), 409

        return jsonify({
            "refresh_token": refresh_token,
            "access_token":  access_token,
            "expires_in":    300,
            "role":          "admin",
        }), 201

    # -----------------------------------------------------------------------
    # User management (admin only). There is exactly one admin, created by the
    # bootstrap; everybody else is a regular user.
    # -----------------------------------------------------------------------

    @api_bp.route("/users", methods=["GET"])
    @auth.require_role("admin")
    def list_users():
        return jsonify({"users": auth.database.list_users()}), 200

    @api_bp.route("/users", methods=["POST"])
    @auth.require_role("admin")
    def create_user():
        data = request.get_json(silent=True) or {}
        username = _normalized_username(data.get("username"))
        password = data.get("password")

        if username is None:
            return jsonify({"error": USERNAME_RULE}), 400
        if not _valid_new_password(password):
            return jsonify({"error": PASSWORD_RULE}), 400

        try:
            auth.create_user(username, password)
        except ValueError:
            return jsonify({"error": "Unable to create user with the provided input."}), 409

        return jsonify({"username": username, "role": "user"}), 201

    @api_bp.route("/users/<username>", methods=["PUT"])
    @auth.require_role("admin")
    def reset_user_password(username):
        data = request.get_json(silent=True) or {}
        password = data.get("password")

        if _normalized_username(username) != username:
            return jsonify({"error": "User not found."}), 404
        if username == g.current_user["sub"]:
            return jsonify({"error": "Use PUT /api/me/password to change your own password."}), 409
        if not _valid_new_password(password):
            return jsonify({"error": PASSWORD_RULE}), 400

        if not auth.set_password(username, password):
            return jsonify({"error": "User not found."}), 404
        return jsonify({"username": username}), 200

    @api_bp.route("/users/<username>", methods=["DELETE"])
    @auth.require_role("admin")
    def delete_user(username):
        if _normalized_username(username) != username:
            return jsonify({"error": "User not found."}), 404
        if username == g.current_user["sub"]:
            return jsonify({"error": "You cannot delete your own account."}), 409

        target = auth.database.get_credentials(username)
        if target is None:
            return jsonify({"error": "User not found."}), 404
        if target["role"] == "admin":
            return jsonify({"error": "The admin account cannot be deleted."}), 409

        if not auth.database.delete_user(username):
            return jsonify({"error": "User not found."}), 404
        return jsonify({"username": username}), 200

    # -----------------------------------------------------------------------
    # PUT /api/me/password  (any signed-in user, needs the current password)
    # Revokes all refresh tokens, so a fresh pair is returned to stay signed in.
    # -----------------------------------------------------------------------

    @api_bp.route("/me/password", methods=["PUT"])
    @auth.require_role("admin", "user")
    def change_own_password():
        data = request.get_json(silent=True) or {}
        current = data.get("current_password")
        new = data.get("new_password")

        if not isinstance(current, str) or not current or len(current) > MAX_PASSWORD_LENGTH:
            return jsonify({"error": "Current password is wrong."}), 403
        if not _valid_new_password(new):
            return jsonify({"error": PASSWORD_RULE}), 400

        try:
            tokens = auth.change_own_password(
                g.current_user["sub"], current, new, request.remote_addr or "unknown"
            )
        except LoginThrottled as exc:
            logger.warning("Password change throttled")
            response = jsonify({"error": "Too many failed attempts. Try again later."})
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429

        if tokens is None:
            return jsonify({"error": "Current password is wrong."}), 403

        refresh_token, access_token = tokens
        return jsonify({
            "refresh_token": refresh_token,
            "access_token":  access_token,
            "expires_in":    300,
        }), 200

    # -----------------------------------------------------------------------
    # PATCH /api/me  (any signed-in user, needs the current password)
    # Changes the username. The role can never be changed: not here, not by the
    # user. Ends all sessions, so a fresh token pair for the new name is returned.
    # -----------------------------------------------------------------------

    @api_bp.route("/me", methods=["PATCH"])
    @auth.require_role("admin", "user")
    def update_own_account():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "A JSON object is required."}), 400

        if "role" in data:
            return jsonify({"error": "The role cannot be changed."}), 403
        unknown = set(data) - {"username", "current_password"}
        if unknown:
            return jsonify({"error": "Only 'username' can be changed."}), 400
        if "username" not in data:
            return jsonify({"error": "Field 'username' is required."}), 400

        new_username = _normalized_username(data.get("username"))
        if new_username is None:
            return jsonify({"error": USERNAME_RULE}), 400

        current = data.get("current_password")
        if not isinstance(current, str) or not current or len(current) > MAX_PASSWORD_LENGTH:
            return jsonify({"error": "Current password is wrong."}), 403

        try:
            tokens = auth.change_own_username(
                g.current_user["sub"], current, new_username, request.remote_addr or "unknown"
            )
        except LoginThrottled as exc:
            logger.warning("Username change throttled")
            response = jsonify({"error": "Too many failed attempts. Try again later."})
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429
        except ValueError:
            return jsonify({"error": "Unable to change the username to the provided value."}), 409

        if tokens is None:
            return jsonify({"error": "Current password is wrong."}), 403

        refresh_token, access_token = tokens
        return jsonify({
            "username":      new_username,
            "role":          g.current_user["role"],
            "refresh_token": refresh_token,
            "access_token":  access_token,
            "expires_in":    300,
        }), 200

    # -----------------------------------------------------------------------
    # DELETE /api/me  (any signed-in regular user, needs the current password)
    # Removes the account with its devices and sessions. The admin can create
    # the user again with POST /api/users. The admin account itself stays.
    # -----------------------------------------------------------------------

    @api_bp.route("/me", methods=["DELETE"])
    @auth.require_role("admin", "user")
    def delete_own_account():
        if g.current_user.get("role") == "admin":
            return jsonify({"error": "The admin account cannot be deleted."}), 409

        data = request.get_json(silent=True) or {}
        current = data.get("current_password")

        if not isinstance(current, str) or not current or len(current) > MAX_PASSWORD_LENGTH:
            return jsonify({"error": "Current password is wrong."}), 403

        try:
            deleted = auth.delete_own_account(
                g.current_user["sub"], current, request.remote_addr or "unknown"
            )
        except LoginThrottled as exc:
            logger.warning("Account deletion throttled")
            response = jsonify({"error": "Too many failed attempts. Try again later."})
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429

        if not deleted:
            return jsonify({"error": "Current password is wrong."}), 403
        return jsonify({"username": g.current_user["sub"]}), 200

    # -----------------------------------------------------------------------
    # Devices. Everybody manages only their own; a device of somebody else is
    # reported exactly like one that does not exist (404).
    # -----------------------------------------------------------------------

    @api_bp.route("/devices", methods=["GET"])
    @auth.require_role("admin", "user")
    def list_devices():
        return jsonify({"devices": auth.database.list_devices(g.current_user["sub"])}), 200

    @api_bp.route("/devices", methods=["POST"])
    @auth.require_role("admin", "user")
    def create_device():
        data = request.get_json(silent=True) or {}
        owner = g.current_user["sub"]

        name = valid_name(data.get("name"))
        address = valid_address(data.get("address"))
        mac = normalize_mac(data.get("mac"))

        if name is None:
            return jsonify({"error": NAME_RULE}), 400
        if address is None:
            return jsonify({"error": ADDRESS_RULE}), 400
        if mac is None:
            return jsonify({"error": MAC_RULE}), 400

        if len(auth.database.list_devices(owner)) >= MAX_DEVICES_PER_USER:
            return jsonify({"error": f"At most {MAX_DEVICES_PER_USER} devices are allowed."}), 409

        try:
            device = auth.database.create_device(owner, name, address, mac)
        except ValueError:
            return jsonify({"error": "You already have a device with this name."}), 409
        return jsonify(device), 201

    @api_bp.route("/devices/<int:device_id>", methods=["DELETE"])
    @auth.require_role("admin", "user")
    def delete_device(device_id):
        if not auth.database.delete_device(g.current_user["sub"], device_id):
            return jsonify({"error": "Device not found."}), 404
        return jsonify({"id": device_id}), 200

    # -----------------------------------------------------------------------
    # POST /api/devices/<id>/wake
    # The MAC comes from the stored device, never from the request, and the
    # destination of the packet is configured in the wake relay.
    # -----------------------------------------------------------------------

    @api_bp.route("/devices/<int:device_id>/wake", methods=["POST"])
    @auth.require_role("admin", "user")
    def wake_device(device_id):
        device = auth.database.get_device(g.current_user["sub"], device_id)
        if device is None:
            return jsonify({"error": "Device not found."}), 404

        try:
            request_wake(device["mac"])
        except WakeUnavailableError:
            logger.error("Wake relay unavailable")
            return jsonify({"error": "Wake-on-LAN is temporarily unavailable."}), 503

        logger.info("Magic packet requested", extra={"device_id": device_id})
        return jsonify({"id": device_id, "status": "sent"}), 200

    return api_bp
