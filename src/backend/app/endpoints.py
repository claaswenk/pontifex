import logging

from flask import Blueprint, jsonify, request, g
from app.auth import BackendAuth, BootstrapConsumedError
from app.services import (
    MAX_DEVICES_PER_USER,
    LoginThrottled,
    WakeUnavailableError,
    check_devices,
    process_pontifex_logic,
    request_wake,
    system_stats,
)
from shared.input_validator import InputValidator as V, InvalidInput

logger = logging.getLogger(__name__)

# Every value from a request goes through shared.input_validator first; the
# handlers below only use what it returns. A refused value ends in the
# handler at the bottom of create_api_blueprint (400 with the rule), unless
# the route needs a different answer (login: always the same 401).


def _body(required: bool = False) -> dict:
    """The JSON body as a dict. A body that is not an object is refused."""
    data = request.get_json(silent=True)
    if data is None and required:
        raise InvalidInput("body", V.BODY_RULE)
    return V.json_object(data)


def _current_password(data: dict) -> str | None:
    """The password sent as proof, or None if it is unusable (answered like a wrong one)."""
    try:
        return V.current_password(data.get("current_password"))
    except InvalidInput:
        return None


def _known_username(value) -> str | None:
    """A username from the URL in canonical form, or None (answered like an unknown user)."""
    try:
        return V.path_username(value)
    except InvalidInput:
        return None


def create_api_blueprint(auth: BackendAuth) -> Blueprint:
    api_bp = Blueprint("api", __name__)

    @api_bp.errorhandler(InvalidInput)
    def refused_input(exc):
        return jsonify({"error": exc.message}), 400

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
        try:
            data = _body()
            username = V.username(data.get("username"))
            password = V.current_password(data.get("password"), "password")
        except InvalidInput:
            return jsonify({"error": "Invalid username or password."}), 401

        try:
            result = auth.login(username, password, request.remote_addr or "unknown")
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
        refresh_token = V.token(_body().get("refresh_token"), "refresh_token")
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
        data = _body()
        if not data.get("refresh_token"):
            return jsonify({"error": "Field 'refresh_token' is required."}), 400

        try:
            refresh_token = V.token(data["refresh_token"], "refresh_token")
        except InvalidInput:  # cannot be one of ours: answered like an unknown token
            return jsonify({"error": "Unauthorized: unknown refresh token."}), 401

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
        data = _body()
        username = V.username(data.get("username"))
        password = V.new_password(data.get("password"))

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
        data = _body()
        username = V.username(data.get("username"))
        password = V.new_password(data.get("password"))

        try:
            auth.create_user(username, password)
        except ValueError:
            return jsonify({"error": "Unable to create user with the provided input."}), 409

        return jsonify({"username": username, "role": "user"}), 201

    @api_bp.route("/users/<username>", methods=["PUT"])
    @auth.require_role("admin")
    def reset_user_password(username):
        username = _known_username(username)
        if username is None:
            return jsonify({"error": "User not found."}), 404
        if username == g.current_user["sub"]:
            return jsonify({"error": "Use PUT /api/me/password to change your own password."}), 409
        password = V.new_password(_body().get("password"))

        if not auth.set_password(username, password):
            return jsonify({"error": "User not found."}), 404
        return jsonify({"username": username}), 200

    # -----------------------------------------------------------------------
    # Forgot password. Accounts have no e-mail address, so the admin is the
    # trusted channel: they issue a one-time token and hand it to the user,
    # who sets the new password with it (POST /api/reset-password, public).
    # The token is valid once for 15 minutes and only its hash is stored.
    # -----------------------------------------------------------------------

    @api_bp.route("/users/<username>/reset-token", methods=["POST"])
    @auth.require_role("admin")
    def issue_reset_token(username):
        username = _known_username(username)
        if username is None:
            return jsonify({"error": "User not found."}), 404
        if username == g.current_user["sub"]:
            return jsonify({"error": "Use PUT /api/me/password to change your own password."}), 409

        token = auth.create_reset_token(username)
        if token is None:
            return jsonify({"error": "User not found."}), 404

        response = jsonify({
            "username":    username,
            "reset_token": token,
            "expires_in":  auth.RESET_TOKEN_TTL_SECONDS,
        })
        response.headers["Cache-Control"] = "no-store"
        return response, 201

    @api_bp.route("/reset-password", methods=["POST"])
    def reset_password():
        data = _body()
        try:
            token = V.token(data.get("reset_token"), "reset_token")
        except InvalidInput:
            return jsonify({"error": "Invalid or expired reset token."}), 401
        new = V.new_password(data.get("new_password"), "new_password")

        try:
            done = auth.reset_password_with_token(token, new, request.remote_addr or "unknown")
        except LoginThrottled as exc:
            logger.warning("Password reset throttled")
            response = jsonify({"error": "Too many failed attempts. Try again later."})
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429

        if not done:
            return jsonify({"error": "Invalid or expired reset token."}), 401
        return jsonify({"status": "ok"}), 200

    @api_bp.route("/users/<username>", methods=["DELETE"])
    @auth.require_role("admin")
    def delete_user(username):
        username = _known_username(username)
        if username is None:
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
        data = _body()
        current = _current_password(data)
        if current is None:
            return jsonify({"error": "Current password is wrong."}), 403
        new = V.new_password(data.get("new_password"), "new_password")

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
        data = _body(required=True)

        if "role" in data:
            return jsonify({"error": "The role cannot be changed."}), 403
        unknown = set(data) - {"username", "current_password"}
        if unknown:
            return jsonify({"error": "Only 'username' can be changed."}), 400
        if "username" not in data:
            return jsonify({"error": "Field 'username' is required."}), 400

        new_username = V.username(data.get("username"))

        current = _current_password(data)
        if current is None:
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

        current = _current_password(_body())
        if current is None:
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
        data = _body()
        owner = g.current_user["sub"]

        name = V.device_name(data.get("name"))
        address = V.address(data.get("address"))
        mac = V.mac(data.get("mac"))

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
        try:
            device_id = V.device_id(device_id)
        except InvalidInput:
            return jsonify({"error": "Device not found."}), 404
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
        try:
            device_id = V.device_id(device_id)
        except InvalidInput:
            return jsonify({"error": "Device not found."}), 404
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
