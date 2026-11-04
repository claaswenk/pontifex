import logging

from flask import Blueprint, jsonify, request, g
from app.auth import BackendAuth, BootstrapConsumedError
from app.services import process_pontifex_logic, wake_on_lan as wol_service

logger = logging.getLogger(__name__)


def create_api_blueprint(auth: BackendAuth) -> Blueprint:
    api_bp = Blueprint("api", __name__)

    # -----------------------------------------------------------------------
    # Health  (public, no auth required)
    # -----------------------------------------------------------------------

    @api_bp.route("/health", methods=["GET"])
    def health_check():
        return jsonify({"status": "healthy", "service": "pontifex-backend"}), 200

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
    # Process (existing stub - requires container key + valid access token)
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

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username:
            return jsonify({"error": "Field 'username' is required."}), 400
        if len(password) < 12:
            return jsonify({"error": "Password must be at least 12 characters."}), 400

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
    # POST /api/create-user/user  (admin only; replaces the admin)
    # -----------------------------------------------------------------------

    @api_bp.route("/create-user/user", methods=["POST"])
    @auth.require_role("admin")
    def create_service_user():
        data = request.get_json(silent=True) or {}

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username:
            return jsonify({"error": "Field 'username' is required."}), 400
        if len(password) < 12:
            return jsonify({"error": "Password must be at least 12 characters."}), 400

        try:
            refresh_token, access_token = auth.create_user(
                username, password, replacing_admin=g.current_user["sub"]
            )
        except ValueError:
            return jsonify({"error": "Unable to create user with the provided input."}), 409

        return jsonify({
            "refresh_token": refresh_token,
            "access_token":  access_token,
            "expires_in":    300,
            "role":          "user",
        }), 201

    # -----------------------------------------------------------------------
    # PUT /api/devices/wol
    # -----------------------------------------------------------------------

    @api_bp.route("/devices/wol", methods=["PUT"])
    @auth.require_role("admin", "user")
    def wake_on_lan():
        data = request.get_json(silent=True) or {}
        if "mac" not in data:
            return jsonify({"error": "Field 'mac' is required."}), 400
        result = wol_service(
            mac_address=data["mac"],
            ip_address=data.get("ip", "255.255.255.255"),
            port=data.get("port", 9),
        )
        return jsonify(result), (200 if result.get("success") else 400)

    return api_bp
