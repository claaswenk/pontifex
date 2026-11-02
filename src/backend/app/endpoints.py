from flask import Blueprint, jsonify, request, g

from app.auth import (
    create_user,
    exchange_refresh_token,
    find_refresh_token_by_username,
    require_initial_api_key,
    require_role,
    revoke_user,
)
from app.services import process_pontifex_logic

api_bp = Blueprint("api", __name__)


# ---------------------------------------------------------------------------
# Health  (public, no auth required)
# ---------------------------------------------------------------------------

@api_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "pontifex-backend"}), 200


# ---------------------------------------------------------------------------
# POST /api/token
# ---------------------------------------------------------------------------

@api_bp.route("/token", methods=["POST"])
def get_access_token():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"error": "Field 'refresh_token' is required."}), 400

    access_token = exchange_refresh_token(refresh_token)
    if access_token is None:
        return jsonify({"error": "Unauthorized: unknown refresh token."}), 401

    return jsonify({"access_token": access_token, "expires_in": 300}), 200


# ---------------------------------------------------------------------------
# Process (existing stub – requires container key + valid access token)
# ---------------------------------------------------------------------------

@api_bp.route("/process", methods=["POST"])
@require_role("admin", "user")
def process_data():
    result = process_pontifex_logic()
    return jsonify({"success": True, "data": result}), 200


# ---------------------------------------------------------------------------
# POST /api/create-user/admin
# ---------------------------------------------------------------------------

@api_bp.route("/create-user/admin", methods=["POST"])
@require_initial_api_key
def create_admin_user():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Field 'username' is required."}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters."}), 400

    try:
        refresh_token, access_token = create_user(username, password, role="admin")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    return jsonify({
        "refresh_token": refresh_token,
        "access_token":  access_token,
        "expires_in":    300,
        "role":          "admin",
    }), 201


# ---------------------------------------------------------------------------
# POST /api/create-user/user
# ---------------------------------------------------------------------------

@api_bp.route("/create-user/user", methods=["POST"])
@require_role("admin")
def create_service_user():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Field 'username' is required."}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters."}), 400

    try:
        refresh_token, access_token = create_user(username, password, role="user")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409

    # The admin account is a one-time bootstrapper. Once the service user
    admin_username = g.current_user["sub"]
    admin_rt = find_refresh_token_by_username(admin_username)
    if admin_rt:
        revoke_user(admin_rt)

    return jsonify({
        "refresh_token": refresh_token,
        "access_token":  access_token,
        "expires_in":    300,
        "role":          "user",
    }), 201
