from flask import Blueprint, jsonify, request
from app.services import process_pontifex_logic, wake_on_lan as wol_service

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

@api_bp.route('/devices/wol', methods=['PUT'])
def wake_on_lan():
    data = request.get_json()
    result = wol_service(mac_address=data['mac'], ip_address=data.get('ip', '255.255.255.255'), port=data.get('port', 9))
    if result.get('success'):
        return jsonify(result), 200
    else:
        return jsonify(result), 400
