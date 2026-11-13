"""
Database container endpoints.

All endpoints require container-to-container authentication from the backend.
The backend calls these endpoints with the data from user requests.
"""

import logging
from flask import Blueprint, jsonify, request
from app.auth import DatabaseAuth
from app.services import get_db_service
from shared.input_validator import InputValidator as V, InvalidInput

api_db = Blueprint("api", __name__)
logger = logging.getLogger(__name__)


@api_db.errorhandler(InvalidInput)
def refused_input(exc):
    return jsonify({"error": exc.message}), 400


def _body() -> dict:
    return V.json_object(request.get_json(silent=True))


def _password_hash(value) -> str:
    """The stored credential (a hash made by the backend): bounded text, never empty."""
    secret = V.text(value, "password", V.MAX_PASSWORD_LENGTH)
    if not secret:
        raise InvalidInput("password", "username and password are required")
    return secret


def _require_backend(f):
    """Decorator factory to require backend container authentication."""
    def decorator(*args, **kwargs):
        auth: DatabaseAuth = api_db.app.extensions["auth"]
        return auth.require_backend(f)(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator


# ---------------------------------------------------------------------------
# 1. Health Check
# ---------------------------------------------------------------------------

@api_db.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "pontifex-database"}), 200


# ---------------------------------------------------------------------------
# 2. Create admin
# POST /api/create-user/admin
# Body: {"username": "...", "password": "..."}
# Headers: X-API-Key (handled by backend)
# ---------------------------------------------------------------------------

@api_db.route("/create-user/admin", methods=["POST"])
@_require_backend
def create_admin():
    data = _body()
    username = V.username(data.get("username"))
    password = _password_hash(data.get("password"))

    db = get_db_service()
    try:
        user_id, username = db.create_admin(username, password)
        return jsonify({
            "success": True,
            "user_id": user_id,
            "username": username
        }), 201
    except Exception as e:
        logger.error(f"Failed to create admin: {e}")
        return jsonify({"error": "Failed to create admin"}), 500


# ---------------------------------------------------------------------------
# 3. Create user
# POST /api/create-user/user
# Body: {"username": "...", "password": "..."}
# ---------------------------------------------------------------------------

@api_db.route("/create-user/user", methods=["POST"])
@_require_backend
def create_user():
    data = _body()
    username = V.username(data.get("username"))
    password = _password_hash(data.get("password"))

    db = get_db_service()
    try:
        user_id, username = db.create_user(username, password)
        return jsonify({
            "success": True,
            "user_id": user_id,
            "username": username
        }), 201
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return jsonify({"error": "Failed to create user"}), 500


# ---------------------------------------------------------------------------
# 4. Create device
# POST /api/create-device
# Body: {"device_name": "...", "address": "..."}
# ---------------------------------------------------------------------------

@api_db.route("/create-device", methods=["POST"])
@_require_backend
def create_device():
    data = _body()
    device_name = V.device_name(data.get("device_name"), "device_name")
    address = data.get("address")
    address = V.address(address) if address else None

    db = get_db_service()
    try:
        device_id, device_name = db.create_device(device_name, address or "")
        return jsonify({
            "success": True,
            "device_id": device_id,
            "device_name": device_name,
            "address": address
        }), 201
    except Exception as e:
        logger.error(f"Failed to create device: {e}")
        return jsonify({"error": "Failed to create device"}), 500


# ---------------------------------------------------------------------------
# 5. Connect user with device
# POST /api/create-connection
# Body: {"username": "...", "device_name": "..."}
# ---------------------------------------------------------------------------

@api_db.route("/create-connection", methods=["POST"])
@_require_backend
def create_connection():
    data = _body()
    username = V.username(data.get("username"))
    device_name = V.device_name(data.get("device_name"), "device_name")

    db = get_db_service()
    if db.create_connection(username, device_name):
        return jsonify({
            "success": True,
            "username": username,
            "device_name": device_name
        }), 201
    else:
        return jsonify({
            "error": "Failed to create connection - user or device not found"
        }), 404


# ---------------------------------------------------------------------------
# 6. Delete user
# POST /api/delete/user
# Body: {"username": "..."}
# ---------------------------------------------------------------------------

@api_db.route("/delete/user", methods=["POST"])
@_require_backend
def delete_user():
    username = V.username(_body().get("username"))

    db = get_db_service()
    if db.delete_user(username):
        return jsonify({
            "success": True,
            "username": username
        }), 200
    else:
        return jsonify({"error": "User not found"}), 404


# ---------------------------------------------------------------------------
# 7. Delete device
# POST /api/delete/device
# Body: {"device_name": "..."}
# Note: The api_calls.md shows username, but schema uses device_name
# We interpret this as deleting a device by its name
# ---------------------------------------------------------------------------

@api_db.route("/delete/device", methods=["POST"])
@_require_backend
def delete_device():
    data = _body()
    username = V.username(data["username"]) if data.get("username") else None
    device_name = V.device_name(data["device_name"], "device_name") if data.get("device_name") else None

    db = get_db_service()

    # If username is provided, delete all devices for that user
    if username:
        user = db.get_user(username)
        if user is None:
            return jsonify({"error": "User not found"}), 404

        user_id = user["user_id"]
        conn = db._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM mapping WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM devices WHERE device_id IN (SELECT device_id FROM mapping WHERE user_id = ?)", (user_id,))
        conn.commit()
        return jsonify({
            "success": True,
            "username": username
        }), 200

    # Otherwise, delete device by name
    if device_name:
        if db.delete_device(device_name):
            return jsonify({
                "success": True,
                "device_name": device_name
            }), 200
        else:
            return jsonify({"error": "Device not found"}), 404

    return jsonify({"error": "username or device_name is required"}), 400


# ---------------------------------------------------------------------------
# 8. Delete connection
# POST /api/delete/connection
# Body: {"username": "...", "device_name": "..."}
# ---------------------------------------------------------------------------

@api_db.route("/delete/connection", methods=["POST"])
@_require_backend
def delete_connection():
    data = _body()
    username = V.username(data.get("username"))
    device_name = V.device_name(data.get("device_name"), "device_name")

    db = get_db_service()
    if db.delete_connection(username, device_name):
        return jsonify({
            "success": True,
            "username": username,
            "device_name": device_name
        }), 200
    else:
        return jsonify({"error": "Connection not found"}), 404
