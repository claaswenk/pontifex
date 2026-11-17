"""
Database container endpoints.

All endpoints require container-to-container authentication from the backend.
The backend calls these endpoints with the data from user requests.
"""

import base64
from functools import wraps
from flask import Blueprint, current_app, jsonify, request
from app.auth import DatabaseAuth
from app.services import get_db_service
from shared.input_validator import InputValidator as V, InvalidInput

api_db = Blueprint("api", __name__)


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
    @wraps(f)
    def decorator(*args, **kwargs):
        auth: DatabaseAuth = current_app.extensions["auth"]
        return auth.require_backend(f)(*args, **kwargs)
    return decorator


# Health

@api_db.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "pontifex-database"}), 200


# Not part of the public API: lets the backend check the container authentication.
@api_db.route("/internal/ping", methods=["GET"])
@_require_backend
def internal_ping():
    return jsonify({"status": "ok", "service": "pontifex-database"}), 200


# ---------------------------------------------------------------------------
# Accounts, tokens and devices for the backend
#
# The backend keeps no data of its own. Everything below is what its
# DatabaseClient needs: the backend hashes passwords and tokens, the database
# only stores what it is given. Every route is for the backend container only.
# ---------------------------------------------------------------------------

def _must_change(data: dict) -> bool:
    """Optional flag: the password was chosen by somebody else. Absent means False."""
    value = data.get("must_change", False)
    if not isinstance(value, bool):
        raise InvalidInput("must_change", "must_change must be true or false.")
    return value


def _expires_at(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**40:
        raise InvalidInput("expires_at", "expires_at must be a unix time.")
    return value


def _token_hash(value) -> str:
    return V.token(value, "token_hash")


@api_db.route("/bootstrap", methods=["GET"])
@_require_backend
def bootstrap_state():
    return jsonify({"consumed": get_db_service().bootstrap_consumed()}), 200


@api_db.route("/bootstrap", methods=["POST"])
@_require_backend
def bootstrap_admin():
    data = _body()
    username = V.username(data.get("username"))
    pw_hash = _password_hash(data.get("pw_hash"))
    token_hash = _token_hash(data.get("token_hash"))
    expires_at = _expires_at(data.get("expires_at"))
    try:
        created = get_db_service().create_bootstrap_admin(username, pw_hash, token_hash, expires_at)
    except ValueError:
        return jsonify({"error": "Username is taken."}), 409
    if created is None:
        return jsonify({"error": "Bootstrap already used."}), 410
    return jsonify({"success": True}), 201


@api_db.route("/accounts", methods=["GET"])
@_require_backend
def list_accounts():
    return jsonify({"users": get_db_service().list_users()}), 200


@api_db.route("/accounts", methods=["POST"])
@_require_backend
def add_account():
    data = _body()
    username = V.username(data.get("username"))
    pw_hash = _password_hash(data.get("pw_hash"))
    role = V.role(data.get("role"))
    must_change = _must_change(data)
    try:
        get_db_service().add_user(username, pw_hash, is_admin=(role == "admin"), must_change=must_change)
    except ValueError:
        return jsonify({"error": "Username is taken."}), 409
    return jsonify({"success": True}), 201


@api_db.route("/accounts/lookup", methods=["POST"])
@_require_backend
def lookup_account():
    credentials = get_db_service().get_credentials(V.username(_body().get("username")))
    if credentials is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(credentials), 200


@api_db.route("/accounts/<username>", methods=["DELETE"])
@_require_backend
def delete_account(username):
    """The account with its devices, pictures and tokens."""
    if not get_db_service().delete_user(V.path_username(username)):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True}), 200


@api_db.route("/accounts/password", methods=["POST"])
@_require_backend
def set_account_password():
    data = _body()
    username = V.username(data.get("username"))
    pw_hash = _password_hash(data.get("pw_hash"))
    if not get_db_service().set_password(username, pw_hash, _must_change(data)):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True}), 200


@api_db.route("/accounts/rename", methods=["POST"])
@_require_backend
def rename_account():
    data = _body()
    username = V.username(data.get("username"))
    new_username = V.username(data.get("new_username"), "new_username")
    try:
        renamed = get_db_service().rename_user(username, new_username)
    except ValueError:
        return jsonify({"error": "Username is taken."}), 409
    if not renamed:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True}), 200


@api_db.route("/tokens", methods=["POST"])
@_require_backend
def add_refresh_token():
    data = _body()
    username = V.username(data.get("username"))
    token_hash = _token_hash(data.get("token_hash"))
    expires_at = _expires_at(data.get("expires_at"))
    if not get_db_service().create_refresh_token(username, token_hash, expires_at):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True}), 201


@api_db.route("/tokens/lookup", methods=["POST"])
@_require_backend
def lookup_refresh_token():
    found = get_db_service().get_by_refresh_token(_token_hash(_body().get("token_hash")))
    if found is None:
        return jsonify({"error": "Token not found"}), 404
    return jsonify({"username": found[0], "role": found[1]}), 200


@api_db.route("/tokens/revoke", methods=["POST"])
@_require_backend
def revoke_refresh_token():
    get_db_service().revoke_refresh_token(_token_hash(_body().get("token_hash")))
    return jsonify({"success": True}), 200


@api_db.route("/reset-tokens", methods=["POST"])
@_require_backend
def add_reset_token():
    data = _body()
    username = V.username(data.get("username"))
    token_hash = _token_hash(data.get("token_hash"))
    expires_at = _expires_at(data.get("expires_at"))
    if not get_db_service().create_reset_token(username, token_hash, expires_at):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"success": True}), 201


@api_db.route("/reset-tokens/use", methods=["POST"])
@_require_backend
def use_reset_token():
    data = _body()
    token_hash = _token_hash(data.get("token_hash"))
    pw_hash = _password_hash(data.get("pw_hash"))
    if not get_db_service().reset_password_with_token(token_hash, pw_hash):
        return jsonify({"error": "Token not found"}), 404
    return jsonify({"success": True}), 200


@api_db.route("/owners/<username>/devices", methods=["GET"])
@_require_backend
def list_owned_devices(username):
    return jsonify({"devices": get_db_service().list_owned_devices(V.path_username(username))}), 200


@api_db.route("/owners/<username>/devices/<int:device_id>", methods=["GET"])
@_require_backend
def get_owned_device(username, device_id):
    device = get_db_service().get_owned_device(V.path_username(username), V.device_id(device_id))
    if device is None:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"device": device}), 200


@api_db.route("/owners/<username>/devices", methods=["POST"])
@_require_backend
def add_owned_device(username):
    owner = V.path_username(username)
    data = _body()
    name = V.device_name(data.get("name"))
    address = V.address(data.get("address"))
    mac = V.mac(data.get("mac"))
    picture = V.image(data["image"]) if data.get("image") is not None else None
    try:
        device = get_db_service().add_owned_device(owner, name, address, mac, picture)
    except ValueError:
        return jsonify({"error": "Device name is taken."}), 409
    if device is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"device": device}), 201


@api_db.route("/owners/<username>/devices/<int:device_id>", methods=["PUT"])
@_require_backend
def update_owned_device(username, device_id):
    owner = V.path_username(username)
    device_id = V.device_id(device_id)
    data = _body()
    name = V.device_name(data.get("name"))
    address = V.address(data.get("address"))
    mac = V.mac(data.get("mac"))
    try:
        device = get_db_service().update_owned_device(owner, device_id, name, address, mac)
    except ValueError:
        return jsonify({"error": "Device name is taken."}), 409
    if device is None:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"device": device}), 200


@api_db.route("/owners/<username>/devices/<int:device_id>", methods=["DELETE"])
@_require_backend
def delete_owned_device(username, device_id):
    if not get_db_service().delete_owned_device(V.path_username(username), V.device_id(device_id)):
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"success": True}), 200


# Pictures travel as base64 text inside the JSON the containers exchange.
# The type is detected from the bytes (InputValidator.image), never taken from the sender.

def _picture_answer(picture: dict):
    return jsonify({
        "media_type": picture["media_type"],
        "image": base64.b64encode(picture["data"]).decode("ascii"),
        "version": picture["version"],
    }), 200


@api_db.route("/owners/<username>/devices/<int:device_id>/picture", methods=["GET"])
@_require_backend
def get_device_picture(username, device_id):
    picture = get_db_service().get_device_picture(V.path_username(username), V.device_id(device_id))
    if picture is None:
        return jsonify({"error": "Picture not found"}), 404
    return _picture_answer(picture)


@api_db.route("/owners/<username>/devices/<int:device_id>/picture", methods=["PUT"])
@_require_backend
def set_device_picture(username, device_id):
    media_type, data = V.image(_body().get("image"))
    version = get_db_service().set_device_picture(
        V.path_username(username), V.device_id(device_id), media_type, data
    )
    if version is None:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"version": version}), 200


@api_db.route("/owners/<username>/devices/<int:device_id>/picture", methods=["DELETE"])
@_require_backend
def delete_device_picture(username, device_id):
    if not get_db_service().delete_device_picture(V.path_username(username), V.device_id(device_id)):
        return jsonify({"error": "Picture not found"}), 404
    return jsonify({"success": True}), 200


@api_db.route("/accounts/<username>/picture", methods=["GET"])
@_require_backend
def get_user_picture(username):
    picture = get_db_service().get_user_picture(V.path_username(username))
    if picture is None:
        return jsonify({"error": "Picture not found"}), 404
    return _picture_answer(picture)


@api_db.route("/accounts/<username>/picture/version", methods=["GET"])
@_require_backend
def get_user_picture_version(username):
    version = get_db_service().get_user_picture_version(V.path_username(username))
    return jsonify({"version": version}), 200


@api_db.route("/accounts/<username>/picture", methods=["PUT"])
@_require_backend
def set_user_picture(username):
    media_type, data = V.image(_body().get("image"))
    version = get_db_service().set_user_picture(V.path_username(username), media_type, data)
    if version is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"version": version}), 200


@api_db.route("/accounts/<username>/picture", methods=["DELETE"])
@_require_backend
def delete_user_picture(username):
    if not get_db_service().delete_user_picture(V.path_username(username)):
        return jsonify({"error": "Picture not found"}), 404
    return jsonify({"success": True}), 200
