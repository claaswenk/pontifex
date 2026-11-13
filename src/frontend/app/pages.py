"""
The pages of the Pontifex UI.

Everything is a plain HTML form: a POST changes something and always answers
with a redirect to a GET page (no resubmit on reload). The browser only ever
holds a random session id (see services.py); every state-changing form carries
the CSRF token of that session.
"""

import datetime
import logging
import secrets
from functools import wraps

from flask import abort, g, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

from app.services import (
    BackendNotVerified,
    BackendUnavailable,
    SessionExpired,
)
from shared.input_validator import InputValidator as V, InvalidInput

log = logging.getLogger(__name__)

COOKIE = "__Host-pontifex-session"
MAX_FLASHES = 5


def _field(name: str, max_len: int, strip: bool = False) -> str:
    """
    A form field as text, or InvalidInput if it is too long or has a NUL.

    Over-long input is refused, not cut: a cut name could turn into a
    different, valid one. The rules of each field (and their messages) stay
    with the backend, which validates everything again.
    """
    value = V.text(request.form.get(name, ""), name, max_len)
    return value.strip() if strip else value

ERROR_TEXT = {
    400: "The request could not be processed.",
    403: "You are not allowed to open this page.",
    404: "This page does not exist.",
    405: "This action is not possible here.",
    413: "The request is too large.",
    502: "The connection to the backend could not be verified.",
    503: "The backend is temporarily unavailable. Try again in a moment.",
}


def _server_time() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _server_epoch() -> int:
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def _backend_message(data: dict, default: str) -> str:
    """The backend's validation message (they only describe rules), capped in length."""
    message = data.get("error")
    return message[:200] if isinstance(message, str) and message else default


def _tokens(data: dict) -> tuple[str, str, int] | None:
    refresh, access, expires = data.get("refresh_token"), data.get("access_token"), data.get("expires_in")
    if isinstance(refresh, str) and isinstance(access, str) and refresh and access:
        return refresh, access, expires if isinstance(expires, int) else 300
    return None


def register_pages(app, sessions, backend) -> None:
    # ------------------------------------------------------------------
    # Session, CSRF, cookie
    # ------------------------------------------------------------------

    def ensure_session():
        """The current session, or a new anonymous one (for the login form's CSRF token)."""
        if g.session is None:
            g.session = sessions.create()
            g.new_cookie = g.session
        return g.session

    def flash(kind: str, text: str) -> None:
        session = ensure_session()
        session.flashes = (session.flashes + [(kind, text)])[-MAX_FLASHES:]

    @app.before_request
    def load_session():
        g.session = None
        g.new_cookie = None
        g.clear_cookie = False
        if request.endpoint in (None, "static", "health", "internal_ping"):
            return None
        try:
            session_id = V.token(request.cookies.get(COOKIE, ""), "session cookie")
        except InvalidInput:
            session_id = ""  # not something we issued: same as no cookie
        g.session = sessions.get(session_id)
        if request.method == "POST":
            try:
                sent = V.token(request.form.get("csrf_token", ""), "csrf_token")
            except InvalidInput:
                sent = ""
            if g.session is None or not secrets.compare_digest(
                sent.encode("utf-8"), g.session.csrf.encode("utf-8")
            ):
                log.warning("Form rejected: missing or wrong CSRF token")
                abort(400)
        return None

    @app.after_request
    def set_cookie(response):
        if g.get("new_cookie") is not None:
            # __Host- prefix: the browser only accepts it with Secure, Path=/ and no Domain.
            response.set_cookie(
                COOKIE, g.new_cookie.id, secure=True, httponly=True, samesite="Strict", path="/"
            )
        elif g.get("clear_cookie"):
            response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="Strict", path="/")
        return response

    @app.context_processor
    def template_context():
        session = g.get("session")
        shown = []
        if session is not None:
            shown, session.flashes = session.flashes, []
        return {
            "user": session if session is not None and session.authenticated else None,
            "csrf_token": session.csrf if session is not None else "",
            "flashes": shown,
            "server_time": _server_time(),
            "server_epoch": _server_epoch(),
        }

    def login_required(role: str | None = None):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                session = g.session
                if session is None or not session.authenticated:
                    return redirect(url_for("login"))
                if role is not None and session.role != role:
                    abort(403)
                return f(*args, **kwargs)
            return decorated
        return decorator

    # ------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------

    def error_page(code: int):
        text = ERROR_TEXT.get(code, "Something went wrong.")
        return render_template("error.html", code=code, text=text, active=None), code

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return error_page(exc.code or 500)

    @app.errorhandler(InvalidInput)
    def refused_input(exc):
        log.warning("Form refused: field %r", exc.field)
        return error_page(400)

    @app.errorhandler(BackendUnavailable)
    def backend_unavailable(_exc):
        return error_page(503)

    @app.errorhandler(BackendNotVerified)
    def backend_not_verified(_exc):
        return error_page(502)

    @app.errorhandler(SessionExpired)
    def session_expired(_exc):
        if g.session is not None:
            sessions.destroy(g.session.id)
            g.session = None
        flash("error", "Your session has ended. Please sign in again.")
        return redirect(url_for("login"), 303)

    @app.errorhandler(Exception)
    def unexpected(exc):
        log.error("Unhandled error: %s", type(exc).__name__, exc_info=True)
        return error_page(500)

    def report(status: int, data: dict, ok_status: int, ok_text: str) -> None:
        if status == ok_status:
            flash("ok", ok_text)
        elif status in (400, 404, 409):
            flash("error", _backend_message(data, "The request was refused."))
        elif status == 429:
            flash("error", "Too many failed attempts. Try again later.")
        else:
            flash("error", "The request could not be completed. Try again later.")

    # ------------------------------------------------------------------
    # Setup, login, logout
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        return redirect(url_for("devices"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if g.session is not None and g.session.authenticated:
            return redirect(url_for("devices"))
        if request.method == "GET":
            ensure_session()
            return render_template("setup.html", active=None)

        key = _field("setup_key", 512)
        username = _field("username", 64, strip=True)
        password = _field("password", 1024)
        if password != _field("password_confirm", 1024):
            flash("error", "The two passwords are not the same.")
            return redirect(url_for("setup"), 303)

        status, data = backend.call(
            "POST", "/api/create-user/admin", {"username": username, "password": password}, token=key
        )
        tokens = _tokens(data) if status == 201 else None
        if tokens is not None:
            g.session = sessions.promote(
                g.session, username.lower(), "admin", tokens[0], tokens[1], tokens[2]
            )
            g.new_cookie = g.session
            return redirect(url_for("devices"), 303)
        if status == 410:
            flash("ok", "Setup is already complete. Please sign in.")
            return redirect(url_for("login"), 303)
        if status == 401:
            flash("error", "The setup key is wrong.")
        elif status in (400, 409):
            flash("error", _backend_message(data, "The account could not be created."))
        else:
            flash("error", "Setup is temporarily unavailable. Try again later.")
        return redirect(url_for("setup"), 303)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.session is not None and g.session.authenticated:
            return redirect(url_for("devices"))
        if request.method == "GET":
            ensure_session()
            return render_template("login.html", active=None)

        try:
            username = _field("username", 64, strip=True)
            password = _field("password", 1024)
        except InvalidInput:  # cannot be a real account: answered like a wrong password
            flash("error", "Invalid username or password.")
            return redirect(url_for("login"), 303)
        status, data = backend.call("POST", "/api/login", {"username": username, "password": password})
        tokens = _tokens(data) if status == 200 else None
        role = data.get("role")
        if tokens is not None and role in ("admin", "user"):
            # A new session id after signing in: an id planted before the login is useless.
            g.session = sessions.promote(
                g.session, username.lower(), role, tokens[0], tokens[1], tokens[2]
            )
            g.new_cookie = g.session
            return redirect(url_for("devices"), 303)
        if status == 429:
            flash("error", "Too many failed attempts. Try again later.")
        elif status == 401:
            flash("error", "Invalid username or password.")
        else:
            flash("error", "Sign-in is temporarily unavailable. Try again later.")
        return redirect(url_for("login"), 303)

    @app.route("/logout", methods=["POST"])
    @login_required()
    def logout():
        try:
            backend.call("POST", "/api/logout", {"refresh_token": g.session.refresh_token})
        except (BackendUnavailable, BackendNotVerified):
            log.warning("Sign-out: the backend could not revoke the refresh token")
        sessions.destroy(g.session.id)
        g.session = None
        g.clear_cookie = True
        return redirect(url_for("login"), 303)

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    @app.route("/devices")
    @login_required()
    def devices():
        status, data = backend.call_for(g.session, "GET", "/api/metrics")
        items = data.get("devices") if status == 200 else None
        load_failed = not isinstance(items, list)
        items = [] if load_failed else [d for d in items if isinstance(d, dict)]
        online = sum(1 for d in items if d.get("status") == "online")
        return render_template(
            "devices.html", active="devices", devices=items, load_failed=load_failed,
            summary={"total": len(items), "online": online, "offline": len(items) - online},
        )

    @app.route("/devices", methods=["POST"])
    @login_required()
    def add_device():
        body = {
            "name": _field("name", 200),
            "address": _field("address", 300),
            "mac": _field("mac", 100),
        }
        status, data = backend.call_for(g.session, "POST", "/api/devices", body)
        report(status, data, 201, "Device added.")
        return redirect(url_for("devices"), 303)

    @app.route("/devices/<int:device_id>/delete", methods=["POST"])
    @login_required()
    def delete_device(device_id):
        status, data = backend.call_for(g.session, "DELETE", f"/api/devices/{device_id}")
        report(status, data, 200, "Device deleted.")
        return redirect(url_for("devices"), 303)

    @app.route("/devices/<int:device_id>/wake", methods=["POST"])
    @login_required()
    def wake_device(device_id):
        status, data = backend.call_for(g.session, "POST", f"/api/devices/{device_id}/wake")
        report(status, data, 200, "Magic packet sent. Reload in a minute to see whether it is online.")
        return redirect(url_for("devices"), 303)

    # ------------------------------------------------------------------
    # Users (admin)
    # ------------------------------------------------------------------

    def valid_username(name: str) -> str:
        try:
            return V.path_username(name)
        except InvalidInput:
            abort(404)

    @app.route("/users")
    @login_required("admin")
    def users():
        status, data = backend.call_for(g.session, "GET", "/api/users")
        items = data.get("users") if status == 200 else None
        load_failed = not isinstance(items, list)
        items = [] if load_failed else [u for u in items if isinstance(u, dict)]
        return render_template("users.html", active="users", users=items, load_failed=load_failed)

    @app.route("/users", methods=["POST"])
    @login_required("admin")
    def add_user():
        body = {
            "username": _field("username", 64, strip=True),
            "password": _field("password", 1024),
        }
        status, data = backend.call_for(g.session, "POST", "/api/users", body)
        report(status, data, 201, "User added.")
        return redirect(url_for("users"), 303)

    @app.route("/users/<name>/password", methods=["POST"])
    @login_required("admin")
    def reset_password(name):
        name = valid_username(name)
        body = {"password": _field("password", 1024)}
        status, data = backend.call_for(g.session, "PUT", f"/api/users/{name}", body)
        if status == 200:
            sessions.destroy_user(name)  # the backend ended their sessions; do the same here
        report(status, data, 200, "Password set. The user was signed out everywhere.")
        return redirect(url_for("users"), 303)

    @app.route("/users/<name>/delete", methods=["POST"])
    @login_required("admin")
    def delete_user(name):
        name = valid_username(name)
        status, data = backend.call_for(g.session, "DELETE", f"/api/users/{name}")
        if status == 200:
            sessions.destroy_user(name)
        report(status, data, 200, "User deleted.")
        return redirect(url_for("users"), 303)

    # ------------------------------------------------------------------
    # Account
    # ------------------------------------------------------------------

    @app.route("/account")
    @login_required()
    def account():
        status, data = backend.call_for(g.session, "GET", "/api/me")
        if status != 200:
            raise BackendUnavailable()
        status, listing = backend.call_for(g.session, "GET", "/api/devices")
        devices_found = listing.get("devices") if status == 200 else None
        return render_template(
            "account.html", active="account",
            account={
                "username": g.session.username, "role": g.session.role,
                "device_count": len(devices_found) if isinstance(devices_found, list) else None,
            },
        )

    @app.route("/account/password", methods=["POST"])
    @login_required()
    def change_password():
        new = _field("new_password", 1024)
        if new != _field("new_password_confirm", 1024):
            flash("error", "The two new passwords are not the same.")
            return redirect(url_for("account"), 303)

        body = {"current_password": _field("current_password", 1024), "new_password": new}
        status, data = backend.call_for(g.session, "PUT", "/api/me/password", body)
        tokens = _tokens(data) if status == 200 else None
        if tokens is not None:
            sessions.set_tokens(g.session, *tokens)
            sessions.destroy_user(g.session.username, keep=g.session.id)
            flash("ok", "Password changed. Your other sessions were signed out.")
        elif status == 403:
            flash("error", "The current password is wrong.")
        else:
            report(status if status != 200 else 502, data, 200, "")
        return redirect(url_for("account"), 303)
