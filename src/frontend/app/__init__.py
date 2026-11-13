import datetime

from flask import Flask, jsonify, redirect, render_template, url_for

# Sample data for the layout preview. Replaced by the backend (/api/metrics and
# the account data) once login and the database are connected. Until then no
# real information is shown, so the pages need no authentication.
SAMPLE_DEVICES = [
    {"name": "NAS", "address": "192.168.1.10", "status": "online", "latency_ms": 2.4},
    {"name": "Desktop PC", "address": "192.168.1.21", "status": "online", "latency_ms": 5.1},
    {"name": "Media server", "address": "192.168.1.30", "status": "offline", "latency_ms": None},
    {"name": "Printer", "address": "192.168.1.45", "status": "offline", "latency_ms": None},
]
SAMPLE_ACCOUNT = {"username": "demo", "role": "user", "token_minutes": 5}


def _server_time() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


def create_app() -> Flask:
    app = Flask(__name__)

    from app.auth import FrontendAuth

    auth = FrontendAuth()
    auth.validate_config()
    auth.init_app(app)
    app.extensions["auth"] = auth

    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.route("/")
    def index():
        return redirect(url_for("devices"))

    @app.route("/devices")
    def devices():
        online = sum(1 for d in SAMPLE_DEVICES if d["status"] == "online")
        return render_template(
            "devices.html",
            active="devices",
            preview=True,
            server_time=_server_time(),
            devices=SAMPLE_DEVICES,
            summary={
                "total": len(SAMPLE_DEVICES),
                "online": online,
                "offline": len(SAMPLE_DEVICES) - online,
            },
        )

    @app.route("/account")
    def account():
        return render_template(
            "account.html",
            active="account",
            preview=True,
            server_time=_server_time(),
            account={**SAMPLE_ACCOUNT, "device_count": len(SAMPLE_DEVICES)},
        )

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "pontifex-frontend"}), 200

    # Backend only: mutual container authentication check.
    @app.route("/internal/ping")
    @auth.require_container("backend")
    def internal_ping():
        return jsonify({"status": "ok", "service": "pontifex-frontend"}), 200

    return app
