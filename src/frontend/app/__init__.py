import datetime

from flask import Flask, jsonify, render_template


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
        now = datetime.datetime.now(datetime.timezone.utc)
        return render_template("index.html", server_time=now.strftime("%Y-%m-%d %H:%M:%S UTC"))

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "pontifex-frontend"}), 200

    # Backend only: mutual container authentication check.
    @app.route("/internal/ping")
    @auth.require_container("backend")
    def internal_ping():
        return jsonify({"status": "ok", "service": "pontifex-frontend"}), 200

    return app
