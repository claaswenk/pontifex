from flask import Flask, jsonify


def create_app(backend=None, sessions=None) -> Flask:
    """``backend`` and ``sessions`` can be replaced in tests; in production they are built from the environment."""
    app = Flask(__name__)
    # Forms are tiny. The routes that take a picture raise the limit for themselves (pages.py).
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    from app.auth import FrontendAuth
    from app.logger import FrontendLogger
    from app.pages import register_pages
    from app.services import BackendClient, SessionStore

    logger = FrontendLogger()
    logger.init_app(app)
    app.extensions["logger"] = logger

    auth = FrontendAuth()
    auth.validate_config()
    auth.init_app(app)
    app.extensions["auth"] = auth

    sessions = SessionStore() if sessions is None else sessions
    backend = BackendClient.from_env(auth.container) if backend is None else backend
    app.extensions["sessions"] = sessions
    register_pages(app, sessions, backend)

    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not response.headers.get("Cache-Control"):
            # Pages show account data: neither the browser nor a proxy may keep them.
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "pontifex-frontend"}), 200

    # Backend only: mutual container authentication check.
    @app.route("/internal/ping")
    @auth.require_container("backend")
    def internal_ping():
        return jsonify({"status": "ok", "service": "pontifex-frontend"}), 200

    return app
