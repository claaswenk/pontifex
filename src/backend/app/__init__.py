import os
from flask import Flask, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

def create_app():
    # Resolve the frontend directory relative to this file's location so it
    # works both inside the container (/app/app/) and in local dev.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(root, "frontend")

    app = Flask(
        __name__,
        static_folder=frontend_dir,
        static_url_path="",
    )
    CORS(app)

    from app.endpoints import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        safe_frontend_root = os.path.abspath(frontend_dir)
        if path:
            sanitized_parts = [secure_filename(part) for part in path.split("/") if part and part not in (".", "..")]
            sanitized_path = os.path.join(*sanitized_parts) if sanitized_parts else ""
            requested_path = os.path.abspath(
                os.path.normpath(os.path.join(safe_frontend_root, sanitized_path))
            )
            if (
                os.path.commonpath([safe_frontend_root, requested_path]) == safe_frontend_root
                and os.path.isfile(requested_path)
            ):
                return send_from_directory(frontend_dir, sanitized_path)
        return send_from_directory(frontend_dir, "index.html")

    return app
