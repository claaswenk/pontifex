import os
from flask import Flask, send_from_directory
from flask_cors import CORS

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
        if path and os.path.isfile(os.path.join(frontend_dir, path)):
            return send_from_directory(frontend_dir, path)
        return send_from_directory(frontend_dir, "index.html")

    return app
