import os
from flask import Flask, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

def create_app():
    # Resolve the frontend directory relative to this file's location so it
    # works both inside the container (/app/app/) and in local dev.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(root, "frontend")

    app = Flask(__name__)
    CORS(app)

    from app.endpoints import api_db
    app.register_blueprint(api_db, url_prefix='/api')

    return app
