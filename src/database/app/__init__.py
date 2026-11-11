from flask import Flask, jsonify
from flask_cors import CORS


def create_app():
    """Create and configure the database container Flask application."""
    app = Flask(__name__)
    CORS(app)

    from app.auth import DatabaseAuth
    from app.endpoints import api_db
    from app.services import get_db_service

    # Initialize authentication
    auth = DatabaseAuth()
    auth.validate_config()
    auth.init_app(app)

    # Initialize database service
    get_db_service()  # Creates the global instance

    # Register blueprints
    app.register_blueprint(api_db, url_prefix="/api")

    # Error handlers
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal error: {error}")
        return jsonify({"error": "Internal server error"}), 500

    return app
