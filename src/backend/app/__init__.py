from flask import Flask, jsonify


def create_app(database=None):
    app = Flask(__name__)

    from app.auth import BackendAuth
    from app.database_client import DatabaseClient, DatabaseUnavailableError
    from app.endpoints import create_api_blueprint
    from app.logger import BackendLogger

    logger = BackendLogger()
    logger.init_app(app)
    app.extensions["logger"] = logger

    client = database or DatabaseClient()
    auth = BackendAuth(client)
    auth.validate_config()
    auth.init_app(app)
    if database is None:
        # Production: talk to the database container over signed TLS.
        client.connect(auth.container)
    app.extensions["auth"] = auth
    app.register_blueprint(create_api_blueprint(auth), url_prefix="/api")

    # Fail closed: if the database cannot be reached, nobody is let in.
    @app.errorhandler(DatabaseUnavailableError)
    def database_unavailable(_exc):
        app.logger.error("Database container unavailable")
        return jsonify({"error": "Service temporarily unavailable."}), 503

    return app
