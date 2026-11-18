"""Tests for BaseLogger and container-specific loggers."""

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from flask import Flask, g, jsonify

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.logger import BaseLogger  # noqa: E402
from app.logger import BackendLogger  # noqa: E402


def _load_logger(name, container):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "src", container, "app", "logger.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FrontendLogger = _load_logger("frontend_logger", "frontend").FrontendLogger
DatabaseLogger = _load_logger("database_logger", "database").DatabaseLogger


class BaseLoggerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "test_container.log")

    def tearDown(self):
        self.tmp.cleanup()

    def test_log_file_created_with_restrictive_permissions(self):
        logger = BaseLogger(log_path=self.log_path)
        logger.info("Test message")
        logger.flush()
        logger.close()

        self.assertTrue(os.path.exists(self.log_path))
        mode = stat.S_IMODE(os.stat(self.log_path).st_mode)
        # 0o600 permissions: readable and writable by owner only
        self.assertEqual(mode & 0o777, 0o600)

    def test_caller_identity_resolution(self):
        app = Flask("test-identity")

        with app.test_request_context("/api/test", environ_base={"REMOTE_ADDR": "192.168.1.50"}):
            # 1. Anonymous IP
            self.assertEqual(BaseLogger.get_caller_identity(), "ip:192.168.1.50")

            # 2. Container peer
            g.container_peer = "database"
            self.assertEqual(BaseLogger.get_caller_identity(), "peer:database")

            # 3. Authenticated JWT user
            g.container_peer = None
            g.current_user = {"sub": "alice", "role": "admin"}
            self.assertEqual(BaseLogger.get_caller_identity(), "user:alice")

            # 4. Frontend session
            g.current_user = None

            class FakeSession:
                username = "bob"

            g.session = FakeSession()
            self.assertEqual(BaseLogger.get_caller_identity(), "user:bob")

    def test_request_lifecycle_logging_in_flask(self):
        app = Flask("test-app")
        logger = BaseLogger(log_path=self.log_path)
        logger.init_app(app)

        @app.route("/api/ping")
        def ping():
            return jsonify({"status": "ok"}), 200

        @app.route("/api/error")
        def trigger_error():
            return jsonify({"error": "forbidden"}), 403

        @app.route("/api/crash")
        def crash():
            raise RuntimeError("internal explosion")

        client = app.test_client()

        # Normal request
        r1 = client.get("/api/ping", environ_base={"REMOTE_ADDR": "10.0.0.1"})
        self.assertEqual(r1.status_code, 200)

        # 403 request
        r2 = client.get("/api/error", environ_base={"REMOTE_ADDR": "10.0.0.2"})
        self.assertEqual(r2.status_code, 403)

        # 500 error
        r3 = client.get("/api/crash", environ_base={"REMOTE_ADDR": "10.0.0.3"})
        self.assertEqual(r3.status_code, 500)

        logger.flush()
        logger.close()

        with open(self.log_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("GET /api/ping status=200", content)
        self.assertIn("[ip:10.0.0.1]", content)
        self.assertIn("GET /api/error status=403", content)
        self.assertIn("[ip:10.0.0.2]", content)
        self.assertIn("GET /api/crash status=500", content)
        self.assertIn("[ip:10.0.0.3]", content)

    def test_sanitization_of_control_characters_and_nul_bytes(self):
        logger = BaseLogger(log_path=self.log_path)
        logger.info("Attack with nul: \x00 and newline: \n and cr: \r", caller="user:\x00admin\n")
        logger.flush()
        logger.close()

        with open(self.log_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("\x00", content)
        self.assertIn(r"\x00", content)
        self.assertIn(r"[user:\x00admin\n]", content)
        self.assertIn(r"Attack with nul: \x00 and newline: \n and cr: \r", content)

    def test_container_logger_subclasses(self):
        frontend_log = os.path.join(self.tmp.name, "frontend.log")
        database_log = os.path.join(self.tmp.name, "database.log")
        backend_log = os.path.join(self.tmp.name, "backend.log")

        f_logger = FrontendLogger(log_path=frontend_log)
        d_logger = DatabaseLogger(log_path=database_log)
        b_logger = BackendLogger(log_path=backend_log)

        self.assertEqual(f_logger.CONTAINER_ID, "frontend")
        self.assertEqual(d_logger.CONTAINER_ID, "database")
        self.assertEqual(b_logger.CONTAINER_ID, "backend")

        f_logger.info("Frontend started")
        d_logger.info("Database started")
        b_logger.info("Backend started")

        f_logger.close()
        d_logger.close()
        b_logger.close()

        with open(frontend_log, "r", encoding="utf-8") as f:
            self.assertIn("Frontend started", f.read())

        with open(database_log, "r", encoding="utf-8") as f:
            self.assertIn("Database started", f.read())

        with open(backend_log, "r", encoding="utf-8") as f:
            self.assertIn("Backend started", f.read())


if __name__ == "__main__":
    unittest.main()
