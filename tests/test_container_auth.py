"""
Container-to-container authentication against real TLS servers.

Two Flask apps run on real HTTPS sockets with their own self-signed
certificates, exactly like the containers do. The attacker tests use a third
server with a different certificate.
"""

import http.client
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared import container_auth as ca  # noqa: E402
from shared.container_auth import (  # noqa: E402
    ContainerAuth, ContainerAuthError, ContainerUnavailableError, fingerprint_of_pem_file,
    pair_secret_env,
)

FRONTEND_SECRET = "f" * 40
DATABASE_SECRET = "d" * 40


def make_cert(directory: str, name: str) -> tuple[str, str]:
    cert, key = os.path.join(directory, f"{name}.crt"), os.path.join(directory, f"{name}.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", key, "-out", cert],
        check=True, capture_output=True,
    )
    return cert, key


class Server:
    def __init__(self, app: Flask, cert: str, key: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self._server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=context)
        self.url = f"https://127.0.0.1:{self._server.server_port}"
        self.port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._thread.join(timeout=5)


def frontend_app(auth: ContainerAuth) -> Flask:
    app = Flask("frontend-under-test")
    auth.init_app(app)

    @app.route("/internal/ping")
    @auth.require("backend")
    def ping():
        return jsonify({"status": "ok"})

    @app.route("/internal/echo", methods=["POST"])
    @auth.require("backend")
    def echo():
        return jsonify({"got": request.get_json(silent=True)})

    @app.route("/user/whoami")
    def whoami():
        # Like a require_role route: no container decorator, the user token decides.
        return jsonify({"authorization": request.headers.get("Authorization", "")})

    return app


def raw_request(port: int, method: str, path: str, headers: dict, body: bytes = b"") -> tuple[int, dict, bytes]:
    """Plain HTTPS request, no container client: what an attacker with captured headers can do."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
    try:
        conn.request(method, path, body=body or None, headers=headers)
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class ContainerAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = make_cert(cls.tmp.name, "frontend")
        cls.evil_cert, cls.evil_key = make_cert(cls.tmp.name, "evil")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        os.environ[pair_secret_env("backend", "frontend")] = FRONTEND_SECRET
        os.environ[pair_secret_env("backend", "database")] = DATABASE_SECRET
        self.server_auth = ContainerAuth("frontend", ("backend",), cert_path=self.cert)
        self.backend = ContainerAuth("backend", ("frontend", "database"))

    # --- happy path ------------------------------------------------------

    def test_secret_env_name_is_symmetric(self):
        self.assertEqual(pair_secret_env("backend", "frontend"), "BACKEND_FRONTEND_SECRET")
        self.assertEqual(pair_secret_env("frontend", "backend"), "BACKEND_FRONTEND_SECRET")

    def test_mutual_authentication_succeeds(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, data = self.backend.client("frontend", server.url).request("GET", "/internal/ping")
        self.assertEqual((status, data), (200, {"status": "ok"}))

    def test_body_is_covered_by_signature(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, data = self.backend.client("frontend", server.url).request(
                "POST", "/internal/echo", {"a": 1})
        self.assertEqual((status, data), (200, {"got": {"a": 1}}))

    def test_user_token_travels_with_the_signed_request_and_response_is_proven(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, data = self.backend.client("frontend", server.url).request(
                "GET", "/user/whoami", headers={"Authorization": "Bearer abc"})
        self.assertEqual((status, data), (200, {"authorization": "Bearer abc"}))

    def test_extra_headers_cannot_override_the_signature(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            client = self.backend.client("frontend", server.url)
            status, _ = client.request(
                "GET", "/internal/ping", headers={ca.HEADER_SIGNATURE: "0" * 64, ca.HEADER_ID: "x"})
        self.assertEqual(status, 200)

    def test_token_route_without_container_headers_still_works_and_gets_no_proof(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, headers, _ = raw_request(
                server.port, "GET", "/user/whoami", {"Authorization": "Bearer abc"})
        self.assertEqual(status, 200)
        self.assertNotIn(ca.HEADER_PROOF, headers)

    def test_wrongly_signed_request_on_a_token_route_is_rejected(self):
        headers = self.backend.sign_request("frontend", "GET", "/user/whoami", b"", "0" * 64)
        headers["Authorization"] = "Bearer abc"
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, response_headers, _ = raw_request(server.port, "GET", "/user/whoami", headers)
        self.assertEqual(status, 401)
        self.assertNotIn(ca.HEADER_PROOF, response_headers)

    def test_token_route_response_from_an_impostor_is_rejected(self):
        evil = Flask("evil")

        @evil.route("/user/whoami")
        def whoami():
            return jsonify({"authorization": "Bearer abc"})

        with Server(evil, self.evil_cert, self.evil_key) as server:
            with self.assertRaises(ContainerAuthError):
                self.backend.client("frontend", server.url).request(
                    "GET", "/user/whoami", headers={"Authorization": "Bearer abc"})

    # --- the server must reject ------------------------------------------

    def test_unsigned_request_is_rejected_without_proof(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, headers, _ = raw_request(server.port, "GET", "/internal/ping", {})
        self.assertEqual(status, 401)
        self.assertNotIn(ca.HEADER_PROOF, headers)

    def test_wrong_secret_is_rejected(self):
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            client = self.backend.client("frontend", server.url)
            self.backend._secret = lambda peer: b"x" * 40  # attacker guesses a secret
            with self.assertRaises(ContainerAuthError):
                client.request("GET", "/internal/ping")

    def test_replay_of_captured_request_is_rejected(self):
        fingerprint = fingerprint_of_pem_file(self.cert)  # public: any TLS client sees it
        headers = self.backend.sign_request("frontend", "GET", "/internal/ping", b"", fingerprint)
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            first, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
            second, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
        self.assertEqual((first, second), (200, 401))

    def test_tampered_body_is_rejected(self):
        fingerprint = fingerprint_of_pem_file(self.cert)
        headers = self.backend.sign_request("frontend", "POST", "/internal/echo", b'{"a": 1}', fingerprint)
        headers["Content-Type"] = "application/json"
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, _, _ = raw_request(server.port, "POST", "/internal/echo", headers, b'{"a": 2}')
        self.assertEqual(status, 401)

    def test_tampered_path_is_rejected(self):
        fingerprint = fingerprint_of_pem_file(self.cert)
        headers = self.backend.sign_request("frontend", "GET", "/internal/other", b"", fingerprint)
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
        self.assertEqual(status, 401)

    def test_stale_timestamp_is_rejected(self):
        fingerprint = fingerprint_of_pem_file(self.cert)
        headers = self.backend.sign_request(
            "frontend", "GET", "/internal/ping", b"", fingerprint,
            timestamp=int(time.time()) - 3600)
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
        self.assertEqual(status, 401)

    def test_signature_for_another_certificate_is_rejected(self):
        # Signed for a different fingerprint than the one this server presents.
        other = fingerprint_of_pem_file(self.evil_cert)
        headers = self.backend.sign_request("frontend", "GET", "/internal/ping", b"", other)
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
        self.assertEqual(status, 401)

    def test_sender_that_is_not_allowed_is_rejected(self):
        # The database holds a valid secret for the backend, but not for this route.
        database = ContainerAuth("database", ("backend",))
        fingerprint = fingerprint_of_pem_file(self.cert)
        headers = database.sign_request("backend", "GET", "/internal/ping", b"", fingerprint)
        with Server(frontend_app(self.server_auth), self.cert, self.key) as server:
            status, _, _ = raw_request(server.port, "GET", "/internal/ping", headers)
        self.assertEqual(status, 401)

    # --- the client must reject ------------------------------------------

    def test_impersonating_server_is_rejected(self):
        # Attacker answers on the frontend's address but has no secret.
        evil = Flask("evil")

        @evil.route("/internal/ping")
        def ping():
            return jsonify({"status": "ok"})

        with Server(evil, self.evil_cert, self.evil_key) as server:
            with self.assertRaises(ContainerAuthError):
                self.backend.client("frontend", server.url).request("GET", "/internal/ping")

    def test_forged_proof_is_rejected(self):
        evil = Flask("evil")

        @evil.route("/internal/ping")
        def ping():
            response = jsonify({"status": "ok"})
            response.headers[ca.HEADER_PROOF] = "0" * 64
            return response

        with Server(evil, self.evil_cert, self.evil_key) as server:
            with self.assertRaises(ContainerAuthError):
                self.backend.client("frontend", server.url).request("GET", "/internal/ping")

    def test_man_in_the_middle_with_own_certificate_fails_both_ways(self):
        """
        The attacker relays everything between backend and the real frontend but
        terminates TLS with its own certificate. It sees the secret-less headers
        and the real response including its proof, yet neither side accepts.
        """
        with Server(frontend_app(self.server_auth), self.cert, self.key) as real:
            relay = Flask("mitm")

            @relay.route("/<path:path>", methods=["GET", "POST"])
            def forward(path):
                status, headers, body = raw_request(
                    real.port, request.method, "/" + path,
                    {k: v for k, v in request.headers.items()
                     if k.lower() not in ("host", "content-length")},
                    request.get_data())
                relayed = relay.response_class(body, status=status, content_type="application/json")
                if ca.HEADER_PROOF in headers:
                    relayed.headers[ca.HEADER_PROOF] = headers[ca.HEADER_PROOF]
                return relayed

            with Server(relay, self.evil_cert, self.evil_key) as mitm:
                with self.assertRaises(ContainerAuthError):
                    self.backend.client("frontend", mitm.url).request("GET", "/internal/ping")

    def test_unreachable_peer_is_unavailable(self):
        with self.assertRaises(ContainerUnavailableError):
            self.backend.client("frontend", "https://127.0.0.1:1").request("GET", "/internal/ping")

    # --- configuration ---------------------------------------------------

    def test_client_requires_https(self):
        with self.assertRaises(ValueError):
            self.backend.client("frontend", "http://frontend:8443")

    def test_unknown_peer_is_refused(self):
        with self.assertRaises(ContainerAuthError):
            self.backend.client("somebody", "https://somebody:1")

    def test_short_secret_fails_startup(self):
        os.environ["BACKEND_FRONTEND_SECRET"] = "short"
        with self.assertRaises(RuntimeError):
            self.backend.validate_config()

    def test_missing_secret_fails_startup(self):
        del os.environ["BACKEND_DATABASE_SECRET"]
        with self.assertRaises(RuntimeError):
            self.backend.validate_config()


class PublicApiStaysIndependentTest(unittest.TestCase):
    """External callers never need (or get) anything of the container protocol."""

    def setUp(self):
        os.environ.update(
            {"BACKEND_FRONTEND_SECRET": FRONTEND_SECRET, "BACKEND_DATABASE_SECRET": DATABASE_SECRET},
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        from app import create_app
        from app.database_client import DatabaseClient
        self.client = create_app(database=DatabaseClient()).test_client()

    def test_public_health_needs_no_headers_and_leaks_no_proof(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(ca.HEADER_PROOF, response.headers)

    def test_internal_route_gives_outsiders_nothing(self):
        response = self.client.get("/api/internal/ping")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(ca.HEADER_PROOF, response.headers)
        self.assertEqual(json.loads(response.data), {"error": "Unauthorized."})

    def test_outsider_with_forged_headers_gets_no_proof(self):
        response = self.client.get("/api/internal/ping", headers={
            ca.HEADER_ID: "frontend", ca.HEADER_TIMESTAMP: str(int(time.time())),
            ca.HEADER_NONCE: "abc", ca.HEADER_SIGNATURE: "0" * 64,
        })
        self.assertIn(response.status_code, (401, 503))
        self.assertNotIn(ca.HEADER_PROOF, response.headers)


class FrontendCallsBackendTest(unittest.TestCase):
    """The real backend app over TLS: the frontend forwards a user token and verifies the answer."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = make_cert(cls.tmp.name, "backend")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        os.environ.update(
            {"BACKEND_FRONTEND_SECRET": FRONTEND_SECRET, "BACKEND_DATABASE_SECRET": DATABASE_SECRET},
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
            TLS_CERT_PATH=self.cert,
        )
        from app import create_app
        from tests.fake_database import FakeDatabase
        self.db = FakeDatabase()
        self.app = create_app(database=self.db)
        self.frontend = ContainerAuth("frontend", ("backend",))
        self.addCleanup(os.environ.pop, "TLS_CERT_PATH", None)

    def _admin_token(self):
        auth = self.app.extensions["auth"]
        self.db.create_bootstrap_admin("root", auth.hash_password("a-long-enough-password"))
        return auth.issue_access_token("root", "admin")

    def test_token_route_returns_data_and_a_verified_proof(self):
        token = self._admin_token()
        with Server(self.app, self.cert, self.key) as server:
            status, data = self.frontend.client("backend", server.url).request(
                "GET", "/api/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual((status, data["username"], data["role"]), (200, "root", "admin"))

    def test_error_answers_of_a_token_route_are_proven_too(self):
        with Server(self.app, self.cert, self.key) as server:
            status, _ = self.frontend.client("backend", server.url).request(
                "GET", "/api/me", headers={"Authorization": "Bearer invalid"})
        self.assertEqual(status, 401)

    def test_frontend_without_the_right_secret_is_rejected_by_the_backend(self):
        token = self._admin_token()
        wrong = ContainerAuth("frontend", ("backend",))
        wrong._secret = lambda peer: b"x" * 40
        with Server(self.app, self.cert, self.key) as server:
            status, _, _ = raw_request(
                server.port, "GET", "/api/me",
                {**wrong.sign_request("backend", "GET", "/api/me", b"", fingerprint_of_pem_file(self.cert)),
                 "Authorization": f"Bearer {token}"})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
