import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.auth import BaseAuth  # noqa: E402
from shared.errors import BootstrapConsumedError  # noqa: E402
from frontend.auth import FrontendAuth  # noqa: E402
from database.auth import DatabaseAuth  # noqa: E402
from app.database_client import DatabaseClient, DatabaseUnavailableError  # noqa: E402

CK = {"X-Container-Key": "container-key"}
PW = "a-long-enough-password"


class FakeDatabase:
    """In-memory stand-in with the same interface as DatabaseClient.

    The real store lives in the database container; the backend only ever
    talks to it through DatabaseClient, so this fake is all it needs here.
    """

    def __init__(self):
        self.users = {}          # username -> (role, refresh_token)
        self.consumed = False
        self.down = False

    def validate_config(self):
        pass

    def _check(self):
        if self.down:
            raise DatabaseUnavailableError("down")

    def create_bootstrap_admin(self, username, pw_hash):
        self._check()
        if self.consumed:
            raise BootstrapConsumedError()
        if username in self.users:
            raise ValueError("taken")
        self.consumed = True
        self.users[username] = ("admin", f"rt-{username}")
        return f"rt-{username}"

    def create_user(self, username, pw_hash, role, *, replacing=None):
        self._check()
        if username in self.users:
            raise ValueError("taken")
        self.users.pop(replacing, None)
        self.users[username] = (role, f"rt-{username}")
        return f"rt-{username}"

    def bootstrap_consumed(self):
        self._check()
        return self.consumed

    def get_by_refresh_token(self, refresh_token):
        self._check()
        for name, (role, rt) in self.users.items():
            if rt == refresh_token:
                return name, role
        return None

    def exists(self, username):
        self._check()
        return username in self.users


class BackendAuthFlowTest(unittest.TestCase):
    def setUp(self):
        os.environ.update(
            CONTAINER_API_KEY="container-key",
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        self.db = FakeDatabase()
        from app import create_app
        self.client = create_app(database=self.db).test_client()

    def _bootstrap(self, key="initial-key"):
        return self.client.post(
            "/api/create-user/admin",
            json={"username": "root", "password": PW},
            headers={"Authorization": f"Bearer {key}"},
        )

    def _bearer(self, token):
        return {**CK, "Authorization": f"Bearer {token}"}

    def test_bootstrap_wrong_key(self):
        self.assertEqual(self._bootstrap("nope").status_code, 401)

    def test_bootstrap_only_once(self):
        self.assertEqual(self._bootstrap().status_code, 201)
        self.assertEqual(self._bootstrap().status_code, 410)

    def test_full_flow_admin_is_replaced(self):
        admin = self._bootstrap().get_json()
        r = self.client.post(
            "/api/create-user/user",
            json={"username": "svc", "password": PW},
            headers=self._bearer(admin["access_token"]),
        )
        self.assertEqual(r.status_code, 201)
        svc = r.get_json()

        # old admin: refresh token dead AND still-valid access token rejected
        self.assertEqual(
            self.client.post("/api/token", json={"refresh_token": admin["refresh_token"]}).status_code, 401
        )
        self.assertEqual(
            self.client.post("/api/create-user/user", json={"username": "x", "password": PW},
                             headers=self._bearer(admin["access_token"])).status_code, 401
        )

        # service user can wake devices (invalid MAC -> 400 from the service layer)
        tok = self.client.post("/api/token", json={"refresh_token": svc["refresh_token"]}).get_json()
        r = self.client.put("/api/devices/wol", json={"mac": "zz"}, headers=self._bearer(tok["access_token"]))
        self.assertEqual(r.status_code, 400)
        # ...but cannot create users
        r = self.client.post("/api/create-user/user", json={"username": "y", "password": PW},
                             headers=self._bearer(tok["access_token"]))
        self.assertEqual(r.status_code, 403)

    def test_wol_requires_auth(self):
        self.assertEqual(self.client.put("/api/devices/wol", json={"mac": "00:11:22:33:44:55"}).status_code, 401)
        self.assertEqual(
            self.client.put("/api/devices/wol", json={"mac": "00:11:22:33:44:55"},
                            headers={"Authorization": "Bearer x"}).status_code, 401)

    def test_database_down_fails_closed(self):
        admin = self._bootstrap().get_json()
        self.db.down = True
        # bootstrap, token exchange and authenticated calls all refuse (503), never allow
        self.assertEqual(self._bootstrap().status_code, 503)
        self.assertEqual(
            self.client.post("/api/token", json={"refresh_token": admin["refresh_token"]}).status_code, 503)
        r = self.client.put("/api/devices/wol", json={"mac": "zz"}, headers=self._bearer(admin["access_token"]))
        self.assertEqual(r.status_code, 503)

    def test_missing_env_fails_startup(self):
        del os.environ["JWT_SECRET"]
        from app import create_app
        with self.assertRaises(RuntimeError):
            create_app(database=FakeDatabase())


class DatabaseClientStubTest(unittest.TestCase):
    """The real client is not written yet: every operation must refuse, never pretend."""

    def test_every_operation_raises(self):
        client = DatabaseClient()
        calls = (
            lambda: client.create_bootstrap_admin("a", "h"),
            lambda: client.create_user("a", "h", "user"),
            client.bootstrap_consumed,
            lambda: client.get_by_refresh_token("x"),
            lambda: client.exists("a"),
        )
        for call in calls:
            with self.assertRaises(NotImplementedError):
                call()

    def test_backend_with_stub_grants_nothing(self):
        os.environ.update(
            CONTAINER_API_KEY="container-key",
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        from app import create_app
        client = create_app().test_client()
        r = client.post("/api/create-user/admin", json={"username": "root", "password": PW},
                        headers={"Authorization": "Bearer initial-key"})
        self.assertGreaterEqual(r.status_code, 500)


class SharedAuthTest(unittest.TestCase):
    def test_subclasses_share_base(self):
        for cls in (FrontendAuth, DatabaseAuth):
            self.assertTrue(issubclass(cls, BaseAuth))

    def test_container_key_check_is_fail_closed(self):
        os.environ.pop("CONTAINER_API_KEY", None)
        from flask import Flask
        app = Flask(__name__)
        auth = FrontendAuth()

        @app.route("/x")
        @auth.require_container_key
        def x():
            return "ok"

        self.assertEqual(app.test_client().get("/x").status_code, 503)


if __name__ == "__main__":
    unittest.main()
