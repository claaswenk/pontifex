import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.auth import BaseAuth  # noqa: E402
from app.database_client import DatabaseClient  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402


def _load_auth(name, container):
    # Every container's package is called "app", so load its auth module by path.
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROOT, "src", container, "app", "auth.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FrontendAuth = _load_auth("frontend_auth", "frontend").FrontendAuth
DatabaseAuth = _load_auth("database_auth", "database").DatabaseAuth

PW = "a-long-enough-password"
SECRETS = {
    "BACKEND_FRONTEND_SECRET": "f" * 40,
    "BACKEND_DATABASE_SECRET": "d" * 40,
}


class BackendAuthFlowTest(unittest.TestCase):
    def setUp(self):
        os.environ.update(
            SECRETS,
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
        return {"Authorization": f"Bearer {token}"}

    def test_bootstrap_wrong_key(self):
        self.assertEqual(self._bootstrap("nope").status_code, 401)

    def test_bootstrap_only_once(self):
        self.assertEqual(self._bootstrap().status_code, 201)
        self.assertEqual(self._bootstrap().status_code, 410)

    def test_admin_survives_creating_users(self):
        admin = self._bootstrap().get_json()
        r = self.client.post(
            "/api/users",
            json={"username": "svc", "password": PW},
            headers=self._bearer(admin["access_token"]),
        )
        self.assertEqual(r.status_code, 201)

        # the admin is NOT replaced any more: token and refresh token still work
        self.assertEqual(
            self.client.post("/api/token", json={"refresh_token": admin["refresh_token"]}).status_code, 200
        )
        self.assertEqual(
            self.client.get("/api/users", headers=self._bearer(admin["access_token"])).status_code, 200
        )

        # a regular user logs in and reaches the device routes, but cannot manage users
        tok = self.client.post("/api/login", json={"username": "svc", "password": PW}).get_json()
        r = self.client.get("/api/devices", headers=self._bearer(tok["access_token"]))
        self.assertEqual(r.status_code, 200)
        r = self.client.post("/api/users", json={"username": "other", "password": PW},
                             headers=self._bearer(tok["access_token"]))
        self.assertEqual(r.status_code, 403)

    def test_old_create_user_route_is_gone(self):
        admin = self._bootstrap().get_json()
        r = self.client.post("/api/create-user/user", json={"username": "svc", "password": PW},
                             headers=self._bearer(admin["access_token"]))
        self.assertIn(r.status_code, (404, 405))

    def test_wake_requires_auth(self):
        self.assertEqual(self.client.post("/api/devices/1/wake").status_code, 401)
        self.assertEqual(
            self.client.post("/api/devices/1/wake", headers={"Authorization": "Bearer x"}).status_code, 401)

    def test_old_free_form_wol_route_is_gone(self):
        admin = self._bootstrap().get_json()
        r = self.client.put("/api/devices/wol", json={"mac": "00:11:22:33:44:55", "ip": "10.0.0.255", "port": 7},
                            headers=self._bearer(admin["access_token"]))
        self.assertIn(r.status_code, (404, 405))

    def test_database_down_fails_closed(self):
        admin = self._bootstrap().get_json()
        self.db.down = True
        # bootstrap, token exchange and authenticated calls all refuse (503), never allow
        self.assertEqual(self._bootstrap().status_code, 503)
        self.assertEqual(
            self.client.post("/api/token", json={"refresh_token": admin["refresh_token"]}).status_code, 503)
        r = self.client.post("/api/devices/1/wake", headers=self._bearer(admin["access_token"]))
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
            lambda: client.get_credentials("a"),
            client.list_users,
            lambda: client.set_password("a", "h"),
            lambda: client.create_reset_token("a", "h", 1),
            lambda: client.reset_password_with_token("h", "p"),
            lambda: client.rename_user("a", "b"),
            lambda: client.delete_user("a"),
            lambda: client.create_refresh_token("a"),
            lambda: client.revoke_refresh_token("x"),
            lambda: client.list_devices("a"),
            lambda: client.get_device("a", 1),
            lambda: client.create_device("a", "nas", "192.168.1.10", "00:11:22:33:44:55"),
            lambda: client.delete_device("a", 1),
        )
        for call in calls:
            with self.assertRaises(NotImplementedError):
                call()

    def test_backend_with_stub_grants_nothing(self):
        os.environ.update(
            SECRETS,
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

    def test_container_route_without_secret_is_refused(self):
        os.environ.pop("BACKEND_FRONTEND_SECRET", None)
        with self.assertRaises(RuntimeError):
            FrontendAuth().validate_config()


if __name__ == "__main__":
    unittest.main()
