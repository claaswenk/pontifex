"""
The backend's DatabaseClient talks to the real database app over real TLS.

The database container runs as a TLS server in its own interpreter (all
containers call their package "app"), on a fresh SQLite file. The client is
built exactly like in the backend: from the pair secret and DATABASE_URL.
The behaviour is the one tests/fake_database.py promises to the backend tests.
"""

import base64
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from app.database_client import DatabaseClient, DatabaseUnavailableError  # noqa: E402
from shared.container_auth import ContainerAuth  # noqa: E402
from shared.errors import BootstrapConsumedError  # noqa: E402
from tests.test_frontend_backend import base_env, make_cert  # noqa: E402

_DATABASE = r"""
import os, ssl, sys
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "database")]
from werkzeug.serving import make_server
from app import create_app

app = create_app()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["TLS_CERT_PATH"], os.environ["TLS_KEY_PATH"])
server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=context)
print(server.server_port, flush=True)
server.serve_forever()
"""

SECRET = "d" * 40
HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"x" * 20).decode()
JPEG = base64.b64encode(b"\xff\xd8\xff\xe0" + b"y" * 20).decode()
SVG = base64.b64encode(b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>").decode()


class DatabaseClientTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cert, key = make_cert(tmp.name)
        env = {
            **base_env(),
            "TLS_CERT_PATH": cert, "TLS_KEY_PATH": key,
            "BACKEND_DATABASE_SECRET": SECRET,
            "DB_PATH": os.path.join(tmp.name, "pontifex.db"),
        }
        log_file = open(os.path.join(tmp.name, "database.log"), "w", encoding="utf-8")
        self.addCleanup(log_file.close)
        server = subprocess.Popen(
            [sys.executable, "-c", f"ROOT = {ROOT!r}\n{_DATABASE}"],
            env=env, stdout=subprocess.PIPE, stderr=log_file, text=True,
        )
        self.addCleanup(server.stdout.close)
        self.addCleanup(server.wait, 10)
        self.addCleanup(server.terminate)
        self.url = f"https://127.0.0.1:{int(server.stdout.readline().strip())}"
        self.client = self.connect(SECRET)

    def connect(self, secret: str) -> DatabaseClient:
        with mock.patch.dict(os.environ, {"BACKEND_DATABASE_SECRET": secret, "DATABASE_URL": self.url}):
            client = DatabaseClient()
            client.connect(ContainerAuth("backend", ("database",)))
        self._env = mock.patch.dict(os.environ, {"BACKEND_DATABASE_SECRET": secret})
        self._env.start()
        self.addCleanup(self._env.stop)
        return client

    def test_bootstrap_only_once(self):
        self.assertFalse(self.client.bootstrap_consumed())
        token = self.client.create_bootstrap_admin("root", HASH)
        self.assertTrue(self.client.bootstrap_consumed())
        self.assertEqual(self.client.get_by_refresh_token(token), ("root", "admin"))
        with self.assertRaises(BootstrapConsumedError):
            self.client.create_bootstrap_admin("eve", HASH)
        self.assertFalse(self.client.exists("eve"))

    def test_accounts(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        with self.assertRaises(ValueError):
            self.client.create_user("anna", HASH, "user")
        self.assertEqual(self.client.get_credentials("anna"),
                         {"username": "anna", "pw_hash": HASH, "role": "user", "must_change": False})
        self.assertIsNone(self.client.get_credentials("nobody"))
        self.assertEqual(sorted(u["username"] for u in self.client.list_users()), ["anna", "root"])
        self.assertTrue(all(set(u) == {"username", "role"} for u in self.client.list_users()))

    def test_the_must_change_flag_travels_with_the_account(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user", must_change=True)
        self.assertTrue(self.client.get_credentials("anna")["must_change"])
        self.assertFalse(self.client.get_credentials("root")["must_change"])
        self.assertTrue(self.client.set_password("anna", HASH + "x"))
        self.assertFalse(self.client.get_credentials("anna")["must_change"])
        self.assertTrue(self.client.set_password("anna", HASH + "y", must_change=True))
        self.assertTrue(self.client.get_credentials("anna")["must_change"])

    def test_password_change_revokes_tokens(self):
        token = self.client.create_bootstrap_admin("root", HASH)
        second = self.client.create_refresh_token("root")
        self.assertTrue(self.client.set_password("root", HASH + "x"))
        self.assertIsNone(self.client.get_by_refresh_token(token))
        self.assertIsNone(self.client.get_by_refresh_token(second))
        self.assertEqual(self.client.get_credentials("root")["pw_hash"], HASH + "x")
        self.assertFalse(self.client.set_password("nobody", HASH))

    def test_revoke_and_unknown_tokens(self):
        token = self.client.create_bootstrap_admin("root", HASH)
        self.client.revoke_refresh_token(token)
        self.assertIsNone(self.client.get_by_refresh_token(token))
        self.client.revoke_refresh_token("never-issued")
        self.assertIsNone(self.client.get_by_refresh_token("never-issued"))
        with self.assertRaises(ValueError):
            self.client.create_refresh_token("nobody")

    def test_reset_token_is_single_use(self):
        token = self.client.create_bootstrap_admin("root", HASH)
        self.assertFalse(self.client.create_reset_token("nobody", "h" * 64, 2**33))
        self.assertTrue(self.client.create_reset_token("root", "a" * 64, 2**33))
        self.assertFalse(self.client.reset_password_with_token("b" * 64, HASH))
        self.assertTrue(self.client.reset_password_with_token("a" * 64, HASH + "y"))
        self.assertFalse(self.client.reset_password_with_token("a" * 64, HASH))
        self.assertIsNone(self.client.get_by_refresh_token(token))
        self.assertEqual(self.client.get_credentials("root")["pw_hash"], HASH + "y")

    def test_expired_reset_token_is_refused(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.assertTrue(self.client.create_reset_token("root", "c" * 64, 1))
        self.assertFalse(self.client.reset_password_with_token("c" * 64, HASH + "z"))
        self.assertEqual(self.client.get_credentials("root")["pw_hash"], HASH)

    def test_rename(self):
        token = self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        self.client.create_device("root", "nas", "192.168.1.10", "00:11:22:33:44:55")
        with self.assertRaises(ValueError):
            self.client.rename_user("root", "anna")
        self.assertFalse(self.client.rename_user("nobody", "x-user"))
        self.assertTrue(self.client.rename_user("root", "boss"))
        self.assertIsNone(self.client.get_by_refresh_token(token))
        self.assertFalse(self.client.exists("root"))
        self.assertEqual([d["name"] for d in self.client.list_devices("boss")], ["nas"])

    def test_devices_belong_to_their_owner(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        device = self.client.create_device("root", "nas", "192.168.1.10", "00:11:22:33:44:55")
        self.assertEqual(set(device), {"id", "name", "address", "mac", "picture"})
        self.assertIsNone(device["picture"])
        self.assertEqual(self.client.get_device("root", device["id"]), device)
        self.assertEqual(self.client.list_devices("root"), [device])
        # anna cannot see, fetch or delete it
        self.assertEqual(self.client.list_devices("anna"), [])
        self.assertIsNone(self.client.get_device("anna", device["id"]))
        self.assertFalse(self.client.delete_device("anna", device["id"]))
        self.assertIsNotNone(self.client.get_device("root", device["id"]))
        # same name twice for one owner, but fine for another one
        with self.assertRaises(ValueError):
            self.client.create_device("root", "nas", "192.168.1.11", "00:11:22:33:44:56")
        self.client.create_device("anna", "nas", "192.168.1.12", "00:11:22:33:44:57")
        with self.assertRaises(ValueError):
            self.client.create_device("nobody", "nas", "192.168.1.10", "00:11:22:33:44:55")
        self.assertTrue(self.client.delete_device("root", device["id"]))
        self.assertFalse(self.client.delete_device("root", device["id"]))
        self.assertEqual(len(self.client.list_devices("anna")), 1)

    def test_a_device_can_be_changed_by_its_owner_only(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        device = self.client.create_device("root", "nas", "192.168.1.10", "00:11:22:33:44:55", PNG)
        other = self.client.create_device("root", "pc", "192.168.1.11", "00:11:22:33:44:56")
        changed = self.client.update_device("root", device["id"], "nas2", "10.0.0.5", "00:11:22:33:44:99")
        self.assertEqual(changed, {**device, "name": "nas2", "address": "10.0.0.5", "mac": "00:11:22:33:44:99"})
        self.assertEqual(self.client.get_device("root", device["id"]), changed)  # the picture version stays
        self.assertEqual(self.client.update_device("root", device["id"], "nas2", "10.0.0.6", "00:11:22:33:44:99")["name"],
                         "nas2")  # the own name is no conflict
        with self.assertRaises(ValueError):
            self.client.update_device("root", device["id"], "pc", "10.0.0.5", "00:11:22:33:44:99")
        self.assertIsNone(self.client.update_device("anna", device["id"], "x", "10.0.0.5", "00:11:22:33:44:99"))
        self.assertIsNone(self.client.update_device("root", 9999, "x", "10.0.0.5", "00:11:22:33:44:99"))
        self.assertEqual(self.client.get_device("root", other["id"]), other)

    def test_a_device_picture_is_stored_replaced_and_private(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        device = self.client.create_device("root", "nas", "192.168.1.10", "00:11:22:33:44:55", PNG)
        self.assertIsInstance(device["picture"], int)
        stored = self.client.get_device_picture("root", device["id"])
        self.assertEqual((stored["media_type"], stored["image"]), ("image/png", PNG))
        self.assertEqual(self.client.list_devices("root")[0]["picture"], stored["version"])
        # a replacement gets a new version (so browsers fetch it again) and a new type
        version = self.client.set_device_picture("root", device["id"], JPEG)
        self.assertNotEqual(version, stored["version"])
        self.assertEqual(self.client.get_device_picture("root", device["id"])["media_type"], "image/jpeg")
        # somebody else's device is "not found" for every picture call
        self.assertIsNone(self.client.get_device_picture("anna", device["id"]))
        self.assertIsNone(self.client.set_device_picture("anna", device["id"], PNG))
        self.assertFalse(self.client.delete_device_picture("anna", device["id"]))
        self.assertIsNotNone(self.client.get_device_picture("root", device["id"]))
        self.assertTrue(self.client.delete_device_picture("root", device["id"]))
        self.assertFalse(self.client.delete_device_picture("root", device["id"]))
        self.assertIsNone(self.client.list_devices("root")[0]["picture"])

    def test_pictures_that_are_not_png_jpeg_or_webp_are_refused(self):
        self.client.create_bootstrap_admin("root", HASH)
        device = self.client.create_device("root", "nas", "192.168.1.10", "00:11:22:33:44:55")
        for bad in (SVG, "not base64!", base64.b64encode(b"x" * 300_000).decode(), ""):
            with self.subTest(bad=bad[:12]):
                with self.assertRaises(ValueError):
                    self.client.set_device_picture("root", device["id"], bad)
                with self.assertRaises(ValueError):
                    self.client.set_user_picture("root", bad)
        self.assertIsNone(self.client.get_device_picture("root", device["id"]))
        # a refused picture does not create the device either
        with self.assertRaises(DatabaseUnavailableError):
            self.client.create_device("root", "bad", "192.168.1.11", "00:11:22:33:44:56", SVG)
        self.assertEqual([d["name"] for d in self.client.list_devices("root")], ["nas"])

    def test_a_user_picture_follows_a_rename_and_goes_with_the_user(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        self.assertIsNone(self.client.get_user_picture_version("anna"))
        version = self.client.set_user_picture("anna", PNG)
        self.assertEqual(self.client.get_user_picture_version("anna"), version)
        self.assertIsNone(self.client.get_user_picture("root"))
        self.assertIsNone(self.client.set_user_picture("nobody", PNG))
        self.assertTrue(self.client.rename_user("anna", "annika"))
        self.assertEqual(self.client.get_user_picture("annika")["image"], PNG)
        self.assertTrue(self.client.delete_user_picture("annika"))
        self.assertFalse(self.client.delete_user_picture("annika"))
        self.client.set_user_picture("annika", PNG)
        self.assertTrue(self.client.delete_user("annika"))
        self.assertIsNone(self.client.get_user_picture("annika"))

    def test_deleting_a_device_or_a_user_removes_the_pictures(self):
        self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        device = self.client.create_device("anna", "pc", "192.168.1.20", "00:11:22:33:44:66", PNG)
        self.assertTrue(self.client.delete_device("anna", device["id"]))
        self.assertIsNone(self.client.get_device_picture("anna", device["id"]))
        # the id is not reused for a new device, so a stale picture cannot leak onto it
        again = self.client.create_device("anna", "pc", "192.168.1.20", "00:11:22:33:44:66")
        self.assertIsNone(self.client.get_device_picture("anna", again["id"]))

    def test_deleting_a_user_removes_devices_and_tokens(self):
        token = self.client.create_bootstrap_admin("root", HASH)
        self.client.create_user("anna", HASH, "user")
        anna_token = self.client.create_refresh_token("anna")
        self.client.create_device("anna", "pc", "192.168.1.20", "00:11:22:33:44:66")
        self.assertTrue(self.client.delete_user("anna"))
        self.assertFalse(self.client.delete_user("anna"))
        self.assertIsNone(self.client.get_by_refresh_token(anna_token))
        self.assertEqual(self.client.list_devices("anna"), [])
        self.assertEqual(self.client.get_by_refresh_token(token), ("root", "admin"))

    def test_a_database_with_another_secret_is_not_trusted(self):
        stranger = self.connect("x" * 40)
        with self.assertRaises(DatabaseUnavailableError):
            stranger.bootstrap_consumed()

    def test_an_unreachable_database_fails_closed(self):
        self.url = "https://127.0.0.1:1"
        lost = self.connect(SECRET)
        with self.assertRaises(DatabaseUnavailableError):
            lost.bootstrap_consumed()


if __name__ == "__main__":
    unittest.main()
