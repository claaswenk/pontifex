"""
The real frontend app talks to the real backend app over real TLS.

Both packages are called "app", so each runs in its own interpreter: the
backend as a TLS server (with the in-memory FakeDatabase), the frontend as a
test client whose BackendClient is built from the environment, exactly like in
the container. This covers setup, login, token renewal, devices, users and
logout through the signed container channel.
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_BACKEND = r"""
import os, ssl, sys
sys.path[:0] = [ROOT, os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]
from werkzeug.serving import make_server
from app import create_app
from tests.fake_database import FakeDatabase

app = create_app(database=FakeDatabase())
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["TLS_CERT_PATH"], os.environ["TLS_KEY_PATH"])
server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=context)
print(server.server_port, flush=True)
server.serve_forever()
"""

_FRONTEND = r"""
import os, re, sys, unittest
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "frontend")]
from app import create_app
from app.pages import COOKIE

PW = "a-long-enough-password"
BASE = "https://localhost"


class Flow(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def csrf(self, client=None):
        client = client or self.client
        if client.get_cookie(COOKIE) is None:
            client.get("/login", base_url=BASE)
        return self.app.extensions["sessions"].get(client.get_cookie(COOKIE).value).csrf

    def post(self, path, data=None, client=None):
        client = client or self.client
        return client.post(path, data={**(data or {}), "csrf_token": self.csrf(client)}, base_url=BASE)

    def page(self, path):
        return self.client.get(path, base_url=BASE).get_data(as_text=True)

    def test_whole_flow(self):
        # wrong setup key
        self.client.get("/setup", base_url=BASE)
        self.post("/setup", {"setup_key": "wrong", "username": "root", "password": PW, "password_confirm": PW})
        self.assertIn("setup key is wrong", self.page("/setup"))

        # real setup
        response = self.post("/setup", {"setup_key": "initial-key", "username": "root",
                                        "password": PW, "password_confirm": PW})
        self.assertEqual(response.status_code, 303)
        self.assertIn("No devices yet", self.page("/devices"))

        # devices
        self.post("/devices", {"name": "ryzen", "address": "10.255.255.1", "mac": "A8:A1:59:29:3D:6D"})
        page = self.page("/devices")
        self.assertIn("Device added.", page)
        self.assertIn("ryzen", page)
        # Online or offline depends on the network the test runs in; both are valid answers.
        self.assertTrue("Online" in page or "Offline" in page)
        device_id = re.search(r"/devices/(\d+)/wake", page).group(1)

        self.post("/devices", {"name": "ryzen", "address": "10.255.255.2", "mac": "a8:a1:59:29:3d:6e"})
        self.assertIn("already have a device", self.page("/devices"))
        self.post("/devices", {"name": "bad", "address": "127.0.0.1", "mac": "a8:a1:59:29:3d:6e"})
        self.assertIn("address", self.page("/devices").lower())

        # users
        self.post("/users", {"username": "anna", "password": PW})
        self.assertIn("User added.", self.page("/users"))
        self.assertIn("anna", self.page("/users"))
        self.post("/users", {"username": "anna", "password": PW})
        self.assertIn("Unable to create user", self.page("/users"))

        # the admin cannot delete themselves through a crafted request
        self.post("/users/root/delete")
        self.assertIn("cannot delete", self.page("/users"))

        # account and password change
        self.assertIn("root", self.page("/account"))
        self.post("/account/password", {"current_password": "wrong-password-1", "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        self.assertIn("current password is wrong", self.page("/account"))
        self.post("/account/password", {"current_password": PW, "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        self.assertIn("Password changed", self.page("/account"))
        self.assertEqual(self.client.get("/devices", base_url=BASE).status_code, 200)

        # anna: own devices only, no user management
        anna = self.app.test_client()
        response = self.post("/login", {"username": "anna", "password": PW}, anna)
        self.assertEqual(response.status_code, 303)
        self.assertIn("No devices yet", anna.get("/devices", base_url=BASE).get_data(as_text=True))
        self.assertEqual(anna.get("/users", base_url=BASE).status_code, 403)

        # anna cannot touch the admin's device
        self.post(f"/devices/{device_id}/delete", client=anna)
        self.assertIn("Device not found", anna.get("/devices", base_url=BASE).get_data(as_text=True))
        self.assertIn("ryzen", self.page("/devices"))

        # wrong password for anna
        wrong = self.app.test_client()
        self.post("/login", {"username": "anna", "password": "nope-nope-nope"}, wrong)
        self.assertIn("Invalid username or password.", wrong.get("/login", base_url=BASE).get_data(as_text=True))

        # delete the device, sign out
        self.post(f"/devices/{device_id}/delete")
        self.assertIn("Device deleted.", self.page("/devices"))
        self.assertEqual(self.post("/logout").status_code, 303)
        self.assertEqual(self.client.get("/devices", base_url=BASE).status_code, 302)

    def test_setup_cannot_be_repeated(self):
        self.client.get("/setup", base_url=BASE)
        self.post("/setup", {"setup_key": "initial-key", "username": "root", "password": PW, "password_confirm": PW})
        other = self.app.test_client()
        other.get("/setup", base_url=BASE)
        response = self.post("/setup", {"setup_key": "initial-key", "username": "eve",
                                        "password": PW, "password_confirm": PW}, other)
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertEqual(other.get("/devices", base_url=BASE).status_code, 302)

    def test_a_backend_with_another_secret_is_not_trusted(self):
        original = os.environ["BACKEND_FRONTEND_SECRET"]
        self.addCleanup(os.environ.__setitem__, "BACKEND_FRONTEND_SECRET", original)
        os.environ["BACKEND_FRONTEND_SECRET"] = "x" * 40
        app = create_app()
        self.app = app
        response = self.post("/login", {"username": "root", "password": PW}, app.test_client())
        self.assertEqual(response.status_code, 502)


unittest.main(argv=["frontend-e2e", "Flow." + os.environ["E2E_CASE"]], verbosity=2)
"""


def base_env() -> dict:
    """Minimal environment; Windows additionally needs SYSTEMROOT for sockets and TLS."""
    env = {"PATH": os.environ["PATH"]}
    if "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def make_cert(directory: str) -> tuple[str, str]:
    cert, key = os.path.join(directory, "backend.crt"), os.path.join(directory, "backend.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", key, "-out", cert],
        check=True, capture_output=True,
    )
    return cert, key


CASES = ("test_whole_flow", "test_setup_cannot_be_repeated", "test_a_backend_with_another_secret_is_not_trusted")


class FrontendWithRealBackendTest(unittest.TestCase):
    """One fresh backend per case: the setup can only be done once per database."""

    def run_case(self, case: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = make_cert(tmp)
            secret = "s" * 40
            backend_env = {
                **base_env(),
                "TLS_CERT_PATH": cert, "TLS_KEY_PATH": key,
                "BACKEND_FRONTEND_SECRET": secret, "BACKEND_DATABASE_SECRET": "d" * 40,
                "JWT_SECRET": "j" * 40, "INITIAL_API_KEY": "initial-key",
            }
            log_path = os.path.join(tmp, "backend.log")
            with open(log_path, "w", encoding="utf-8") as log_file:
                backend = subprocess.Popen(
                    [sys.executable, "-c", f"ROOT = {ROOT!r}\n{_BACKEND}"],
                    env=backend_env, stdout=subprocess.PIPE, stderr=log_file, text=True,
                )
                try:
                    port = int(backend.stdout.readline().strip())
                    frontend_env = {
                        **base_env(),
                        "BACKEND_FRONTEND_SECRET": secret,
                        "BACKEND_URL": f"https://127.0.0.1:{port}",
                        "E2E_CASE": case,
                    }
                    proc = subprocess.run(
                        [sys.executable, "-W", "error::UserWarning", "-c", f"ROOT = {ROOT!r}\n{_FRONTEND}"],
                        env=frontend_env, capture_output=True, text=True, timeout=100, check=False,
                    )
                finally:
                    backend.terminate()
                    backend.wait(timeout=10)
                    backend.stdout.close()
            with open(log_path, encoding="utf-8") as fh:
                backend_log = fh.read()[-3000:]
        self.assertEqual(proc.returncode, 0, proc.stderr[-4000:] + "\nBACKEND LOG:\n" + backend_log)
        self.assertIn("Ran 1 test", proc.stderr)
        self.assertNotIn("skipped", proc.stderr)

    def test_whole_flow(self):
        self.run_case(CASES[0])

    def test_setup_cannot_be_repeated(self):
        self.run_case(CASES[1])

    def test_a_backend_with_another_secret_is_not_trusted(self):
        self.run_case(CASES[2])


if __name__ == "__main__":
    unittest.main()
