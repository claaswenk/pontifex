"""
Frontend behaviour against a fake backend.

The frontend and the backend both call their package "app", so these cases run in
their own interpreter (started by test_frontend_pages.py) with only the frontend
on sys.path. The fake sits at the transport level: the real BackendClient,
including the token renewal, is under test.
"""

import base64
import io
import os
import re
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "frontend")]
os.environ["BACKEND_FRONTEND_SECRET"] = "f" * 40

from app import create_app  # noqa: E402
from app.pages import COOKIE  # noqa: E402
from app.services import (  # noqa: E402
    ABSOLUTE_TIMEOUT_SECONDS, IDLE_TIMEOUT_SECONDS, MAX_SESSIONS, BackendClient, SessionStore,
)
from shared.container_auth import ContainerAuthError, ContainerUnavailableError  # noqa: E402

HTTPS = "https://localhost"
PW = "a-long-enough-password"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"x" * 40
PNG_B64 = base64.b64encode(PNG_BYTES).decode()


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class FakeTransport:
    """Stands in for ContainerClient: answers like the backend would."""

    def __init__(self):
        self.calls = []
        self.routes = {}
        self.error = None
        self.devices = [{"id": 1, "name": "nas", "address": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01",
                         "status": "online", "latency_ms": 2.4, "picture": None}]
        self.me_picture = None
        self.users = [{"username": "root", "role": "admin"}, {"username": "anna", "role": "user"}]
        self.valid_access = "access-1"
        self.routes[("POST", "/api/token")] = self._token
        self.routes[("GET", "/api/metrics")] = lambda b, t: (200, {"devices": self.devices})
        self.routes[("GET", "/api/devices")] = lambda b, t: (200, {"devices": self.devices})
        self.routes[("GET", "/api/devices/1")] = lambda b, t: (200, self.devices[0])
        self.routes[("GET", "/api/me")] = lambda b, t: (
            200, {"username": "root", "role": "admin", "picture": self.me_picture})
        self.routes[("GET", "/api/users")] = lambda b, t: (200, {"users": self.users})

    def _token(self, body, token):
        if body.get("refresh_token") == "refresh-1":
            return 200, {"access_token": "access-1", "expires_in": 300}
        return 401, {"error": "Unauthorized: unknown refresh token."}

    def request(self, method, path, body=None, headers=None):
        auth = (headers or {}).get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
        self.calls.append((method, path, body, token))
        if self.error is not None:
            raise self.error
        route = self.routes.get((method, path))
        if route is None:
            return 404, {"error": "Not found."}
        needs_token = path not in ("/api/login", "/api/token", "/api/logout", "/api/create-user/admin")
        if needs_token and token != self.valid_access:
            return 401, {"error": "Unauthorized: invalid or expired access token."}
        return route(body, token)

    def calls_to(self, method, path):
        return [c for c in self.calls if c[0] == method and c[1] == path]


class FrontendCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.transport = FakeTransport()
        self.transport.routes[("POST", "/api/login")] = self._login
        self.sessions = SessionStore(clock=self.clock)
        self.backend = BackendClient(self.transport, clock=self.clock)
        self.app = create_app(backend=self.backend, sessions=self.sessions)
        self.client = self.app.test_client()

    def _login(self, body, token):
        if body["password"] == PW and body["username"] in ("root", "anna"):
            role = "admin" if body["username"] == "root" else "user"
            return 200, {"refresh_token": "refresh-1", "access_token": "access-1",
                         "expires_in": 300, "role": role}
        return 401, {"error": "Invalid username or password."}

    # -- helpers ------------------------------------------------------------

    def get(self, path, client=None):
        return (client or self.client).get(path, base_url=HTTPS)

    def csrf(self, client=None):
        """The CSRF token of the client's session (a visit to /login creates one if needed)."""
        client = client or self.client
        if client.get_cookie(COOKIE) is None:
            self.get("/login", client)
        return self.sessions.get(client.get_cookie(COOKIE).value).csrf

    def post(self, path, data=None, client=None, token=True):
        client = client or self.client
        data = dict(data or {})
        if token:
            data["csrf_token"] = self.csrf(client)
        return client.post(path, data=data, base_url=HTTPS)

    def sign_in(self, username="root", client=None):
        response = self.post("/login", {"username": username, "password": PW}, client)
        self.assertEqual(response.status_code, 303, response.get_data(as_text=True))
        return response

    def page(self, path, client=None):
        return self.get(path, client).get_data(as_text=True)

    def flashed(self, path="/devices", client=None):
        return self.page(path, client)


class AccessControlTest(FrontendCase):
    def test_pages_need_a_login(self):
        for path in ("/devices", "/users", "/account"):
            response = self.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/login"), path)

    def test_root_redirects_to_devices(self):
        self.assertTrue(self.get("/").headers["Location"].endswith("/devices"))

    def test_every_post_needs_the_csrf_token(self):
        self.sign_in()
        for path in ("/devices", "/devices/1/wake", "/devices/1/delete", "/devices/1/edit",
                     "/devices/1/picture/delete", "/users",
                     "/users/anna/password", "/users/anna/delete", "/account/password",
                     "/account/picture", "/account/picture/delete", "/logout"):
            before = len(self.transport.calls)
            response = self.client.post(path, data={}, base_url=HTTPS)
            self.assertEqual(response.status_code, 400, path)
            response = self.client.post(path, data={"csrf_token": "wrong"}, base_url=HTTPS)
            self.assertEqual(response.status_code, 400, path)
            self.assertEqual(len(self.transport.calls), before, path)

    def test_post_without_any_session_is_refused(self):
        response = self.app.test_client().post("/login", data={"username": "root", "password": PW},
                                               base_url=HTTPS)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.transport.calls_to("POST", "/api/login"), [])

    def test_csrf_token_of_another_session_is_refused(self):
        other = self.app.test_client()
        foreign = self.csrf(other)
        self.get("/login")
        response = self.client.post("/login", data={"csrf_token": foreign, "username": "root",
                                                    "password": PW}, base_url=HTTPS)
        self.assertEqual(response.status_code, 400)

    def test_regular_user_cannot_open_user_management(self):
        self.sign_in("anna")
        self.assertEqual(self.get("/users").status_code, 403)
        response = self.post("/users", {"username": "bob", "password": PW})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.transport.calls_to("POST", "/api/users"), [])

    def test_regular_user_sees_no_users_link(self):
        self.sign_in("anna")
        self.assertNotIn(">Users<", self.page("/devices"))

    def test_admin_sees_the_users_link(self):
        self.sign_in("root")
        self.assertIn(">Users<", self.page("/devices"))

    def test_unknown_page_is_a_plain_404(self):
        response = self.get("/does-not-exist")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Error 404", response.get_data(as_text=True))


class SessionAndCookieTest(FrontendCase):
    def test_cookie_flags(self):
        cookie = self.get("/login").headers["Set-Cookie"]
        self.assertTrue(cookie.startswith(COOKIE + "="))
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Domain", cookie)
        self.assertTrue(COOKIE.startswith("__Host-"))

    def test_login_issues_a_new_session_id(self):
        before = self.get("/login").headers["Set-Cookie"].split(";")[0]
        after = self.sign_in().headers["Set-Cookie"].split(";")[0]
        self.assertNotEqual(before, after)

    def test_an_id_planted_before_the_login_does_not_work_afterwards(self):
        self.get("/login")
        planted = self.client.get_cookie(COOKIE).value
        self.sign_in()
        victim = self.app.test_client()
        victim.set_cookie(COOKIE, planted, domain="localhost")
        response = self.get("/devices", victim)
        self.assertEqual(response.status_code, 302)

    def test_the_browser_never_receives_a_token(self):
        response = self.sign_in()
        everything = str(response.headers) + response.get_data(as_text=True)
        everything += self.page("/devices") + self.page("/account")
        for secret in ("refresh-1", "access-1"):
            self.assertNotIn(secret, everything)

    def test_logout_ends_the_session_and_tells_the_backend(self):
        self.transport.routes[("POST", "/api/logout")] = lambda b, t: (200, {"status": "ok"})
        self.sign_in()
        old = self.client.get_cookie(COOKIE).value
        response = self.post("/logout")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.transport.calls_to("POST", "/api/logout")[0][2], {"refresh_token": "refresh-1"})
        stale = self.app.test_client()
        stale.set_cookie(COOKIE, old, domain="localhost")
        self.assertEqual(self.get("/devices", stale).status_code, 302)
        self.assertEqual(len(self.sessions), 0)

    def test_logout_works_even_if_the_backend_is_down(self):
        self.sign_in()
        self.transport.error = ContainerUnavailableError("down")
        response = self.post("/logout")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_idle_session_expires(self):
        self.sign_in()
        self.clock.now += IDLE_TIMEOUT_SECONDS + 1
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_session_expires_after_the_absolute_limit_even_when_used(self):
        self.sign_in()
        for _ in range(int(ABSOLUTE_TIMEOUT_SECONDS // (IDLE_TIMEOUT_SECONDS // 2)) + 2):
            self.clock.now += IDLE_TIMEOUT_SECONDS // 2
            response = self.get("/devices")
            if response.status_code == 302:
                return
        self.fail("session never expired")

    def test_session_store_is_bounded_and_keeps_signed_in_users(self):
        store = SessionStore(clock=self.clock)
        user = store.promote(store.create(), "root", "admin", "r", "a", 300)
        for _ in range(MAX_SESSIONS + 50):
            store.create()
        self.assertLessEqual(len(store), MAX_SESSIONS)
        self.assertIsNotNone(store.get(user.id))

    def test_no_cookie_on_health(self):
        response = self.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Set-Cookie", response.headers)

    def test_security_headers_and_no_store(self):
        response = self.get("/login")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe", csp)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("Strict-Transport-Security", response.headers)

    def test_no_inline_scripts_or_styles(self):
        pages = [self.page(p) for p in ("/login", "/setup", "/nope")]  # signed out
        self.sign_in()
        pages += [self.page(p) for p in ("/devices", "/users", "/account")]
        self.assertEqual(len(pages), 6)
        for body in pages:
            body = body.lower()
            self.assertIn("<html", body)
            # The one allowed script is the external file; nothing inline.
            scripts = [tag.lower() for tag in re.findall(r"<script[^>]*>", body, flags=re.IGNORECASE)]
            self.assertEqual(scripts, ['<script src="/static/app.js" defer>'])
            for forbidden in ("style=", "onclick", "onsubmit", "onload", "javascript:"):
                self.assertNotIn(forbidden, body)

    def test_footer_clock_carries_the_server_epoch_for_the_script(self):
        body = self.page("/login")
        epoch = int(re.search(r'<time id="server-time" data-epoch="(\d+)">', body).group(1))
        self.assertAlmostEqual(epoch, time.time(), delta=5)

    def test_the_script_file_is_served_and_has_no_eval(self):
        response = self.get("/static/app.js")
        self.assertEqual(response.status_code, 200)
        source = response.get_data(as_text=True)
        for forbidden in ("eval(", "innerHTML", "document.write", "new Function"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("Set-Cookie", response.headers)


class LoginAndSetupTest(FrontendCase):
    def test_login_forwards_the_credentials_and_redirects(self):
        response = self.sign_in()
        self.assertTrue(response.headers["Location"].endswith("/devices"))
        self.assertEqual(self.transport.calls_to("POST", "/api/login")[0][2],
                         {"username": "root", "password": PW})

    def test_wrong_password_gives_a_generic_message(self):
        self.get("/login")
        self.post("/login", {"username": "root", "password": "wrong"})
        page = self.page("/login")
        self.assertIn("Invalid username or password.", page)
        self.assertNotIn("Unauthorized", page)

    def test_the_message_is_shown_only_once(self):
        self.post("/login", {"username": "root", "password": "wrong"})
        self.assertIn("Invalid username or password.", self.page("/login"))
        self.assertNotIn("Invalid username or password.", self.page("/login"))

    def test_throttled_login_says_so(self):
        self.transport.routes[("POST", "/api/login")] = lambda b, t: (429, {"error": "x"})
        self.post("/login", {"username": "root", "password": "x"})
        self.assertIn("Too many failed attempts", self.page("/login"))

    def test_login_when_the_backend_fails_does_not_blame_the_password(self):
        self.transport.routes[("POST", "/api/login")] = lambda b, t: (503, {"error": "db"})
        self.post("/login", {"username": "root", "password": PW})
        page = self.page("/login")
        self.assertIn("temporarily unavailable", page)
        self.assertNotIn("Invalid username", page)

    def test_a_malformed_login_answer_signs_nobody_in(self):
        self.transport.routes[("POST", "/api/login")] = lambda b, t: (200, {"role": "admin"})
        self.post("/login", {"username": "root", "password": PW})
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_an_unknown_role_signs_nobody_in(self):
        self.transport.routes[("POST", "/api/login")] = lambda b, t: (
            200, {"refresh_token": "r", "access_token": "a", "expires_in": 300, "role": "root"})
        self.post("/login", {"username": "root", "password": PW})
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_signed_in_user_is_sent_away_from_login(self):
        self.sign_in()
        self.assertTrue(self.get("/login").headers["Location"].endswith("/devices"))

    def test_frontend_login_throttling_after_multiple_failures(self):
        # 5 failed attempts
        for _ in range(5):
            r = self.post("/login", {"username": "root", "password": "wrong-password"})
            self.assertEqual(r.status_code, 303)
        # 6th attempt is throttled on the frontend side
        r = self.post("/login", {"username": "root", "password": "wrong-password"})
        self.assertEqual(r.status_code, 303)
        page = self.page("/login")
        self.assertIn("Too many failed attempts. Try again later.", page)

    def test_setup_creates_the_admin_and_signs_in(self):
        self.transport.routes[("POST", "/api/create-user/admin")] = lambda b, t: (
            201, {"refresh_token": "refresh-1", "access_token": "access-1",
                  "expires_in": 300, "role": "admin"})
        self.get("/setup")
        response = self.post("/setup", {"setup_key": "the-key", "username": "Root",
                                        "password": PW, "password_confirm": PW})
        self.assertEqual(response.status_code, 303)
        call = self.transport.calls_to("POST", "/api/create-user/admin")[0]
        self.assertEqual((call[2], call[3]), ({"username": "Root", "password": PW}, "the-key"))
        self.assertEqual(self.get("/devices").status_code, 200)
        self.assertIn(">Users<", self.page("/devices"))

    def test_setup_with_different_passwords_does_not_call_the_backend(self):
        self.get("/setup")
        self.post("/setup", {"setup_key": "k", "username": "root", "password": PW,
                             "password_confirm": PW + "x"})
        self.assertEqual(self.transport.calls, [])
        self.assertIn("not the same", self.page("/setup"))

    def test_a_refused_setup_keeps_the_name_and_never_the_key_or_passwords(self):
        self.transport.routes[("POST", "/api/create-user/admin")] = lambda b, t: (401, {"error": "Unauthorized."})
        self.get("/setup")
        key = "setup-key-" + PW
        self.post("/setup", {"setup_key": key, "username": "boss", "password": PW, "password_confirm": PW})
        page = self.page("/setup")
        self.assertRegex(page, r'id="username"[^>]*value="boss"')
        self.assertRegex(page, r'id="setup_key"[^>]*aria-invalid="true"')
        for secret in (key, PW):
            self.assertNotIn(secret, page)

    def test_setup_with_a_wrong_key(self):
        self.transport.routes[("POST", "/api/create-user/admin")] = lambda b, t: (401, {"error": "Unauthorized."})
        self.get("/setup")
        self.post("/setup", {"setup_key": "bad", "username": "root", "password": PW, "password_confirm": PW})
        self.assertIn("setup key is wrong", self.page("/setup"))
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_setup_after_it_was_done_points_to_the_login(self):
        self.transport.routes[("POST", "/api/create-user/admin")] = lambda b, t: (410, {"error": "gone"})
        self.get("/setup")
        response = self.post("/setup", {"setup_key": "k", "username": "root", "password": PW,
                                        "password_confirm": PW})
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertIn("already complete", self.page("/login"))

    def test_setup_shows_the_password_rule_of_the_backend(self):
        self.transport.routes[("POST", "/api/create-user/admin")] = lambda b, t: (
            400, {"error": "Password must be 12-1024 characters."})
        self.get("/setup")
        self.post("/setup", {"setup_key": "k", "username": "root", "password": "short",
                             "password_confirm": "short"})
        self.assertIn("Password must be 12-1024 characters.", self.page("/setup"))


class DevicesTest(FrontendCase):
    def setUp(self):
        super().setUp()
        self.sign_in()

    def test_list_shows_the_state_in_words(self):
        self.transport.devices.append({"id": 2, "name": "pc", "address": "10.0.0.2",
                                       "status": "offline", "latency_ms": None})
        page = self.page("/devices")
        self.assertIn("status--online", page)
        self.assertIn("status--offline", page)
        self.assertIn("Online", page)
        self.assertIn("Offline", page)
        self.assertRegex(page, r'class="tile__value">2<')

    def test_device_data_is_escaped(self):
        self.transport.devices[0]["name"] = "<script>alert(1)</script>"
        page = self.page("/devices")
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)

    def test_a_backend_failure_is_shown_not_hidden_as_an_empty_list(self):
        self.transport.routes[("GET", "/api/metrics")] = lambda b, t: (503, {"error": "x"})
        page = self.page("/devices")
        self.assertIn("could not be loaded", page)
        self.assertNotIn("No devices yet", page)

    def test_add_device_forwards_the_form(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (201, {"id": 5, **b})
        response = self.post("/devices", {"name": "ryzen", "address": "192.168.178.50",
                                          "mac": "A8:A1:59:29:3D:6D"})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.transport.calls_to("POST", "/api/devices")[0][2],
                         {"name": "ryzen", "address": "192.168.178.50", "mac": "A8:A1:59:29:3D:6D"})
        self.assertIn("Device added.", self.page("/devices"))

    def test_add_device_shows_the_validation_message(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (
            400, {"error": "MAC address must be six hex pairs."})
        self.post("/devices", {"name": "x", "address": "10.0.0.2", "mac": "nope"})
        self.assertIn("MAC address must be six hex pairs.", self.page("/devices"))

    def test_a_refused_form_keeps_the_input_and_marks_only_the_faulty_field(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (
            400, {"error": "MAC must be six hex pairs.", "field": "mac"})
        self.post("/devices", {"name": "ryzen", "address": "10.0.0.2", "mac": "nope"})
        page = self.page("/devices")
        for kept in ('value="ryzen"', 'value="10.0.0.2"', 'value="nope"'):
            self.assertIn(kept, page)
        self.assertEqual(page.count('aria-invalid="true"'), 1)
        self.assertRegex(page, r'id="mac"[^>]*aria-invalid="true"')
        # shown once: the next visit is a clean form
        again = self.page("/devices")
        self.assertNotIn('value="ryzen"', again)
        self.assertNotIn("aria-invalid", again)

    def test_a_duplicate_name_marks_the_name_field(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (
            409, {"error": "You already have a device with this name.", "field": "name"})
        self.post("/devices", {"name": "nas", "address": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:01"})
        self.assertRegex(self.page("/devices"), r'id="name"[^>]*aria-invalid="true"')

    def test_kept_values_are_escaped(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (400, {"error": "x", "field": "name"})
        self.post("/devices", {"name": '"><script>alert(1)</script>', "address": "a", "mac": "b"})
        page = self.page("/devices")
        self.assertNotIn("<script>alert", page)
        self.assertIn("&#34;&gt;&lt;script&gt;", page)

    def test_a_refusal_of_one_page_does_not_show_on_another(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (400, {"error": "x", "field": "mac"})
        self.post("/devices", {"name": "ryzen", "address": "10.0.0.2", "mac": "nope"})
        self.assertNotIn('value="ryzen"', self.page("/account"))
        self.assertNotIn('value="ryzen"', self.page("/devices"))  # it was used up by the visit before

    def test_a_field_name_from_the_backend_cannot_break_the_page(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (
            400, {"error": "x", "field": '"><img src=x onerror=alert(1)>'})
        self.post("/devices", {"name": "a", "address": "b", "mac": "c"})
        page = self.page("/devices")
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("onerror", page)

    def test_add_device_with_a_picture_sends_it_as_base64(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (201, {"id": 5, "picture": 1, **b})
        response = self.client.post("/devices", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "ryzen", "address": "10.0.0.2", "mac": "A8:A1:59:29:3D:6D",
            "image": (io.BytesIO(PNG_BYTES), "me.png"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.transport.calls_to("POST", "/api/devices")[0][2]["image"], PNG_B64)

    def test_a_form_without_a_chosen_file_sends_no_image(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (201, {"id": 5, **b})
        self.client.post("/devices", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "ryzen", "address": "10.0.0.2", "mac": "A8:A1:59:29:3D:6D",
            "image": (io.BytesIO(b""), ""),
        })
        self.assertNotIn("image", self.transport.calls_to("POST", "/api/devices")[0][2])

    def test_a_picture_that_is_not_an_image_never_reaches_the_backend(self):
        svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>"
        for content in (svg, b"MZ" + b"\x00" * 50, b"GIF89a" + b"x" * 30, b"short"):
            with self.subTest(content=content[:6]):
                self.client.post("/devices", base_url=HTTPS, content_type="multipart/form-data", data={
                    "csrf_token": self.csrf(), "name": "ryzen", "address": "10.0.0.2", "mac": "A8:A1:59:29:3D:6D",
                    "image": (io.BytesIO(content), "x.png"),  # a PNG name does not make it one
                })
                page = self.page("/devices")
                self.assertIn("Picture must be a PNG, JPEG or WebP", page)
                self.assertIn('value="ryzen"', page)
        self.assertEqual(self.transport.calls_to("POST", "/api/devices"), [])

    def test_a_too_big_upload_is_refused_before_it_is_read(self):
        response = self.client.post("/devices", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "n", "address": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:01",
            "image": (io.BytesIO(PNG_BYTES + b"x" * 400_000), "big.png"),
        })
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.transport.calls_to("POST", "/api/devices"), [])

    def test_only_the_picture_routes_take_more_than_a_small_form(self):
        for path in ("/users", "/login", "/account/password", "/devices/1/wake"):
            with self.subTest(path=path):
                response = self.client.post(path, base_url=HTTPS, data={"csrf_token": self.csrf(), "x": "y" * 100_000})
                self.assertEqual(response.status_code, 413)

    def test_the_picture_of_a_device_is_served_as_an_image_and_never_sniffed(self):
        self.transport.routes[("GET", "/api/devices/1/picture")] = lambda b, t: (
            200, {"media_type": "image/png", "image": PNG_B64, "version": 3})
        response = self.get("/devices/1/picture")
        self.assertEqual((response.status_code, response.mimetype), (200, "image/png"))
        self.assertEqual(response.get_data(), PNG_BYTES)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("private", response.headers["Cache-Control"])
        self.assertNotIn("no-store", response.headers["Cache-Control"])

    def test_a_picture_needs_a_login_and_unknown_ones_are_404(self):
        self.assertEqual(self.get("/devices/1/picture", self.app.test_client()).status_code, 302)
        self.assertEqual(self.get("/devices/1/picture").status_code, 404)  # the fake has no such route

    def test_a_picture_with_a_type_the_page_does_not_serve_is_not_passed_on(self):
        for media in ("image/svg+xml", "text/html", "image/gif"):
            with self.subTest(media=media):
                self.transport.routes[("GET", "/api/devices/1/picture")] = lambda b, t, m=media: (
                    200, {"media_type": m, "image": PNG_B64, "version": 1})
                self.assertEqual(self.get("/devices/1/picture").status_code, 503)

    def test_the_list_shows_the_round_picture_with_its_version(self):
        self.transport.devices[0]["picture"] = 7
        page = self.page("/devices")
        self.assertIn('src="/devices/1/picture?v=7"', page)
        self.assertIn('class="pic"', page)
        self.assertNotIn("<svg class=\"device-icon\"", page.split("Add a device")[0])

    def test_a_device_without_a_picture_keeps_the_icon(self):
        page = self.page("/devices")
        self.assertIn('class="device-icon"', page)
        self.assertNotIn('class="pic"', page)

    def test_a_picture_can_be_replaced_for_one_device(self):
        self.transport.routes[("PUT", "/api/devices/1")] = lambda b, t: (200, {"id": 1, **b})
        self.transport.routes[("PUT", "/api/devices/1/picture")] = lambda b, t: (200, {"id": 1, "picture": 9})
        response = self.client.post("/devices/1/edit", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "nas", "address": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01",
            "image": (io.BytesIO(PNG_BYTES), "me.png"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.transport.calls_to("PUT", "/api/devices/1/picture")[0][2], {"image": PNG_B64})
        self.assertIn("Device saved.", self.page("/devices"))

    def test_saving_without_choosing_a_file_keeps_the_picture(self):
        self.transport.routes[("PUT", "/api/devices/1")] = lambda b, t: (200, {"id": 1, **b})
        self.client.post("/devices/1/edit", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "nas", "address": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01",
        })
        self.assertEqual(self.transport.calls_to("PUT", "/api/devices/1/picture"), [])

    def test_the_picture_of_a_device_can_be_removed(self):
        self.transport.routes[("DELETE", "/api/devices/1/picture")] = lambda b, t: (200, {"id": 1, "picture": None})
        response = self.post("/devices/1/picture/delete")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["Location"].endswith("/devices/1/edit"))
        self.assertEqual(len(self.transport.calls_to("DELETE", "/api/devices/1/picture")), 1)

    def test_the_list_shows_the_mac_and_an_edit_link(self):
        page = self.page("/devices")
        self.assertIn("<code>aa:bb:cc:dd:ee:01</code>", page)
        self.assertIn('href="/devices/1/edit"', page)

    def test_the_edit_page_shows_the_current_values(self):
        page = self.page("/devices/1/edit")
        for value in ("nas", "192.168.1.10", "aa:bb:cc:dd:ee:01"):
            self.assertIn(f'value="{value}"', page)

    def test_the_edit_page_needs_a_login_and_an_own_device(self):
        self.assertEqual(self.get("/devices/1/edit", self.app.test_client()).status_code, 302)
        self.assertEqual(self.get("/devices/2/edit").status_code, 404)  # the fake has no such device

    def test_a_device_can_be_edited(self):
        self.transport.routes[("PUT", "/api/devices/1")] = lambda b, t: (200, {"id": 1, **b})
        response = self.post("/devices/1/edit", {"name": "nas2", "address": "10.0.0.9",
                                                 "mac": "AA:BB:CC:DD:EE:02"})
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["Location"].endswith("/devices"))
        self.assertEqual(self.transport.calls_to("PUT", "/api/devices/1")[0][2],
                         {"name": "nas2", "address": "10.0.0.9", "mac": "AA:BB:CC:DD:EE:02"})
        self.assertIn("Device saved.", self.page("/devices"))

    def test_a_refused_edit_keeps_every_value_and_marks_only_the_bad_field(self):
        self.transport.routes[("PUT", "/api/devices/1")] = lambda b, t: (
            400, {"error": "MAC address is not valid.", "field": "mac"})
        response = self.post("/devices/1/edit", {"name": "nas2", "address": "10.0.0.9", "mac": "nope"})
        self.assertTrue(response.headers["Location"].endswith("/devices/1/edit"))
        page = self.page("/devices/1/edit")
        self.assertIn('value="nas2"', page)
        self.assertIn('value="10.0.0.9"', page)
        self.assertIn('value="nope" aria-invalid="true"', page)
        self.assertEqual(page.count('aria-invalid="true"'), 1)

    def test_an_edit_to_a_taken_name_is_reported(self):
        self.transport.routes[("PUT", "/api/devices/1")] = lambda b, t: (
            409, {"error": "You already have a device with this name.", "field": "name"})
        self.post("/devices/1/edit", {"name": "other", "address": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:02"})
        page = self.page("/devices/1/edit")
        self.assertIn("already have a device", page)
        self.assertIn('value="other" aria-invalid="true"', page)

    def test_an_edit_with_a_bad_picture_never_reaches_the_backend(self):
        self.client.post("/devices/1/edit", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "name": "nas", "address": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:01", "image": (io.BytesIO(b"MZ" + b"\x00" * 50), "x.png"),
        })
        self.assertEqual(self.transport.calls_to("PUT", "/api/devices/1"), [])
        self.assertIn("Picture must be a PNG, JPEG or WebP", self.page("/devices/1/edit"))

    def test_the_live_state_is_json_and_needs_a_login(self):
        self.assertEqual(self.get("/devices/live", self.app.test_client()).status_code, 302)
        data = self.get("/devices/live").get_json()
        self.assertEqual(data["devices"], [{"id": 1, "status": "online", "latency_ms": 2.4}])
        self.assertEqual(data["summary"], {"total": 1, "online": 1, "offline": 0})

    def test_the_live_state_fails_with_503_when_the_backend_is_down(self):
        self.transport.error = ContainerUnavailableError("down")
        self.assertEqual(self.get("/devices/live").status_code, 503)

    def test_polling_the_live_state_does_not_extend_the_session(self):
        session = self.sessions.get(self.client.get_cookie(COOKIE).value, touch=False)
        before = session.last_seen
        self.clock.now += 60
        self.get("/devices/live")
        self.assertEqual(self.sessions.get(self.client.get_cookie(COOKIE).value, touch=False).last_seen, before)
        self.get("/devices")
        self.assertGreater(self.sessions.get(self.client.get_cookie(COOKIE).value, touch=False).last_seen, before)

    def test_the_list_carries_what_the_script_needs(self):
        page = self.page("/devices")
        self.assertIn('data-live="/devices/live"', page)
        self.assertIn('data-device-id="1"', page)
        self.assertIn("data-latency", page)
        self.assertIn('data-count="online"', page)

    def test_messages_are_marked_so_that_they_fade(self):
        self.transport.routes[("POST", "/api/devices/1/wake")] = lambda b, t: (200, {"id": 1, "status": "sent"})
        self.post("/devices/1/wake")
        self.assertIn("data-flash", self.page("/devices"))

    def test_duplicate_name_is_reported(self):
        self.transport.routes[("POST", "/api/devices")] = lambda b, t: (
            409, {"error": "You already have a device with this name."})
        self.post("/devices", {"name": "nas", "address": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff"})
        self.assertIn("already have a device", self.page("/devices"))

    def test_wake_calls_the_device_route_and_sends_no_mac(self):
        self.transport.routes[("POST", "/api/devices/1/wake")] = lambda b, t: (200, {"id": 1, "status": "sent"})
        response = self.post("/devices/1/wake", {"mac": "aa:bb:cc:dd:ee:ff", "ip": "8.8.8.8"})
        self.assertEqual(response.status_code, 303)
        call = self.transport.calls_to("POST", "/api/devices/1/wake")[0]
        self.assertIsNone(call[2])
        self.assertIn("Magic packet sent", self.page("/devices"))

    def test_wake_when_the_relay_is_down(self):
        self.transport.routes[("POST", "/api/devices/1/wake")] = lambda b, t: (
            503, {"error": "Wake-on-LAN is temporarily unavailable."})
        self.post("/devices/1/wake")
        self.assertIn("could not be completed", self.page("/devices"))

    def test_wake_of_a_foreign_device(self):
        self.transport.routes[("POST", "/api/devices/9/wake")] = lambda b, t: (404, {"error": "Device not found."})
        self.post("/devices/9/wake")
        self.assertIn("Device not found.", self.page("/devices"))

    def test_delete_device(self):
        self.transport.routes[("DELETE", "/api/devices/1")] = lambda b, t: (200, {"id": 1})
        self.post("/devices/1/delete")
        self.assertEqual(len(self.transport.calls_to("DELETE", "/api/devices/1")), 1)
        self.assertIn("Device deleted.", self.page("/devices"))

    def test_device_id_must_be_a_number(self):
        for path in ("/devices/abc/wake", "/devices/1%2F..%2Fusers/delete"):
            self.assertEqual(self.client.post(path, data={}, base_url=HTTPS).status_code, 404, path)

    def test_get_does_not_change_anything(self):
        for path in ("/devices/1/wake", "/devices/1/delete", "/logout", "/users/anna/delete"):
            self.assertEqual(self.get(path).status_code, 405, path)


class TokenRenewalTest(FrontendCase):
    def setUp(self):
        super().setUp()
        self.sign_in()
        self.transport.calls.clear()

    def test_an_expiring_access_token_is_renewed_before_use(self):
        self.clock.now += 290
        self.assertEqual(self.get("/devices").status_code, 200)
        self.assertEqual(len(self.transport.calls_to("POST", "/api/token")), 1)

    def test_a_fresh_token_is_not_renewed(self):
        self.get("/devices")
        self.assertEqual(self.transport.calls_to("POST", "/api/token"), [])

    def test_a_token_the_backend_rejects_is_renewed_once_and_retried(self):
        self.sessions.get(self.client.get_cookie(COOKIE).value).access_token = "stale"
        self.assertEqual(self.get("/devices").status_code, 200)
        self.assertEqual(len(self.transport.calls_to("GET", "/api/metrics")), 2)

    def test_a_revoked_refresh_token_ends_the_session(self):
        self.transport.routes[("POST", "/api/token")] = lambda b, t: (401, {"error": "x"})
        self.clock.now += 290
        response = self.get("/devices")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertIn("session has ended", self.page("/login"))
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_a_backend_that_keeps_saying_401_does_not_loop(self):
        self.transport.valid_access = "something-else"
        response = self.get("/devices")
        self.assertEqual(response.status_code, 303)
        self.assertLessEqual(len(self.transport.calls), 4)


class BackendTrustTest(FrontendCase):
    def test_unreachable_backend_shows_a_503_page_without_details(self):
        self.sign_in()
        self.transport.error = ContainerUnavailableError("backend unreachable at 10.1.2.3")
        response = self.get("/devices")
        self.assertEqual(response.status_code, 503)
        body = response.get_data(as_text=True)
        self.assertIn("temporarily unavailable", body)
        self.assertNotIn("10.1.2.3", body)

    def test_unverified_backend_shows_a_502_page_and_no_data(self):
        self.sign_in()
        self.transport.error = ContainerAuthError("response proof does not match")
        response = self.get("/devices")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("proof", response.get_data(as_text=True))

    def test_login_with_an_unverified_backend_signs_nobody_in(self):
        self.get("/login")
        self.transport.error = ContainerAuthError("impostor")
        response = self.post("/login", {"username": "root", "password": PW})
        self.assertEqual(response.status_code, 502)
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_missing_backend_url_fails_every_call_cleanly(self):
        app = create_app(backend=BackendClient(None), sessions=SessionStore())
        client = app.test_client()
        page = client.get("/login", base_url=HTTPS).get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        response = client.post("/login", data={"csrf_token": token, "username": "a", "password": "b"},
                               base_url=HTTPS)
        self.assertEqual(response.status_code, 503)

    def test_unexpected_exception_gives_a_generic_500(self):
        self.sign_in()
        self.transport.routes[("GET", "/api/metrics")] = lambda b, t: 1 / 0
        self.app.config["PROPAGATE_EXCEPTIONS"] = False
        response = self.get("/devices")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("ZeroDivision", response.get_data(as_text=True))


class UsersTest(FrontendCase):
    def setUp(self):
        super().setUp()
        self.sign_in("root")

    def test_list(self):
        page = self.page("/users")
        self.assertIn("anna", page)
        self.assertIn("root", page)

    def test_the_admin_row_has_no_delete_button_and_no_reset_form(self):
        page = self.page("/users")
        self.assertNotIn("/users/root/delete", page)
        self.assertNotIn("/users/root/password", page)
        self.assertIn("/users/anna/delete", page)

    def test_add_user(self):
        self.transport.routes[("POST", "/api/users")] = lambda b, t: (201, {"username": b["username"], "role": "user"})
        self.post("/users", {"username": " Bob ", "password": PW})
        self.assertEqual(self.transport.calls_to("POST", "/api/users")[0][2], {"username": "Bob", "password": PW})
        self.assertIn("User added.", self.page("/users"))

    def test_add_user_shows_the_rule_when_refused(self):
        self.transport.routes[("POST", "/api/users")] = lambda b, t: (
            400, {"error": "Username must be 3-64 characters: lower case letters, digits, '.', '_' or '-'."})
        self.post("/users", {"username": "x", "password": PW})
        self.assertIn("Username must be 3-64 characters", self.page("/users"))

    def test_a_refused_new_user_keeps_the_name_but_never_the_password(self):
        self.transport.routes[("POST", "/api/users")] = lambda b, t: (
            409, {"error": "That username is taken.", "field": "username"})
        self.post("/users", {"username": "anna", "password": PW})
        page = self.page("/users")
        self.assertIn('value="anna"', page)
        self.assertIn('aria-invalid="true"', page)
        self.assertNotIn(PW, page)

    def test_reset_password(self):
        self.transport.routes[("PUT", "/api/users/anna")] = lambda b, t: (200, {"username": "anna"})
        self.post("/users/anna/password", {"password": PW + "new"})
        self.assertEqual(self.transport.calls_to("PUT", "/api/users/anna")[0][2], {"password": PW + "new"})
        self.assertIn("Password set", self.page("/users"))

    def test_reset_password_signs_the_user_out_here_too(self):
        self.transport.routes[("PUT", "/api/users/anna")] = lambda b, t: (200, {"username": "anna"})
        anna = self.app.test_client()
        self.sign_in("anna", anna)
        self.assertEqual(self.get("/devices", anna).status_code, 200)
        self.post("/users/anna/password", {"password": PW + "new"})
        self.assertEqual(self.get("/devices", anna).status_code, 302)
        self.assertEqual(self.get("/devices").status_code, 200)  # the admin stays

    def test_delete_user_removes_their_sessions(self):
        self.transport.routes[("DELETE", "/api/users/anna")] = lambda b, t: (200, {"username": "anna"})
        anna = self.app.test_client()
        self.sign_in("anna", anna)
        self.post("/users/anna/delete")
        self.assertEqual(self.get("/devices", anna).status_code, 302)

    def test_delete_refused_by_the_backend_keeps_the_sessions(self):
        self.transport.routes[("DELETE", "/api/users/anna")] = lambda b, t: (409, {"error": "no"})
        anna = self.app.test_client()
        self.sign_in("anna", anna)
        self.post("/users/anna/delete")
        self.assertEqual(self.get("/devices", anna).status_code, 200)

    def test_odd_user_names_never_reach_the_backend(self):
        for name in ("A", "..", "a%2F..%2Fb", "x" * 80, "UPPER", "a b"):
            self.client.post(f"/users/{name}/delete", data={}, base_url=HTTPS)
            response = self.post(f"/users/{name}/delete")
            self.assertIn(response.status_code, (404, 405), name)
        self.assertEqual([c for c in self.transport.calls if c[0] == "DELETE"], [])


class AccountTest(FrontendCase):
    def setUp(self):
        super().setUp()
        self.sign_in("root")

    def test_account_page(self):
        page = self.page("/account")
        self.assertIn("root", page)
        self.assertIn("admin", page)

    def test_change_password(self):
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (
            200, {"refresh_token": "refresh-1", "access_token": "access-1", "expires_in": 300})
        self.post("/account/password", {"current_password": PW, "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/password")[0][2],
                         {"current_password": PW, "new_password": PW + "2"})
        self.assertIn("Password changed", self.page("/account"))

    def test_change_password_keeps_this_session_and_ends_the_others(self):
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (
            200, {"refresh_token": "refresh-1", "access_token": "access-1", "expires_in": 300})
        other = self.app.test_client()
        self.sign_in("root", other)
        self.post("/account/password", {"current_password": PW, "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        self.assertEqual(self.get("/devices").status_code, 200)
        self.assertEqual(self.get("/devices", other).status_code, 302)

    def test_wrong_current_password(self):
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (403, {"error": "Current password is wrong."})
        self.post("/account/password", {"current_password": "bad", "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        self.assertIn("current password is wrong", self.page("/account"))

    def test_different_new_passwords_do_not_reach_the_backend(self):
        self.post("/account/password", {"current_password": PW, "new_password": PW + "2",
                                        "new_password_confirm": PW + "3"})
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/password"), [])
        self.assertIn("not the same", self.page("/account"))

    def test_a_weak_new_password_shows_the_backend_rule(self):
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (
            400, {"error": "Password must be 12-1024 characters."})
        self.post("/account/password", {"current_password": PW, "new_password": "short",
                                        "new_password_confirm": "short"})
        self.assertIn("Password must be 12-1024 characters.", self.page("/account"))

    def test_password_fields_are_never_echoed(self):
        self.post("/account/password", {"current_password": "secret-current", "new_password": "x",
                                        "new_password_confirm": "y"})
        self.assertNotIn("secret-current", self.page("/account"))

    def test_a_wrong_current_password_marks_that_field(self):
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (403, {"error": "no"})
        self.post("/account/password", {"current_password": "bad", "new_password": PW + "2",
                                        "new_password_confirm": PW + "2"})
        page = self.page("/account")
        self.assertEqual(page.count('aria-invalid="true"'), 1)
        self.assertNotIn(PW + "2", page)

    def test_without_a_picture_the_initial_is_shown(self):
        page = self.page("/account")
        self.assertNotIn("/account/picture?v=", page)
        self.assertIn("avatar--large", page)

    def test_the_own_picture_is_shown_in_the_menu_and_on_the_profile(self):
        self.transport.me_picture = 4
        page = self.page("/account")
        self.assertIn('src="/account/picture?v=4"', page)
        self.assertIn("Remove picture", page)

    def test_the_own_picture_can_be_uploaded(self):
        self.transport.routes[("PUT", "/api/me/picture")] = lambda b, t: (200, {"picture": 8})
        response = self.client.post("/account/picture", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "image": (io.BytesIO(PNG_BYTES), "me.png"),
        })
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/picture")[0][2], {"image": PNG_B64})
        self.assertIn("Picture saved.", self.page("/account"))

    def test_an_own_picture_that_is_not_an_image_never_reaches_the_backend(self):
        self.client.post("/account/picture", base_url=HTTPS, content_type="multipart/form-data", data={
            "csrf_token": self.csrf(), "image": (io.BytesIO(b"<svg onload=1></svg>"), "me.png"),
        })
        self.assertIn("Picture must be a PNG, JPEG or WebP", self.page("/account"))
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/picture"), [])

    def test_the_own_picture_is_served_and_can_be_removed(self):
        self.transport.routes[("GET", "/api/me/picture")] = lambda b, t: (
            200, {"media_type": "image/png", "image": PNG_B64, "version": 4})
        response = self.get("/account/picture")
        self.assertEqual((response.status_code, response.mimetype), (200, "image/png"))
        self.assertEqual(response.get_data(), PNG_BYTES)
        self.transport.routes[("DELETE", "/api/me/picture")] = lambda b, t: (200, {"picture": None})
        self.assertEqual(self.post("/account/picture/delete").status_code, 303)
        self.assertEqual(len(self.transport.calls_to("DELETE", "/api/me/picture")), 1)


class MustChangePasswordTest(FrontendCase):
    """The first sign-in with a password the admin chose leads to the password change and nowhere else."""

    NEW = "/account/new-password"

    def setUp(self):
        super().setUp()
        self.transport.routes[("POST", "/api/login")] = lambda b, t: (200, {
            "refresh_token": "refresh-1", "access_token": "access-1", "expires_in": 300,
            "role": "user", "must_change_password": True})
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (
            200, {"refresh_token": "refresh-1", "access_token": "access-1", "expires_in": 300})

    def change(self, new=PW + "2", confirm=None):
        return self.post("/account/password", {"current_password": PW, "new_password": new,
                                               "new_password_confirm": new if confirm is None else confirm})

    def test_the_sign_in_leads_to_the_password_change(self):
        response = self.sign_in("anna")
        self.assertTrue(response.headers["Location"].endswith(self.NEW))
        page = self.page(self.NEW)
        self.assertIn("Choose your password", page)
        self.assertIn("Please choose your own password", page)

    def test_every_other_page_leads_back_to_it(self):
        self.sign_in("anna")
        for path in ("/devices", "/devices/live", "/users", "/account", "/account/picture", "/devices/1/edit"):
            with self.subTest(path=path):
                response = self.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.headers["Location"].endswith(self.NEW))

    def test_nothing_else_reaches_the_backend(self):
        self.sign_in("anna")
        self.get("/devices")
        self.post("/devices", {"name": "x", "address": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:02"})
        self.post("/devices/1/wake")
        self.post("/account/picture/delete")
        self.assertEqual([c[:2] for c in self.transport.calls], [("POST", "/api/login")])

    def test_the_page_has_no_main_navigation_but_a_sign_out(self):
        self.sign_in("anna")
        page = self.page(self.NEW)
        self.assertNotIn(">Devices</a>", page)
        self.assertNotIn(">Account", page)
        self.assertIn("Sign out", page)

    def test_the_new_password_opens_the_app(self):
        self.sign_in("anna")
        response = self.change()
        self.assertTrue(response.headers["Location"].endswith("/devices"))
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/password")[0][2],
                         {"current_password": PW, "new_password": PW + "2"})
        page = self.page("/devices")  # the welcome note is shown once
        self.assertIn("Welcome to Pontifex", page)
        self.assertIn(">Devices</a>", page)
        # the page for the first password is not reachable any more
        self.assertTrue(self.get(self.NEW).headers["Location"].endswith("/account"))

    def test_a_refused_change_stays_on_the_page_and_marks_the_field(self):
        self.sign_in("anna")
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (
            400, {"error": "The new password must differ from the temporary one.", "field": "new_password"})
        response = self.change(PW)
        self.assertTrue(response.headers["Location"].endswith(self.NEW))
        page = self.page(self.NEW)
        self.assertIn("must differ", page)
        self.assertEqual(page.count('aria-invalid="true"'), 1)
        self.assertNotIn(PW, page)
        self.assertEqual(self.get("/devices").status_code, 302)

    def test_two_different_new_passwords_stay_on_the_page(self):
        self.sign_in("anna")
        response = self.change(PW + "2", PW + "3")
        self.assertTrue(response.headers["Location"].endswith(self.NEW))
        self.assertEqual(self.transport.calls_to("PUT", "/api/me/password"), [])
        self.assertIn("not the same", self.page(self.NEW))

    def test_a_wrong_current_password_marks_that_field(self):
        self.sign_in("anna")
        self.transport.routes[("PUT", "/api/me/password")] = lambda b, t: (403, {"error": "no"})
        self.change()
        self.assertEqual(self.page(self.NEW).count('aria-invalid="true"'), 1)

    def test_signing_out_is_possible(self):
        self.sign_in("anna")
        self.assertEqual(self.post("/logout").status_code, 303)
        self.assertEqual(self.get(self.NEW).status_code, 302)

    def test_a_user_who_does_not_have_to_change_goes_straight_in(self):
        self.transport.routes[("POST", "/api/login")] = self._login
        response = self.sign_in("anna")
        self.assertTrue(response.headers["Location"].endswith("/devices"))
        self.assertTrue(self.get(self.NEW).headers["Location"].endswith("/account"))


class InputValidationTest(FrontendCase):
    """Form input is checked before it is used; over-long input is refused, never cut."""

    def setUp(self):
        super().setUp()
        self.sign_in("root")
        self.transport.calls.clear()

    def test_an_overlong_field_is_refused_and_not_forwarded_cut_short(self):
        for path, data in (
            ("/users", {"username": "a" * 300, "password": PW}),
            ("/users", {"username": "bob", "password": "p" * 5000}),
            ("/devices", {"name": "n" * 500, "address": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:01"}),
            ("/devices", {"name": "nas", "address": "10.0.0.2", "mac": "a" * 500}),
            ("/users/anna/password", {"password": "p" * 5000}),
        ):
            with self.subTest(path=path, field=list(data)[0]):
                self.assertEqual(self.post(path, data).status_code, 400)
        self.assertEqual([c for c in self.transport.calls if c[0] != "GET"], [])

    def test_a_nul_byte_never_reaches_the_backend(self):
        self.assertEqual(self.post("/devices", {"name": "a\x00b", "address": "10.0.0.2", "mac": "x"}).status_code, 400)
        self.assertEqual(self.transport.calls_to("POST", "/api/devices"), [])

    def test_login_with_hostile_input_is_the_generic_failure_and_not_forwarded(self):
        other = self.app.test_client()
        self.get("/login", other)
        for username, password in (("a" * 100, PW), ("root", "p" * 2000), ("ro\x00ot", PW)):
            with self.subTest(username=username[:6]):
                response = self.post("/login", {"username": username, "password": password}, other)
                self.assertEqual(response.status_code, 303)
                self.assertIn("Invalid username or password.", self.page("/login", other))
        self.assertEqual(self.transport.calls_to("POST", "/api/login"), [])

    def test_a_session_cookie_that_we_could_not_have_issued_is_just_no_session(self):
        other = self.app.test_client()
        for value in ("x" * 500, "a b", "a;b", "' OR 1=1 --", "../x"):
            with self.subTest(cookie=value[:10]):
                other.set_cookie(COOKIE, value, domain="localhost")
                self.assertEqual(self.get("/devices", other).status_code, 302)

    def test_a_csrf_token_with_odd_content_is_refused(self):
        for token in ("x" * 500, "a b", "' OR 1=1 --", "\x00"):
            with self.subTest(token=token[:10]):
                response = self.client.post("/logout", data={"csrf_token": token}, base_url=HTTPS)
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.get("/devices").status_code, 200)

    def test_user_names_in_paths_follow_the_backend_rule_exactly(self):
        self.transport.routes[("DELETE", "/api/users/anna.k")] = lambda b, t: (200, {"username": "anna.k"})
        self.post("/users/anna.k/delete")
        self.assertEqual(len(self.transport.calls_to("DELETE", "/api/users/anna.k")), 1)


if __name__ == "__main__":
    unittest.main()
