import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from app.services import LoginThrottle, LoginThrottled  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class LoginThrottleTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.throttle = LoginThrottle(clock=self.clock)

    def _fail(self, user="anna", address="10.0.0.1", times=1):
        for _ in range(times):
            self.throttle.check(user, address)
            self.throttle.failure(user, address)

    def test_blocks_the_account_after_the_limit(self):
        self._fail(times=LoginThrottle.MAX_PER_ACCOUNT)
        with self.assertRaises(LoginThrottled) as ctx:
            self.throttle.check("anna", "10.0.0.1")
        self.assertGreaterEqual(ctx.exception.retry_after, 1)

    def test_username_case_does_not_help_an_attacker(self):
        self._fail(user="Anna", times=LoginThrottle.MAX_PER_ACCOUNT)
        with self.assertRaises(LoginThrottled):
            self.throttle.check("ANNA", "10.0.0.1")

    def test_other_account_from_the_same_address_is_still_allowed(self):
        self._fail(times=LoginThrottle.MAX_PER_ACCOUNT)
        self.throttle.check("bernd", "10.0.0.1")

    def test_blocks_an_address_that_tries_many_names(self):
        for i in range(LoginThrottle.MAX_PER_ADDRESS):
            self._fail(user=f"user{i}")
        with self.assertRaises(LoginThrottled):
            self.throttle.check("someone-new", "10.0.0.1")
        self.throttle.check("someone-new", "10.0.0.2")

    def test_window_expires(self):
        self._fail(times=LoginThrottle.MAX_PER_ACCOUNT)
        self.clock.now += LoginThrottle.WINDOW_SECONDS + 1
        self.throttle.check("anna", "10.0.0.1")

    def test_success_clears_the_account_counter(self):
        self._fail(times=LoginThrottle.MAX_PER_ACCOUNT - 1)
        self.throttle.success("anna", "10.0.0.1")
        self._fail(times=LoginThrottle.MAX_PER_ACCOUNT - 1)
        self.throttle.check("anna", "10.0.0.1")

    def test_memory_is_bounded(self):
        throttle = LoginThrottle(clock=self.clock)
        throttle.MAX_KEYS = 20
        for i in range(200):
            throttle.failure(f"user{i}", f"10.0.{i}.1")
        self.assertLessEqual(len(throttle._failures), 20)


class LoginEndpointsTest(unittest.TestCase):
    def setUp(self):
        os.environ.update(
            SECRETS,
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        self.db = FakeDatabase()
        from app import create_app
        self.app = create_app(database=self.db)
        self.client = self.app.test_client()
        self.client.post(
            "/api/create-user/admin",
            json={"username": "root", "password": PW},
            headers={"Authorization": "Bearer initial-key"},
        )

    def _login(self, username="root", password=PW):
        return self.client.post("/api/login", json={"username": username, "password": password})

    @staticmethod
    def _bearer(token):
        return {"Authorization": f"Bearer {token}"}

    def test_login_returns_tokens_and_role(self):
        r = self._login()
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(body["role"], "admin")
        self.assertEqual(body["expires_in"], 300)
        self.assertTrue(body["refresh_token"])
        self.assertTrue(body["access_token"])

    def test_access_token_from_login_is_accepted(self):
        token = self._login().get_json()["access_token"]
        r = self.client.get("/api/me", headers=self._bearer(token))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["username"], "root")
        self.assertEqual(r.get_json()["role"], "admin")

    def test_refresh_token_from_login_can_be_exchanged(self):
        refresh = self._login().get_json()["refresh_token"]
        r = self.client.post("/api/token", json={"refresh_token": refresh})
        self.assertEqual(r.status_code, 200)

    def test_wrong_password_and_unknown_user_look_identical(self):
        wrong = self._login(password="not-the-password")
        unknown = self._login(username="nobody")
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(wrong.get_json(), unknown.get_json())
        self.assertNotIn("access_token", wrong.get_json())

    def test_unknown_user_still_runs_a_password_check(self):
        calls = []
        original = self.app.extensions["auth"].verify_password
        self.app.extensions["auth"].verify_password = lambda p, h: calls.append(h) or original(p, h)
        self._login(username="nobody")
        self.assertEqual(len(calls), 1)

    def test_malformed_input_is_401_and_never_500(self):
        bad = (
            {},
            {"username": "root"},
            {"password": PW},
            {"username": 7, "password": PW},
            {"username": "root", "password": ["x"]},
            {"username": "   ", "password": PW},
            {"username": "root", "password": ""},
            {"username": "r" * 65, "password": PW},
            {"username": "root", "password": "p" * 1025},
        )
        for payload in bad:
            with self.subTest(payload=str(payload)[:40]):
                self.assertEqual(self.client.post("/api/login", json=payload).status_code, 401)
        self.assertEqual(self.client.post("/api/login", data="not json").status_code, 401)

    def test_repeated_failures_lock_the_account_with_429(self):
        for _ in range(5):
            self.assertEqual(self._login(password="wrong").status_code, 401)
        locked = self._login(password="wrong")
        self.assertEqual(locked.status_code, 429)
        self.assertGreaterEqual(int(locked.headers["Retry-After"]), 1)
        # even the correct password is refused while locked
        self.assertEqual(self._login().status_code, 429)

    def test_database_down_is_503_not_a_login(self):
        self.db.down = True
        self.assertEqual(self._login().status_code, 503)

    def test_logout_revokes_the_refresh_token(self):
        refresh = self._login().get_json()["refresh_token"]
        self.assertEqual(self.client.post("/api/logout", json={"refresh_token": refresh}).status_code, 200)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": refresh}).status_code, 401)

    def test_logout_ignores_unknown_tokens_and_needs_a_field(self):
        self.assertEqual(self.client.post("/api/logout", json={"refresh_token": "nope"}).status_code, 200)
        self.assertEqual(self.client.post("/api/logout", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/logout", json={"refresh_token": 5}).status_code, 400)

    def test_me_requires_a_token(self):
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(self.client.get("/api/me", headers=self._bearer("garbage")).status_code, 401)


if __name__ == "__main__":
    unittest.main()
