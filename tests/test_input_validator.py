"""
Tests for shared/input_validator.py, and for the places that must use it.

Run with:
    python -m unittest tests.test_input_validator -v
"""

import ast
import logging
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.input_validator import InputValidator as V, InvalidInput  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402

ATTACKS = (
    "' OR '1'='1", "'; DROP TABLE users; --", "admin'--", "1 UNION SELECT password FROM users",
    "../../etc/passwd", "..\\..\\windows", "%2e%2e%2f", "<script>alert(1)</script>", "javascript:alert(1)",
    "{{7*7}}", "${jndi:ldap://x}", "$(id)", "`id`", "a && b", "name\r\nSet-Cookie: x=1", "a\x00b",
)


def refused(check, *args):
    try:
        check(*args)
    except InvalidInput:
        return True
    return False


class UsernameTest(unittest.TestCase):
    def test_canonical_form(self):
        self.assertEqual(V.username("  Anna.K "), "anna.k")
        self.assertEqual(V.username("a_b-c.9"), "a_b-c.9")

    def test_bad_names(self):
        bad = ("", "ab", "a b", "-lead", ".lead", "x" * 65, "ünï", "ann\na", "an\u202ena", "KELVIN\u212a",
               5, None, ["a"], {"a": 1}, True, b"anna")
        for value in bad:
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.username, value))

    def test_every_attack_is_refused(self):
        for value in ATTACKS:
            with self.subTest(value=value):
                self.assertTrue(refused(V.username, value))

    def test_path_names_must_already_be_canonical(self):
        self.assertEqual(V.path_username("anna"), "anna")
        for value in ("Anna", " anna", "anna ", "a%2Fb"):
            with self.subTest(value=value):
                self.assertTrue(refused(V.path_username, value))

    def test_rule_message_is_the_documented_one(self):
        with self.assertRaises(InvalidInput) as caught:
            V.username("x")
        self.assertEqual(caught.exception.message, V.USERNAME_RULE)
        self.assertEqual(caught.exception.field, "username")


class PasswordTest(unittest.TestCase):
    def test_length_and_type(self):
        self.assertEqual(V.new_password("a" * 12), "a" * 12)
        self.assertEqual(V.new_password("a" * 1024), "a" * 1024)
        for value in ("a" * 11, "a" * 1025, "", 123456789012, None, ["a" * 12], True):
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.new_password, value))

    def test_passwords_may_contain_anything_but_nul_and_lone_surrogates(self):
        for password in ("' OR 1=1 -- and more", "<script>alert(1)</script>", "pässwörd-ünïcode-✓✓", "with space  s"):
            with self.subTest(password=password):
                self.assertEqual(V.new_password(password), password)
        self.assertTrue(refused(V.new_password, "a" * 12 + "\x00"))
        self.assertTrue(refused(V.new_password, "a" * 12 + "\ud800"))

    def test_a_password_is_never_logged(self):
        with self.assertLogs("shared.input_validator", level="WARNING") as logs:
            logging.getLogger("shared.input_validator").warning("marker")
            V.new_password("'; DROP TABLE users; --")
            refused(V.new_password, "<script>" + "x" * 2000)
        self.assertEqual(len(logs.output), 1)

    def test_current_password(self):
        self.assertEqual(V.current_password("wrong"), "wrong")
        for value in ("", "x" * 1025, None, 5):
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.current_password, value))


class TokenTest(unittest.TestCase):
    def test_accepts_what_we_issue(self):
        import secrets
        for _ in range(20):
            token = secrets.token_urlsafe(32)
            self.assertEqual(V.token(token), token)

    def test_refuses_everything_else(self):
        for value in ("", "x" * 129, "a b", "a/b", "a;b", "a'b", "a\n", "tok\x00en", "tökén", None, 5, ["a"], ATTACKS[0]):
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.token, value))


class DeviceTest(unittest.TestCase):
    def test_names(self):
        self.assertEqual(V.device_name("  Mein NAS "), "Mein NAS")
        self.assertEqual(V.device_name("Büro-PC ✓"), "Büro-PC ✓")
        for value in ("", "   ", "x" * 65, "a\nb", "a\x00b", "a\u202eb", "a\u2028b", "a\x7fb", None, 7, ["a"]):
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.device_name, value))

    def test_names_that_look_like_attacks_are_stored_text_but_logged(self):
        with self.assertLogs("shared.input_validator", level="WARNING") as logs:
            self.assertEqual(V.device_name("<script>x</script>"), "<script>x</script>")
        self.assertIn("markup", logs.output[0])
        self.assertNotIn("x</script>", logs.output[0])

    def test_addresses(self):
        self.assertEqual(V.address(" 192.168.1.10 "), "192.168.1.10")
        self.assertEqual(V.address("NAS.fritz.box"), "nas.fritz.box")
        self.assertEqual(V.address("fd00::1"), "fd00::1")
        bad = ("", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "224.0.0.1", "http://nas", "nas/x", "nas name",
               "-nas", "nas-", "a..b", "a" * 254, ("a" * 64) + ".de", "nas\n.de", "nás.de", "nas.de;ls", "nas%00",
               None, 5, ["a"])
        for value in bad:
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.address, value))

    def test_macs(self):
        for given in ("AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01", "aabb.ccdd.ee01", "aabbccddee01", " AA:BB:CC:DD:EE:01 "):
            with self.subTest(given=given):
                self.assertEqual(V.mac(given), "aa:bb:cc:dd:ee:01")
        bad = ("", "zz:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:01:02", "ff:ff:ff:ff:ff:ff",
               "00:00:00:00:00:00", "01:00:5e:00:00:01", "a" * 100, "aa:bb:cc:dd\n:ee:01", None, 5, ["aa"])
        for value in bad:
            with self.subTest(value=repr(value)[:20]):
                self.assertTrue(refused(V.mac, value))

    def test_device_ids(self):
        self.assertEqual(V.device_id(1), 1)
        for value in (0, -1, 2**63, True, "1", 1.0, None, [1]):
            with self.subTest(value=repr(value)):
                self.assertTrue(refused(V.device_id, value))


class StructureTest(unittest.TestCase):
    def test_json_object(self):
        self.assertEqual(V.json_object(None), {})
        self.assertEqual(V.json_object({"a": 1}), {"a": 1})
        for value in ([], ["a"], "text", 5, True):
            with self.subTest(value=repr(value)):
                self.assertTrue(refused(V.json_object, value))

    def test_roles_are_an_allow_list(self):
        self.assertEqual(V.role("admin"), "admin")
        for value in ("root", "Admin", "", None, ["admin"], "admin\n"):
            with self.subTest(value=repr(value)):
                self.assertTrue(refused(V.role, value))


class PerformanceTest(unittest.TestCase):
    def test_hostile_long_input_is_rejected_quickly(self):
        started = time.monotonic()
        for check in (V.username, V.token, V.address, V.mac, V.device_name):
            for value in ("a" * 100_000, "a-" * 50_000, "a." * 50_000, "1" * 100_000 + "!"):
                self.assertTrue(refused(check, value))
        self.assertLess(time.monotonic() - started, 1.0)


class BackendEndpointsTest(unittest.TestCase):
    """Hostile input through the real API: always a clean refusal, never a 500, nothing stored."""

    def setUp(self):
        os.environ.update(SECRETS, JWT_SECRET="test-jwt-secret-with-at-least-32-bytes", INITIAL_API_KEY="initial-key")
        self.db = FakeDatabase()
        from app import create_app
        self.client = create_app(database=self.db).test_client()
        admin = self.client.post(
            "/api/create-user/admin", json={"username": "root", "password": PW},
            headers={"Authorization": "Bearer initial-key"},
        ).get_json()
        self.admin = {"Authorization": f"Bearer {admin['access_token']}"}

    def test_attacks_as_names_are_refused_and_nothing_is_stored(self):
        for attack in ATTACKS:
            with self.subTest(attack=attack):
                r = self.client.post("/api/users", json={"username": attack, "password": PW}, headers=self.admin)
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.get_json()["error"], V.USERNAME_RULE)
        self.assertEqual(set(self.db.accounts), {"root"})

    def test_attacks_as_device_fields_are_refused(self):
        for attack in ATTACKS[:-1]:  # the last one is only a NUL, covered below
            for field in ("address", "mac"):
                with self.subTest(attack=attack, field=field):
                    body = {"name": "nas", "address": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", field: attack}
                    self.assertEqual(self.client.post("/api/devices", json=body, headers=self.admin).status_code, 400)
        self.assertEqual(self.client.get("/api/devices", headers=self.admin).get_json()["devices"], [])

    def test_attacks_in_the_url_are_a_404_and_touch_nothing(self):
        for attack in ("..%2F..%2Fetc", "anna%27%3B%20DROP%20TABLE%20users", "%00", "ANNA", "a%20b", "x" * 65):
            for method, path in (("put", "/api/users/{}"), ("delete", "/api/users/{}"), ("post", "/api/users/{}/reset-token")):
                with self.subTest(attack=attack, method=method):
                    r = getattr(self.client, method)(path.format(attack), json={"password": PW}, headers=self.admin)
                    self.assertIn(r.status_code, (404, 405))
        self.assertEqual(set(self.db.accounts), {"root"})

    def test_tokens_with_odd_content_are_just_unknown(self):
        for token in (ATTACKS[0], "x" * 5000, "tök", "a b"):
            with self.subTest(token=token[:12]):
                self.assertEqual(self.client.post("/api/token", json={"refresh_token": token}).status_code, 401)
                self.assertEqual(self.client.post("/api/reset-password",
                                                  json={"reset_token": token, "new_password": PW}).status_code, 401)
                self.assertEqual(self.client.post("/api/logout", json={"refresh_token": token}).status_code, 400)

    def test_tokens_of_the_wrong_type_are_refused_not_crashed_on(self):
        for token in (5, True, ["a"], {"a": 1}):
            with self.subTest(token=repr(token)):
                self.assertIn(self.client.post("/api/token", json={"refresh_token": token}).status_code, (400, 401))

    def test_nul_and_lone_surrogates_in_a_password_are_refused(self):
        for password in (PW + "\x00", PW + "\ud800"):
            with self.subTest(password=repr(password[-2:])):
                r = self.client.post("/api/users", json={"username": "clara", "password": password}, headers=self.admin)
                self.assertEqual(r.status_code, 400)
        self.assertEqual(
            self.client.post("/api/login", json={"username": "root", "password": PW + "\x00"}).status_code, 401)

    def test_a_body_that_is_not_an_object_is_400(self):
        for body in ([], ["a"], "text", 5):
            with self.subTest(body=repr(body)):
                self.assertEqual(self.client.post("/api/users", json=body, headers=self.admin).status_code, 400)
                self.assertEqual(self.client.post("/api/devices", json=body, headers=self.admin).status_code, 400)

    def test_huge_ids_in_the_url_are_a_404(self):
        for device_id in (2**63, 10**30):
            with self.subTest(device_id=device_id):
                self.assertEqual(self.client.delete(f"/api/devices/{device_id}", headers=self.admin).status_code, 404)
                self.assertEqual(self.client.post(f"/api/devices/{device_id}/wake", headers=self.admin).status_code, 404)

    def test_attack_attempts_are_logged_without_the_value(self):
        with self.assertLogs("shared.input_validator", level="WARNING") as logs:
            self.client.post("/api/users", json={"username": "x'; DROP TABLE users; --", "password": PW},
                             headers=self.admin)
        self.assertTrue(any("sql" in line for line in logs.output))
        self.assertFalse(any("DROP" in line for line in logs.output))


class PreparedStatementsTest(unittest.TestCase):
    """Nothing in the database container builds SQL from text."""

    EXECUTORS = {"execute", "executemany"}

    def _sources(self):
        folder = os.path.join(ROOT, "src", "database", "app")
        for name in sorted(os.listdir(folder)):
            if name.endswith(".py"):
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8") as handle:
                    yield name, ast.parse(handle.read())

    def test_every_query_is_a_literal_with_placeholders(self):
        checked = 0
        for name, tree in self._sources():
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in self.EXECUTORS):
                    continue
                checked += 1
                query = node.args[0]
                where = f"{name}:{node.lineno}"
                self.assertIsInstance(query, ast.Constant, f"{where}: SQL must be a plain string literal")
                self.assertIsInstance(query.value, str, where)
        self.assertGreater(checked, 10)

    def test_executescript_only_runs_the_schema_file(self):
        for name, tree in self._sources():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "executescript":
                    self.assertEqual(ast.unparse(node.args[0]), "schema", f"{name}:{node.lineno}")


class EndpointsUseTheValidatorTest(unittest.TestCase):
    """Every container reads its input through the validator, not from raw request data."""

    RAW = ("request.get_json", "request.form", "request.args", "request.values", "request.cookies")

    def test_raw_request_reads_only_happen_inside_the_wrappers(self):
        wrapped = {
            os.path.join("src", "backend", "app", "endpoints.py"): {"request.get_json": ("def _body",)},
            os.path.join("src", "database", "app", "endpoints.py"): {"request.get_json": ("def _body",)},
            os.path.join("src", "frontend", "app", "pages.py"): {
                "request.form": ("def _field", "csrf_token"),
                "request.cookies": ("session_id",),
            },
        }
        for relative, kinds in wrapped.items():
            with open(os.path.join(ROOT, relative), encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            for number, line in enumerate(lines, 1):
                for name in self.RAW:
                    if name not in line:
                        continue
                    context = "\n".join(lines[max(0, number - 12):number])
                    allowed = kinds.get(name, ())
                    self.assertTrue(
                        any(marker in context or marker in line for marker in allowed) or (
                            name == "request.cookies" and "V.token" in context),
                        f"{relative}:{number} reads {name} outside the validator wrappers",
                    )


if __name__ == "__main__":
    unittest.main()
