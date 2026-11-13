import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402

PW2 = "another-long-password"


class UserManagementTest(unittest.TestCase):
    def setUp(self):
        os.environ.update(
            SECRETS,
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        self.db = FakeDatabase()
        from app import create_app
        self.client = create_app(database=self.db).test_client()
        admin = self.client.post(
            "/api/create-user/admin",
            json={"username": "root", "password": PW},
            headers={"Authorization": "Bearer initial-key"},
        ).get_json()
        self.admin = {"Authorization": f"Bearer {admin['access_token']}"}

    def _add(self, name="anna", password=PW):
        return self.client.post("/api/users", json={"username": name, "password": password}, headers=self.admin)

    def _user_headers(self, name="anna", password=PW):
        token = self.client.post("/api/login", json={"username": name, "password": password}).get_json()
        return {"Authorization": f"Bearer {token['access_token']}"}

    # -- create / list -------------------------------------------------------

    def test_admin_creates_and_lists_users_without_hashes(self):
        self.assertEqual(self._add().status_code, 201)
        self._add("bernd")
        r = self.client.get("/api/users", headers=self.admin)
        self.assertEqual(r.status_code, 200)
        users = r.get_json()["users"]
        self.assertEqual({u["username"] for u in users}, {"root", "anna", "bernd"})
        self.assertEqual({u["role"] for u in users if u["username"] == "anna"}, {"user"})
        for u in users:
            self.assertEqual(set(u), {"username", "role"})

    def test_new_user_can_log_in_and_is_a_regular_user(self):
        self._add()
        r = self.client.post("/api/login", json={"username": "anna", "password": PW})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["role"], "user")

    def test_username_is_stored_lower_case(self):
        r = self._add("  Anna.K  ")
        self.assertEqual(r.get_json()["username"], "anna.k")
        self.assertEqual(self._add("ANNA.K").status_code, 409)
        self.assertEqual(self.client.post("/api/login", json={"username": "ANNA.K", "password": PW}).status_code, 200)

    def test_duplicate_name_is_409(self):
        self._add()
        self.assertEqual(self._add().status_code, 409)

    def test_invalid_names_and_passwords_are_400(self):
        for name in ("", "ab", "a b", "../x", "x" * 65, "-lead", 5, None, ["a"]):
            with self.subTest(name=name):
                self.assertEqual(self._add(name).status_code, 400)
        for password in ("short", "x" * 1025, 123456789012, None):
            with self.subTest(password=str(password)[:10]):
                self.assertEqual(self._add("clara", password).status_code, 400)

    # -- permissions -----------------------------------------------------------

    def test_regular_users_cannot_manage_users(self):
        self._add()
        user = self._user_headers()
        self.assertEqual(self.client.get("/api/users", headers=user).status_code, 403)
        self.assertEqual(
            self.client.post("/api/users", json={"username": "x" * 5, "password": PW}, headers=user).status_code, 403)
        self.assertEqual(self.client.put("/api/users/root", json={"password": PW2}, headers=user).status_code, 403)
        self.assertEqual(self.client.delete("/api/users/root", headers=user).status_code, 403)

    def test_user_management_needs_a_token(self):
        self.assertEqual(self.client.get("/api/users").status_code, 401)
        self.assertEqual(self.client.post("/api/users", json={}).status_code, 401)
        self.assertEqual(self.client.delete("/api/users/anna").status_code, 401)

    # -- reset password (admin) ---------------------------------------------------

    def test_admin_resets_a_password_and_old_sessions_die(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        r = self.client.put("/api/users/anna", json={"password": PW2}, headers=self.admin)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": old["refresh_token"]}).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW}).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW2}).status_code, 200)

    def test_reset_rules(self):
        self._add()
        self.assertEqual(self.client.put("/api/users/nobody", json={"password": PW2}, headers=self.admin).status_code, 404)
        self.assertEqual(self.client.put("/api/users/anna", json={"password": "short"}, headers=self.admin).status_code, 400)
        # the admin changes their own password through /api/me/password
        self.assertEqual(self.client.put("/api/users/root", json={"password": PW2}, headers=self.admin).status_code, 409)
        self.assertEqual(self.client.put("/api/users/Anna", json={"password": PW2}, headers=self.admin).status_code, 404)

    # -- delete ---------------------------------------------------------------------

    def test_admin_deletes_a_user_with_sessions_and_devices(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        self.db.create_device("anna", "nas", "192.168.1.10", "00:11:22:33:44:55")
        self.assertEqual(self.client.delete("/api/users/anna", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": old["refresh_token"]}).status_code, 401)
        self.assertEqual(self.client.get("/api/me", headers={"Authorization": f"Bearer {old['access_token']}"}).status_code, 401)
        self.assertEqual(self.db.list_devices("anna"), [])

    def test_delete_rules(self):
        self.assertEqual(self.client.delete("/api/users/nobody", headers=self.admin).status_code, 404)
        # neither oneself nor the admin account can be removed
        self.assertEqual(self.client.delete("/api/users/root", headers=self.admin).status_code, 409)
        self.assertTrue(self.db.exists("root"))

    # -- own password -----------------------------------------------------------------

    def test_change_own_password_returns_fresh_tokens(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        headers = {"Authorization": f"Bearer {old['access_token']}"}
        r = self.client.put("/api/me/password", json={"current_password": PW, "new_password": PW2}, headers=headers)
        self.assertEqual(r.status_code, 200)
        fresh = r.get_json()
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": old["refresh_token"]}).status_code, 401)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": fresh["refresh_token"]}).status_code, 200)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW2}).status_code, 200)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW}).status_code, 401)

    def test_admin_can_change_their_own_password(self):
        r = self.client.put("/api/me/password", json={"current_password": PW, "new_password": PW2}, headers=self.admin)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.post("/api/login", json={"username": "root", "password": PW2}).status_code, 200)

    def test_change_own_password_needs_the_current_one(self):
        self._add()
        headers = self._user_headers()
        for body in (
            {"current_password": "wrong-wrong-wrong", "new_password": PW2},
            {"new_password": PW2},
            {"current_password": 5, "new_password": PW2},
        ):
            with self.subTest(body=str(body)):
                self.assertEqual(self.client.put("/api/me/password", json=body, headers=headers).status_code, 403)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW}).status_code, 200)

    def test_new_password_must_be_valid(self):
        self._add()
        r = self.client.put("/api/me/password", json={"current_password": PW, "new_password": "short"},
                            headers=self._user_headers())
        self.assertEqual(r.status_code, 400)

    def test_guessing_the_current_password_is_throttled(self):
        self._add()
        headers = self._user_headers()
        body = {"current_password": "wrong-wrong-wrong", "new_password": PW2}
        for _ in range(5):
            self.assertEqual(self.client.put("/api/me/password", json=body, headers=headers).status_code, 403)
        self.assertEqual(self.client.put("/api/me/password", json=body, headers=headers).status_code, 429)
        right = {"current_password": PW, "new_password": PW2}
        self.assertEqual(self.client.put("/api/me/password", json=right, headers=headers).status_code, 429)

    # -- change own username ---------------------------------------------------------

    def _rename(self, headers, new="annika", password=PW):
        return self.client.patch(
            "/api/me", json={"username": new, "current_password": password}, headers=headers)

    def test_user_renames_self_and_keeps_role_devices_and_password(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        headers = {"Authorization": f"Bearer {old['access_token']}"}
        self.db.create_device("anna", "nas", "192.168.1.10", "00:11:22:33:44:55")

        r = self._rename(headers, "  Annika.K ")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual((body["username"], body["role"]), ("annika.k", "user"))

        fresh = {"Authorization": f"Bearer {body['access_token']}"}
        me = self.client.get("/api/me", headers=fresh).get_json()
        self.assertEqual((me["username"], me["role"]), ("annika.k", "user"))
        self.assertEqual([d["name"] for d in self.db.list_devices("annika.k")], ["nas"])
        self.assertEqual(self.db.list_devices("anna"), [])
        self.assertEqual(self.client.post("/api/login", json={"username": "annika.k", "password": PW}).status_code, 200)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW}).status_code, 401)

    def test_rename_ends_old_sessions(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        headers = {"Authorization": f"Bearer {old['access_token']}"}
        fresh = self._rename(headers).get_json()
        self.assertEqual(self.client.get("/api/me", headers=headers).status_code, 401)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": old["refresh_token"]}).status_code, 401)
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": fresh["refresh_token"]}).status_code, 200)

    def test_role_cannot_be_changed(self):
        self._add()
        headers = self._user_headers()
        for body in (
            {"role": "admin"},
            {"username": "annika", "current_password": PW, "role": "admin"},
            {"username": "annika", "current_password": PW, "role": "user"},
        ):
            with self.subTest(body=str(body)):
                self.assertEqual(self.client.patch("/api/me", json=body, headers=headers).status_code, 403)
        me = self.client.get("/api/me", headers=headers).get_json()
        self.assertEqual((me["username"], me["role"]), ("anna", "user"))

    def test_admin_can_rename_but_stays_admin(self):
        r = self._rename(self.admin, "boss")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["role"], "admin")
        self.assertEqual(self.db.get_credentials("boss")["role"], "admin")
        self.assertFalse(self.db.exists("root"))

    def test_rename_needs_the_current_password(self):
        self._add()
        headers = self._user_headers()
        for body in (
            {"username": "annika", "current_password": "wrong-wrong-wrong"},
            {"username": "annika"},
            {"username": "annika", "current_password": 5},
            {"username": "annika", "current_password": ""},
        ):
            with self.subTest(body=str(body)):
                self.assertEqual(self.client.patch("/api/me", json=body, headers=headers).status_code, 403)
        self.assertTrue(self.db.exists("anna"))

    def test_rename_rejects_taken_same_and_invalid_names(self):
        self._add()
        self._add("bernd")
        headers = self._user_headers()
        for name in ("bernd", "root", "BERND", "anna", " Anna "):
            with self.subTest(name=name):
                self.assertEqual(self._rename(headers, name).status_code, 409)
        for name in ("", "ab", "a b", "../x", "x" * 65, 5, None, ["a"]):
            with self.subTest(name=name):
                self.assertEqual(self._rename(headers, name).status_code, 400)
        self.assertTrue(self.db.exists("anna"))
        self.assertTrue(self.db.exists("bernd"))

    def test_rename_rejects_other_fields_and_bad_bodies(self):
        self._add()
        headers = self._user_headers()
        self.assertEqual(self.client.patch("/api/me", json={"current_password": PW}, headers=headers).status_code, 400)
        self.assertEqual(
            self.client.patch("/api/me", json={"username": "annika", "current_password": PW, "email": "a@b.c"},
                              headers=headers).status_code, 400)
        self.assertEqual(self.client.patch("/api/me", json=["annika"], headers=headers).status_code, 400)
        self.assertEqual(self.client.patch("/api/me", data="not json", headers=headers).status_code, 400)

    def test_rename_needs_a_token(self):
        self.assertEqual(self.client.patch("/api/me", json={"username": "annika", "current_password": PW}).status_code, 401)

    def test_guessing_the_password_to_rename_is_throttled(self):
        self._add()
        headers = self._user_headers()
        for _ in range(5):
            self.assertEqual(self._rename(headers, password="wrong-wrong-wrong").status_code, 403)
        self.assertEqual(self._rename(headers, password="wrong-wrong-wrong").status_code, 429)
        self.assertEqual(self._rename(headers).status_code, 429)
        self.assertTrue(self.db.exists("anna"))

    def test_rename_when_database_is_down_is_503(self):
        self._add()
        headers = self._user_headers()
        self.db.down = True
        self.assertEqual(self._rename(headers).status_code, 503)

    # -- delete own account ----------------------------------------------------------

    def _delete_me(self, headers, password=PW):
        return self.client.delete("/api/me", json={"current_password": password}, headers=headers)

    def test_user_deletes_own_account_and_admin_can_recreate_it(self):
        self._add()
        old = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        headers = {"Authorization": f"Bearer {old['access_token']}"}
        self.db.create_device("anna", "nas", "192.168.1.10", "00:11:22:33:44:55")

        r = self._delete_me(headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"username": "anna"})
        self.assertFalse(self.db.exists("anna"))
        self.assertEqual(self.db.list_devices("anna"), [])
        self.assertEqual(self.client.post("/api/token", json={"refresh_token": old["refresh_token"]}).status_code, 401)
        self.assertEqual(self.client.get("/api/me", headers=headers).status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW}).status_code, 401)

        self.assertEqual(self._add(password=PW2).status_code, 201)
        self.assertEqual(self.client.post("/api/login", json={"username": "anna", "password": PW2}).status_code, 200)
        self.assertEqual(self.db.list_devices("anna"), [])

    def test_delete_own_account_needs_the_current_password(self):
        self._add()
        headers = self._user_headers()
        for body in ({"current_password": "wrong-wrong-wrong"}, {}, {"current_password": 5}, {"current_password": ""}):
            with self.subTest(body=str(body)):
                r = self.client.delete("/api/me", json=body, headers=headers)
                self.assertEqual(r.status_code, 403)
        self.assertTrue(self.db.exists("anna"))

    def test_delete_own_account_needs_a_token(self):
        self.assertEqual(self.client.delete("/api/me", json={"current_password": PW}).status_code, 401)

    def test_admin_cannot_delete_own_account(self):
        self.assertEqual(self._delete_me(self.admin).status_code, 409)
        self.assertTrue(self.db.exists("root"))

    def test_guessing_the_password_to_delete_an_account_is_throttled(self):
        self._add()
        headers = self._user_headers()
        for _ in range(5):
            self.assertEqual(self._delete_me(headers, "wrong-wrong-wrong").status_code, 403)
        self.assertEqual(self._delete_me(headers, "wrong-wrong-wrong").status_code, 429)
        self.assertEqual(self._delete_me(headers).status_code, 429)
        self.assertTrue(self.db.exists("anna"))

    def test_database_down_is_503(self):
        self.db.down = True
        self.assertEqual(self.client.get("/api/users", headers=self.admin).status_code, 503)


if __name__ == "__main__":
    unittest.main()
