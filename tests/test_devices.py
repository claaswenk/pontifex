import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from app.services import normalize_mac, valid_address, valid_name  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402

MAC = "AA:BB:CC:DD:EE:01"


class ValidationTest(unittest.TestCase):
    def test_mac_spellings_are_normalized(self):
        for given in ("AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01", "aabb.ccdd.ee01", "aabbccddee01", "  AA:BB:CC:DD:EE:01 "):
            with self.subTest(given=given):
                self.assertEqual(normalize_mac(given), "aa:bb:cc:dd:ee:01")

    def test_bad_macs_are_refused(self):
        bad = (
            "", "zz:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:01:02", "aabbccddee0",
            "ff:ff:ff:ff:ff:ff",   # broadcast
            "00:00:00:00:00:00",   # all zero
            "01:00:5e:00:00:01",   # multicast
            None, 5, ["aa"], "a" * 100,
        )
        for given in bad:
            with self.subTest(given=str(given)[:20]):
                self.assertIsNone(normalize_mac(given))

    def test_addresses(self):
        self.assertEqual(valid_address(" 192.168.1.10 "), "192.168.1.10")
        self.assertEqual(valid_address("NAS.fritz.box"), "nas.fritz.box")
        self.assertEqual(valid_address("fd00::1"), "fd00::1")
        for bad in ("", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "224.0.0.1", "http://nas", "nas/x",
                    "nas name", "-nas", "a" * 254, None, 5):
            with self.subTest(bad=str(bad)[:20]):
                self.assertIsNone(valid_address(bad))

    def test_names(self):
        self.assertEqual(valid_name("  Mein NAS "), "Mein NAS")
        for bad in ("", "   ", "x" * 65, "a\nb", "a\x00b", None, 7):
            with self.subTest(bad=str(bad)[:20]):
                self.assertIsNone(valid_name(bad))


class DeviceEndpointsTest(unittest.TestCase):
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
        self.client.post("/api/users", json={"username": "anna", "password": PW}, headers=self.admin)
        self.anna = self._login("anna")

    def _login(self, name):
        token = self.client.post("/api/login", json={"username": name, "password": PW}).get_json()
        return {"Authorization": f"Bearer {token['access_token']}"}

    def _add(self, headers=None, **fields):
        body = {"name": "nas", "address": "192.168.1.10", "mac": MAC}
        body.update(fields)
        return self.client.post("/api/devices", json=body, headers=headers or self.anna)

    def test_create_list_and_normalized_storage(self):
        r = self._add(name="  NAS ", address="NAS.fritz.box", mac="AA-BB-CC-DD-EE-01")
        self.assertEqual(r.status_code, 201)
        device = r.get_json()
        self.assertEqual(device["name"], "NAS")
        self.assertEqual(device["address"], "nas.fritz.box")
        self.assertEqual(device["mac"], "aa:bb:cc:dd:ee:01")
        self.assertIn("id", device)
        listed = self.client.get("/api/devices", headers=self.anna).get_json()["devices"]
        self.assertEqual(listed, [device])

    def test_admin_has_their_own_devices_like_everyone(self):
        self._add(headers=self.admin, name="admin-pc")
        self.assertEqual(
            [d["name"] for d in self.client.get("/api/devices", headers=self.admin).get_json()["devices"]], ["admin-pc"])
        self.assertEqual(self.client.get("/api/devices", headers=self.anna).get_json()["devices"], [])

    def test_users_only_see_their_own_devices(self):
        self._add()
        self.client.post("/api/users", json={"username": "bernd", "password": PW}, headers=self.admin)
        bernd = self._login("bernd")
        self.assertEqual(self.client.get("/api/devices", headers=bernd).get_json()["devices"], [])

    def test_somebody_elses_device_is_404_and_untouched(self):
        device_id = self._add().get_json()["id"]
        self.client.post("/api/users", json={"username": "bernd", "password": PW}, headers=self.admin)
        bernd = self._login("bernd")
        self.assertEqual(self.client.delete(f"/api/devices/{device_id}", headers=bernd).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/devices/{device_id}", headers=self.admin).status_code, 404)
        self.assertEqual(len(self.client.get("/api/devices", headers=self.anna).get_json()["devices"]), 1)

    def test_delete_own_device(self):
        device_id = self._add().get_json()["id"]
        self.assertEqual(self.client.delete(f"/api/devices/{device_id}", headers=self.anna).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/devices/{device_id}", headers=self.anna).status_code, 404)
        self.assertEqual(self.client.get("/api/devices", headers=self.anna).get_json()["devices"], [])

    def test_delete_with_a_non_numeric_id_deletes_nothing(self):
        self._add()
        for path in ("/api/devices/abc", "/api/devices/1;2", "/api/devices/-1"):
            with self.subTest(path=path):
                self.assertIn(self.client.delete(path, headers=self.anna).status_code, (404, 405))
        self.assertEqual(len(self.client.get("/api/devices", headers=self.anna).get_json()["devices"]), 1)

    def test_invalid_input_is_400_and_stores_nothing(self):
        for fields in (
            {"name": ""}, {"name": "x" * 65}, {"name": 5}, {"name": None},
            {"address": "127.0.0.1"}, {"address": "http://x"}, {"address": ""}, {"address": 5},
            {"mac": "zz"}, {"mac": "ff:ff:ff:ff:ff:ff"}, {"mac": 5},
        ):
            with self.subTest(fields=str(fields)):
                self.assertEqual(self._add(**fields).status_code, 400)
        self.assertEqual(self.client.post("/api/devices", json={}, headers=self.anna).status_code, 400)
        self.assertEqual(self.client.get("/api/devices", headers=self.anna).get_json()["devices"], [])

    def test_duplicate_name_is_409_but_other_users_may_reuse_it(self):
        self.assertEqual(self._add().status_code, 201)
        self.assertEqual(self._add(address="192.168.1.11").status_code, 409)
        self.assertEqual(self._add(headers=self.admin).status_code, 201)

    def test_device_limit(self):
        from app.services import MAX_DEVICES_PER_USER
        for i in range(MAX_DEVICES_PER_USER):
            self.db.create_device("anna", f"d{i}", "192.168.1.10", MAC)
        self.assertEqual(self._add().status_code, 409)

    def test_everything_needs_a_token(self):
        self.assertEqual(self.client.get("/api/devices").status_code, 401)
        self.assertEqual(self.client.post("/api/devices", json={}).status_code, 401)
        self.assertEqual(self.client.delete("/api/devices/1").status_code, 401)

    def test_database_down_is_503(self):
        self.db.down = True
        self.assertEqual(self.client.get("/api/devices", headers=self.anna).status_code, 503)

    def test_metrics_reports_the_device_id(self):
        device_id = self._add().get_json()["id"]
        from unittest import mock
        from app import services
        with mock.patch.object(services, "_probe", return_value=None):
            body = self.client.get("/api/metrics", headers=self.anna).get_json()
        self.assertEqual(body["devices"][0]["id"], device_id)
        self.assertEqual(body["devices"][0]["status"], "offline")


if __name__ == "__main__":
    unittest.main()
