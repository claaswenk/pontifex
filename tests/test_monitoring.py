import os
import socket
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from app import services  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402


class FakeDeviceDatabase(FakeDatabase):
    @property
    def devices(self):
        return self.owned

    @devices.setter
    def devices(self, value):
        self.owned = value


class SystemStatsTest(unittest.TestCase):
    def test_shape_and_ranges(self):
        stats = services.system_stats()
        self.assertTrue(0.0 <= stats["cpu"]["percent"] <= 100.0)
        self.assertGreaterEqual(stats["cpu"]["cores_logical"], 1)
        self.assertTrue(0.0 <= stats["memory"]["percent"] <= 100.0)
        self.assertGreater(stats["memory"]["total_bytes"], 0)
        self.assertGreaterEqual(stats["host_uptime_seconds"], 0)
        self.assertGreaterEqual(stats["service_uptime_seconds"], 0)

    def test_unreadable_disk_path_does_not_fail(self):
        with mock.patch.dict(os.environ, {"MONITOR_DISK_PATH": os.path.join(ROOT, "does-not-exist")}):
            self.assertIsNone(services.system_stats()["disk"])


class ResolveSafeIpTest(unittest.TestCase):
    def test_private_lan_is_allowed(self):
        for address in ("192.168.1.10", "10.0.0.5", "172.16.0.9"):
            self.assertEqual(services._resolve_safe_ip(address), address)

    def test_dangerous_targets_are_refused(self):
        for address in ("127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "240.0.0.1"):
            self.assertIsNone(services._resolve_safe_ip(address), address)

    def test_garbage_is_refused(self):
        for address in ("", "   ", None, "http://192.168.1.10", "a b", "host/path", "-bad.example", "a" * 300):
            self.assertIsNone(services._resolve_safe_ip(address), repr(address))

    def test_hostname_resolving_to_loopback_is_refused(self):
        loopback = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with mock.patch.object(services.socket, "getaddrinfo", return_value=loopback):
            self.assertIsNone(services._resolve_safe_ip("evil.example.com"))

    def test_hostname_resolving_to_lan_is_allowed(self):
        lan = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 0))]
        with mock.patch.object(services.socket, "getaddrinfo", return_value=lan):
            self.assertEqual(services._resolve_safe_ip("nas.local"), "192.168.1.20")

    def test_unresolvable_hostname_is_refused(self):
        with mock.patch.object(services.socket, "getaddrinfo", side_effect=socket.gaierror):
            self.assertIsNone(services._resolve_safe_ip("nope.invalid"))


class CheckDevicesTest(unittest.TestCase):
    @staticmethod
    def _fake_connect(address_port, timeout=None):
        host, port = address_port
        if host == "192.168.1.10" and port == 80:
            return mock.MagicMock()          # open port
        if host == "192.168.1.11" and port == 22:
            raise ConnectionRefusedError()   # RST: host is up
        raise TimeoutError()                 # silence

    def _check(self, devices):
        with mock.patch.object(services.socket, "create_connection", side_effect=self._fake_connect):
            return services.check_devices(devices)

    def test_open_port_refused_port_and_silence(self):
        result = self._check([
            {"name": "nas", "address": "192.168.1.10"},
            {"name": "pc", "address": "192.168.1.11"},
            {"name": "off", "address": "192.168.1.12"},
        ])
        self.assertEqual([d["name"] for d in result], ["nas", "pc", "off"])
        self.assertEqual([d["status"] for d in result], ["online", "online", "offline"])
        self.assertIsNotNone(result[0]["latency_ms"])
        self.assertIsNone(result[2]["latency_ms"])

    def test_forbidden_address_is_offline_and_never_connected(self):
        with mock.patch.object(services.socket, "create_connection") as connect:
            result = services.check_devices([{"name": "lo", "address": "127.0.0.1"}])
        connect.assert_not_called()
        self.assertEqual(result[0]["status"], "offline")

    def test_empty_list(self):
        self.assertEqual(services.check_devices([]), [])

    def test_limit(self):
        devices = [{"name": str(i), "address": "192.168.1.12"} for i in range(services.MAX_DEVICES_PER_REQUEST + 25)]
        self.assertEqual(len(self._check(devices)), services.MAX_DEVICES_PER_REQUEST)


class MonitoringEndpointsTest(unittest.TestCase):
    def setUp(self):
        os.environ.update(
            SECRETS,
            JWT_SECRET="test-jwt-secret-with-at-least-32-bytes",
            INITIAL_API_KEY="initial-key",
        )
        self.db = FakeDeviceDatabase()
        from app import create_app
        self.client = create_app(database=self.db).test_client()
        admin = self.client.post(
            "/api/create-user/admin",
            json={"username": "root", "password": PW},
            headers={"Authorization": "Bearer initial-key"},
        ).get_json()
        self.headers = {"Authorization": f"Bearer {admin['access_token']}"}

    def test_health_stays_public(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_monitoring_requires_token(self):
        self.assertEqual(self.client.get("/api/monitoring").status_code, 401)

    def test_monitoring_returns_stats(self):
        r = self.client.get("/api/monitoring", headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertIn("cpu", r.get_json()["stats"])

    def test_metrics_requires_token(self):
        self.assertEqual(self.client.get("/api/metrics").status_code, 401)

    def test_metrics_only_checks_own_devices(self):
        self.db.devices = {
            "root": [{"name": "nas", "address": "192.168.1.10"}],
            "someone-else": [{"name": "secret", "address": "192.168.1.99"}],
        }
        with mock.patch.object(services.socket, "create_connection",
                               side_effect=CheckDevicesTest._fake_connect):
            r = self.client.get("/api/metrics", headers=self.headers)
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual([d["name"] for d in body["devices"]], ["nas"])
        self.assertEqual(body["summary"], {"total": 1, "online": 1, "offline": 0})

    def test_metrics_ignores_addresses_from_the_request(self):
        with mock.patch.object(services.socket, "create_connection") as connect:
            r = self.client.get("/api/metrics?address=192.168.1.10", headers=self.headers)
        self.assertEqual(r.get_json()["devices"], [])
        connect.assert_not_called()

    def test_metrics_with_database_down_is_503(self):
        self.db.down = True
        r = self.client.get("/api/metrics", headers=self.headers)
        self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
