import os
import socketserver
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from app import services  # noqa: E402
from tests.fake_database import FakeDatabase  # noqa: E402
from tests.test_auth import PW, SECRETS  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"
HAS_UNIX_SOCKETS = hasattr(socketserver, "UnixStreamServer")


class MagicPacketTest(unittest.TestCase):
    def test_layout(self):
        packet = services.magic_packet(MAC)
        self.assertEqual(len(packet), 102)
        self.assertEqual(packet[:6], b"\xff" * 6)
        self.assertEqual(packet[6:], bytes.fromhex("aabbccddee01") * 16)


class HandleWakeRequestTest(unittest.TestCase):
    def _ask(self, raw):
        sent = []
        reply = services.handle_wake_request(raw, sent.append)
        return reply, sent

    def test_valid_request_sends_once(self):
        self.assertEqual(self._ask(b"WAKE aa:bb:cc:dd:ee:01\n"), (b"OK\n", [MAC]))

    def test_everything_else_is_refused_and_sends_nothing(self):
        bad = (
            b"", b"\n", b"WAKE\n", b"WAKE \n", b"WAKE aa:bb:cc:dd:ee\n",
            b"WAKE AA:BB:CC:DD:EE:01\n",              # the backend always sends lower case
            b"WAKE aabbccddee01\n",
            b"WAKE aa:bb:cc:dd:ee:01",                # no newline
            b"WAKE aa:bb:cc:dd:ee:01\nWAKE aa:bb:cc:dd:ee:02\n",
            b"WAKE aa:bb:cc:dd:ee:01 10.0.0.255 7\n",  # no destination or port from the caller
            b"wake aa:bb:cc:dd:ee:01\n",
            b"WAKE ff:ff:ff:ff:ff:ff\n", b"WAKE 00:00:00:00:00:00\n", b"WAKE 01:00:5e:00:00:01\n",
            b"GET / HTTP/1.1\r\n", b"\x00" * 64,
        )
        for raw in bad:
            with self.subTest(raw=raw[:30]):
                reply, sent = self._ask(raw)
                self.assertEqual(reply, b"ERR\n")
                self.assertEqual(sent, [])

    def test_a_send_failure_is_an_error(self):
        def boom(_mac):
            raise OSError("network down")
        self.assertEqual(services.handle_wake_request(b"WAKE aa:bb:cc:dd:ee:01\n", boom), b"ERR\n")


class RelayConfigTest(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)
        for name in (services.WAKE_SOCKET_ENV, services.WOL_BROADCAST_ENV, services.WOL_PORT_ENV):
            os.environ.pop(name, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_defaults(self):
        self.assertEqual(services._relay_config(), (services.DEFAULT_WAKE_SOCKET, "255.255.255.255", 9))

    def test_configured_values(self):
        os.environ[services.WOL_BROADCAST_ENV] = "192.168.178.255"
        os.environ[services.WOL_PORT_ENV] = "7"
        self.assertEqual(services._relay_config()[1:], ("192.168.178.255", 7))

    def test_bad_values_stop_the_relay(self):
        for name, value in (
            (services.WOL_BROADCAST_ENV, "not-an-ip"), (services.WOL_BROADCAST_ENV, "127.0.0.1"),
            (services.WOL_BROADCAST_ENV, "224.0.0.1"), (services.WOL_BROADCAST_ENV, "0.0.0.0"),
            (services.WOL_BROADCAST_ENV, "169.254.1.255"), (services.WOL_BROADCAST_ENV, "example.com"),
            (services.WOL_PORT_ENV, "nine"), (services.WOL_PORT_ENV, "0"), (services.WOL_PORT_ENV, "70000"),
        ):
            with self.subTest(name=name, value=value):
                os.environ.pop(services.WOL_BROADCAST_ENV, None)
                os.environ.pop(services.WOL_PORT_ENV, None)
                os.environ[name] = value
                with self.assertRaises(RuntimeError):
                    services._relay_config()


class SendMagicPacketTest(unittest.TestCase):
    def test_real_udp_datagrams_arrive(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            services.send_magic_packet(MAC, "127.0.0.1", receiver.getsockname()[1])
            for _ in range(services.WAKE_REPEAT):
                data, _ = receiver.recvfrom(256)
                self.assertEqual(data, services.magic_packet(MAC))

    def test_sends_the_packet_a_few_times_to_the_configured_destination(self):
        from unittest import mock
        with mock.patch.object(services.socket, "socket") as factory:
            sock = factory.return_value.__enter__.return_value
            services.send_magic_packet(MAC, "192.168.178.255", 9)
        sock.setsockopt.assert_called_once_with(services.socket.SOL_SOCKET, services.socket.SO_BROADCAST, 1)
        self.assertEqual(sock.sendto.call_count, services.WAKE_REPEAT)
        for call in sock.sendto.call_args_list:
            self.assertEqual(call.args, (services.magic_packet(MAC), ("192.168.178.255", 9)))


class WakeRelayDouble:
    """A relay stand-in that records what it was asked and answers as told."""

    def __init__(self, reply=b"OK\n"):
        self.requests = []
        self.reply = reply
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "wake.sock")
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                outer.requests.append(self.rfile.readline())
                self.wfile.write(outer.reply)

        self.server = socketserver.UnixStreamServer(self.path, Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        try:
            os.unlink(self.path)
            os.rmdir(self.dir)
        except OSError:
            pass


@unittest.skipUnless(HAS_UNIX_SOCKETS, "needs Unix sockets")
class RequestWakeTest(unittest.TestCase):
    def setUp(self):
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_sends_only_the_mac(self):
        with WakeRelayDouble() as relay:
            os.environ[services.WAKE_SOCKET_ENV] = relay.path
            services.request_wake(MAC)
        self.assertEqual(relay.requests, [b"WAKE aa:bb:cc:dd:ee:01\n"])

    def test_refusal_is_an_error(self):
        with WakeRelayDouble(reply=b"ERR\n") as relay:
            os.environ[services.WAKE_SOCKET_ENV] = relay.path
            with self.assertRaises(services.WakeUnavailableError):
                services.request_wake(MAC)

    def test_missing_relay_is_an_error(self):
        os.environ[services.WAKE_SOCKET_ENV] = os.path.join(tempfile.gettempdir(), "no-such-pontifex.sock")
        with self.assertRaises(services.WakeUnavailableError):
            services.request_wake(MAC)


@unittest.skipUnless(HAS_UNIX_SOCKETS, "needs Unix sockets")
class RelayServerTest(unittest.TestCase):
    """The real relay loop on a real Unix socket, with the UDP sending replaced."""

    def setUp(self):
        import socket
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "wake.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        # Room for the whole burst in test_connections_beyond_the_limit...,
        # so a slow accept loop cannot make connect() fail with ECONNREFUSED.
        self.listener.listen(services.MAX_RELAY_CONNECTIONS + 4)
        self.sent = []
        self.thread = threading.Thread(
            target=services.serve_wake_relay, args=(self.listener, self.sent.append), daemon=True)
        self.thread.start()
        self._env = dict(os.environ)
        os.environ[services.WAKE_SOCKET_ENV] = self.path

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.listener.close()
        self.thread.join(timeout=3)
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_backend_client_and_relay_work_together(self):
        services.request_wake(MAC)
        services.request_wake("a8:a1:59:29:3d:6d")
        self.assertEqual(self.sent, [MAC, "a8:a1:59:29:3d:6d"])

    def test_a_silent_or_broken_client_does_not_block_the_next_one(self):
        import socket
        silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        silent.connect(self.path)  # connects and says nothing until the relay gives up on it
        try:
            services.request_wake(MAC)
        finally:
            silent.close()
        self.assertEqual(self.sent, [MAC])

    def test_a_forged_request_gets_err_and_sends_nothing(self):
        import socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.path)
            client.sendall(b"WAKE aa:bb:cc:dd:ee:01 10.0.0.255\n")
            self.assertEqual(client.recv(16), b"ERR\n")
        self.assertEqual(self.sent, [])

    def test_connections_beyond_the_limit_are_dropped_and_the_relay_recovers(self):
        import socket
        silent = []
        try:
            for _ in range(services.MAX_RELAY_CONNECTIONS):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(self.path)
                silent.append(client)
            with self.assertRaises(services.WakeUnavailableError):
                services.request_wake(MAC)  # all slots taken: closed without an answer
        finally:
            for client in silent:
                client.close()
        deadline = time.monotonic() + 5
        while True:  # the slots free up once the silent connections are gone
            try:
                services.request_wake(MAC)
                break
            except services.WakeUnavailableError:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.05)
        self.assertEqual(self.sent, [MAC])


@unittest.skipUnless(HAS_UNIX_SOCKETS, "needs Unix sockets")
class RunWakeRelayTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "wake.sock")
        self._env = dict(os.environ)
        os.environ[services.WAKE_SOCKET_ENV] = self.path
        os.environ[services.WOL_BROADCAST_ENV] = "192.168.178.255"
        os.environ.pop(services.WOL_PORT_ENV, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_refuses_to_replace_something_that_is_not_a_socket(self):
        with open(self.path, "w") as f:
            f.write("precious")
        with self.assertRaises(RuntimeError):
            services.run_wake_relay()
        with open(self.path) as f:
            self.assertEqual(f.read(), "precious")

    def test_bad_configuration_stops_before_binding(self):
        os.environ[services.WOL_BROADCAST_ENV] = "127.0.0.1"
        with self.assertRaises(RuntimeError):
            services.run_wake_relay()
        self.assertFalse(os.path.exists(self.path))

    def test_socket_is_private_and_removed_on_exit(self):
        import socket
        from unittest import mock

        modes = []

        def serve_once(listener, send):
            modes.append(os.stat(self.path).st_mode & 0o777)
            raise SystemExit(0)

        with mock.patch.object(services, "serve_wake_relay", serve_once), \
                mock.patch.object(services.signal, "signal"):
            with self.assertRaises(SystemExit):
                services.run_wake_relay()
        self.assertEqual(modes, [0o700])  # sockets start as 0777, the umask leaves the owner only
        self.assertFalse(os.path.exists(self.path))


@unittest.skipUnless(HAS_UNIX_SOCKETS, "needs Unix sockets")
class WakeEndpointTest(unittest.TestCase):
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
        token = self.client.post("/api/login", json={"username": "anna", "password": PW}).get_json()
        self.anna = {"Authorization": f"Bearer {token['access_token']}"}
        self.device = self.client.post(
            "/api/devices",
            json={"name": "ryzen", "address": "192.168.178.50", "mac": "A8:A1:59:29:3D:6D"},
            headers=self.anna,
        ).get_json()
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def _wake(self, device_id=None, headers=None, **kwargs):
        return self.client.post(
            f"/api/devices/{device_id or self.device['id']}/wake", headers=headers or self.anna, **kwargs)

    def test_wakes_the_stored_mac(self):
        with WakeRelayDouble() as relay:
            os.environ[services.WAKE_SOCKET_ENV] = relay.path
            r = self._wake()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"id": self.device["id"], "status": "sent"})
        self.assertEqual(relay.requests, [b"WAKE a8:a1:59:29:3d:6d\n"])

    def test_nothing_from_the_request_reaches_the_relay(self):
        with WakeRelayDouble() as relay:
            os.environ[services.WAKE_SOCKET_ENV] = relay.path
            self._wake(json={"mac": "11:22:33:44:55:66", "ip": "10.0.0.255", "port": 7})
        self.assertEqual(relay.requests, [b"WAKE a8:a1:59:29:3d:6d\n"])

    def test_somebody_elses_device_is_404_and_sends_nothing(self):
        with WakeRelayDouble() as relay:
            os.environ[services.WAKE_SOCKET_ENV] = relay.path
            r = self._wake(headers=self.admin)
            self.assertEqual(r.status_code, 404)
            self.assertEqual(self._wake(device_id=9999).status_code, 404)
        self.assertEqual(relay.requests, [])

    def test_relay_down_is_503_with_a_generic_message(self):
        os.environ[services.WAKE_SOCKET_ENV] = os.path.join(tempfile.gettempdir(), "no-such-pontifex.sock")
        r = self._wake()
        self.assertEqual(r.status_code, 503)
        self.assertNotIn("sock", r.get_data(as_text=True))

    def test_needs_a_token(self):
        self.assertEqual(self.client.post(f"/api/devices/{self.device['id']}/wake").status_code, 401)


if __name__ == "__main__":
    unittest.main()
