"""
End-to-end: the real backend and frontend processes authenticate each other.

Both run.py files are started as separate processes with their own
self-signed certificates and talk to each other over real HTTPS. Each side
must log that it accepted the other one, and a wrong secret must make both
sides fail.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "s" * 40


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_cert(directory: str, name: str) -> tuple[str, str]:
    cert, key = os.path.join(directory, f"{name}.crt"), os.path.join(directory, f"{name}.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", key, "-out", cert],
        check=True, capture_output=True,
    )
    return cert, key


class TwoContainersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.procs = []
        self.backend_port, self.frontend_port = free_port(), free_port()

    def tearDown(self):
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            proc.wait(timeout=10)
        self.tmp.cleanup()

    def start(self, name: str, subdir: str, port: int, peer_env: str, peer_port: int, secret: str):
        cert, key = make_cert(self.tmp.name, name)
        log_path = os.path.join(self.tmp.name, f"{name}.log")
        env = {
            "PATH": os.environ["PATH"],
            "PYTHONPATH": os.path.join(ROOT, "src"),
            "PORT": str(port),
            "TLS_CERT_PATH": cert,
            "TLS_KEY_PATH": key,
            "BACKEND_FRONTEND_SECRET": secret,
            "BACKEND_DATABASE_SECRET": "d" * 40,
            "JWT_SECRET": "j" * 40,
            "INITIAL_API_KEY": "initial-key",
            peer_env: f"https://127.0.0.1:{peer_port}",
            "PEER_CHECK_INTERVAL_SECONDS": "1",
        }
        with open(log_path, "w", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                [sys.executable, "run.py"], cwd=os.path.join(ROOT, "src", subdir),
                env=env, stdout=log_file, stderr=subprocess.STDOUT,
            )
        self.procs.append(proc)
        return log_path

    def log_has(self, path: str, text: str, timeout: float = 25.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with open(path, encoding="utf-8") as fh:
                if text in fh.read():
                    return True
            time.sleep(0.3)
        return False

    def test_both_sides_authenticate_each_other(self):
        backend = self.start("backend", "backend", self.backend_port, "FRONTEND_URL",
                             self.frontend_port, SECRET)
        frontend = self.start("frontend", "frontend", self.frontend_port, "BACKEND_URL",
                              self.backend_port, SECRET)

        self.assertTrue(self.log_has(backend, "Peer frontend: mutual authentication OK"),
                        "backend did not authenticate the frontend")
        self.assertTrue(self.log_has(frontend, "Peer backend: mutual authentication OK"),
                        "frontend did not authenticate the backend")

    def test_different_secrets_fail_on_both_sides(self):
        backend = self.start("backend", "backend", self.backend_port, "FRONTEND_URL",
                             self.frontend_port, SECRET)
        frontend = self.start("frontend", "frontend", self.frontend_port, "BACKEND_URL",
                              self.backend_port, "x" * 40)

        self.assertTrue(self.log_has(backend, "Peer frontend: auth_failed"),
                        "backend accepted a frontend with a different secret")
        self.assertTrue(self.log_has(frontend, "Peer backend: auth_failed"),
                        "frontend accepted a backend with a different secret")
        for path in (backend, frontend):
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("mutual authentication OK", fh.read())

    def test_container_starts_without_peer_url(self):
        env_less = self.start("frontend", "frontend", self.frontend_port, "UNUSED_URL",
                              self.backend_port, SECRET)
        self.assertTrue(self.log_has(env_less, "BACKEND_URL not set: peer backend is not monitored"))


if __name__ == "__main__":
    unittest.main()
