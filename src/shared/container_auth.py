"""
Container-to-container authentication: a shared secret bound to the TLS certificate.

A key that travels in a header can be captured by anyone who impersonates a
peer (spoofing, MitM) or who simply gets it from a compromised container.
Here the secret NEVER leaves a container. It is only used to sign:

    request   HMAC(secret, sender, receiver, method, path, query, timestamp,
                   nonce, certificate fingerprint, sha256(body))
    response  HMAC(secret, responder, requester, method, path, nonce, status,
                   certificate fingerprint, sha256(body))

The certificate fingerprint is the SHA-256 of the DER certificate the TLS
server presents. The caller uses the one it actually observed on the
connection, the server uses its own. Consequences:
"""

import hashlib
import hmac
import http.client
import json
import logging
import os
import re
import secrets
import ssl
import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import g, jsonify, request

log = logging.getLogger(__name__)

HEADER_ID = "X-Container-Id"
HEADER_TIMESTAMP = "X-Container-Timestamp"
HEADER_NONCE = "X-Container-Nonce"
HEADER_SIGNATURE = "X-Container-Signature"
HEADER_PROOF = "X-Container-Proof"

MAX_CLOCK_SKEW_SECONDS = 30
MIN_SECRET_LENGTH = 32
_PROTOCOL_LABEL = "pontifex-container-auth-v1"
_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


class ContainerAuthError(Exception):
    """A peer failed to prove its identity (or the request was not signed)."""


class ContainerUnavailableError(Exception):
    """A peer could not be reached or answered with something unusable."""


def pair_secret_env(a: str, b: str) -> str:
    """Env variable holding the secret of a container pair, e.g. BACKEND_FRONTEND_SECRET."""
    return "_".join(sorted((a, b))).upper() + "_SECRET"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_of_der(der: bytes) -> str:
    return _sha256_hex(der)


def fingerprint_of_pem_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        match = _PEM_CERT.search(fh.read())
    if match is None:
        raise RuntimeError(f"No PEM certificate found in {path}")
    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(match.group(0)))


class ContainerAuth:
    def __init__(self, own_id: str, peers: tuple[str, ...], cert_path: str | None = None) -> None:
        if not own_id:
            raise ValueError("A container id is required.")
        self.own_id = own_id
        self.peers = tuple(peers)
        self._cert_path = cert_path
        self._seen_nonces: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()
        self._own_fingerprint: str | None = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def validate_config(self) -> None:
        """Fail fast at startup if a pair secret is missing or too short."""
        problems = []
        for peer in self.peers:
            name = pair_secret_env(self.own_id, peer)
            value = os.environ.get(name, "")
            if len(value) < MIN_SECRET_LENGTH:
                problems.append(f"{name} (at least {MIN_SECRET_LENGTH} characters)")
        if problems:
            raise RuntimeError("Missing or too short container secrets: " + ", ".join(problems))

    def _secret(self, peer: str) -> bytes:
        if peer not in self.peers:
            raise ContainerAuthError(f"unknown peer {peer!r}")
        value = os.environ.get(pair_secret_env(self.own_id, peer), "")
        if len(value) < MIN_SECRET_LENGTH:
            raise RuntimeError(f"{pair_secret_env(self.own_id, peer)} is not configured")
        return value.encode("utf-8")

    def own_fingerprint(self) -> str:
        """Fingerprint of the certificate this container's own server presents."""
        if self._own_fingerprint is None:
            path = self._cert_path or os.environ.get("TLS_CERT_PATH", "")
            if not path:
                raise RuntimeError("TLS_CERT_PATH is not set")
            self._own_fingerprint = fingerprint_of_pem_file(path)
        return self._own_fingerprint

    # ------------------------------------------------------------------
    # Signing primitives
    # ------------------------------------------------------------------

    @staticmethod
    def _mac(secret: bytes, *fields: str) -> str:
        if any("\n" in field for field in fields):
            raise ValueError("newline in signed field")
        message = "\n".join((_PROTOCOL_LABEL, *fields)).encode("utf-8")
        return hmac.new(secret, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _equal(provided: str, expected: str) -> bool:
        return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

    def sign_request(self, peer: str, method: str, path: str, body: bytes,
                     fingerprint: str, *, timestamp: int | None = None,
                     nonce: str | None = None) -> dict[str, str]:
        """Headers for a request to ``peer``; ``fingerprint`` is the one observed on the connection."""
        ts = str(int(time.time()) if timestamp is None else timestamp)
        nonce = nonce or secrets.token_hex(16)
        signature = self._mac(
            self._secret(peer), "request", self.own_id, peer, method.upper(), path, "",
            ts, nonce, fingerprint, _sha256_hex(body),
        )
        return {
            HEADER_ID: self.own_id,
            HEADER_TIMESTAMP: ts,
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: signature,
        }

    def verify_response(self, peer: str, method: str, path: str, nonce: str,
                        status: int, body: bytes, fingerprint: str, proof: str | None) -> None:
        """Raise ContainerAuthError unless ``peer`` proved it holds the secret on this very connection."""
        if not proof:
            raise ContainerAuthError("response carries no proof")
        expected = self._mac(
            self._secret(peer), "response", peer, self.own_id, method.upper(), path,
            nonce, str(status), fingerprint, _sha256_hex(body),
        )
        if not self._equal(proof, expected):
            raise ContainerAuthError("response proof does not match (wrong peer or wrong certificate)")

    # ------------------------------------------------------------------
    # Server side
    # ------------------------------------------------------------------

    def _remember_nonce(self, sender: str, nonce: str, now: float) -> None:
        with self._lock:
            self._seen_nonces = {k: exp for k, exp in self._seen_nonces.items() if exp > now}
            if (sender, nonce) in self._seen_nonces:
                raise ContainerAuthError("replayed request")
            self._seen_nonces[(sender, nonce)] = now + 2 * MAX_CLOCK_SKEW_SECONDS

    def _verify_request(self, allowed: tuple[str, ...]) -> tuple[str, str]:
        sender = request.headers.get(HEADER_ID, "")
        timestamp = request.headers.get(HEADER_TIMESTAMP, "")
        nonce = request.headers.get(HEADER_NONCE, "")
        signature = request.headers.get(HEADER_SIGNATURE, "")

        if not (sender and timestamp and nonce and signature):
            raise ContainerAuthError("container headers missing")
        if sender not in allowed or sender not in self.peers:
            raise ContainerAuthError(f"sender {sender!r} not allowed here")
        try:
            sent_at = int(timestamp)
        except ValueError as exc:
            raise ContainerAuthError("malformed timestamp") from exc

        now = time.time()
        if abs(now - sent_at) > MAX_CLOCK_SKEW_SECONDS:
            raise ContainerAuthError("timestamp outside the allowed window")

        try:
            expected = self._mac(
                self._secret(sender), "request", sender, self.own_id, request.method,
                request.path, request.query_string.decode("latin-1"), timestamp, nonce,
                self.own_fingerprint(), _sha256_hex(request.get_data()),
            )
        except ValueError as exc:
            raise ContainerAuthError("malformed request") from exc
        if not self._equal(signature, expected):
            raise ContainerAuthError("signature mismatch")

        # Only a correctly signed nonce is stored, so outsiders cannot fill the cache.
        self._remember_nonce(sender, nonce, now)
        return sender, nonce

    def require(self, *allowed: str):
        """Only the named peers, proving the pair secret on this connection, may call the route."""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if g.get("container_peer") not in allowed:
                    log.warning("Container authentication rejected: no valid proof from %s", allowed)
                    return jsonify({"error": "Unauthorized."}), 401
                return f(*args, **kwargs)
            return decorated
        return decorator

    def init_app(self, app) -> None:
        """
        Verify signed requests and sign their responses.

        Every request that carries container headers is verified here, on any
        route. A valid one is answered with a proof, so a peer that forwards a
        user token (``require_role`` routes) can still verify the backend.
        Requests without container headers pass untouched: the public API
        needs no container secret. Wrongly signed requests are rejected.
        """
        @app.before_request
        def verify_signed_request():
            if not any(h in request.headers for h in (HEADER_ID, HEADER_SIGNATURE)):
                return None
            try:
                g.container_peer, g.container_nonce = self._verify_request(self.peers)
            except ContainerAuthError as exc:
                log.warning("Container authentication rejected: %s", exc)
                return jsonify({"error": "Unauthorized."}), 401
            except (RuntimeError, OSError) as exc:
                log.error("Container authentication unavailable: %s", exc)
                return jsonify({"error": "Container authentication not configured."}), 503
            return None

        @app.after_request
        def add_proof(response):
            nonce = g.get("container_nonce")
            peer = g.get("container_peer")
            if nonce is None or peer is None:
                return response
            response.headers[HEADER_PROOF] = self._mac(
                self._secret(peer), "response", self.own_id, peer, request.method, request.path,
                nonce, str(response.status_code), self.own_fingerprint(),
                _sha256_hex(response.get_data()),
            )
            return response

    # ------------------------------------------------------------------
    # Client side
    # ------------------------------------------------------------------

    def client(self, peer: str, base_url: str) -> "ContainerClient":
        return ContainerClient(self, peer, base_url)


class ContainerClient:
    TIMEOUT_SECONDS = 5

    def __init__(self, auth: ContainerAuth, peer: str, base_url: str) -> None:
        url = urlparse(base_url)
        if url.scheme != "https" or not url.hostname:
            raise ValueError("base_url must be an https:// URL")
        auth._secret(peer)  # unknown peer or missing secret fails here, not on first use
        self._auth = auth
        self._peer = peer
        self._host = url.hostname
        self._port = url.port or 443

    def request(self, method: str, path: str, body: dict | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict]:
        """
        One authenticated round trip. ``path`` must be plain ASCII without a query string.

        ``headers`` carries extra request headers, e.g. ``Authorization: Bearer <token>``
        for routes that need a user token. They never replace the container headers.

        Raises ContainerAuthError if the peer cannot prove it holds the secret,
        ContainerUnavailableError if it cannot be reached.
        """
        # The peers use self-signed certificates created at first start, so the
        # certificate chain cannot be validated. Trust is established by the
        # secret instead: the signature and the response proof are both bound to
        # the fingerprint of the certificate seen here, which makes an
        # impersonating or intercepting server fail verification.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        payload = b"" if body is None else json.dumps(body).encode("utf-8")
        connection = http.client.HTTPSConnection(
            self._host, self._port, timeout=self.TIMEOUT_SECONDS, context=context
        )
        try:
            connection.connect()
            der = connection.sock.getpeercert(binary_form=True)
            if not der:
                raise ContainerAuthError("peer presented no certificate")
            fingerprint = fingerprint_of_der(der)

            signed = self._auth.sign_request(self._peer, method, path, payload, fingerprint)
            send = {**(headers or {}), **signed}
            if payload:
                send["Content-Type"] = "application/json"
            connection.request(method, path, body=payload or None, headers=send)
            response = connection.getresponse()
            raw = response.read()
            status, proof = response.status, response.getheader(HEADER_PROOF)
        except (OSError, http.client.HTTPException) as exc:
            raise ContainerUnavailableError(f"{self._peer} unreachable") from exc
        finally:
            connection.close()

        self._auth.verify_response(
            self._peer, method, path, signed[HEADER_NONCE], status, raw, fingerprint, proof
        )
        try:
            data = json.loads(raw or b"{}")
        except ValueError as exc:
            raise ContainerUnavailableError(f"{self._peer} sent malformed JSON") from exc
        if not isinstance(data, dict):
            raise ContainerUnavailableError(f"{self._peer} sent an unexpected payload")
        return status, data


class PeerMonitor:
    """
    Keeps the container-to-container authentication active in one direction.

    It pings a peer's authenticated route at a fixed interval. One successful
    ping proves both sides: the peer accepted our signature, and we accepted
    its proof. State changes are logged, so a wrong secret, a swapped
    certificate or a missing peer shows up in the logs of both containers.

    States: unknown, authenticated, auth_failed, unreachable, error-<status>
    """

    def __init__(self, client: ContainerClient, peer: str, path: str, interval: float) -> None:
        self.peer = peer
        self.state = "unknown"
        self._client = client
        self._path = path
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"peer-monitor-{peer}", daemon=True)

    def check(self) -> str:
        detail = ""
        try:
            status, _ = self._client.request("GET", self._path)
            state = "authenticated" if status == 200 else f"error-{status}"
        except ContainerAuthError as exc:
            state, detail = "auth_failed", f" ({exc})"
        except ContainerUnavailableError:
            state = "unreachable"

        if state != self.state:
            if state == "authenticated":
                log.info("Peer %s: mutual authentication OK", self.peer)
            else:
                log.warning("Peer %s: %s%s", self.peer, state, detail)
            self.state = state
        return state

    def _run(self) -> None:
        while not self._stop.is_set():
            self.check()
            self._stop.wait(self._interval)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


def start_peer_monitors(auth: ContainerAuth, targets: dict[str, tuple[str, str]]) -> list[PeerMonitor]:
    """
    Start one monitor per peer whose URL is configured.

    ``targets`` maps a peer to (env variable holding its https URL, route to ping).
    A peer without a configured URL is skipped, an invalid URL stops the container.
    Interval: PEER_CHECK_INTERVAL_SECONDS (default 30).
    """
    interval = float(os.environ.get("PEER_CHECK_INTERVAL_SECONDS", "30"))
    if interval <= 0:
        raise RuntimeError("PEER_CHECK_INTERVAL_SECONDS must be greater than 0")

    monitors = []
    for peer, (url_env, path) in targets.items():
        url = os.environ.get(url_env, "")
        if not url:
            log.info("%s not set: peer %s is not monitored", url_env, peer)
            continue
        monitor = PeerMonitor(auth.client(peer, url), peer, path, interval)
        monitor.start()
        monitors.append(monitor)
    return monitors
