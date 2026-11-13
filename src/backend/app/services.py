import concurrent.futures
import ipaddress
import logging
import math
import os
import re
import signal
import socket
import stat
import threading
import time

import psutil

from shared.input_validator import InputValidator, InvalidInput

logger = logging.getLogger(__name__)

# Worst case (every device offline): devices * ports * timeout / workers seconds
CONNECT_TIMEOUT_SECONDS = 1.0
MAX_PARALLEL_CHECKS = 32
MAX_DEVICES_PER_REQUEST = 100
# A device counts as online if one of these ports answers (see check_devices)
ALIVE_CHECK_PORTS = (22, 80, 443, 445, 3389)

_START_TIME = time.time()

def process_pontifex_logic():
    return True

# ---------------------------------------------------------------------------
# Wake-on-LAN
#
# The backend never sends the magic packet itself: it runs in the container
# network, where a UDP broadcast does not reach the LAN. A small relay with
# host networking does the sending. The backend only asks it, over a Unix
# socket, to wake one MAC address. It cannot choose the destination or the
# port: those are the relay's own configuration.
#
# Protocol, one request per connection:
#     request   b"WAKE aa:bb:cc:dd:ee:ff\n"
#     reply     b"OK\n"  or  b"ERR\n"
# ---------------------------------------------------------------------------

WAKE_SOCKET_ENV = "WAKE_SOCKET_PATH"
DEFAULT_WAKE_SOCKET = "/run/pontifex/wake.sock"
WAKE_TIMEOUT_SECONDS = 2


class WakeUnavailableError(Exception):
    """The wake relay is unreachable or refused the request. The backend answers 503."""


def magic_packet(mac):
    """6 x 0xFF followed by the MAC repeated 16 times. ``mac`` must be normalized."""
    return b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16


def request_wake(mac):
    """Ask the wake relay to send a magic packet for ``mac`` (already normalized)."""
    path = os.environ.get(WAKE_SOCKET_ENV, DEFAULT_WAKE_SOCKET)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(WAKE_TIMEOUT_SECONDS)
            sock.connect(path)
            sock.sendall(f"WAKE {mac}\n".encode("ascii"))
            reply = sock.recv(16)
    except (OSError, AttributeError) as exc:  # AttributeError: no AF_UNIX on this platform
        raise WakeUnavailableError("wake relay unreachable") from exc
    if reply.strip() != b"OK":
        raise WakeUnavailableError("wake relay refused the request")


# --- The relay itself (runs in its own container with host networking) -------
#
#   python -c "from app.services import run_wake_relay; run_wake_relay()"
#
# It listens on the Unix socket only, accepts nothing but "WAKE <mac>", and
# sends the packet to WOL_BROADCAST:WOL_PORT from its own environment.

WOL_BROADCAST_ENV = "WOL_BROADCAST"
WOL_PORT_ENV = "WOL_PORT"
DEFAULT_WOL_BROADCAST = "255.255.255.255"
DEFAULT_WOL_PORT = 9
WAKE_REPEAT = 3
MAX_RELAY_CONNECTIONS = 8
_WAKE_REQUEST = re.compile(rb"WAKE ([0-9a-f]{2}(?::[0-9a-f]{2}){5})\n")


def _relay_config():
    """(socket path, broadcast address, port) from the environment, or RuntimeError."""
    path = os.environ.get(WAKE_SOCKET_ENV, DEFAULT_WAKE_SOCKET)
    try:
        broadcast = ipaddress.IPv4Address(os.environ.get(WOL_BROADCAST_ENV, DEFAULT_WOL_BROADCAST))
        port = int(os.environ.get(WOL_PORT_ENV, DEFAULT_WOL_PORT))
    except ValueError as exc:
        raise RuntimeError(f"{WOL_BROADCAST_ENV} must be an IPv4 address and {WOL_PORT_ENV} a number") from exc
    if broadcast.is_loopback or broadcast.is_multicast or broadcast.is_unspecified or broadcast.is_link_local:
        raise RuntimeError(f"{WOL_BROADCAST_ENV} must be the broadcast address of your LAN, e.g. 192.168.1.255")
    if not 1 <= port <= 65535:
        raise RuntimeError(f"{WOL_PORT_ENV} must be between 1 and 65535")
    return path, str(broadcast), port


def send_magic_packet(mac, broadcast, port):
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(WAKE_REPEAT):
            sock.sendto(packet, (broadcast, port))


def handle_wake_request(raw, send):
    """The reply for one raw request. ``send(mac)`` is only called for a valid one."""
    match = _WAKE_REQUEST.fullmatch(raw)
    mac = normalize_mac(match.group(1).decode("ascii")) if match else None
    if mac is None:
        return b"ERR\n"
    try:
        send(mac)
    except OSError:
        logger.error("Sending the magic packet failed")
        return b"ERR\n"
    return b"OK\n"


def serve_wake_relay(listener, send):
    """
    Answer requests until the listening socket is closed.

    Each connection gets its own thread, so a client that connects and stays
    silent only occupies one of MAX_RELAY_CONNECTIONS slots for at most
    WAKE_TIMEOUT_SECONDS. Connections beyond the limit are dropped at once.
    """
    slots = threading.BoundedSemaphore(MAX_RELAY_CONNECTIONS)

    def handle(conn):
        try:
            with conn:
                conn.settimeout(WAKE_TIMEOUT_SECONDS)
                try:
                    raw = conn.recv(64)
                    conn.sendall(handle_wake_request(raw, send))
                except OSError:
                    pass  # the client went away or was too slow
        finally:
            slots.release()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        if not slots.acquire(blocking=False):
            conn.close()
            continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def run_wake_relay():
    path, broadcast, port = _relay_config()

    if os.path.exists(path):
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            raise RuntimeError(f"{path} exists and is not a socket")
        os.unlink(path)  # left over from an earlier run

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous_umask = os.umask(0o077)  # only the relay's user may connect
    try:
        listener.bind(path)
    finally:
        os.umask(previous_umask)
    listener.listen(8)

    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)  # as PID 1 a container would otherwise ignore it

    logger.warning("Wake relay ready: %s -> %s:%d", path, broadcast, port)
    try:
        serve_wake_relay(listener, lambda mac: send_magic_packet(mac, broadcast, port))
    finally:
        listener.close()
        if os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

def system_stats():
    """
    Resource usage of the machine that hosts the backend container.

    CPU, memory, load and host uptime come from /proc, which a container shares
    with its host, so they describe the host (on Windows/macOS: the Podman VM).
    The disk figures describe the filesystem mounted at MONITOR_DISK_PATH
    (default "/") inside the container.
    """
    memory = psutil.virtual_memory()

    disk_path = os.environ.get("MONITOR_DISK_PATH", "/")
    try:
        disk = psutil.disk_usage(disk_path)
        disk_info = {
            "path": disk_path,
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "percent": disk.percent,
        }
    except OSError:
        logger.warning("Disk usage not available for %s", disk_path)
        disk_info = None

    try:
        load_1, load_5, load_15 = os.getloadavg()
        load = {"1m": round(load_1, 2), "5m": round(load_5, 2), "15m": round(load_15, 2)}
    except (AttributeError, OSError):  # not available on Windows
        load = None

    return {
        # interval makes the first call meaningful (0.0 otherwise)
        "cpu": {
            "percent": psutil.cpu_percent(interval=0.2),
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
        },
        "memory": {
            "total_bytes": memory.total,
            "used_bytes": memory.used,
            "available_bytes": memory.available,
            "percent": memory.percent,
        },
        "disk": disk_info,
        "load_average": load,
        "host_uptime_seconds": int(time.time() - psutil.boot_time()),
        "service_uptime_seconds": int(time.time() - _START_TIME),
    }


_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)


def _resolve_safe_ip(address):
    """
    The IP to probe, or None if the address is invalid or not allowed.

    Loopback, link-local (incl. cloud metadata 169.254.169.254), multicast,
    unspecified and reserved targets are refused, so the endpoint cannot be
    used to probe the backend's own host or internal services. Private LAN
    ranges stay allowed: they are what is being monitored. Names are resolved
    once here and the probe connects to that IP, so the checked address and
    the connected address cannot differ.
    """
    address = (address or "").strip()
    if not address or len(address) > 253:
        return None

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        if not _HOSTNAME.fullmatch(address):
            return None
        try:
            infos = socket.getaddrinfo(address, None, type=socket.SOCK_STREAM)
            ip = ipaddress.ip_address(infos[0][4][0])
        except (OSError, ValueError, IndexError):
            return None

    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return None
    return str(ip)


def _probe(address, port):
    """Latency in ms if the device answers on ``port``, else None."""
    ip = _resolve_safe_ip(address)
    if ip is None:
        return None

    started = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            pass
    except ConnectionRefusedError:
        pass  # an RST also proves that the host is up
    except OSError:  # timeout, no route, ...
        return None
    return round((time.perf_counter() - started) * 1000, 1)


def check_devices(devices):
    """
    Online/offline state for ``[{"name": ..., "address": ...}, ...]``.

    ICMP ping needs raw sockets, which the unprivileged container does not
    have. A device counts as online if any of ALIVE_CHECK_PORTS accepts or
    refuses a TCP connection (silence = offline). All (device, port) probes
    run in parallel, so one dead device does not delay the rest. Input order
    is kept and at most MAX_DEVICES_PER_REQUEST are checked.
    """
    devices = list(devices)[:MAX_DEVICES_PER_REQUEST]
    if not devices:
        return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_CHECKS) as pool:
        futures = [
            [pool.submit(_probe, device.get("address", ""), port) for port in ALIVE_CHECK_PORTS]
            for device in devices
        ]
        latencies = [[f.result() for f in per_device] for per_device in futures]

    results = []
    for device, per_port in zip(devices, latencies):
        answered = [ms for ms in per_port if ms is not None]
        results.append({
            "id": device.get("id"),
            "name": device.get("name", ""),
            "address": device.get("address", ""),
            "status": "online" if answered else "offline",
            "latency_ms": min(answered) if answered else None,
        })
    return results


# ---------------------------------------------------------------------------
# Login throttle
#
# Failed logins are counted per (account, client address) and per client
# address. Once a limit is reached, further attempts are refused until the
# oldest counted failure leaves the window, whatever password is sent. A
# successful login clears the counter of that account only.
#
# The counters live in memory. A restart of the backend resets them, which is
# an accepted trade-off for a single-instance deployment.
# ---------------------------------------------------------------------------

class LoginThrottled(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("too many failed logins")
        self.retry_after = retry_after


class LoginThrottle:
    WINDOW_SECONDS = 900
    MAX_PER_ACCOUNT = 5
    MAX_PER_ADDRESS = 30
    MAX_KEYS = 10_000

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[tuple, list[float]] = {}

    @staticmethod
    def _keys(username: str, address: str) -> tuple[tuple, tuple]:
        return ("account", username.casefold(), address), ("address", address)

    def _recent(self, key: tuple, now: float) -> list[float]:
        stamps = [t for t in self._failures.get(key, ()) if now - t < self.WINDOW_SECONDS]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def _retry_after(self, stamps: list[float], now: float) -> int:
        return max(1, math.ceil(stamps[0] + self.WINDOW_SECONDS - now))

    def check(self, username: str, address: str) -> None:
        """Raise LoginThrottled if this attempt must not even be evaluated."""
        account_key, address_key = self._keys(username, address)
        with self._lock:
            now = self._clock()
            for key, limit in ((account_key, self.MAX_PER_ACCOUNT), (address_key, self.MAX_PER_ADDRESS)):
                stamps = self._recent(key, now)
                if len(stamps) >= limit:
                    raise LoginThrottled(self._retry_after(stamps, now))

    def failure(self, username: str, address: str) -> None:
        with self._lock:
            now = self._clock()
            for key in self._keys(username, address):
                if key not in self._failures and len(self._failures) >= self.MAX_KEYS:
                    self._make_room(now)
                self._failures.setdefault(key, []).append(now)

    def success(self, username: str, address: str) -> None:
        with self._lock:
            self._failures.pop(self._keys(username, address)[0], None)

    def _make_room(self, now: float) -> None:
        for key in list(self._failures):
            self._recent(key, now)
        if len(self._failures) >= self.MAX_KEYS:
            stalest = min(self._failures, key=lambda k: self._failures[k][-1])
            del self._failures[stalest]


# ---------------------------------------------------------------------------
# Input rules for devices
#
# The rules live in shared.input_validator. These helpers keep the old
# "value or None" shape for code that does not want an exception. Pure syntax
# checks: no name is resolved and nothing is contacted. Resolving and the
# refusal of loopback and similar targets happen when a device is probed
# (_resolve_safe_ip).
# ---------------------------------------------------------------------------

MAX_DEVICES_PER_USER = 100


def _or_none(check, value):
    try:
        return check(value)
    except InvalidInput:
        return None


def valid_name(value) -> str | None:
    """The trimmed name, or None if it is not acceptable."""
    return _or_none(InputValidator.device_name, value)


def valid_address(value) -> str | None:
    """The trimmed host name or IP literal, or None if it is not acceptable."""
    return _or_none(InputValidator.address, value)


def normalize_mac(value) -> str | None:
    """``aa:bb:cc:dd:ee:ff`` for any common spelling, or None."""
    return _or_none(InputValidator.mac, value)
