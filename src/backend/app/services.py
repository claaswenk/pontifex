import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import time

import psutil

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

def wake_on_lan(mac_address, ip_address, port):

    NON_HEX_CHARS = re.compile(r"[^a-f0-9]", re.IGNORECASE)
    MAC_PATTERN = re.compile(r"^[a-f0-9]{12}$", re.IGNORECASE)

    def _clean_mac_address(mac_address_supplied):

        mac_address_cleaned = NON_HEX_CHARS.sub("", mac_address_supplied)
        if MAC_PATTERN.fullmatch(mac_address_cleaned):
            return mac_address_cleaned
        else:
            raise ValueError(f"[Error] Invalid MAC address: {mac_address_supplied}")

    def _evaluate_ip_address(ip_address):

        ip = ip_address.strip()

        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            try:
                ip = str(ipaddress.IPv4Network(ip, strict=False).broadcast_address)
            except Exception as e:
                raise ValueError(f"[Error] Invalid IP address: {ip_address}") from e
        return ip

    def _generate_magic_packet(mac_address):

        return bytes.fromhex("FF" * 6 + mac_address * 16)

    def _send_udp_broadcast(payload, ip_address, port):

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(payload, (ip_address, port))

    def _validate_port_number(port_number):

        if not isinstance(port_number, int):
            raise TypeError(f"[Error] Port number must be of type Integer.")
        elif 0 <= port_number <= 65535:
            return port_number
        else:
            raise ValueError(f"[Error] Invalid port number: {port_number}")

    def wake(mac_address, *, ip_address="255.255.255.255", port=9, return_dest=False):

        try:
            mac_cleaned = _clean_mac_address(mac_address)
            valid_ip_address = _evaluate_ip_address(ip_address)
            valid_port = _validate_port_number(port)
        except (ValueError, TypeError):
            return {"success": False, "error": "Invalid wake-on-LAN request parameters."}

        payload = _generate_magic_packet(mac_cleaned)

        try:
            _send_udp_broadcast(payload, valid_ip_address, valid_port)
        except OSError:
            return {"success": False, "error": "Failed to send wake-on-LAN packet."}

        if return_dest is True:
            return {"success": True, "ip": valid_ip_address, "port": str(valid_port)}
        return {"success": True}

    return wake(mac_address, ip_address=ip_address, port=port, return_dest=True)


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
            "name": device.get("name", ""),
            "address": device.get("address", ""),
            "status": "online" if answered else "offline",
            "latency_ms": min(answered) if answered else None,
        })
    return results
