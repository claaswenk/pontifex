import ipaddress
import re
import socket

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
        except (ValueError, TypeError) as e:
            return {"success": False, "error": str(e)}

        payload = _generate_magic_packet(mac_cleaned)

        try:
            _send_udp_broadcast(payload, valid_ip_address, valid_port)
        except OSError as e:
            return {"success": False, "error": f"Cannot send broadcast to IP address: {valid_ip_address}"}

        if return_dest is True:
            return {"success": True, "ip": valid_ip_address, "port": str(valid_port)}
        return {"success": True}

    return wake(mac_address, ip_address=ip_address, port=port, return_dest=True)
