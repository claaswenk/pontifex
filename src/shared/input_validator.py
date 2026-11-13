"""
Input validation shared by all containers.

Everything that comes from outside (a JSON body, a form field, a URL segment,
a cookie, the answer of another container) goes through ``InputValidator``
first. Only the returned value is used afterwards, never the raw input.

How it protects:

* Allow-lists, not block-lists. A value is accepted only if it has the type,
  the length and the characters the field is meant to have. Anything else is
  refused with the rule of the field, so the answer never depends on what the
  attacker sent.
* Length is checked before any pattern is applied, and the patterns have no
  nested quantifiers, so a long input cannot make a pattern run for long.
* Strings are text only: no NUL, no control or format characters (line breaks,
  zero-width and bidi characters) where the field is a name, and nothing that
  cannot be encoded as UTF-8 (lone surrogates break hashing and JSON output).
* SQL is never built from input. The database service uses ``?`` parameters
  only (tests/test_input_validator.py scans for anything else), so validation
  here is the second layer, not the only one.
* Values that look like an attack (SQL fragments, path traversal, markup,
  template or shell syntax, line breaks) are logged as a warning with the
  field name and the kind. The value itself is never logged, and passwords are
  never inspected: they may contain any character.
"""

import ipaddress
import logging
import re
import unicodedata

log = logging.getLogger(__name__)

_USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_MAC_DIGITS = re.compile(r"[0-9a-f]{12}")
_MAC_SEPARATORS = re.compile(r"[:\-.]")

# Kinds of attack the log reports. Detection only: the allow-lists above decide.
_SIGNATURES = (
    ("sql", re.compile(
        r"\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|delete|insert|update|alter|select)\b"
        r"|['\"]\s*(?:or|and)\s+['\"\d]|--\s|/\*", re.IGNORECASE)),
    ("path traversal", re.compile(r"\.\.[/\\]|%2e%2e|%2f|%5c", re.IGNORECASE)),
    ("markup", re.compile(r"<[a-z/!]|javascript:", re.IGNORECASE)),
    ("template", re.compile(r"\{\{|\{%|\$\{|#\{")),
    ("shell", re.compile(r"\$\(|`|\|\||&&")),
    ("control characters", re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")),
)


class InvalidInput(ValueError):
    """An input was refused. ``message`` describes the rule and is safe to show."""

    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field
        self.message = message


class InputValidator:
    MIN_PASSWORD_LENGTH = 12
    MAX_PASSWORD_LENGTH = 1024
    MAX_NAME_LENGTH = 64
    MAX_ADDRESS_LENGTH = 253
    MAX_TOKEN_LENGTH = 128
    MAX_ID = 2**63 - 1          # what the database can hold
    ROLES = ("admin", "user")

    USERNAME_RULE = "Username must be 3-64 characters: lower case letters, digits, '.', '_' or '-'."
    PASSWORD_RULE = f"Password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters."
    NAME_RULE = f"Name must be 1-{MAX_NAME_LENGTH} characters without control characters."
    ADDRESS_RULE = "Address must be a host name or an IPv4/IPv6 address that is not loopback, link-local or multicast."
    MAC_RULE = "MAC must be six hex pairs such as AA:BB:CC:DD:EE:FF and must be a unicast address."
    INVALID_VALUE_MESSAGE = "Invalid token."
    BODY_RULE = "A JSON object is required."

    # ------------------------------------------------------------------
    # Building blocks
    # ------------------------------------------------------------------

    @staticmethod
    def _report(field: str, value: str) -> None:
        sample = value[:256]
        kinds = [kind for kind, pattern in _SIGNATURES if pattern.search(sample)]
        if kinds:
            log.warning("Input in field %r looks like an attack: %s", field, ", ".join(kinds))

    @classmethod
    def _reject(cls, field: str, message: str, value=None, scan: bool = True):
        if scan and isinstance(value, str):
            cls._report(field, value)
        raise InvalidInput(field, message)

    @classmethod
    def _string(cls, value, field: str, message: str, max_len: int, scan: bool = True) -> str:
        """A ``str`` of at most ``max_len`` characters without NUL that encodes as UTF-8."""
        if not isinstance(value, str):
            cls._reject(field, message)
        if len(value) > max_len or "\x00" in value:
            cls._reject(field, message, value, scan)
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            cls._reject(field, message)
        return value

    @classmethod
    def text(cls, value, field: str, max_len: int) -> str:
        """Plain bounded text, for fields whose content is judged elsewhere (passwords, keys)."""
        return cls._string(value, field, f"Field '{field}' is invalid.", max_len, scan=False)

    # ------------------------------------------------------------------
    # Structure
    # ------------------------------------------------------------------

    @classmethod
    def json_object(cls, data) -> dict:
        """The parsed JSON body as a dict. No body is an empty dict; anything but an object is refused."""
        if data is None:
            return {}
        if not isinstance(data, dict):
            cls._reject("body", cls.BODY_RULE)
        return data

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    @classmethod
    def username(cls, value, field: str = "username") -> str:
        """Canonical form (trimmed, lower case) of a valid username."""
        name = cls._string(value, field, cls.USERNAME_RULE, 256).strip()
        # ASCII first: lower() maps some other characters (e.g. the Kelvin sign) to ASCII letters.
        if not name.isascii() or not _USERNAME.fullmatch(name.lower()):
            cls._reject(field, cls.USERNAME_RULE, name)
        return name.lower()

    @classmethod
    def path_username(cls, value, field: str = "username") -> str:
        """A username from a URL: it must already be in canonical form."""
        name = cls.username(value, field)
        if name != value:
            cls._reject(field, cls.USERNAME_RULE, value)
        return name

    @classmethod
    def new_password(cls, value, field: str = "password") -> str:
        password = cls._string(value, field, cls.PASSWORD_RULE, cls.MAX_PASSWORD_LENGTH, scan=False)
        if len(password) < cls.MIN_PASSWORD_LENGTH:
            cls._reject(field, cls.PASSWORD_RULE, scan=False)
        return password

    @classmethod
    def current_password(cls, value, field: str = "current_password") -> str:
        """An existing password: only bounded, its strength was judged when it was set."""
        password = cls._string(value, field, "Password is wrong.", cls.MAX_PASSWORD_LENGTH, scan=False)
        if not password:
            cls._reject(field, "Password is wrong.", scan=False)
        return password

    @classmethod
    def token(cls, value, field: str = "token") -> str:
        """Refresh token, reset token or session id: URL-safe characters (and '.') only."""
        token = cls._string(value, field, cls.INVALID_VALUE_MESSAGE, cls.MAX_TOKEN_LENGTH)
        if not _TOKEN.fullmatch(token):
            cls._reject(field, cls.INVALID_VALUE_MESSAGE, token)
        return token

    @classmethod
    def role(cls, value, field: str = "role") -> str:
        if not isinstance(value, str) or value not in cls.ROLES:
            cls._reject(field, "Unknown role.")
        return value

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    @classmethod
    def device_id(cls, value, field: str = "id") -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= cls.MAX_ID:
            cls._reject(field, "Device not found.")
        return value

    @classmethod
    def device_name(cls, value, field: str = "name") -> str:
        """The trimmed name. Free text, so the character classes are what is refused, not words."""
        name = cls._string(value, field, cls.NAME_RULE, 256).strip()
        if not name or len(name) > cls.MAX_NAME_LENGTH or any(
            unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") for c in name
        ):
            cls._reject(field, cls.NAME_RULE, name)
        cls._report(field, name)  # accepted, but worth a log line (the pages escape it on output)
        return name

    @classmethod
    def address(cls, value, field: str = "address") -> str:
        """Host name (lower case) or IP literal. Pure syntax: nothing is resolved or contacted."""
        address = cls._string(value, field, cls.ADDRESS_RULE, 512).strip()
        if not address or len(address) > cls.MAX_ADDRESS_LENGTH:
            cls._reject(field, cls.ADDRESS_RULE, address)
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            host = address.lower()
            if not address.isascii() or not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
                cls._reject(field, cls.ADDRESS_RULE, address)
            return host
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            cls._reject(field, cls.ADDRESS_RULE, address)
        return str(ip)

    @classmethod
    def mac(cls, value, field: str = "mac") -> str:
        """``aa:bb:cc:dd:ee:ff`` for any common spelling of a unicast MAC address."""
        text = cls._string(value, field, cls.MAC_RULE, 32)
        digits = _MAC_SEPARATORS.sub("", text.strip()).lower()
        if not _MAC_DIGITS.fullmatch(digits):
            cls._reject(field, cls.MAC_RULE, text)
        if int(digits[1], 16) & 1 or digits == "0" * 12:  # group bit set (includes ff:ff:...)
            cls._reject(field, cls.MAC_RULE, text)
        return ":".join(digits[i:i + 2] for i in range(0, 12, 2))
