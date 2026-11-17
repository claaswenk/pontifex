"""In-memory stand-in with the same interface as DatabaseClient.

The real store lives in the database container; the backend only ever talks to
it through DatabaseClient, so this fake is all the backend tests need.
"""

import base64
import itertools
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.errors import BootstrapConsumedError  # noqa: E402
from shared.input_validator import InputValidator as V, InvalidInput  # noqa: E402
from app.database_client import DatabaseUnavailableError  # noqa: E402


class FakeDatabase:
    def __init__(self):
        self.accounts = {}   # username -> {"role": str, "pw_hash": str, "must_change": bool}
        self.tokens = {}     # refresh token -> username
        self.owned = {}      # username -> [{"id", "name", "address", "mac", "picture"}]
        self.pictures = {}   # ("device", id) or ("user", name) -> {"media_type", "image", "version"}
        self.resets = {}     # reset token hash -> (username, expires_at)
        self.consumed = False
        self.down = False
        self._counter = itertools.count(1)

    def validate_config(self):
        pass

    def _check(self):
        if self.down:
            raise DatabaseUnavailableError("down")

    def _new_token(self, username):
        token = f"rt-{username}-{next(self._counter)}"
        self.tokens[token] = username
        return token

    def _drop_resets(self, username):
        self.resets = {h: v for h, v in self.resets.items() if v[0] != username}

    def _forget(self, username):
        self.accounts.pop(username, None)
        for device in self.owned.pop(username, []):
            self.pictures.pop(("device", device["id"]), None)
        self.pictures.pop(("user", username), None)
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}
        self._drop_resets(username)

    # -- accounts ----------------------------------------------------------

    def create_bootstrap_admin(self, username, pw_hash):
        self._check()
        if self.consumed:
            raise BootstrapConsumedError()
        if username in self.accounts:
            raise ValueError("taken")
        self.consumed = True
        self.accounts[username] = {"role": "admin", "pw_hash": pw_hash, "must_change": False}
        return self._new_token(username)

    def create_user(self, username, pw_hash, role, must_change=False):
        self._check()
        if username in self.accounts:
            raise ValueError("taken")
        self.accounts[username] = {"role": role, "pw_hash": pw_hash, "must_change": must_change}

    def bootstrap_consumed(self):
        self._check()
        return self.consumed

    def exists(self, username):
        self._check()
        return username in self.accounts

    def get_credentials(self, username):
        self._check()
        account = self.accounts.get(username)
        if account is None:
            return None
        return {"username": username, "pw_hash": account["pw_hash"], "role": account["role"],
                "must_change": account["must_change"]}

    def list_users(self):
        self._check()
        return [{"username": name, "role": a["role"]} for name, a in self.accounts.items()]

    def settle(self, *usernames):
        """Test helper: these accounts chose their own password (the admin-set one is replaced)."""
        for username in usernames:
            self.accounts[username]["must_change"] = False

    def set_password(self, username, pw_hash, must_change=False):
        self._check()
        if username not in self.accounts:
            return False
        self.accounts[username]["pw_hash"] = pw_hash
        self.accounts[username]["must_change"] = must_change
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}
        self._drop_resets(username)
        return True

    def create_reset_token(self, username, token_hash, expires_at):
        self._check()
        if username not in self.accounts:
            return False
        self._drop_resets(username)
        self.resets[token_hash] = (username, expires_at)
        return True

    def reset_password_with_token(self, token_hash, pw_hash):
        self._check()
        entry = self.resets.pop(token_hash, None)
        if entry is None:
            return False
        username, expires_at = entry
        if expires_at <= time.time() or username not in self.accounts:
            return False
        self.set_password(username, pw_hash)
        return True

    def rename_user(self, username, new_username):
        self._check()
        if username not in self.accounts:
            return False
        if new_username in self.accounts:
            raise ValueError("taken")
        self.accounts[new_username] = self.accounts.pop(username)
        if username in self.owned:
            self.owned[new_username] = self.owned.pop(username)
        if ("user", username) in self.pictures:
            self.pictures[("user", new_username)] = self.pictures.pop(("user", username))
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}
        self._drop_resets(username)
        return True

    def delete_user(self, username):
        self._check()
        if username not in self.accounts:
            return False
        self._forget(username)
        return True

    # -- refresh tokens ----------------------------------------------------

    def get_by_refresh_token(self, refresh_token):
        self._check()
        username = self.tokens.get(refresh_token)
        if username is None:
            return None
        return username, self.accounts[username]["role"]

    def create_refresh_token(self, username):
        self._check()
        if username not in self.accounts:
            raise ValueError("unknown user")
        return self._new_token(username)

    def revoke_refresh_token(self, refresh_token):
        self._check()
        self.tokens.pop(refresh_token, None)

    # -- devices -----------------------------------------------------------

    def list_devices(self, username):
        self._check()
        return [dict(d) for d in self.owned.get(username, [])]

    def get_device(self, username, device_id):
        self._check()
        for device in self.owned.get(username, []):
            if device["id"] == device_id:
                return dict(device)
        return None

    def create_device(self, username, name, address, mac, image=None):
        self._check()
        devices = self.owned.setdefault(username, [])
        if any(d["name"] == name for d in devices):
            raise ValueError("name taken")
        device = {"id": next(self._counter), "name": name, "address": address, "mac": mac,
                  "picture": None}
        devices.append(device)
        if image is not None:
            device["picture"] = self.set_device_picture(username, device["id"], image)
        return dict(device)

    def update_device(self, username, device_id, name, address, mac):
        self._check()
        devices = self.owned.get(username, [])
        device = next((d for d in devices if d["id"] == device_id), None)
        if device is None:
            return None
        if any(d["name"] == name and d["id"] != device_id for d in devices):
            raise ValueError("name taken")
        device.update(name=name, address=address, mac=mac)
        return dict(device)

    def delete_device(self, username, device_id):
        self._check()
        devices = self.owned.get(username, [])
        kept = [d for d in devices if d["id"] != device_id]
        if len(kept) == len(devices):
            return False
        self.owned[username] = kept
        self.pictures.pop(("device", device_id), None)
        return True

    # -- pictures ----------------------------------------------------------

    def _store(self, key, image):
        try:
            media_type, _ = V.image(image)
        except InvalidInput as exc:
            raise ValueError(exc.message) from exc
        version = next(self._counter)
        self.pictures[key] = {"media_type": media_type, "image": image, "version": version}
        return version

    def set_device_picture(self, username, device_id, image):
        self._check()
        for device in self.owned.get(username, []):
            if device["id"] == device_id:
                device["picture"] = self._store(("device", device_id), image)
                return device["picture"]
        return None

    def get_device_picture(self, username, device_id):
        self._check()
        if self.get_device(username, device_id) is None:
            return None
        return self.pictures.get(("device", device_id))

    def delete_device_picture(self, username, device_id):
        self._check()
        for device in self.owned.get(username, []):
            if device["id"] == device_id and self.pictures.pop(("device", device_id), None):
                device["picture"] = None
                return True
        return False

    def set_user_picture(self, username, image):
        self._check()
        if username not in self.accounts:
            return None
        return self._store(("user", username), image)

    def get_user_picture(self, username):
        self._check()
        return self.pictures.get(("user", username))

    def get_user_picture_version(self, username):
        self._check()
        picture = self.pictures.get(("user", username))
        return None if picture is None else picture["version"]

    def delete_user_picture(self, username):
        self._check()
        return self.pictures.pop(("user", username), None) is not None
