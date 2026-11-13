"""In-memory stand-in with the same interface as DatabaseClient.

The real store lives in the database container; the backend only ever talks to
it through DatabaseClient, so this fake is all the backend tests need.
"""

import itertools
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "src", "backend")]

from shared.errors import BootstrapConsumedError  # noqa: E402
from app.database_client import DatabaseUnavailableError  # noqa: E402


class FakeDatabase:
    def __init__(self):
        self.accounts = {}   # username -> {"role": str, "pw_hash": str}
        self.tokens = {}     # refresh token -> username
        self.owned = {}      # username -> [{"id", "name", "address", "mac"}]
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

    def _forget(self, username):
        self.accounts.pop(username, None)
        self.owned.pop(username, None)
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}

    # -- accounts ----------------------------------------------------------

    def create_bootstrap_admin(self, username, pw_hash):
        self._check()
        if self.consumed:
            raise BootstrapConsumedError()
        if username in self.accounts:
            raise ValueError("taken")
        self.consumed = True
        self.accounts[username] = {"role": "admin", "pw_hash": pw_hash}
        return self._new_token(username)

    def create_user(self, username, pw_hash, role):
        self._check()
        if username in self.accounts:
            raise ValueError("taken")
        self.accounts[username] = {"role": role, "pw_hash": pw_hash}

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
        return {"username": username, "pw_hash": account["pw_hash"], "role": account["role"]}

    def list_users(self):
        self._check()
        return [{"username": name, "role": a["role"]} for name, a in self.accounts.items()]

    def set_password(self, username, pw_hash):
        self._check()
        if username not in self.accounts:
            return False
        self.accounts[username]["pw_hash"] = pw_hash
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}
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
        self.tokens = {t: u for t, u in self.tokens.items() if u != username}
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

    def create_device(self, username, name, address, mac):
        self._check()
        devices = self.owned.setdefault(username, [])
        if any(d["name"] == name for d in devices):
            raise ValueError("name taken")
        device = {"id": next(self._counter), "name": name, "address": address, "mac": mac}
        devices.append(device)
        return dict(device)

    def delete_device(self, username, device_id):
        self._check()
        devices = self.owned.get(username, [])
        kept = [d for d in devices if d["id"] != device_id]
        if len(kept) == len(devices):
            return False
        self.owned[username] = kept
        return True
