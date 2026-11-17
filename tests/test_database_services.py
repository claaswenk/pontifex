"""
Unit tests for DatabaseService (the SQLite layer of the database container).

The same code is also exercised over TLS by tests/test_database_client.py.

Run with:
    python -m unittest tests.test_database_services -v
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database', 'app'))

from services import DatabaseService  # noqa: E402

HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"
PNG = ("image/png", b"\x89PNG\r\n\x1a\n" + b"x" * 20)


class DatabaseTestCase(unittest.TestCase):
    """Gives every test a DatabaseService on a fresh temporary database."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)
        self.temp_db_path = os.path.join(self._tmpdir, "test.db")
        self.db = DatabaseService(db_path=self.temp_db_path)

    def rows(self, query, params=()):
        with sqlite3.connect(self.temp_db_path) as conn:
            return conn.execute(query, params).fetchall()


class TestAccounts(DatabaseTestCase):
    def test_a_user_can_be_added_once(self):
        self.db.add_user("anna", HASH)
        self.assertEqual(self.db.get_credentials("anna"),
                         {"username": "anna", "pw_hash": HASH, "role": "user", "must_change": False})
        with self.assertRaises(ValueError):
            self.db.add_user("anna", HASH)

    def test_a_password_set_by_somebody_else_has_to_be_replaced(self):
        self.db.add_user("anna", HASH, must_change=True)
        self.assertTrue(self.db.get_credentials("anna")["must_change"])
        self.db.set_password("anna", HASH + "x")  # her own choice
        self.assertFalse(self.db.get_credentials("anna")["must_change"])
        self.db.set_password("anna", HASH + "y", must_change=True)  # the admin again
        self.assertTrue(self.db.get_credentials("anna")["must_change"])

    def test_a_reset_token_is_the_users_own_choice(self):
        self.db.add_user("anna", HASH, must_change=True)
        self.db.create_reset_token("anna", "r" * 64, 2**33)
        self.assertTrue(self.db.reset_password_with_token("r" * 64, HASH + "z"))
        self.assertFalse(self.db.get_credentials("anna")["must_change"])

    def test_a_database_from_before_the_flag_gets_the_column(self):
        path = os.path.join(self._tmpdir, "old.db")
        with sqlite3.connect(path) as conn:
            conn.execute('CREATE TABLE users (user_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, '
                         'username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, '
                         'is_admin INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
            conn.execute("INSERT INTO users (username, password) VALUES ('anna', ?)", (HASH,))
        old = DatabaseService(db_path=path)
        self.assertFalse(old.get_credentials("anna")["must_change"])

    def test_unknown_user(self):
        self.assertIsNone(self.db.get_credentials("nobody"))
        self.assertFalse(self.db.delete_user("nobody"))

    def test_deleting_a_user_removes_devices_pictures_and_tokens(self):
        self.db.add_user("anna", HASH)
        self.db.add_user("bernd", HASH)
        mine = self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01", PNG)
        theirs = self.db.add_owned_device("bernd", "nas", "192.168.1.11", "aa:bb:cc:dd:ee:02")
        self.db.set_user_picture("anna", *PNG)
        self.db.create_refresh_token("anna", "t" * 64, 2**33)

        self.assertTrue(self.db.delete_user("anna"))

        self.assertIsNone(self.db.get_credentials("anna"))
        self.assertEqual(self.rows("SELECT device_id FROM devices"), [(theirs["id"],)])
        self.assertEqual(self.rows("SELECT * FROM device_pictures"), [])
        self.assertEqual(self.rows("SELECT * FROM user_pictures"), [])
        self.assertEqual(self.rows("SELECT * FROM refresh_tokens"), [])
        self.assertIsNone(self.db.get_by_refresh_token("t" * 64))
        self.assertNotEqual(mine["id"], theirs["id"])


class TestOwnedDevices(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.db.add_user("anna", HASH)
        self.db.add_user("bernd", HASH)

    def test_a_device_belongs_to_one_owner(self):
        device = self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01")
        self.assertEqual(self.db.list_owned_devices("anna"), [device])
        self.assertEqual(self.db.list_owned_devices("bernd"), [])
        self.assertIsNone(self.db.get_owned_device("bernd", device["id"]))
        self.assertFalse(self.db.delete_owned_device("bernd", device["id"]))
        self.assertTrue(self.db.delete_owned_device("anna", device["id"]))

    def test_names_are_unique_per_owner(self):
        self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01")
        with self.assertRaises(ValueError):
            self.db.add_owned_device("anna", "nas", "192.168.1.11", "aa:bb:cc:dd:ee:02")
        self.assertIsNotNone(self.db.add_owned_device("bernd", "nas", "192.168.1.11", "aa:bb:cc:dd:ee:02"))
        self.assertIsNone(self.db.add_owned_device("nobody", "nas", "192.168.1.11", "aa:bb:cc:dd:ee:02"))

    def test_an_edit_changes_the_fields_and_keeps_the_picture(self):
        device = self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01", PNG)
        other = self.db.add_owned_device("anna", "pc", "192.168.1.11", "aa:bb:cc:dd:ee:02")
        changed = self.db.update_owned_device("anna", device["id"], "nas2", "10.0.0.5", "aa:bb:cc:dd:ee:09")
        self.assertEqual(changed, {**device, "name": "nas2", "address": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:09"})
        self.assertEqual(self.db.get_device_picture("anna", device["id"])["version"], device["picture"])
        self.assertEqual(self.db.get_owned_device("anna", other["id"]), other)

    def test_an_edit_may_keep_the_own_name_but_not_take_another(self):
        device = self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01")
        self.db.add_owned_device("anna", "pc", "192.168.1.11", "aa:bb:cc:dd:ee:02")
        self.assertEqual(
            self.db.update_owned_device("anna", device["id"], "nas", "10.0.0.5", "aa:bb:cc:dd:ee:01")["address"],
            "10.0.0.5")
        with self.assertRaises(ValueError):
            self.db.update_owned_device("anna", device["id"], "pc", "10.0.0.5", "aa:bb:cc:dd:ee:01")

    def test_an_edit_of_somebody_elses_or_an_unknown_device_changes_nothing(self):
        device = self.db.add_owned_device("anna", "nas", "192.168.1.10", "aa:bb:cc:dd:ee:01")
        self.assertIsNone(self.db.update_owned_device("bernd", device["id"], "x", "10.0.0.5", "aa:bb:cc:dd:ee:09"))
        self.assertIsNone(self.db.update_owned_device("anna", 9999, "x", "10.0.0.5", "aa:bb:cc:dd:ee:09"))
        self.assertEqual(self.db.get_owned_device("anna", device["id"]), device)


class TestSchemaInitialization(DatabaseTestCase):
    def _columns(self, table):
        return {row[1]: row[2] for row in self.rows(f"PRAGMA table_info({table})")}

    def test_schema_created(self):
        tables = [row[0] for row in self.rows("SELECT name FROM sqlite_master WHERE type='table'")]
        for name in ("users", "devices", "mapping", "bootstrap", "refresh_tokens", "reset_tokens",
                     "device_pictures", "user_pictures"):
            self.assertIn(name, tables)

    def test_users_table_structure(self):
        for column in ("user_id", "username", "password", "is_admin", "created_at"):
            self.assertIn(column, self._columns("users"))

    def test_devices_table_structure(self):
        for column in ("device_id", "devicename", "device_address", "mac", "created_at"):
            self.assertIn(column, self._columns("devices"))

    def test_mapping_table_structure(self):
        for column in ("user_id", "device_id"):
            self.assertIn(column, self._columns("mapping"))


if __name__ == "__main__":
    unittest.main()
