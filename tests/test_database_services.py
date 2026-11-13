"""
Unit tests for DatabaseService.

Run with:
    python -m unittest tests.test_database_services -v
"""

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database', 'app'))

from services import DatabaseService  # noqa: E402


# =============================================================================
# Base test case
# =============================================================================

class DatabaseTestCase(unittest.TestCase):
    """Gives every test a DatabaseService on a fresh temporary database."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)
        self.temp_db_path = os.path.join(self._tmpdir, "test.db")
        self.db_service = DatabaseService(db_path=self.temp_db_path)


# =============================================================================
# User Tests
# =============================================================================

class TestUserOperations(DatabaseTestCase):
    """Tests for user-related operations."""

    def test_create_admin(self):
        """Test creating an admin user."""
        user_id, username = self.db_service.create_admin("admin", "password123")

        self.assertEqual(user_id, 1)
        self.assertEqual(username, "admin")

        # Verify user exists
        user = self.db_service.get_user("admin")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")

    def test_create_user(self):
        """Test creating a regular user."""
        # Create admin first (not required by schema, but for consistency)
        self.db_service.create_admin("admin", "admin123")

        # Create regular user
        user_id, username = self.db_service.create_user("user", "password123")

        self.assertEqual(user_id, 2)  # Second user
        self.assertEqual(username, "user")

        # Verify user exists
        user = self.db_service.get_user("user")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "user")

    def test_get_user_not_found(self):
        """Test getting a non-existent user."""
        user = self.db_service.get_user("nonexistent")
        self.assertIsNone(user)

    def test_delete_user(self):
        """Test deleting a user."""
        # Create user
        self.db_service.create_user("to_delete", "password")

        # Verify user exists
        user = self.db_service.get_user("to_delete")
        self.assertIsNotNone(user)

        # Delete user
        result = self.db_service.delete_user("to_delete")
        self.assertIs(result, True)

        # Verify user is gone
        user = self.db_service.get_user("to_delete")
        self.assertIsNone(user)

    def test_delete_user_not_found(self):
        """Test deleting a non-existent user."""
        result = self.db_service.delete_user("nonexistent")
        self.assertIs(result, False)

    def test_duplicate_username(self):
        """Test that duplicate usernames are handled."""
        self.db_service.create_user("user", "password1")

        with self.assertRaises(sqlite3.IntegrityError):
            self.db_service.create_user("user", "password2")


# =============================================================================
# Device Tests
# =============================================================================

class TestDeviceOperations(DatabaseTestCase):
    """Tests for device-related operations."""

    def test_create_device(self):
        """Test creating a device."""
        device_id, device_name = self.db_service.create_device("router1", "192.168.1.1")

        self.assertEqual(device_id, 1)
        self.assertEqual(device_name, "router1")

        # Verify device exists
        device = self.db_service.get_device_by_name("router1")
        self.assertIsNotNone(device)
        self.assertEqual(device["devicename"], "router1")
        self.assertEqual(device["device_address"], "192.168.1.1")

    def test_get_device_not_found(self):
        """Test getting a non-existent device."""
        device = self.db_service.get_device_by_name("nonexistent")
        self.assertIsNone(device)

    def test_delete_device(self):
        """Test deleting a device."""
        # Create device
        self.db_service.create_device("router1", "192.168.1.1")

        # Verify device exists
        device = self.db_service.get_device_by_name("router1")
        self.assertIsNotNone(device)

        # Delete device
        result = self.db_service.delete_device("router1")
        self.assertIs(result, True)

        # Verify device is gone
        device = self.db_service.get_device_by_name("router1")
        self.assertIsNone(device)

    def test_delete_device_not_found(self):
        """Test deleting a non-existent device."""
        result = self.db_service.delete_device("nonexistent")
        self.assertIs(result, False)


# =============================================================================
# Connection Tests
# =============================================================================

class TestConnectionOperations(DatabaseTestCase):
    """Tests for connection (user-device mapping) operations."""

    def test_create_connection(self):
        """Test creating a connection between user and device."""
        # Create user and device
        self.db_service.create_user("user1", "password")
        self.db_service.create_device("device1", "192.168.1.1")

        # Create connection
        result = self.db_service.create_connection("user1", "device1")
        self.assertIs(result, True)

        # Verify connection exists
        devices = self.db_service.get_devices_by_user("user1")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["devicename"], "device1")

    def test_create_connection_user_not_found(self):
        """Test creating a connection with non-existent user."""
        self.db_service.create_device("device1", "192.168.1.1")

        result = self.db_service.create_connection("nonexistent", "device1")
        self.assertIs(result, False)

    def test_create_connection_device_not_found(self):
        """Test creating a connection with non-existent device."""
        self.db_service.create_user("user1", "password")

        result = self.db_service.create_connection("user1", "nonexistent")
        self.assertIs(result, False)

    def test_create_duplicate_connection(self):
        """Test creating a duplicate connection."""
        self.db_service.create_user("user1", "password")
        self.db_service.create_device("device1", "192.168.1.1")

        # First connection
        result1 = self.db_service.create_connection("user1", "device1")
        self.assertIs(result1, True)

        # Duplicate connection
        result2 = self.db_service.create_connection("user1", "device1")
        self.assertIs(result2, False)  # Should return False for duplicate

    def test_delete_connection(self):
        """Test deleting a connection."""
        self.db_service.create_user("user1", "password")
        self.db_service.create_device("device1", "192.168.1.1")
        self.db_service.create_connection("user1", "device1")

        # Verify connection exists
        devices = self.db_service.get_devices_by_user("user1")
        self.assertEqual(len(devices), 1)

        # Delete connection
        result = self.db_service.delete_connection("user1", "device1")
        self.assertIs(result, True)

        # Verify connection is gone
        devices = self.db_service.get_devices_by_user("user1")
        self.assertEqual(len(devices), 0)

    def test_delete_connection_not_found(self):
        """Test deleting a non-existent connection."""
        result = self.db_service.delete_connection("nonexistent", "device")
        self.assertIs(result, False)

    def test_get_devices_by_user(self):
        """Test getting all devices for a user."""
        self.db_service.create_user("user1", "password")
        self.db_service.create_device("device1", "192.168.1.1")
        self.db_service.create_device("device2", "192.168.1.2")
        self.db_service.create_connection("user1", "device1")
        self.db_service.create_connection("user1", "device2")

        devices = self.db_service.get_devices_by_user("user1")
        self.assertEqual(len(devices), 2)

    def test_get_devices_by_nonexistent_user(self):
        """Test getting devices for a non-existent user."""
        devices = self.db_service.get_devices_by_user("nonexistent")
        self.assertEqual(len(devices), 0)


# =============================================================================
# Schema Tests
# =============================================================================

class TestSchemaInitialization(DatabaseTestCase):
    """Tests for database schema initialization."""

    def _columns(self, table):
        with sqlite3.connect(self.temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info({table})")
            columns = {row[1]: row[2] for row in cursor.fetchall()}
        conn.close()
        return columns

    def test_schema_created(self):
        """Test that schema is created correctly."""
        with sqlite3.connect(self.temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.assertIn("users", tables)
        self.assertIn("devices", tables)
        self.assertIn("mapping", tables)

    def test_users_table_structure(self):
        """Test users table has correct columns."""
        columns = self._columns("users")

        self.assertIn("user_id", columns)
        self.assertIn("username", columns)
        self.assertIn("password", columns)
        self.assertIn("created_at", columns)

    def test_devices_table_structure(self):
        """Test devices table has correct columns."""
        columns = self._columns("devices")

        self.assertIn("device_id", columns)
        self.assertIn("devicename", columns)
        self.assertIn("device_address", columns)
        self.assertIn("created_at", columns)

    def test_mapping_table_structure(self):
        """Test mapping table has correct columns."""
        columns = self._columns("mapping")

        self.assertIn("user_id", columns)
        self.assertIn("device_id", columns)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration(DatabaseTestCase):
    """Integration tests for complex scenarios."""

    def test_full_workflow(self):
        """Test a complete workflow: user + device + connection."""
        # Create admin
        admin_id, admin_name = self.db_service.create_admin("admin", "admin123")
        self.assertEqual(admin_id, 1)

        # Create user
        user_id, user_name = self.db_service.create_user("user", "user123")
        self.assertEqual(user_id, 2)

        # Create devices
        device1_id, device1_name = self.db_service.create_device("device1", "10.0.0.1")
        device2_id, device2_name = self.db_service.create_device("device2", "10.0.0.2")
        self.assertEqual(device1_id, 1)
        self.assertEqual(device2_id, 2)

        # Connect user to devices
        self.assertIs(self.db_service.create_connection("user", "device1"), True)
        self.assertIs(self.db_service.create_connection("user", "device2"), True)

        # Verify user has 2 devices
        devices = self.db_service.get_devices_by_user("user")
        self.assertEqual(len(devices), 2)

        # Delete one connection
        self.assertIs(self.db_service.delete_connection("user", "device1"), True)

        # Verify user has 1 device left
        devices = self.db_service.get_devices_by_user("user")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["devicename"], "device2")

        # Cleanup
        self.assertIs(self.db_service.delete_user("user"), True)
        # Note: ON DELETE CASCADE deletes mappings, but NOT devices themselves
        # So devices still exist and can be deleted
        self.assertIs(self.db_service.delete_device("device1"), True)
        self.assertIs(self.db_service.delete_device("device2"), True)


if __name__ == "__main__":
    unittest.main()
