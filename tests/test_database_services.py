"""
Unit tests for DatabaseService.

Run with:
    python -m pytest tests/test_database_services.py -v
"""

import os
import tempfile
import pytest
import sqlite3
from typing import Generator

# Add src to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'database', 'app'))

from services import DatabaseService


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_db_path() -> Generator[str, None, None]:
    """Create a temporary database file for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    yield db_path
    # Cleanup after test
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def db_service(temp_db_path: str) -> DatabaseService:
    """Create a DatabaseService instance with a temporary database."""
    # Set DB_PATH environment variable for the service
    old_db_path = os.environ.get('DB_PATH')
    os.environ['DB_PATH'] = temp_db_path

    # Create service (this will initialize the database)
    service = DatabaseService(db_path=temp_db_path)

    # Restore old DB_PATH
    if old_db_path:
        os.environ['DB_PATH'] = old_db_path
    else:
        os.environ.pop('DB_PATH', None)

    yield service

    # Cleanup: delete the database file
    if os.path.exists(temp_db_path):
        os.unlink(temp_db_path)


# =============================================================================
# User Tests
# =============================================================================

class TestUserOperations:
    """Tests for user-related operations."""

    def test_create_admin(self, db_service: DatabaseService):
        """Test creating an admin user."""
        user_id, username = db_service.create_admin("admin", "password123")

        assert user_id == 1
        assert username == "admin"

        # Verify user exists
        user = db_service.get_user("admin")
        assert user is not None
        assert user["username"] == "admin"

    def test_create_user(self, db_service: DatabaseService):
        """Test creating a regular user."""
        # Create admin first (not required by schema, but for consistency)
        db_service.create_admin("admin", "admin123")

        # Create regular user
        user_id, username = db_service.create_user("user", "password123")

        assert user_id == 2  # Second user
        assert username == "user"

        # Verify user exists
        user = db_service.get_user("user")
        assert user is not None
        assert user["username"] == "user"

    def test_get_user_not_found(self, db_service: DatabaseService):
        """Test getting a non-existent user."""
        user = db_service.get_user("nonexistent")
        assert user is None

    def test_delete_user(self, db_service: DatabaseService):
        """Test deleting a user."""
        # Create user
        db_service.create_user("to_delete", "password")

        # Verify user exists
        user = db_service.get_user("to_delete")
        assert user is not None

        # Delete user
        result = db_service.delete_user("to_delete")
        assert result is True

        # Verify user is gone
        user = db_service.get_user("to_delete")
        assert user is None

    def test_delete_user_not_found(self, db_service: DatabaseService):
        """Test deleting a non-existent user."""
        result = db_service.delete_user("nonexistent")
        assert result is False

    def test_duplicate_username(self, db_service: DatabaseService):
        """Test that duplicate usernames are handled."""
        db_service.create_user("user", "password1")

        with pytest.raises(sqlite3.IntegrityError):
            db_service.create_user("user", "password2")


# =============================================================================
# Device Tests
# =============================================================================

class TestDeviceOperations:
    """Tests for device-related operations."""

    def test_create_device(self, db_service: DatabaseService):
        """Test creating a device."""
        device_id, device_name = db_service.create_device("router1", "192.168.1.1")

        assert device_id == 1
        assert device_name == "router1"

        # Verify device exists
        device = db_service.get_device_by_name("router1")
        assert device is not None
        assert device["devicename"] == "router1"
        assert device["device_address"] == "192.168.1.1"

    def test_get_device_not_found(self, db_service: DatabaseService):
        """Test getting a non-existent device."""
        device = db_service.get_device_by_name("nonexistent")
        assert device is None

    def test_delete_device(self, db_service: DatabaseService):
        """Test deleting a device."""
        # Create device
        db_service.create_device("router1", "192.168.1.1")

        # Verify device exists
        device = db_service.get_device_by_name("router1")
        assert device is not None

        # Delete device
        result = db_service.delete_device("router1")
        assert result is True

        # Verify device is gone
        device = db_service.get_device_by_name("router1")
        assert device is None

    def test_delete_device_not_found(self, db_service: DatabaseService):
        """Test deleting a non-existent device."""
        result = db_service.delete_device("nonexistent")
        assert result is False


# =============================================================================
# Connection Tests
# =============================================================================

class TestConnectionOperations:
    """Tests for connection (user-device mapping) operations."""

    def test_create_connection(self, db_service: DatabaseService):
        """Test creating a connection between user and device."""
        # Create user and device
        db_service.create_user("user1", "password")
        db_service.create_device("device1", "192.168.1.1")

        # Create connection
        result = db_service.create_connection("user1", "device1")
        assert result is True

        # Verify connection exists
        devices = db_service.get_devices_by_user("user1")
        assert len(devices) == 1
        assert devices[0]["devicename"] == "device1"

    def test_create_connection_user_not_found(self, db_service: DatabaseService):
        """Test creating a connection with non-existent user."""
        db_service.create_device("device1", "192.168.1.1")

        result = db_service.create_connection("nonexistent", "device1")
        assert result is False

    def test_create_connection_device_not_found(self, db_service: DatabaseService):
        """Test creating a connection with non-existent device."""
        db_service.create_user("user1", "password")

        result = db_service.create_connection("user1", "nonexistent")
        assert result is False

    def test_create_duplicate_connection(self, db_service: DatabaseService):
        """Test creating a duplicate connection."""
        db_service.create_user("user1", "password")
        db_service.create_device("device1", "192.168.1.1")

        # First connection
        result1 = db_service.create_connection("user1", "device1")
        assert result1 is True

        # Duplicate connection
        result2 = db_service.create_connection("user1", "device1")
        assert result2 is False  # Should return False for duplicate

    def test_delete_connection(self, db_service: DatabaseService):
        """Test deleting a connection."""
        db_service.create_user("user1", "password")
        db_service.create_device("device1", "192.168.1.1")
        db_service.create_connection("user1", "device1")

        # Verify connection exists
        devices = db_service.get_devices_by_user("user1")
        assert len(devices) == 1

        # Delete connection
        result = db_service.delete_connection("user1", "device1")
        assert result is True

        # Verify connection is gone
        devices = db_service.get_devices_by_user("user1")
        assert len(devices) == 0

    def test_delete_connection_not_found(self, db_service: DatabaseService):
        """Test deleting a non-existent connection."""
        result = db_service.delete_connection("nonexistent", "device")
        assert result is False

    def test_get_devices_by_user(self, db_service: DatabaseService):
        """Test getting all devices for a user."""
        db_service.create_user("user1", "password")
        db_service.create_device("device1", "192.168.1.1")
        db_service.create_device("device2", "192.168.1.2")
        db_service.create_connection("user1", "device1")
        db_service.create_connection("user1", "device2")

        devices = db_service.get_devices_by_user("user1")
        assert len(devices) == 2

    def test_get_devices_by_nonexistent_user(self, db_service: DatabaseService):
        """Test getting devices for a non-existent user."""
        devices = db_service.get_devices_by_user("nonexistent")
        assert len(devices) == 0


# =============================================================================
# Schema Tests
# =============================================================================

class TestSchemaInitialization:
    """Tests for database schema initialization."""

    def test_schema_created(self, temp_db_path: str):
        """Test that schema is created correctly."""
        # Create a new service (this will initialize the schema)
        service = DatabaseService(db_path=temp_db_path)

        # Verify tables exist
        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            assert "users" in tables
            assert "devices" in tables
            assert "mapping" in tables

    def test_users_table_structure(self, temp_db_path: str):
        """Test users table has correct columns."""
        service = DatabaseService(db_path=temp_db_path)

        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(users)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            assert "user_id" in columns
            assert "username" in columns
            assert "password" in columns
            assert "created_at" in columns

    def test_devices_table_structure(self, temp_db_path: str):
        """Test devices table has correct columns."""
        service = DatabaseService(db_path=temp_db_path)

        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(devices)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            assert "device_id" in columns
            assert "devicename" in columns
            assert "device_address" in columns
            assert "created_at" in columns

    def test_mapping_table_structure(self, temp_db_path: str):
        """Test mapping table has correct columns."""
        service = DatabaseService(db_path=temp_db_path)

        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(mapping)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            assert "user_id" in columns
            assert "device_id" in columns


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for complex scenarios."""

    def test_full_workflow(self, db_service: DatabaseService):
        """Test a complete workflow: user + device + connection."""
        # Create admin
        admin_id, admin_name = db_service.create_admin("admin", "admin123")
        assert admin_id == 1

        # Create user
        user_id, user_name = db_service.create_user("user", "user123")
        assert user_id == 2

        # Create devices
        device1_id, device1_name = db_service.create_device("device1", "10.0.0.1")
        device2_id, device2_name = db_service.create_device("device2", "10.0.0.2")
        assert device1_id == 1
        assert device2_id == 2

        # Connect user to devices
        assert db_service.create_connection("user", "device1") is True
        assert db_service.create_connection("user", "device2") is True

        # Verify user has 2 devices
        devices = db_service.get_devices_by_user("user")
        assert len(devices) == 2

        # Delete one connection
        assert db_service.delete_connection("user", "device1") is True

        # Verify user has 1 device left
        devices = db_service.get_devices_by_user("user")
        assert len(devices) == 1
        assert devices[0]["devicename"] == "device2"

        # Cleanup
        assert db_service.delete_user("user") is True
        # Note: ON DELETE CASCADE deletes mappings, but NOT devices themselves
        # So devices still exist and can be deleted
        assert db_service.delete_device("device1") is True
        assert db_service.delete_device("device2") is True


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    # Allow running directly with python
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v"],
        cwd=os.path.dirname(__file__)
    )
    sys.exit(result.returncode)
