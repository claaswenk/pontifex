"""
Database services for user, device, and connection management.

This module provides the database operations for the database container.
All operations use the schema defined in schema.sql.
"""

import logging
import os
import sqlite3
from sqlite3 import Connection
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class DatabaseService:
    """Main database service class for SQLite operations."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("DB_PATH", "database.sqlite")
        self._connection: Optional[Connection] = None
        self._ensure_database()

    def _get_connection(self) -> Connection:
        """Get or create the database connection."""
        if self._connection is None:
            if not os.path.exists(self.db_path):
                logger.warning(f"Database file not found at {self.db_path}, creating...")
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def _ensure_database(self) -> None:
        """Initialize the database schema."""
        conn = self._get_connection()
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema = f.read()
            conn.executescript(schema)
            conn.commit()
            logger.info("Database schema initialized")

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------

    def create_admin(self, username: str, password: str) -> Tuple[int, str]:
        """
        Create an admin user.

        Args:
            username: The username
            password: The plain text password (will be stored as-is in this implementation)

        Returns:
            Tuple of (user_id, username)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            (username, password, 1)
        )
        user_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Created admin user: {username} (ID: {user_id})")
        return user_id, username

    def create_user(self, username: str, password: str) -> Tuple[int, str]:
        """
        Create a regular user.

        Args:
            username: The username
            password: The plain text password

        Returns:
            Tuple of (user_id, username)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )
        user_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Created user: {username} (ID: {user_id})")
        return user_id, username

    def get_user(self, username: str) -> Optional[sqlite3.Row]:
        """
        Get a user by username.

        Args:
            username: The username to look up

        Returns:
            The user row or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        return cursor.fetchone()

    def delete_user(self, username: str) -> bool:
        """
        Delete a user and all associated connections.

        Args:
            username: The username to delete

        Returns:
            True if user was deleted, False if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get user_id
        user = self.get_user(username)
        if user is None:
            logger.warning(f"User not found: {username}")
            return False

        user_id = user["user_id"]

        try:
            # Delete connections
            cursor.execute(
                "DELETE FROM mapping WHERE user_id = ?",
                (user_id,)
            )
            # Delete user
            cursor.execute(
                "DELETE FROM users WHERE user_id = ?",
                (user_id,)
            )
            conn.commit()
            logger.info(f"Deleted user: {username} (ID: {user_id})")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete user {username}: {e}")
            return False

    # ------------------------------------------------------------------
    # Device operations
    # ------------------------------------------------------------------

    def create_device(self, device_name: str, address: str) -> Tuple[int, str]:
        """
        Create a device.

        Args:
            device_name: The name of the device
            address: The address of the device

        Returns:
            Tuple of (device_id, device_name)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO devices (devicename, device_address) VALUES (?, ?)",
            (device_name, address)
        )
        device_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Created device: {device_name} (ID: {device_id}, address: {address})")
        return device_id, device_name

    def get_device_by_name(self, device_name: str) -> Optional[sqlite3.Row]:
        """
        Get a device by its name.

        Args:
            device_name: The device name

        Returns:
            The device row or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM devices WHERE devicename = ?",
            (device_name,)
        )
        return cursor.fetchone()

    def get_devices_by_user(self, username: str) -> list:
        """
        Get all devices connected to a user.

        Args:
            username: The username

        Returns:
            List of device rows
        """
        user = self.get_user(username)
        if user is None:
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT d.*
            FROM mapping m
            JOIN devices d ON m.device_id = d.device_id
            WHERE m.user_id = ?
        """, (user["user_id"],))

        return [row for row in cursor.fetchall()]

    def delete_device(self, device_name: str) -> bool:
        """
        Delete a device by name.

        Args:
            device_name: The device name to delete

        Returns:
            True if device was deleted, False if not found
        """
        device = self.get_device_by_name(device_name)
        if device is None:
            logger.warning(f"Device not found: {device_name}")
            return False

        conn = self._get_connection()
        cursor = conn.cursor()
        device_id = device["device_id"]

        try:
            # Delete connections
            cursor.execute(
                "DELETE FROM mapping WHERE device_id = ?",
                (device_id,)
            )
            # Delete device
            cursor.execute(
                "DELETE FROM devices WHERE device_id = ?",
                (device_id,)
            )
            conn.commit()
            logger.info(f"Deleted device: {device_name} (ID: {device_id})")
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete device {device_name}: {e}")
            return False

    # ------------------------------------------------------------------
    # Connection operations (user to device mapping)
    # ------------------------------------------------------------------

    def create_connection(self, username: str, device_name: str) -> bool:
        """
        Connect a user to a device.

        Args:
            username: The username
            device_name: The device name

        Returns:
            True if connection was created, False if user or device not found
        """
        user = self.get_user(username)
        device = self.get_device_by_name(device_name)

        if user is None:
            logger.warning(f"User not found: {username}")
            return False
        if device is None:
            logger.warning(f"Device not found: {device_name}")
            return False

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO mapping (user_id, device_id) VALUES (?, ?)",
                (user["user_id"], device["device_id"])
            )
            conn.commit()
            logger.info(f"Created connection: {username} -> {device_name}")
            return True
        except sqlite3.IntegrityError:
            # Connection already exists
            logger.warning(f"Connection already exists: {username} -> {device_name}")
            return False
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create connection: {e}")
            return False

    def delete_connection(self, username: str, device_name: str) -> bool:
        """
        Remove a connection between a user and a device.

        Args:
            username: The username
            device_name: The device name

        Returns:
            True if connection was deleted, False if not found
        """
        user = self.get_user(username)
        device = self.get_device_by_name(device_name)

        if user is None:
            logger.warning(f"User not found: {username}")
            return False
        if device is None:
            logger.warning(f"Device not found: {device_name}")
            return False

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM mapping WHERE user_id = ? AND device_id = ?",
            (user["user_id"], device["device_id"])
        )

        if cursor.rowcount > 0:
            conn.commit()
            logger.info(f"Deleted connection: {username} -> {device_name}")
            return True
        else:
            logger.warning(f"Connection not found: {username} -> {device_name}")
            return False


# Global database service instance
db_service: Optional[DatabaseService] = None


def get_db_service() -> DatabaseService:
    """Get or create the global database service instance."""
    global db_service
    if db_service is None:
        db_service = DatabaseService()
    return db_service
