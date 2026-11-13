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
        self._ensure_database_path()
        self._ensure_database()

    def _ensure_database_path(self) -> None:
        """Ensure the database directory exists and is writable."""
        db_path = self.db_path
        db_dir = os.path.dirname(db_path)

        # If there's a directory component, ensure it exists
        if db_dir and db_dir != '':
            try:
                os.makedirs(db_dir, mode=0o755, exist_ok=True)
                logger.info(f"Ensured database directory exists: {db_dir}")
            except PermissionError as e:
                logger.error(f"Permission denied creating directory {db_dir}: {e}")

        # Test if we can write to the database location
        if not os.path.exists(db_path):
            try:
                # Create and remove a test file
                test_path = f"{db_path}.tmp_test"
                with open(test_path, 'w') as f:
                    f.write('test')
                os.remove(test_path)
                logger.info(f"Database location {db_path} is writable")
            except PermissionError as e:
                logger.error(f"Permission denied writing to {db_path}: {e}")
                logger.error(f"Current user UID/GID: {os.getuid()}/{os.getgid()}")

                # Try to get directory info
                try:
                    dir_path = db_dir if db_dir else '.'
                    stat = os.stat(dir_path)
                    logger.error(f"Directory {dir_path} permissions: {oct(stat.st_mode)}")
                    logger.error(f"Directory {dir_path} owner: {stat.st_uid}:{stat.st_gid}")
                except Exception:
                    pass

                raise RuntimeError(
                    f"Cannot write to database at {db_path}. "
                    f"User {os.getuid()} needs write permissions."
                )

    def _get_connection(self) -> Connection:
        """Get or create the database connection."""
        if self._connection is None:
            if not os.path.exists(self.db_path):
                logger.info(f"Database file not found at {self.db_path}, will be created")

            try:
                # SQLite needs write permissions on the directory AND the file
                self._connection = sqlite3.connect(self.db_path)
                self._connection.row_factory = sqlite3.Row
                self._connection.execute("PRAGMA foreign_keys = ON")
                logger.info(f"Connected to database at {self.db_path}")
            except sqlite3.OperationalError as e:
                logger.error(f"Failed to open database {self.db_path}: {e}")
                logger.error(f"Current user UID/GID: {os.getuid()}/{os.getgid()}")

                # Try to provide helpful debugging info
                try:
                    db_dir = os.path.dirname(self.db_path) if self.db_path else '.'
                    stat = os.stat(db_dir)
                    logger.error(f"Directory {db_dir} permissions: {oct(stat.st_mode)}")
                except Exception:
                    pass

                raise RuntimeError(f"Cannot open database: {e}")
        return self._connection

    def _ensure_database(self) -> None:
        """Initialize the database schema."""
        conn = self._get_connection()
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema = f.read()
            try:
                conn.executescript(schema)
                conn.commit()
                logger.info("Database schema initialized")
            except sqlite3.OperationalError as e:
                logger.error(f"Failed to initialize schema: {e}")
                raise
        else:
            logger.warning(f"Schema file not found at {schema_path}, using existing database")

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

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            user_id = cursor.lastrowid
            conn.commit()
            logger.info(f"Created admin user: {username} (ID: {user_id})")
            return user_id, username
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create admin: {e}")
            raise

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

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            user_id = cursor.lastrowid
            conn.commit()
            logger.info(f"Created user: {username} (ID: {user_id})")
            return user_id, username
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create user: {e}")
            raise

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

        user = self.get_user(username)
        if user is None:
            logger.warning(f"User not found: {username}")
            return False

        user_id = user["user_id"]

        try:
            cursor.execute(
                "DELETE FROM mapping WHERE user_id = ?",
                (user_id,)
            )
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

        try:
            cursor.execute(
                "INSERT INTO devices (devicename, device_address) VALUES (?, ?)",
                (device_name, address)
            )
            device_id = cursor.lastrowid
            conn.commit()
            logger.info(f"Created device: {device_name} (ID: {device_id}, address: {address})")
            return device_id, device_name
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create device: {e}")
            raise

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
            cursor.execute(
                "DELETE FROM mapping WHERE device_id = ?",
                (device_id,)
            )
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
