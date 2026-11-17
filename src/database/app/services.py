"""
Database services: accounts, tokens, devices and pictures.

This module provides the database operations for the database container.
All operations use the schema defined in schema.sql.

Thread-safety: SQLite connections are created per-method to avoid
"SQLite objects created in a thread can only be used in that same thread" errors.
"""

import logging
import os
import sqlite3
import time
from sqlite3 import Connection
from typing import Optional, Tuple
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseService:
    """Main database service class for SQLite operations."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("DB_PATH", "database.sqlite")
        self._ensure_database_path()
        self._initialize_schema()

    @contextmanager
    def _get_connection(self) -> Connection:
        """
        Context manager for SQLite connections.
        Creates a new connection for each use and closes it automatically.
        Thread-safe: each thread gets its own connection.
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()

    def _ensure_database_path(self) -> None:
        """Ensure the database directory exists and is writable."""
        db_path = self.db_path
        db_dir = os.path.dirname(db_path)

        if db_dir and db_dir != '':
            try:
                os.makedirs(db_dir, mode=0o755, exist_ok=True)
                logger.info(f"Ensured database directory exists: {db_dir}")
            except PermissionError as e:
                logger.error(f"Permission denied creating directory {db_dir}: {e}")
                raise RuntimeError(f"Cannot create database directory {db_dir}: {e}")

        # Test if we can write to the database location
        if not os.path.exists(db_path):
            try:
                test_path = f"{db_path}.tmp_test"
                with open(test_path, 'w') as f:
                    f.write('test')
                os.remove(test_path)
                logger.info(f"Database location {db_path} is writable")
            except PermissionError as e:
                logger.error(f"Permission denied writing to {db_path}: {e}")
                raise RuntimeError(f"Cannot write to database at {db_path}")

    def _initialize_schema(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
            if os.path.exists(schema_path):
                with open(schema_path, 'r') as f:
                    schema = f.read()
                try:
                    conn.executescript(schema)
                    # A database from before "must_change" existed: nobody is forced to change.
                    columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)")]
                    if "must_change" not in columns:
                        conn.execute('ALTER TABLE users ADD COLUMN "must_change" INTEGER NOT NULL DEFAULT 0')
                    conn.commit()
                    logger.info("Database schema initialized")
                except sqlite3.OperationalError as e:
                    logger.error(f"Failed to initialize schema: {e}")
                    raise
            else:
                logger.warning(f"Schema file not found at {schema_path}")

    # ------------------------------------------------------------------
    # Accounts for the backend: roles, bootstrap, passwords
    # ------------------------------------------------------------------

    @staticmethod
    def _role(is_admin) -> str:
        return "admin" if is_admin else "user"

    @staticmethod
    def _user_id(conn: Connection, username: str) -> Optional[int]:
        row = conn.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()
        return None if row is None else row["user_id"]

    def bootstrap_consumed(self) -> bool:
        with self._get_connection() as conn:
            return conn.execute("SELECT 1 FROM bootstrap WHERE id = 1").fetchone() is not None

    def create_bootstrap_admin(self, username: str, pw_hash: str,
                               token_hash: str, expires_at: int) -> Optional[int]:
        """
        The first and only admin, created together with the bootstrap flag and a
        refresh token in one transaction. None if the bootstrap was used before,
        ValueError if the name is taken (then nothing is consumed).
        """
        with self._get_connection() as conn:
            try:
                conn.execute("INSERT INTO bootstrap (id) VALUES (1)")
            except sqlite3.IntegrityError:
                return None
            try:
                cursor = conn.execute(
                    "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                    (username, pw_hash),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("username taken") from exc
            conn.execute(
                "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, cursor.lastrowid, expires_at),
            )
            conn.commit()
            logger.info("Created the bootstrap admin")
            return cursor.lastrowid

    def add_user(self, username: str, pw_hash: str, is_admin: bool = False,
                 must_change: bool = False) -> int:
        """A new account. ValueError if the name is taken."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO users (username, password, is_admin, must_change) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, 1 if is_admin else 0, 1 if must_change else 0),
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ValueError("username taken") from exc

    def get_credentials(self, username: str) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT username, password, is_admin, must_change FROM users WHERE username = ?", (username,)
            ).fetchone()
        if row is None:
            return None
        return {"username": row["username"], "pw_hash": row["password"],
                "role": self._role(row["is_admin"]), "must_change": bool(row["must_change"])}

    def list_users(self) -> list:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT username, is_admin FROM users ORDER BY user_id").fetchall()
        return [{"username": r["username"], "role": self._role(r["is_admin"])} for r in rows]

    def set_password(self, username: str, pw_hash: str, must_change: bool = False) -> bool:
        """
        New password hash; every refresh and reset token of the user is revoked.
        ``must_change`` is True for a password somebody else chose.
        """
        with self._get_connection() as conn:
            user_id = self._user_id(conn, username)
            if user_id is None:
                return False
            conn.execute("UPDATE users SET password = ?, must_change = ? WHERE user_id = ?",
                         (pw_hash, 1 if must_change else 0, user_id))
            conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))
            conn.commit()
            return True

    def rename_user(self, username: str, new_username: str) -> bool:
        """The devices follow the account. ValueError if the new name is taken."""
        try:
            with self._get_connection() as conn:
                user_id = self._user_id(conn, username)
                if user_id is None:
                    return False
                conn.execute("UPDATE users SET username = ? WHERE user_id = ?", (new_username, user_id))
                conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
                conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))
                conn.commit()
                return True
        except sqlite3.IntegrityError as exc:
            raise ValueError("username taken") from exc

    def delete_user(self, username: str) -> bool:
        """Delete the account. Its devices, pictures and tokens go with it. False if unknown."""
        with self._get_connection() as conn:
            user_id = self._user_id(conn, username)
            if user_id is None:
                return False
            conn.execute(
                "DELETE FROM devices WHERE device_id IN (SELECT device_id FROM mapping WHERE user_id = ?)",
                (user_id,),
            )
            conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            conn.commit()
            logger.info(f"Deleted user: {username} (ID: {user_id})")
            return True
    # ------------------------------------------------------------------
    # Tokens (only hashes are stored)
    # ------------------------------------------------------------------

    def create_refresh_token(self, username: str, token_hash: str, expires_at: int) -> bool:
        with self._get_connection() as conn:
            user_id = self._user_id(conn, username)
            if user_id is None:
                return False
            conn.execute(
                "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires_at),
            )
            conn.commit()
            return True

    def get_by_refresh_token(self, token_hash: str) -> Optional[Tuple[str, str]]:
        """(username, role) of a valid, unexpired token, else None."""
        now = int(time.time())
        with self._get_connection() as conn:
            conn.execute("DELETE FROM refresh_tokens WHERE expires_at <= ?", (now,))
            conn.commit()
            row = conn.execute(
                "SELECT u.username, u.is_admin FROM refresh_tokens t "
                "JOIN users u ON u.user_id = t.user_id WHERE t.token_hash = ?",
                (token_hash,),
            ).fetchone()
        return None if row is None else (row["username"], self._role(row["is_admin"]))

    def revoke_refresh_token(self, token_hash: str) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM refresh_tokens WHERE token_hash = ?", (token_hash,))
            conn.commit()

    def create_reset_token(self, username: str, token_hash: str, expires_at: int) -> bool:
        """Replaces an earlier unused reset token of the user."""
        with self._get_connection() as conn:
            user_id = self._user_id(conn, username)
            if user_id is None:
                return False
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user_id,))
            conn.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, expires_at),
            )
            conn.commit()
            return True

    def reset_password_with_token(self, token_hash: str, pw_hash: str) -> bool:
        """One use only: the token is gone afterwards, valid or not."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT user_id, expires_at FROM reset_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                return False
            if conn.execute("DELETE FROM reset_tokens WHERE token_hash = ?", (token_hash,)).rowcount == 0:
                return False  # a parallel request used it first
            if row["expires_at"] <= int(time.time()):
                conn.commit()
                return False
            conn.execute("UPDATE users SET password = ?, must_change = 0 WHERE user_id = ?",
                         (pw_hash, row["user_id"]))
            conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (row["user_id"],))
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (row["user_id"],))
            conn.commit()
            return True

    # ------------------------------------------------------------------
    # Devices of one owner
    # ------------------------------------------------------------------

    # Every query below is a plain literal with placeholders (no string building).

    @staticmethod
    def _device(row) -> dict:
        """``picture`` is the version of the device's picture, None without one."""
        return {"id": row["device_id"], "name": row["devicename"],
                "address": row["device_address"] or "", "mac": row["mac"] or "",
                "picture": row["picture"]}

    def list_owned_devices(self, username: str) -> list:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT d.device_id, d.devicename, d.device_address, d.mac, p.version AS picture "
                "FROM mapping m JOIN devices d ON d.device_id = m.device_id "
                "JOIN users u ON u.user_id = m.user_id "
                "LEFT JOIN device_pictures p ON p.device_id = d.device_id "
                "WHERE u.username = ? ORDER BY d.device_id",
                (username,),
            ).fetchall()
        return [self._device(r) for r in rows]

    def get_owned_device(self, username: str, device_id: int) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT d.device_id, d.devicename, d.device_address, d.mac, p.version AS picture "
                "FROM mapping m JOIN devices d ON d.device_id = m.device_id "
                "JOIN users u ON u.user_id = m.user_id "
                "LEFT JOIN device_pictures p ON p.device_id = d.device_id "
                "WHERE u.username = ? AND d.device_id = ?",
                (username, device_id),
            ).fetchone()
        return None if row is None else self._device(row)

    def add_owned_device(self, username: str, name: str, address: str, mac: str,
                         picture: Optional[Tuple[str, bytes]] = None) -> Optional[dict]:
        """
        None if the owner is unknown, ValueError if they already have a device of that name.
        ``picture`` is ``(media type, bytes)`` and is stored in the same transaction.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")  # the name check and the insert must not interleave
            user_id = self._user_id(conn, username)
            if user_id is None:
                return None
            taken = conn.execute(
                "SELECT 1 FROM mapping m "
                "JOIN devices d ON d.device_id = m.device_id JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND d.devicename = ?",
                (username, name),
            ).fetchone()
            if taken:
                raise ValueError("name taken")
            cursor = conn.execute(
                "INSERT INTO devices (devicename, device_address, mac) VALUES (?, ?, ?)",
                (name, address, mac),
            )
            conn.execute("INSERT INTO mapping (user_id, device_id) VALUES (?, ?)", (user_id, cursor.lastrowid))
            version = None
            if picture is not None:
                version = self._new_version()
                conn.execute(
                    "INSERT INTO device_pictures (device_id, media_type, data, version) VALUES (?, ?, ?, ?)",
                    (cursor.lastrowid, picture[0], picture[1], version),
                )
            conn.commit()
            return {"id": cursor.lastrowid, "name": name, "address": address, "mac": mac,
                    "picture": version}

    def update_owned_device(self, username: str, device_id: int, name: str, address: str,
                            mac: str) -> Optional[dict]:
        """
        The changed device, None if the owner has no such device, ValueError if
        they already have another device of that name. The picture stays.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")  # the name check and the update must not interleave
            owned = conn.execute(
                "SELECT 1 FROM mapping m JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND m.device_id = ?",
                (username, device_id),
            ).fetchone()
            if owned is None:
                return None
            taken = conn.execute(
                "SELECT 1 FROM mapping m "
                "JOIN devices d ON d.device_id = m.device_id JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND d.devicename = ? AND d.device_id != ?",
                (username, name, device_id),
            ).fetchone()
            if taken:
                raise ValueError("name taken")
            conn.execute(
                "UPDATE devices SET devicename = ?, device_address = ?, mac = ? WHERE device_id = ?",
                (name, address, mac, device_id),
            )
            conn.commit()
        return self.get_owned_device(username, device_id)

    def delete_owned_device(self, username: str, device_id: int) -> bool:
        with self._get_connection() as conn:
            owned = conn.execute(
                "SELECT 1 FROM mapping m JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND m.device_id = ?",
                (username, device_id),
            ).fetchone()
            if owned is None:
                return False
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            conn.commit()
            return True

    # ------------------------------------------------------------------
    # Pictures (of the owner's devices and of the account)
    # ------------------------------------------------------------------

    @staticmethod
    def _new_version() -> int:
        """Milliseconds since the epoch: a new upload never reuses a URL a browser may have cached."""
        return time.time_ns() // 1_000_000

    @staticmethod
    def _picture(row) -> Optional[dict]:
        if row is None:
            return None
        return {"media_type": row["media_type"], "data": bytes(row["data"]), "version": row["version"]}

    def set_device_picture(self, username: str, device_id: int, media_type: str,
                           data: bytes) -> Optional[int]:
        """The new version of the picture, None if the owner has no such device."""
        with self._get_connection() as conn:
            owned = conn.execute(
                "SELECT 1 FROM mapping m JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND m.device_id = ?",
                (username, device_id),
            ).fetchone()
            if owned is None:
                return None
            version = self._new_version()
            conn.execute(
                "INSERT INTO device_pictures (device_id, media_type, data, version) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(device_id) DO UPDATE SET media_type = excluded.media_type, "
                "data = excluded.data, version = excluded.version",
                (device_id, media_type, data, version),
            )
            conn.commit()
            return version

    def get_device_picture(self, username: str, device_id: int) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT p.media_type, p.data, p.version FROM device_pictures p "
                "JOIN mapping m ON m.device_id = p.device_id JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ? AND p.device_id = ?",
                (username, device_id),
            ).fetchone()
        return self._picture(row)

    def delete_device_picture(self, username: str, device_id: int) -> bool:
        """False if the owner has no such device or it has no picture."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM device_pictures WHERE device_id = ? AND device_id IN "
                "(SELECT m.device_id FROM mapping m JOIN users u ON u.user_id = m.user_id "
                "WHERE u.username = ?)",
                (device_id, username),
            )
            conn.commit()
            return cursor.rowcount > 0

    def set_user_picture(self, username: str, media_type: str, data: bytes) -> Optional[int]:
        """The new version of the picture, None if the user is unknown."""
        with self._get_connection() as conn:
            user_id = self._user_id(conn, username)
            if user_id is None:
                return None
            version = self._new_version()
            conn.execute(
                "INSERT INTO user_pictures (user_id, media_type, data, version) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET media_type = excluded.media_type, "
                "data = excluded.data, version = excluded.version",
                (user_id, media_type, data, version),
            )
            conn.commit()
            return version

    def get_user_picture(self, username: str) -> Optional[dict]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT p.media_type, p.data, p.version FROM user_pictures p "
                "JOIN users u ON u.user_id = p.user_id WHERE u.username = ?",
                (username,),
            ).fetchone()
        return self._picture(row)

    def get_user_picture_version(self, username: str) -> Optional[int]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT p.version FROM user_pictures p "
                "JOIN users u ON u.user_id = p.user_id WHERE u.username = ?",
                (username,),
            ).fetchone()
        return None if row is None else row["version"]

    def delete_user_picture(self, username: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM user_pictures WHERE user_id IN (SELECT user_id FROM users WHERE username = ?)",
                (username,),
            )
            conn.commit()
            return cursor.rowcount > 0


# Global database service instance
db_service: Optional[DatabaseService] = None


def get_db_service() -> DatabaseService:
    """Get or create the global database service instance."""
    global db_service
    if db_service is None:
        db_service = DatabaseService()
    return db_service
