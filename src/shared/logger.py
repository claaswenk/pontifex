"""
Shared logging primitives for every Pontifex container.

``BaseLogger`` provides structured, tamper-resistant request and security logging
for Pontifex services. Each container (backend, frontend, database) subclasses it,
specifying its CONTAINER_ID, and logs every incoming request, caller identity,
error, and security-relevant event to a container-specific log destination.

Features:
- Individual per-container log isolation.
- Restrictive file permissions
- Identity tracking
- Full request lifecycle recording
- Unhandled error and exception capture.
"""

import datetime
import logging
import os
import sys
import threading
import time
from typing import Any, Optional

from flask import Flask, g, request


class BaseLogger:
    CONTAINER_ID: str = ""
    LOG_DIR_ENV: str = "LOG_DIR"
    LOG_PATH_ENV: str = "LOG_PATH"
    DEFAULT_LOG_DIR: str = "/app/logs"
    FILE_PERMISSIONS: int = 0o600
    DIR_PERMISSIONS: int = 0o700

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._log_path = log_path or self._resolve_log_path()
        self._file_handler: Optional[logging.Handler] = None
        self._logger = logging.getLogger(f"pontifex.{self.CONTAINER_ID or 'generic'}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._setup_file_handler()

    def _resolve_log_path(self) -> Optional[str]:
        explicit_path = os.environ.get(self.LOG_PATH_ENV)
        if explicit_path:
            return explicit_path
        log_dir = os.environ.get(self.LOG_DIR_ENV, self.DEFAULT_LOG_DIR)
        container_name = self.CONTAINER_ID or "app"
        return os.path.join(log_dir, f"{container_name}.log")

    def _setup_file_handler(self) -> None:
        if not self._log_path:
            return
        try:
            log_dir = os.path.dirname(self._log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, mode=self.DIR_PERMISSIONS, exist_ok=True)
            # Ensure file exists with restrictive permissions
            if not os.path.exists(self._log_path):
                fd = os.open(
                    self._log_path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                    self.FILE_PERMISSIONS,
                )
                os.close(fd)
            else:
                try:
                    os.chmod(self._log_path, self.FILE_PERMISSIONS)
                except OSError:
                    pass

            abs_log_path = os.path.abspath(self._log_path)
            for h in list(self._logger.handlers):
                if isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == abs_log_path:
                    self._logger.removeHandler(h)

            handler = logging.FileHandler(self._log_path, encoding="utf-8")
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] [container:%(name)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
            handler.setFormatter(formatter)
            handler.setLevel(logging.INFO)
            self._logger.addHandler(handler)
            self._file_handler = handler
        except (OSError, PermissionError):
            # Fall back silently if volume/directory is not configured or unwritable outside container
            pass

    @property
    def log_path(self) -> Optional[str]:
        return self._log_path

    # ------------------------------------------------------------------
    # Identity extraction ("from who")
    # ------------------------------------------------------------------

    @staticmethod
    def get_caller_identity() -> str:
        """Resolve caller identity from request context (JWT, peer, session, or IP)."""
        if not request:
            return "system"

        # 1. Container peer identity (container-to-container HMAC)
        peer = getattr(g, "container_peer", None)
        if peer:
            return f"peer:{peer}"

        # 2. Authenticated user from access token (JWT 'sub')
        current_user = getattr(g, "current_user", None)
        if isinstance(current_user, dict) and current_user.get("sub"):
            return f"user:{current_user['sub']}"

        # 3. Authenticated session in frontend
        session = getattr(g, "session", None)
        if session and hasattr(session, "username") and session.username:
            return f"user:{session.username}"

        # 4. Remote IP fallback
        remote_ip = request.remote_addr or "unknown"
        return f"ip:{remote_ip}"

    # ------------------------------------------------------------------
    # Logging methods
    # ------------------------------------------------------------------

    def _format_msg(self, msg: str, caller: Optional[str] = None) -> str:
        identity = caller or self.get_caller_identity()
        return f"[{identity}] {msg}"

    def info(self, msg: str, *, caller: Optional[str] = None) -> None:
        self._logger.info(self._format_msg(msg, caller))

    def warning(self, msg: str, *, caller: Optional[str] = None) -> None:
        self._logger.warning(self._format_msg(msg, caller))

    def error(self, msg: str, *, caller: Optional[str] = None, exc_info: Any = None) -> None:
        self._logger.error(self._format_msg(msg, caller), exc_info=exc_info)

    def security(self, msg: str, *, caller: Optional[str] = None) -> None:
        self._logger.warning(self._format_msg(f"SECURITY: {msg}", caller))

    # ------------------------------------------------------------------
    # Flask application lifecycle integration
    # ------------------------------------------------------------------

    def init_app(self, app: Flask) -> None:
        """Hook into Flask lifecycle to log every incoming request and exception."""
        if getattr(app, "_pontifex_logger_initialized", False):
            return
        app._pontifex_logger_initialized = True

        @app.before_request
        def record_start_time():
            g.logger_request_start = time.monotonic()

        @app.after_request
        def log_request_completion(response):
            try:
                start = getattr(g, "logger_request_start", None)
                duration_ms = (
                    (time.monotonic() - start) * 1000.0 if start is not None else 0.0
                )
                caller = self.get_caller_identity()
                status = response.status_code
                method = request.method
                path = request.path

                level = logging.INFO
                if status >= 500:
                    level = logging.ERROR
                elif status >= 400:
                    level = logging.WARNING

                msg = self._format_msg(
                    f"{method} {path} status={status} duration={duration_ms:.2f}ms",
                    caller=caller,
                )
                self._logger.log(level, msg)
            except Exception as err:
                sys.stderr.write(f"Logger error in after_request: {err}\n")
            return response

        @app.teardown_request
        def log_teardown_exception(exc):
            if exc:
                caller = self.get_caller_identity()
                self.error(
                    f"Unhandled error during {request.method} {request.path}: {exc}",
                    caller=caller,
                    exc_info=exc,
                )

    def flush(self) -> None:
        """Flush the file handler."""
        if self._file_handler:
            self._file_handler.flush()

    def close(self) -> None:
        """Close log handlers on shutdown."""
        if self._file_handler:
            self._file_handler.close()
            self._logger.removeHandler(self._file_handler)
            self._file_handler = None
