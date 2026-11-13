"""
Frontend services: browser sessions and the connection to the backend.

Sessions live in the memory of this process only (a restart signs everybody out).
The browser holds nothing but a random session id in a cookie. The refresh and
access tokens of the backend never reach the browser.
"""

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from shared.container_auth import ContainerAuthError, ContainerUnavailableError

log = logging.getLogger(__name__)

IDLE_TIMEOUT_SECONDS = 30 * 60
ABSOLUTE_TIMEOUT_SECONDS = 12 * 60 * 60
MAX_SESSIONS = 1000
# An access token that expires within this time is renewed before it is used.
ACCESS_TOKEN_MARGIN_SECONDS = 30
BACKEND_TIMEOUT_SECONDS = 15


class BackendUnavailable(Exception):
    """The backend cannot be reached or answered with something unusable."""


class BackendNotVerified(Exception):
    """The backend could not prove that it holds the shared container secret."""


class SessionExpired(Exception):
    """The backend no longer accepts the tokens of this session."""


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@dataclass
class Session:
    id: str
    csrf: str
    created: float
    last_seen: float
    username: str | None = None
    role: str | None = None
    refresh_token: str | None = None
    access_token: str | None = None
    access_expires: float = 0.0
    flashes: list = field(default_factory=list)  # [(kind, text)], shown once

    @property
    def authenticated(self) -> bool:
        return self.refresh_token is not None


class SessionStore:
    """
    Anonymous sessions only carry the CSRF token of the login and setup forms.
    Signing in replaces the session (new id), so an id planted beforehand is useless.
    """

    def __init__(self, clock=time.time) -> None:
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _expired(self, session: Session, now: float) -> bool:
        return (
            now - session.last_seen > IDLE_TIMEOUT_SECONDS
            or now - session.created > ABSOLUTE_TIMEOUT_SECONDS
        )

    def create(self) -> Session:
        with self._lock:
            now = self._clock()
            self._sessions = {k: s for k, s in self._sessions.items() if not self._expired(s, now)}
            while len(self._sessions) >= MAX_SESSIONS:
                # Anonymous sessions go first, so visitors cannot push out signed-in users.
                oldest = min(self._sessions.values(), key=lambda s: (s.authenticated, s.last_seen))
                del self._sessions[oldest.id]
            session = Session(
                id=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(32),
                created=now, last_seen=now,
            )
            self._sessions[session.id] = session
            return session

    def get(self, session_id: str) -> Session | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            now = self._clock()
            if self._expired(session, now):
                del self._sessions[session_id]
                return None
            session.last_seen = now
            return session

    def promote(self, old: Session, username: str, role: str, refresh_token: str,
                access_token: str, expires_in: int) -> Session:
        """Replace an anonymous session by a signed-in one with a new id and a new CSRF token."""
        self.destroy(old.id)
        session = self.create()
        session.username = username
        session.role = role
        self.set_tokens(session, refresh_token, access_token, expires_in)
        return session

    def set_tokens(self, session: Session, refresh_token: str, access_token: str,
                   expires_in: int) -> None:
        session.refresh_token = refresh_token
        session.access_token = access_token
        session.access_expires = self._clock() + expires_in

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def destroy_user(self, username: str, keep: str | None = None) -> None:
        """End every session of a user (except ``keep``), e.g. after a password change."""
        with self._lock:
            self._sessions = {
                k: s for k, s in self._sessions.items() if s.username != username or k == keep
            }


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class BackendClient:
    """The frontend's only way to the backend: signed requests, verified answers."""

    def __init__(self, client, clock=time.time) -> None:
        self._client = client
        self._clock = clock
        if client is not None:
            client.TIMEOUT_SECONDS = BACKEND_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls, container_auth, clock=time.time) -> "BackendClient":
        url = os.environ.get("BACKEND_URL", "")
        if not url:
            log.warning("BACKEND_URL is not set: every page that needs the backend shows an error")
            return cls(None, clock)
        return cls(container_auth.client("backend", url), clock)

    def call(self, method: str, path: str, body: dict | None = None,
             token: str | None = None) -> tuple[int, dict]:
        """One round trip. A 4xx or 5xx answer is returned, not raised."""
        if self._client is None:
            raise BackendUnavailable()
        headers = {"Authorization": f"Bearer {token}"} if token else None
        try:
            return self._client.request(method, path, body, headers=headers)
        except ContainerAuthError as exc:
            log.error("Backend could not be verified: %s", exc)
            raise BackendNotVerified() from exc
        except ContainerUnavailableError as exc:
            log.error("Backend unavailable: %s", exc)
            raise BackendUnavailable() from exc

    def call_for(self, session: Session, method: str, path: str,
                 body: dict | None = None) -> tuple[int, dict]:
        """
        A call on behalf of a signed-in user. Renews the access token when it is
        (about to be) expired and retries once when the backend rejects it.
        Raises SessionExpired when the refresh token is no longer valid.
        """
        if not session.access_token or session.access_expires - self._clock() < ACCESS_TOKEN_MARGIN_SECONDS:
            self._renew(session)
        status, data = self.call(method, path, body, session.access_token)
        if status == 401:
            self._renew(session)
            status, data = self.call(method, path, body, session.access_token)
            if status == 401:
                raise SessionExpired()
        return status, data

    def _renew(self, session: Session) -> None:
        status, data = self.call("POST", "/api/token", {"refresh_token": session.refresh_token})
        if status == 401:
            raise SessionExpired()
        token = data.get("access_token")
        if status != 200 or not isinstance(token, str):
            raise BackendUnavailable()
        expires_in = data.get("expires_in")
        session.access_token = token
        session.access_expires = self._clock() + (expires_in if isinstance(expires_in, int) else 300)
