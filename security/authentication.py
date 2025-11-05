"""Authentication helpers for the security demo app."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Mapping, Optional

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from .audit import audit_event


@dataclass(frozen=True)
class AuthenticatedUser:
    """Simple data object representing an authenticated user."""

    username: str
    role: str


def _build_user_store() -> Dict[str, Dict[str, str]]:
    """Create an in-memory user store with hashed passwords."""

    def _hashed(password: str) -> str:
        return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

    return {
        "admin": {
            "username": "admin",
            "password_hash": _hashed("Admin#1234"),
            "role": "admin",
        },
        "alice": {
            "username": "alice",
            "password_hash": _hashed("User#1234"),
            "role": "editor",
        },
        "bob": {
            "username": "bob",
            "password_hash": _hashed("AnalystPass123!"),
            "role": "viewer",
        },
        "carol": {
            "username": "carol",
            "password_hash": _hashed("ViewerPass123!"),
            "role": "viewer",
        },
    }


_USERS = _build_user_store()


class AuthenticationEnforcer:
    """Centralized authentication manager implementing security patterns."""

    SESSION_KEY = "user"
    EXPIRES_AT_KEY = "expires_at"
    SESSION_DURATION = timedelta(minutes=30)

    def __init__(
        self,
        user_store: Optional[Mapping[str, Mapping[str, str]]] = None,
    ) -> None:
        self._user_store = user_store or _USERS

    def _new_expiry(self) -> datetime:
        return datetime.now(timezone.utc) + self.SESSION_DURATION

    def _persist_session(self, user: AuthenticatedUser) -> None:
        session[self.SESSION_KEY] = {
            "username": user.username,
            "role": user.role,
            self.EXPIRES_AT_KEY: self._new_expiry().isoformat(),
        }

    def authenticate(self, username: str, password: str) -> Optional[AuthenticatedUser]:
        """Validate credentials, manage session state, and return the user."""
        username = (username or "").strip()
        password = password or ""

        audit_event("login_attempt", username or None)

        if not username or not password:
            audit_event("login_failed", username or None, {"reason": "missing_credentials"})
            return None

        record = self._user_store.get(username.lower())
        if not record:
            audit_event("login_failed", username, {"reason": "unknown_user"})
            return None

        if not check_password_hash(record["password_hash"], password):
            audit_event("login_failed", username, {"reason": "invalid_password"})
            return None

        user = AuthenticatedUser(username=record["username"], role=record["role"])
        self._persist_session(user)
        audit_event("login_success", user.username)
        return user

    def check_authentication(self) -> Optional[AuthenticatedUser]:
        """Ensure the session is valid and refresh expiration."""
        data = session.get(self.SESSION_KEY)
        if not data:
            return None

        username = data.get("username")
        role = data.get("role")
        expires_at = data.get(self.EXPIRES_AT_KEY)

        if not username or not role or not expires_at:
            self.logout()
            return None

        try:
            expiry = datetime.fromisoformat(expires_at)
        except ValueError:
            self.logout()
            return None

        now = datetime.now(timezone.utc)
        if expiry <= now:
            audit_event("session_expired", username)
            self.logout()
            return None

        refreshed_user = AuthenticatedUser(username=username, role=role)
        # Sliding expiration: extend session on activity.
        refreshed_data = dict(session[self.SESSION_KEY])
        refreshed_data[self.EXPIRES_AT_KEY] = self._new_expiry().isoformat()
        session[self.SESSION_KEY] = refreshed_data
        return refreshed_user

    def logout(self) -> None:
        """Terminate the current session and log the event."""
        data = session.pop(self.SESSION_KEY, None)
        username = data.get("username") if isinstance(data, dict) else None
        audit_event("logout", username)


auth_enforcer = AuthenticationEnforcer()


def authenticate_user(username: str, password: str) -> Optional[AuthenticatedUser]:
    """Backwards-compatible wrapper around the AuthenticationEnforcer."""
    return auth_enforcer.authenticate(username, password)
