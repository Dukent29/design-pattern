"""Authentication helpers for the security demo app."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

from .audit import audit_event
from .db import get_session, init_db
from .models import User

try:
    from sqlalchemy import select
    from sqlalchemy.exc import SQLAlchemyError
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy is required for database persistence. Install it with 'pip install sqlalchemy'."
    ) from exc


@dataclass(frozen=True)
class AuthenticatedUser:
    """Simple data object representing an authenticated user."""

    username: str
    role: str


_DEFAULT_USERS = (
    ("admin", "Admin#1234", "admin"),
    ("alice", "User#1234", "editor"),
    ("bob", "AnalystPass123!", "viewer"),
    ("carol", "ViewerPass123!", "viewer"),
    ("charlie", "User#1234", "viewer"),
)


class SQLUserStore:
    """MySQL-backed user repository."""

    def __init__(self) -> None:
        init_db()
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        with get_session() as session:
            for username, password, role in _DEFAULT_USERS:
                normalized = username.lower()
                exists = session.scalar(select(User.id).where(User.username == normalized))
                if exists:
                    continue
                user = User(
                    username=normalized,
                    password_hash=generate_password_hash(password),
                    role=role.lower(),
                )
                session.add(user)

    def find_by_username(self, username: str) -> Optional[User]:
        if not username:
            return None
        with get_session() as session:
            return session.scalar(select(User).where(User.username == username.lower()))

    def create_user(self, username: str, password: str, role: str) -> User:
        normalized_username = (username or "").strip().lower()
        if not normalized_username:
            raise ValueError("Le nom d’utilisateur est obligatoire.")

        with get_session() as session:
            existing = session.scalar(select(User).where(User.username == normalized_username))
            if existing:
                raise ValueError("Cet utilisateur existe déjà.")

            if not role:
                raise ValueError("Le rôle est obligatoire.")

            user = User(
                username=normalized_username,
                password_hash=generate_password_hash(password),
                role=role.lower(),
            )
            session.add(user)
            session.flush()
            session.refresh(user)
            return user


class AuthenticationEnforcer:
    """Centralized authentication manager implementing security patterns."""

    SESSION_KEY = "user"
    EXPIRES_AT_KEY = "expires_at"
    SESSION_DURATION = timedelta(minutes=30)

    def __init__(
        self,
        user_store: Optional[SQLUserStore] = None,
    ) -> None:
        self._user_store = user_store or SQLUserStore()

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

        try:
            record = self._user_store.find_by_username(username)
        except SQLAlchemyError as exc:
            audit_event("login_failed", username, {"reason": "db_error"})
            raise RuntimeError(f"Database error while fetching user: {exc}") from exc

        if not record:
            audit_event("login_failed", username, {"reason": "unknown_user"})
            return None

        if not check_password_hash(record.password_hash, password):
            audit_event("login_failed", username, {"reason": "invalid_password"})
            return None

        user = AuthenticatedUser(username=record.username, role=record.role)
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
        refreshed_data = dict(session[self.SESSION_KEY])
        refreshed_data[self.EXPIRES_AT_KEY] = self._new_expiry().isoformat()
        session[self.SESSION_KEY] = refreshed_data
        return refreshed_user

    def logout(self) -> None:
        """Terminate the current session and log the event."""
        data = session.pop(self.SESSION_KEY, None)
        username = data.get("username") if isinstance(data, dict) else None
        audit_event("logout", username)

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
    ) -> AuthenticatedUser:
        """Create a new user in the backing user store."""
        try:
            record = self._user_store.create_user(username, password, role)
        except SQLAlchemyError as exc:
            audit_event("user_creation_failed", username, {"reason": "db_error"})
            raise RuntimeError(f"Database error while creating user: {exc}") from exc

        audit_event("user_created", record.username, {"role": record.role})
        return AuthenticatedUser(username=record.username, role=record.role)


auth_enforcer = AuthenticationEnforcer()


def authenticate_user(username: str, password: str) -> Optional[AuthenticatedUser]:
    """Backwards-compatible wrapper around the AuthenticationEnforcer."""
    return auth_enforcer.authenticate(username, password)
