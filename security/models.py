"""SQLAlchemy models for the security application."""

from __future__ import annotations

try:
    from sqlalchemy import Column, DateTime, Integer, String, func
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy is required for database persistence. Install it with 'pip install sqlalchemy'."
    ) from exc

from .db import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"mysql_charset": "utf8mb4"}

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User username={self.username!r} role={self.role!r}>"
