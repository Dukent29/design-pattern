"""Database utilities for SQL-backed persistence."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

try:
    import pymysql  # noqa: F401  (ensure driver available)
except ImportError as exc:  # pragma: no cover - surface helpful error
    raise RuntimeError(
        "PyMySQL is required for MySQL connectivity. Install it with 'pip install pymysql'."
    ) from exc

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, declarative_base, scoped_session, sessionmaker
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "SQLAlchemy is required for database persistence. Install it with 'pip install sqlalchemy'."
    ) from exc

# Default credentials: root user without password on localhost, DB named security-patterns.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:@localhost:3306/security-patterns",
)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    future=True,
)

SessionFactory = scoped_session(
    sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        future=True,
        expire_on_commit=False,
    )
)

Base = declarative_base()


def init_db() -> None:
    """Create database tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session() -> Iterator[Session]:
    """Provide a transactional scope for operations."""
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
