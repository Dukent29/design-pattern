"""Audit logging utilities for security-relevant events."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Mapping, Optional


_LOGGER_NAME = "security.audit"
_LOG_PATH = (Path(__file__).resolve().parent.parent / "security.log").resolve()


def _configure_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(_LOG_PATH, encoding="utf-8")
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


_LOGGER = _configure_logger()


def audit_event(event: str, username: Optional[str], metadata: Optional[Mapping[str, str]] = None) -> None:
    """Record a security-relevant event for later review."""
    safe_user = username or "anonymous"
    safe_metadata = metadata or {}
    metadata_str = " ".join(f"{key}={value}" for key, value in safe_metadata.items())
    message = f"event={event} user={safe_user}"
    if metadata_str:
        message = f"{message} {metadata_str}"

    _LOGGER.info(message)
