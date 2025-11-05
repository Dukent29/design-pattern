"""Audit logging utilities for security-relevant events."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Mapping, Optional

from flask import has_request_context, request

_LOGGER_NAME = "security.audit"
_LOG_PATH = (Path(__file__).resolve().parent.parent / "security.log").resolve()
_MAX_BYTES = 512_000
_BACKUP_COUNT = 3


def _safe_details(details: Optional[Any]) -> Any:
    if details is None:
        return {}
    if isinstance(details, Mapping):
        return dict(details)
    return details


class SecurityAuditLogger:
    """Structured audit logger that writes JSON entries to a rotating file."""

    def __init__(self, log_file: Optional[Path] = None) -> None:
        self.log_path = Path(log_file) if log_file else _LOG_PATH
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        logger_name = f"{_LOGGER_NAME}.{self.log_path.name}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.log_path,
                maxBytes=_MAX_BYTES,
                backupCount=_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def log(
        self,
        event_type: str,
        user: Optional[str],
        ip_address: Optional[str],
        severity: str,
        details: Optional[Any] = None,
    ) -> None:
        severity_normalized = (severity or "INFO").upper()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user": user or "-",
            "ip_address": ip_address or "-",
            "severity": severity_normalized,
            "details": _safe_details(details),
        }
        message = json.dumps(entry, default=str, separators=(",", ":"))

        if severity_normalized == "ERROR":
            self.logger.error(message)
        elif severity_normalized in {"WARN", "WARNING"}:
            self.logger.warning(message)
        else:
            self.logger.info(message)


_DEFAULT_AUDIT_LOGGER = SecurityAuditLogger()


def _resolve_ip(explicit_ip: Optional[str]) -> Optional[str]:
    if explicit_ip:
        return explicit_ip
    if not has_request_context():
        return None

    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or request.remote_addr
    return request.remote_addr


def audit_event(
    event: str,
    username: Optional[str],
    metadata: Optional[Mapping[str, Any]] = None,
    *,
    severity: str = "INFO",
    ip_address: Optional[str] = None,
) -> None:
    """Record a security-relevant event for later review using structured JSON logs."""
    resolved_ip = _resolve_ip(ip_address)
    _DEFAULT_AUDIT_LOGGER.log(
        event_type=event,
        user=username,
        ip_address=resolved_ip,
        severity=severity,
        details=_safe_details(metadata),
    )
