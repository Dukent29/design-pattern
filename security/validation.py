"""Input validation helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping


class InputValidator:
    """Whitelist-based input validation and sanitization utilities."""

    EMAIL_RE = re.compile(
        r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$"
    )
    PASSWORD_RE = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$"
    )
    USERNAME_RE = re.compile(r"^[A-Za-z0-9]{3,20}$")

    HTML_ESCAPE_MAP = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;",
    }

    SQL_PATTERNS = [
        re.compile(r"(?i)\bunion\s+select\b"),
        re.compile(r"(?i)\bdrop\s+table\b"),
        re.compile(r"(?i)\binsert\s+into\b"),
        re.compile(r"(?i)\bdelete\s+from\b"),
        re.compile(r"(?i)\bupdate\s+\w+\s+set\b"),
        re.compile(r"(?i)\bexec(?:ute)?\s"),
        re.compile(r"(?i)(?:'|\"|\b)\s*or\s+(?:'|\"|)\s*1\s*=\s*1"),
    ]

    SQL_TOKENS = (
        "--",
        ";--",
        ";#",
        "/*",
        "*/",
        "@@",
        " or 1=1",
        "' or '1'='1",
        "\" or \"1\"=\"1",
    )

    def validate_email(self, value: str) -> bool:
        """Return True if the value matches a basic email format."""
        if not value:
            return False
        return bool(self.EMAIL_RE.fullmatch(value.strip()))

    def validate_password(self, value: str) -> bool:
        """Ensure the password meets complexity rules."""
        if not value:
            return False
        return bool(self.PASSWORD_RE.fullmatch(value))

    def validate_username(self, value: str) -> bool:
        """Validate usernames (3-20 alphanumeric characters)."""
        if not value:
            return False
        return bool(self.USERNAME_RE.fullmatch(value.strip()))

    def validate_age(self, value: int | str) -> bool:
        """Ensure age is an integer between 13 and 120."""
        try:
            age = int(value)
        except (TypeError, ValueError):
            return False
        return 13 <= age <= 120

    def sanitize_html(self, value: str) -> str:
        """Escape HTML-sensitive characters for safe rendering."""
        if value is None:
            return ""
        escaped = value
        for char, replacement in self.HTML_ESCAPE_MAP.items():
            escaped = escaped.replace(char, replacement)
        return escaped

    def detect_sql_injection(self, value: str) -> bool:
        """Detect obvious signatures of SQL injection attempts."""
        if not value:
            return False

        for pattern in self.SQL_PATTERNS:
            if pattern.search(value):
                return True

        lowered = value.lower()
        return any(token in lowered for token in self.SQL_TOKENS)


@dataclass(frozen=True)
class ValidationResult:
    """Represents the result of validating user-supplied input."""

    is_valid: bool
    data: Dict[str, str]
    errors: List[str]


_validator = InputValidator()


def validate_login_form(form: Mapping[str, str]) -> ValidationResult:
    """Validate login form data and return a structured result."""
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""

    errors: List[str] = []

    if not username:
        errors.append("Username is required.")
    elif not _validator.validate_username(username):
        errors.append("Username must be 3-20 alphanumeric characters.")

    if not password:
        errors.append("Password is required.")
    elif not _validator.validate_password(password):
        errors.append(
            "Password must be 8+ chars and include upper, lower, number, and special characters."
        )

    return ValidationResult(
        is_valid=not errors,
        data={"username": username, "password": password},
        errors=errors,
    )
