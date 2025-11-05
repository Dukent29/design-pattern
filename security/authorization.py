"""Authorization helpers implementing RBAC and decorators."""

from __future__ import annotations

from functools import wraps
from typing import Callable, Iterable, Mapping, MutableMapping, Optional, Set, TypeVar

from flask import abort, flash, redirect, url_for

from .authentication import auth_enforcer
from .audit import audit_event


F = TypeVar("F", bound=Callable[..., object])

_DEFAULT_ROLE_PERMISSIONS: Mapping[str, Set[str]] = {
    "admin": {"read", "write", "delete", "admin"},
    "editor": {"read", "write"},
    "viewer": {"read"},
}


class AuthorizationEnforcer:
    """Centralized RBAC engine for route protection and permission checks."""

    def __init__(
        self,
        role_permissions: Optional[Mapping[str, Iterable[str]]] = None,
        resource_permissions: Optional[Mapping[str, Mapping[str, Iterable[str]]]] = None,
    ) -> None:
        role_permissions = role_permissions or _DEFAULT_ROLE_PERMISSIONS
        self._role_permissions: MutableMapping[str, Set[str]] = {
            role.lower(): {permission.lower() for permission in permissions}
            for role, permissions in role_permissions.items()
        }
        self._resource_permissions: MutableMapping[str, MutableMapping[str, Set[str]]] = {
            resource.lower(): {
                role.lower(): {action.lower() for action in actions}
                for role, actions in role_map.items()
            }
            for resource, role_map in (resource_permissions or {}).items()
        }

    def permissions_for(self, role: str) -> Set[str]:
        """Return the permission set for the given role (case insensitive)."""
        if not role:
            return set()
        return set(self._role_permissions.get(role.lower(), set()))

    def can_access(self, user: Optional[Mapping[str, str]], resource: str, action: str) -> bool:
        """Evaluate whether the provided user can perform an action on a resource."""
        if not user:
            return False

        role = (user.get("role") or "").lower()
        if not role:
            return False

        permissions = self._role_permissions.get(role, set())
        if not permissions:
            return False

        normalized_action = action.lower()
        # Admin permission acts as a wildcard for all actions.
        if "admin" in permissions:
            return True

        resource_key = resource.lower()
        resource_rules = self._resource_permissions.get(resource_key)
        if resource_rules is not None:
            allowed_actions = resource_rules.get(role, set())
            return normalized_action in allowed_actions

        return normalized_action in permissions


authorization_enforcer = AuthorizationEnforcer()


def current_user() -> Optional[dict]:
    """Return the current user dictionary stored in the session."""
    user = auth_enforcer.check_authentication()
    if not user:
        return None
    return {"username": user.username, "role": user.role}


def require_roles(*allowed_roles: str) -> Callable[[F], F]:
    """
    Protect a Flask route with role-based access control.

    When the wrapped view is called, the current user is injected as the keyword
    argument ``user``. If no user is logged in, the client is redirected to the
    login page. If the user lacks the required role, a 403 error is raised.
    """

    normalized_roles = {role.lower() for role in allowed_roles}

    def decorator(view_func: F) -> F:
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login"))

            role = (user.get("role") or "").lower()
            if normalized_roles and role not in normalized_roles:
                flash("You do not have permission to view that page.", "error")
                audit_event("authorization_denied", user.get("username"), {"required_roles": ",".join(normalized_roles)})
                abort(403)

            kwargs.setdefault("user", user)
            return view_func(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator


def require_permission(resource: str, action: str) -> Callable[[F], F]:
    """
    Decorator enforcing fine-grained permission checks for a resource.

    The decorated view receives the current user in the ``user`` keyword argument.
    """

    def decorator(view_func: F) -> F:
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))

            if not authorization_enforcer.can_access(user, resource, action):
                flash("You do not have the required permission for that action.", "error")
                audit_event(
                    "authorization_denied",
                    user.get("username"),
                    {"resource": resource, "action": action},
                )
                abort(403)

            kwargs.setdefault("user", user)
            return view_func(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator
