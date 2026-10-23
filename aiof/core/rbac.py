from __future__ import annotations

from typing import Set, Dict, List, Optional
from functools import wraps


class PermissionDeniedError(Exception):
    def __init__(self, message: str, status_code: int = 403):
        super().__init__(message)
        self.status_code = status_code
        self.detail = message


ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "Admin": {"*"},
    "Senior Analyst": {
        "case:create",
        "case:read",
        "case:update",
        "evidence:add",
        "integration:run",
        "alert:triage",
        "report:generate",
        "audit:read",
    },
    "Junior Analyst": {
        "case:read",
        "evidence:add",
        "alert:triage",
        "report:generate",
    },
    "Auditor": {
        "case:read",
        "audit:read",
        "report:generate",
        "compliance:export",
    },
    "Guest": {
        "case:read",
    },
}


class RBACManager:
    @staticmethod
    def has_permission(role: str, permission: str) -> bool:
        perms = ROLE_PERMISSIONS.get(role, set())
        if "*" in perms:
            return True
        return permission in perms

    @staticmethod
    def verify_access(role: str, required_permission: str) -> bool:
        if not RBACManager.has_permission(role, required_permission):
            raise PermissionDeniedError(
                f"Access denied: Role '{role}' lacks required permission '{required_permission}'"
            )
        return True


def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, x_user_role: Optional[str] = "Junior Analyst", **kwargs):
            RBACManager.verify_access(x_user_role or "Junior Analyst", permission)
            return await func(*args, x_user_role=x_user_role, **kwargs)
        return wrapper
    return decorator
