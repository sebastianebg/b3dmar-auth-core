"""Generic RBAC types and FastAPI dependency factories.

DB-agnostic: each consuming project provides its own Role/Permission enums
and a user-lookup callable. This module provides the permission-checking
logic and FastAPI `Depends()` factories.
"""

from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any, TypeVar

from fastapi import Depends, HTTPException, status

R = TypeVar("R", bound=Enum)
P = TypeVar("P", bound=Enum)

# Type alias: maps each role to a set of permissions it holds
RolePermissionMatrix = dict[Any, set[Any]]


def has_permission(
    role: str,
    permission: Any,
    matrix: RolePermissionMatrix,
    role_enum: type[Enum],
) -> bool:
    """Check if a role has a specific permission.

    Args:
        role: Role value as stored in the DB (string).
        permission: Permission enum member to check.
        matrix: Role-to-permissions mapping dict.
        role_enum: The Role enum class to parse the string into.

    Returns:
        True if the role holds the permission, False if role is unknown or lacks it.
    """
    try:
        parsed_role = role_enum(role)
        return permission in matrix.get(parsed_role, set())
    except ValueError:
        return False


def get_permissions_for_role(
    role: str,
    matrix: RolePermissionMatrix,
    role_enum: type[Enum],
) -> set[Any]:
    """Get all permissions for a given role string."""
    try:
        parsed_role = role_enum(role)
        return matrix.get(parsed_role, set())
    except ValueError:
        return set()


# --- FastAPI dependency factories ---
#
# These are parameterized factories. Each consuming project calls them with
# its own Permission enum values and a `get_current_user` dependency that
# returns a user object with a `.role` attribute.
#
# Usage:
#     from b3dmar_auth import require_permission
#     from myapp.permissions import Permission
#     from myapp.deps import get_current_user
#
#     checker = PermissionChecker(
#         get_current_user=get_current_user,
#         role_enum=Role,
#         permission_matrix=ROLE_PERMISSIONS,
#     )
#
#     @router.delete("/{id}")
#     async def delete_item(
#         current_user: Annotated[User, Depends(checker.require(Permission.ITEM_DELETE))],
#     ):
#         ...


class PermissionChecker:
    """Configurable FastAPI permission dependency factory.

    Instantiate once per project with your user-lookup dependency,
    role enum, and permission matrix. Then call `.require()`,
    `.require_any()`, or `.require_all()` to generate FastAPI deps.
    """

    def __init__(
        self,
        get_current_user: Callable[..., Awaitable[Any]],
        role_enum: type[Enum],
        permission_matrix: RolePermissionMatrix,
        role_attribute: str = "role",
        superuser_attribute: str | None = None,
    ):
        """
        Args:
            get_current_user: FastAPI dependency that returns the authenticated user object.
            role_enum: The project's Role enum class.
            permission_matrix: Mapping of Role -> set of Permission values.
            role_attribute: Attribute name on the user object that holds the role string.
            superuser_attribute: If set, attribute name for a boolean superuser bypass flag.
        """
        self._get_current_user = get_current_user
        self._role_enum = role_enum
        self._matrix = permission_matrix
        self._role_attr = role_attribute
        self._superuser_attr = superuser_attribute

    def _check(self, user: Any, permission: Any) -> bool:
        if self._superuser_attr and getattr(user, self._superuser_attr, False):
            return True
        role = getattr(user, self._role_attr)
        return has_permission(role, permission, self._matrix, self._role_enum)

    def require(self, permission: Any) -> Callable[..., Any]:
        """Dependency factory: require a single permission."""
        get_user = self._get_current_user

        async def _check_permission(
            user: Any = Depends(get_user),
        ) -> Any:
            if not self._check(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission.value} required",
                )
            return user

        return _check_permission

    def require_any(self, *permissions: Any) -> Callable[..., Any]:
        """Dependency factory: require any one of the given permissions."""
        get_user = self._get_current_user

        async def _check_any(
            user: Any = Depends(get_user),
        ) -> Any:
            if not any(self._check(user, p) for p in permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: one of {[p.value for p in permissions]} required",
                )
            return user

        return _check_any

    def require_all(self, *permissions: Any) -> Callable[..., Any]:
        """Dependency factory: require all of the given permissions."""
        get_user = self._get_current_user

        async def _check_all(
            user: Any = Depends(get_user),
        ) -> Any:
            missing = [p for p in permissions if not self._check(user, p)]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {[p.value for p in missing]} required",
                )
            return user

        return _check_all


# --- Standalone factory functions (for projects that prefer free functions) ---


def require_permission(
    permission: Any,
    get_current_user: Callable[..., Awaitable[Any]],
    role_enum: type[Enum],
    permission_matrix: RolePermissionMatrix,
    role_attribute: str = "role",
) -> Callable[..., Any]:
    """Standalone require_permission factory (non-class API)."""
    checker = PermissionChecker(
        get_current_user=get_current_user,
        role_enum=role_enum,
        permission_matrix=permission_matrix,
        role_attribute=role_attribute,
    )
    return checker.require(permission)


def require_any_permission(
    *permissions: Any,
    get_current_user: Callable[..., Awaitable[Any]],
    role_enum: type[Enum],
    permission_matrix: RolePermissionMatrix,
    role_attribute: str = "role",
) -> Callable[..., Any]:
    """Standalone require_any_permission factory."""
    checker = PermissionChecker(
        get_current_user=get_current_user,
        role_enum=role_enum,
        permission_matrix=permission_matrix,
        role_attribute=role_attribute,
    )
    return checker.require_any(*permissions)


def require_all_permissions(
    *permissions: Any,
    get_current_user: Callable[..., Awaitable[Any]],
    role_enum: type[Enum],
    permission_matrix: RolePermissionMatrix,
    role_attribute: str = "role",
) -> Callable[..., Any]:
    """Standalone require_all_permissions factory."""
    checker = PermissionChecker(
        get_current_user=get_current_user,
        role_enum=role_enum,
        permission_matrix=permission_matrix,
        role_attribute=role_attribute,
    )
    return checker.require_all(*permissions)
