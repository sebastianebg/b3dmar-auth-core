"""Minimal Admin/User Permissions

Simplest possible setup: two roles, binary admin check.
Good starting point for early-stage projects that need auth
but don't yet need granular permissions.

Upgrade path: add roles and permissions as your product grows
without changing the wiring pattern.
"""

from enum import Enum
from typing import Set

from b3dmar_auth.rbac import PermissionChecker


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class Permission(str, Enum):
    # Standard CRUD
    READ = "resource:read"
    WRITE = "resource:write"
    DELETE = "resource:delete"

    # Admin
    USER_MANAGE = "user:manage"
    SYSTEM_CONFIG = "system:config"


ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.USER: {
        Permission.READ,
        Permission.WRITE,
    },
    Role.ADMIN: set(Permission),
}


# --- Wiring example ---
#
# checker = PermissionChecker(
#     get_current_user=get_current_user,
#     role_enum=Role,
#     permission_matrix=ROLE_PERMISSIONS,
# )
#
# # Any authenticated user
# @router.get("/items")
# async def list_items(
#     user: Annotated[User, Depends(checker.require(Permission.READ))],
# ): ...
#
# # Admin only
# @router.delete("/users/{id}")
# async def delete_user(
#     user: Annotated[User, Depends(checker.require(Permission.USER_MANAGE))],
# ): ...
