"""SaaS Multi-Tenant Permissions

Standard three-tier role hierarchy for tenant-scoped SaaS products.
Owner controls billing and user management, admin handles day-to-day
operations, members have read/write access to core resources.

Tenant isolation is assumed to be handled separately (RLS, middleware, etc.).
This template only covers role-based permissions within a tenant.

Copy this file into your project and customize the Permission enum
for your domain.
"""

from enum import Enum
from typing import Set

from b3dmar_auth.rbac import PermissionChecker


class Role(str, Enum):
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"


class Permission(str, Enum):
    # Core resource CRUD — rename to your domain (e.g. job:view, project:create)
    RESOURCE_VIEW = "resource:view"
    RESOURCE_CREATE = "resource:create"
    RESOURCE_UPDATE = "resource:update"
    RESOURCE_DELETE = "resource:delete"
    RESOURCE_EXPORT = "resource:export"

    # Configuration / settings within the tenant
    CONFIG_VIEW = "config:view"
    CONFIG_MANAGE = "config:manage"

    # User management within the tenant
    USER_VIEW = "user:view"
    USER_INVITE = "user:invite"
    USER_MANAGE = "user:manage"  # role changes, deactivation

    # Billing
    BILLING_VIEW = "billing:view"
    BILLING_MANAGE = "billing:manage"


ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.MEMBER: {
        Permission.RESOURCE_VIEW,
        Permission.RESOURCE_CREATE,
        Permission.RESOURCE_UPDATE,
        Permission.RESOURCE_EXPORT,
        Permission.CONFIG_VIEW,
    },
    Role.ADMIN: {
        Permission.RESOURCE_VIEW,
        Permission.RESOURCE_CREATE,
        Permission.RESOURCE_UPDATE,
        Permission.RESOURCE_DELETE,
        Permission.RESOURCE_EXPORT,
        Permission.CONFIG_VIEW,
        Permission.CONFIG_MANAGE,
        Permission.USER_VIEW,
        Permission.USER_INVITE,
        Permission.BILLING_VIEW,
    },
    Role.OWNER: set(Permission),  # all permissions
}


# --- Wiring example (paste into your deps.py) ---
#
# from myapp.deps import get_current_user
#
# checker = PermissionChecker(
#     get_current_user=get_current_user,
#     role_enum=Role,
#     permission_matrix=ROLE_PERMISSIONS,
# )
#
# @router.delete("/{id}")
# async def delete_resource(
#     user: Annotated[User, Depends(checker.require(Permission.RESOURCE_DELETE))],
# ):
#     ...
