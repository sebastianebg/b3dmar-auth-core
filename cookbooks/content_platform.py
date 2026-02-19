"""Content Platform Permissions

Three-tier role hierarchy for content-centric apps: knowledge bases,
CMS, note-taking, wikis, document management.

Viewer can read, editor can create/modify, admin manages users and system.
No multi-tenancy assumed — each user owns their own content.
"""

from enum import Enum
from typing import Set

from b3dmar_auth.rbac import PermissionChecker


class Role(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


class Permission(str, Enum):
    # Content lifecycle
    CONTENT_VIEW = "content:view"
    CONTENT_CREATE = "content:create"
    CONTENT_UPDATE = "content:update"
    CONTENT_DELETE = "content:delete"

    # Search / discovery
    SEARCH = "search:execute"

    # Collections / folders / tags
    ORGANIZE_VIEW = "organize:view"
    ORGANIZE_MANAGE = "organize:manage"

    # Import / export
    IMPORT = "data:import"
    EXPORT = "data:export"

    # User & invite management
    USER_VIEW = "user:view"
    USER_MANAGE = "user:manage"
    INVITE_MANAGE = "invite:manage"

    # Billing & system
    BILLING_MANAGE = "billing:manage"
    SYSTEM_CONFIG = "system:config"


ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.CONTENT_VIEW,
        Permission.SEARCH,
        Permission.ORGANIZE_VIEW,
        Permission.EXPORT,
    },
    Role.EDITOR: {
        Permission.CONTENT_VIEW,
        Permission.CONTENT_CREATE,
        Permission.CONTENT_UPDATE,
        Permission.CONTENT_DELETE,
        Permission.SEARCH,
        Permission.ORGANIZE_VIEW,
        Permission.ORGANIZE_MANAGE,
        Permission.IMPORT,
        Permission.EXPORT,
    },
    Role.ADMIN: set(Permission),  # all permissions
}


# --- Wiring example ---
#
# checker = PermissionChecker(
#     get_current_user=get_current_user,
#     role_enum=Role,
#     permission_matrix=ROLE_PERMISSIONS,
# )
#
# # Viewer+ can read
# @router.get("/documents")
# async def list_docs(
#     user: Annotated[User, Depends(checker.require(Permission.CONTENT_VIEW))],
# ): ...
#
# # Editor+ can write
# @router.post("/documents")
# async def create_doc(
#     user: Annotated[User, Depends(checker.require(Permission.CONTENT_CREATE))],
# ): ...
#
# # Admin only
# @router.post("/invites")
# async def create_invite(
#     user: Annotated[User, Depends(checker.require(Permission.INVITE_MANAGE))],
# ): ...
