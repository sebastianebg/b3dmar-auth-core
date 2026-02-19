"""API / Data Platform Permissions

Expanded role hierarchy for platforms that process data, run pipelines,
or expose APIs to external consumers. Includes compliance and audit roles
common in regulated industries.

Suited for: ETL platforms, data processing, integration hubs, AI/ML platforms.
"""

from enum import Enum
from typing import Set

from b3dmar_auth.rbac import PermissionChecker


class Role(str, Enum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Permission(str, Enum):
    # Pipeline / workflow management
    PIPELINE_VIEW = "pipeline:view"
    PIPELINE_CREATE = "pipeline:create"
    PIPELINE_UPDATE = "pipeline:update"
    PIPELINE_DELETE = "pipeline:delete"
    PIPELINE_EXECUTE = "pipeline:execute"

    # Data access
    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_DELETE = "data:delete"
    DATA_EXPORT = "data:export"

    # Secrets / credentials
    SECRET_VIEW = "secret:view"
    SECRET_MANAGE = "secret:manage"

    # API keys
    APIKEY_VIEW = "apikey:view"
    APIKEY_MANAGE = "apikey:manage"

    # Audit & compliance
    AUDIT_READ = "audit:read"
    COMPLIANCE_REPORT = "compliance:report"

    # User & system administration
    USER_MANAGE = "user:manage"
    ROLE_MANAGE = "role:manage"
    SYSTEM_CONFIG = "system:config"


ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.PIPELINE_VIEW,
        Permission.DATA_READ,
        Permission.APIKEY_VIEW,
    },
    Role.DEVELOPER: {
        Permission.PIPELINE_VIEW,
        Permission.PIPELINE_CREATE,
        Permission.PIPELINE_UPDATE,
        Permission.PIPELINE_EXECUTE,
        Permission.DATA_READ,
        Permission.DATA_WRITE,
        Permission.SECRET_VIEW,
        Permission.APIKEY_VIEW,
        Permission.APIKEY_MANAGE,
    },
    Role.OPERATOR: {
        Permission.PIPELINE_VIEW,
        Permission.PIPELINE_EXECUTE,
        Permission.DATA_READ,
        Permission.DATA_WRITE,
        Permission.DATA_EXPORT,
        Permission.SECRET_VIEW,
        Permission.SECRET_MANAGE,
        Permission.APIKEY_VIEW,
        Permission.APIKEY_MANAGE,
        Permission.AUDIT_READ,
    },
    Role.AUDITOR: {
        Permission.PIPELINE_VIEW,
        Permission.DATA_READ,
        Permission.AUDIT_READ,
        Permission.COMPLIANCE_REPORT,
    },
    Role.ADMIN: set(Permission),  # all permissions
}


# --- Wiring example ---
#
# checker = PermissionChecker(
#     get_current_user=get_current_user,
#     role_enum=Role,
#     permission_matrix=ROLE_PERMISSIONS,
#     superuser_attribute="is_superuser",  # optional bypass flag
# )
#
# @router.post("/pipelines/{id}/execute")
# async def execute_pipeline(
#     user: Annotated[User, Depends(checker.require(Permission.PIPELINE_EXECUTE))],
# ): ...
#
# @router.get("/audit/events")
# async def list_audit_events(
#     user: Annotated[User, Depends(
#         checker.require_any(Permission.AUDIT_READ, Permission.COMPLIANCE_REPORT)
#     )],
# ): ...
