"""b3dmar-auth-core: Shared auth primitives."""

from b3dmar_auth.jwt import (
    TokenConfig,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from b3dmar_auth.password import hash_password, verify_password
from b3dmar_auth.rbac import (
    PermissionChecker,
    has_permission,
    require_all_permissions,
    require_any_permission,
    require_permission,
)
from b3dmar_auth.revocation import TokenRevocation
from b3dmar_auth.schemas import TokenPayload, TokenResponse
from b3dmar_auth.state import StateSigner, StateSignerConfig

__all__ = [
    "PermissionChecker",
    "StateSigner",
    "StateSignerConfig",
    "TokenConfig",
    "TokenPayload",
    "TokenResponse",
    "TokenRevocation",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "has_permission",
    "hash_password",
    "require_all_permissions",
    "require_any_permission",
    "require_permission",
    "verify_password",
]
