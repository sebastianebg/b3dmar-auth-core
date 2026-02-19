# b3dmar-auth-core

Shared auth primitives — stateless, DB-agnostic building blocks for JWT handling, password hashing, RBAC, and token revocation.

## Modules

| Module | What it does |
|--------|-------------|
| `jwt` | Token creation/validation — HS256, type discrimination (`access`/`refresh`), JTI, issuer/audience, extra claims |
| `password` | Argon2id hashing with OWASP-recommended parameters |
| `rbac` | Generic `PermissionChecker` with FastAPI dependency factories — bring your own Role/Permission enums |
| `revocation` | Redis per-JTI token denylist with fail-open/closed modes |
| `rate_limit` | Preconfigured slowapi limiter with standard auth endpoint rates |
| `schemas` | Pydantic models for token payloads and responses |

## Install

```bash
# From GitHub (pin to a commit SHA for production)
uv add "b3dmar-auth-core @ git+https://github.com/sebastianebg/b3dmar-auth-core.git@main"

# Local development
uv add --editable ../b3dmar-auth-core
```

## Usage

### JWT

```python
from b3dmar_auth import TokenConfig, create_access_token, create_refresh_token, decode_token

config = TokenConfig(
    secret_key="your-secret",
    access_token_expire_minutes=15,
    refresh_token_expire_days=7,
    issuer="my-app",
    audience="my-api",
)

access = create_access_token(config, subject=user_id, extra_claims={"tenant_id": "t-1"})
refresh = create_refresh_token(config, subject=user_id)

decoded = decode_token(config, access, expected_type="access")
# decoded.sub, decoded.extra["tenant_id"], decoded.jti
```

### Password Hashing

```python
from b3dmar_auth import hash_password, verify_password

hashed = hash_password("correct-horse-battery-staple")
assert verify_password("correct-horse-battery-staple", hashed)
```

### RBAC with FastAPI

```python
from enum import Enum
from b3dmar_auth import PermissionChecker

class Role(str, Enum):
    MEMBER = "member"
    ADMIN = "admin"

class Permission(str, Enum):
    READ = "item:read"
    DELETE = "item:delete"

ROLE_PERMISSIONS = {
    Role.MEMBER: {Permission.READ},
    Role.ADMIN: {Permission.READ, Permission.DELETE},
}

checker = PermissionChecker(
    get_current_user=get_current_user,  # your FastAPI dependency
    role_enum=Role,
    permission_matrix=ROLE_PERMISSIONS,
)

@router.delete("/{id}")
async def delete_item(
    user: Annotated[User, Depends(checker.require(Permission.DELETE))],
):
    ...
```

### Token Revocation

```python
from b3dmar_auth import TokenRevocation
from b3dmar_auth.revocation import FailureMode

revocation = TokenRevocation(
    redis=redis_client,
    failure_mode=FailureMode.CLOSED,  # fail-safe in production
)

await revocation.revoke(jti="abc-123", expires_at=token.exp)
if await revocation.is_revoked("abc-123"):
    raise Unauthorized
```

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest -v
ruff check src/ tests/
mypy src/
```

## Cookbooks

Ready-to-copy permission templates in [`cookbooks/`](cookbooks/):

| Template | Roles | Use case |
|----------|-------|----------|
| [`minimal_admin`](cookbooks/minimal_admin.py) | user, admin | Early-stage projects with binary admin check |
| [`content_platform`](cookbooks/content_platform.py) | viewer, editor, admin | Knowledge bases, CMS, document management |
| [`saas_multitenant`](cookbooks/saas_multitenant.py) | member, admin, owner | Tenant-scoped SaaS with billing and user management |
| [`api_platform`](cookbooks/api_platform.py) | viewer, developer, operator, auditor, admin | Data pipelines, integration hubs, regulated industries |

Copy any template into your project as a starting point, then customize the `Permission` enum for your domain.

## Design Principles

- **DB-agnostic** — never touches storage. Each consuming project provides its own user-lookup, DB layer, and tenant model.
- **Domain-agnostic** — no hardcoded roles or permissions. Each project defines its own enums and matrix.
- **Minimal surface** — only the stateless pieces that were duplicated across repos. Tenancy, RLS, audit logging, and frontend auth remain repo-specific.

