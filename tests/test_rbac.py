"""Tests for RBAC permission checking and FastAPI dependency factories."""

from dataclasses import dataclass
from enum import Enum

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from b3dmar_auth.rbac import (
    PermissionChecker,
    get_permissions_for_role,
    has_permission,
)


# Test enums mimicking a real project
class Role(str, Enum):
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"


class Permission(str, Enum):
    READ = "item:read"
    WRITE = "item:write"
    DELETE = "item:delete"
    MANAGE_USERS = "user:manage"


MATRIX: dict[Role, set[Permission]] = {
    Role.MEMBER: {Permission.READ},
    Role.ADMIN: {Permission.READ, Permission.WRITE, Permission.DELETE},
    Role.OWNER: {Permission.READ, Permission.WRITE, Permission.DELETE, Permission.MANAGE_USERS},
}


class TestHasPermission:
    def test_member_can_read(self) -> None:
        assert has_permission("member", Permission.READ, MATRIX, Role)

    def test_member_cannot_write(self) -> None:
        assert not has_permission("member", Permission.WRITE, MATRIX, Role)

    def test_admin_can_delete(self) -> None:
        assert has_permission("admin", Permission.DELETE, MATRIX, Role)

    def test_admin_cannot_manage_users(self) -> None:
        assert not has_permission("admin", Permission.MANAGE_USERS, MATRIX, Role)

    def test_owner_has_all(self) -> None:
        for perm in Permission:
            assert has_permission("owner", perm, MATRIX, Role)

    def test_unknown_role_denied(self) -> None:
        assert not has_permission("hacker", Permission.READ, MATRIX, Role)


class TestGetPermissionsForRole:
    def test_member_permissions(self) -> None:
        perms = get_permissions_for_role("member", MATRIX, Role)
        assert perms == {Permission.READ}

    def test_unknown_role(self) -> None:
        perms = get_permissions_for_role("unknown", MATRIX, Role)
        assert perms == set()


# --- FastAPI integration tests ---


@dataclass
class FakeUser:
    id: str
    role: str
    is_superuser: bool = False


async def fake_get_current_user() -> FakeUser:
    """Default: returns a member user."""
    return FakeUser(id="user-1", role="member")


async def fake_get_admin_user() -> FakeUser:
    return FakeUser(id="user-2", role="admin")


async def fake_get_superuser() -> FakeUser:
    return FakeUser(id="user-3", role="member", is_superuser=True)


class TestPermissionChecker:
    def test_require_allowed(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_current_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.get("/items")
        async def read_items(user: FakeUser = Depends(checker.require(Permission.READ))) -> dict:
            return {"user": user.id}

        client = TestClient(app)
        resp = client.get("/items")
        assert resp.status_code == 200
        assert resp.json()["user"] == "user-1"

    def test_require_denied(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_current_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.delete("/items/{id}")
        async def delete_item(user: FakeUser = Depends(checker.require(Permission.DELETE))) -> dict:
            return {"deleted": True}

        client = TestClient(app)
        resp = client.delete("/items/1")
        assert resp.status_code == 403
        assert "item:delete" in resp.json()["detail"]

    def test_require_any_one_matches(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_current_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.get("/mixed")
        async def mixed(
            user: FakeUser = Depends(checker.require_any(Permission.READ, Permission.WRITE)),
        ) -> dict:
            return {"ok": True}

        client = TestClient(app)
        assert client.get("/mixed").status_code == 200

    def test_require_any_none_match(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_current_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.get("/admin-stuff")
        async def admin_stuff(
            user: FakeUser = Depends(
                checker.require_any(Permission.DELETE, Permission.MANAGE_USERS)
            ),
        ) -> dict:
            return {"ok": True}

        client = TestClient(app)
        assert client.get("/admin-stuff").status_code == 403

    def test_require_all(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_admin_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.post("/dangerous")
        async def dangerous(
            user: FakeUser = Depends(
                checker.require_all(Permission.WRITE, Permission.DELETE)
            ),
        ) -> dict:
            return {"ok": True}

        client = TestClient(app)
        assert client.post("/dangerous").status_code == 200

    def test_require_all_partial_denied(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_admin_user,
            role_enum=Role,
            permission_matrix=MATRIX,
        )
        app = FastAPI()

        @app.post("/owner-only")
        async def owner_only(
            user: FakeUser = Depends(
                checker.require_all(Permission.DELETE, Permission.MANAGE_USERS)
            ),
        ) -> dict:
            return {"ok": True}

        client = TestClient(app)
        resp = client.post("/owner-only")
        assert resp.status_code == 403
        assert "user:manage" in resp.json()["detail"]

    def test_superuser_bypass(self) -> None:
        checker = PermissionChecker(
            get_current_user=fake_get_superuser,
            role_enum=Role,
            permission_matrix=MATRIX,
            superuser_attribute="is_superuser",
        )
        app = FastAPI()

        @app.delete("/items/{id}")
        async def delete_item(
            user: FakeUser = Depends(checker.require(Permission.MANAGE_USERS)),
        ) -> dict:
            return {"deleted": True}

        client = TestClient(app)
        resp = client.delete("/items/1")
        assert resp.status_code == 200
