"""Tests for Redis-based token revocation."""

from datetime import datetime, timedelta, timezone

import pytest

from b3dmar_auth.revocation import FailureMode, TokenRevocation

fakeredis = pytest.importorskip("fakeredis")


@pytest.fixture
async def redis():
    server = fakeredis.FakeAsyncRedis()
    yield server
    await server.flushall()


@pytest.fixture
def revocation_closed(redis) -> TokenRevocation:
    return TokenRevocation(redis=redis, failure_mode=FailureMode.CLOSED)


@pytest.fixture
def revocation_open(redis) -> TokenRevocation:
    return TokenRevocation(redis=redis, failure_mode=FailureMode.OPEN)


class TestTokenRevocation:
    async def test_revoke_and_check(self, revocation_closed: TokenRevocation) -> None:
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await revocation_closed.revoke("jti-1", expires)
        assert await revocation_closed.is_revoked("jti-1")

    async def test_unrevoked_token(self, revocation_closed: TokenRevocation) -> None:
        assert not await revocation_closed.is_revoked("jti-unknown")

    async def test_expired_ttl_not_set(self, revocation_closed: TokenRevocation) -> None:
        """Tokens already past expiry should not be added to the denylist."""
        expires = datetime.now(timezone.utc) - timedelta(hours=1)
        await revocation_closed.revoke("jti-expired", expires)
        assert not await revocation_closed.is_revoked("jti-expired")

    async def test_bulk_revoke(self, revocation_closed: TokenRevocation) -> None:
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await revocation_closed.revoke_bulk(["jti-a", "jti-b", "jti-c"], expires)
        assert await revocation_closed.is_revoked("jti-a")
        assert await revocation_closed.is_revoked("jti-b")
        assert await revocation_closed.is_revoked("jti-c")
        assert not await revocation_closed.is_revoked("jti-d")


class TestFailureMode:
    async def test_closed_mode_fails_safe(self) -> None:
        """When Redis is down, CLOSED mode treats all tokens as revoked."""

        class BrokenRedis:
            async def exists(self, key: str) -> bool:
                raise ConnectionError("Redis down")

        rev = TokenRevocation(redis=BrokenRedis(), failure_mode=FailureMode.CLOSED)
        assert await rev.is_revoked("any-jti") is True

    async def test_open_mode_fails_permissive(self) -> None:
        """When Redis is down, OPEN mode treats all tokens as valid."""

        class BrokenRedis:
            async def exists(self, key: str) -> bool:
                raise ConnectionError("Redis down")

        rev = TokenRevocation(redis=BrokenRedis(), failure_mode=FailureMode.OPEN)
        assert await rev.is_revoked("any-jti") is False
