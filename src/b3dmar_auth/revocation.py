"""Redis-based JWT token revocation.

Per-JTI denylist with self-cleaning TTL. Supports both fail-open (dev/soft)
and fail-closed (production) modes on Redis unavailability.
"""

import logging
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)

REVOKED_TOKEN_PREFIX = "revoked:refresh:"


class FailureMode(str, Enum):
    """Behavior when Redis is unavailable during revocation checks."""

    OPEN = "open"  # Treat token as valid (dev-friendly, less secure)
    CLOSED = "closed"  # Treat token as revoked (production-safe)


class TokenRevocation:
    """Redis-backed token revocation store.

    Each project instantiates one with its Redis connection and failure mode.

    Usage:
        revocation = TokenRevocation(redis=redis_client, failure_mode=FailureMode.CLOSED)
        await revocation.revoke(jti="abc-123", expires_at=token.exp)
        if await revocation.is_revoked(jti="abc-123"):
            raise Unauthorized
    """

    def __init__(
        self,
        redis: object,
        failure_mode: FailureMode = FailureMode.CLOSED,
        key_prefix: str = REVOKED_TOKEN_PREFIX,
    ):
        self._redis = redis
        self._failure_mode = failure_mode
        self._prefix = key_prefix

    async def revoke(self, jti: str, expires_at: datetime) -> None:
        """Add a token's JTI to the revocation denylist.

        TTL is set to the remaining token lifetime so entries self-clean.
        Silent on Redis errors — revocation is best-effort.
        """
        try:
            ttl_seconds = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl_seconds > 0:
                await self._redis.setex(f"{self._prefix}{jti}", ttl_seconds, "1")  # type: ignore[union-attr]
        except Exception:
            logger.warning("Redis unavailable for token revocation, silent failure")

    async def is_revoked(self, jti: str) -> bool:
        """Check if a token's JTI has been revoked.

        Behavior on Redis failure depends on `failure_mode`:
        - CLOSED (production): treats token as revoked (fail-safe)
        - OPEN (dev): treats token as valid (fail-convenient)
        """
        try:
            return bool(await self._redis.exists(f"{self._prefix}{jti}"))  # type: ignore[union-attr]
        except Exception:
            if self._failure_mode == FailureMode.CLOSED:
                logger.error("Redis unavailable for revocation check, failing CLOSED")
                return True
            logger.warning("Redis unavailable for revocation check, failing OPEN")
            return False

    async def revoke_bulk(self, jtis: list[str], expires_at: datetime) -> None:
        """Revoke multiple tokens in a pipeline for efficiency."""
        try:
            ttl_seconds = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl_seconds <= 0:
                return
            pipe = self._redis.pipeline()  # type: ignore[union-attr]
            for jti in jtis:
                pipe.setex(f"{self._prefix}{jti}", ttl_seconds, "1")  # type: ignore[union-attr]
            await pipe.execute()  # type: ignore[union-attr]
        except Exception:
            logger.warning("Redis unavailable for bulk token revocation, silent failure")
