"""Signed state tokens using itsdangerous.

Generic signed-token utility for CSRF state, auth codes, and other
short-lived signed payloads. Wraps itsdangerous.URLSafeTimedSerializer.
"""

from dataclasses import dataclass
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class StateError(Exception):
    """Base error for state token operations."""


class StateExpiredError(StateError):
    """Raised when a state token has exceeded its max_age."""


class StateInvalidError(StateError):
    """Raised when a state token has been tampered with or is malformed."""


@dataclass(frozen=True)
class StateSignerConfig:
    """Configuration for the state signer.

    Args:
        secret_key: Signing secret (use your JWT secret or a dedicated one).
        salt: Domain separator so tokens from different contexts can't be replayed.
    """

    secret_key: str
    salt: str = "b3dmar-state"

    def __post_init__(self) -> None:
        if not self.secret_key:
            raise ValueError("secret_key must not be empty")


class StateSigner:
    """Sign and verify short-lived state tokens."""

    def __init__(self, config: StateSignerConfig) -> None:
        self._serializer = URLSafeTimedSerializer(config.secret_key, salt=config.salt)

    def sign(self, data: dict[str, Any]) -> str:
        """Serialize and sign *data* into a URL-safe token."""
        result: str = self._serializer.dumps(data)
        return result

    def unsign(self, token: str, max_age: int = 300) -> dict[str, Any]:
        """Verify signature and return the original payload.

        Args:
            token: Signed token string.
            max_age: Maximum age in seconds (default 5 minutes).

        Raises:
            StateExpiredError: Token older than *max_age*.
            StateInvalidError: Bad signature or malformed token.
        """
        try:
            data: dict[str, Any] = self._serializer.loads(token, max_age=max_age)
        except SignatureExpired as e:
            raise StateExpiredError("State token has expired") from e
        except BadSignature as e:
            raise StateInvalidError("State token is invalid") from e
        return data
