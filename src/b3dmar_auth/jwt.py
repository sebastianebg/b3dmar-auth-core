"""JWT token creation and validation.

Standardized HS256 JWT handling with type discrimination (access vs refresh),
JTI for revocation, and configurable TTLs. DB-agnostic — never touches storage.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
from jwt.exceptions import ExpiredSignatureError, PyJWTError

ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised when token creation or validation fails."""


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""


class InvalidTokenError(TokenError):
    """Raised when a token is structurally invalid or has wrong claims."""


@dataclass(frozen=True)
class TokenConfig:
    """JWT configuration. Each consuming project instantiates one of these."""

    secret_key: str
    algorithm: str = ALGORITHM
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str | None = None
    audience: str | None = None

    def __post_init__(self) -> None:
        if not self.secret_key:
            raise ValueError("secret_key must not be empty")


@dataclass(frozen=True)
class DecodedToken:
    """Result of successfully decoding a JWT."""

    sub: str
    type: str
    exp: datetime
    iat: datetime
    jti: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def create_access_token(
    config: TokenConfig,
    subject: str | uuid.UUID,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a signed access token.

    Args:
        config: JWT configuration.
        subject: User identifier (UUID or string), stored in `sub` claim.
        expires_delta: Override default access token TTL.
        extra_claims: Additional claims merged into the payload (e.g. tenant_id, email).

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=config.access_token_expire_minutes))

    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "iat": now,
        "type": "access",
    }
    if config.issuer:
        payload["iss"] = config.issuer
    if config.audience:
        payload["aud"] = config.audience
    if extra_claims:
        payload.update(extra_claims)

    return pyjwt.encode(payload, config.secret_key, algorithm=config.algorithm)


def create_refresh_token(
    config: TokenConfig,
    subject: str | uuid.UUID,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a signed refresh token with a unique JTI for revocation.

    Args:
        config: JWT configuration.
        subject: User identifier (UUID or string), stored in `sub` claim.
        expires_delta: Override default refresh token TTL.
        extra_claims: Additional claims merged into the payload (e.g. tenant_id).

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=config.refresh_token_expire_days))

    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "iat": now,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    if config.issuer:
        payload["iss"] = config.issuer
    if config.audience:
        payload["aud"] = config.audience
    if extra_claims:
        payload.update(extra_claims)

    return pyjwt.encode(payload, config.secret_key, algorithm=config.algorithm)


def decode_token(
    config: TokenConfig,
    token: str,
    expected_type: str | None = None,
) -> DecodedToken:
    """Decode and validate a JWT.

    Args:
        config: JWT configuration.
        token: Encoded JWT string.
        expected_type: If set, validates the `type` claim matches (e.g. "access" or "refresh").

    Returns:
        DecodedToken with parsed claims.

    Raises:
        TokenExpiredError: Token has expired.
        InvalidTokenError: Token is invalid (bad signature, wrong type, missing claims).
    """
    decode_options: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"algorithms": [config.algorithm]}

    if config.audience:
        kwargs["audience"] = config.audience
    if config.issuer:
        kwargs["issuer"] = config.issuer

    try:
        payload = pyjwt.decode(token, config.secret_key, **kwargs, options=decode_options)
    except ExpiredSignatureError as e:
        raise TokenExpiredError("Token has expired") from e
    except PyJWTError as e:
        raise InvalidTokenError(f"Invalid token: {e}") from e

    sub = payload.get("sub")
    token_type = payload.get("type")
    exp = payload.get("exp")
    iat = payload.get("iat")

    if not sub:
        raise InvalidTokenError("Token missing 'sub' claim")
    if not token_type:
        raise InvalidTokenError("Token missing 'type' claim")
    if expected_type and token_type != expected_type:
        raise InvalidTokenError(f"Expected token type '{expected_type}', got '{token_type}'")

    # Extract known claims, put the rest in extra
    known_keys = {"sub", "type", "exp", "iat", "jti", "iss", "aud"}
    extra = {k: v for k, v in payload.items() if k not in known_keys}

    return DecodedToken(
        sub=sub,
        type=token_type,
        exp=datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc),
        iat=datetime.fromtimestamp(iat, tz=timezone.utc) if iat else datetime.now(timezone.utc),
        jti=payload.get("jti"),
        extra=extra,
    )
