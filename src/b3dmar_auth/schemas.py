"""Shared Pydantic models for auth tokens."""

from uuid import UUID

from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """JWT token payload claims.

    The `sub` field holds the user UUID. Additional claims (e.g. tenant_id)
    can be passed via `extra_claims` at token creation time and will appear
    as top-level keys in the decoded payload.
    """

    sub: UUID
    type: str = Field(pattern=r"^(access|refresh)$")
    exp: float
    iat: float
    jti: str | None = None

    model_config = {"extra": "allow"}


class TokenResponse(BaseModel):
    """Standard token response body."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPairResponse(TokenResponse):
    """Token response that includes a refresh token in the body.

    Use this for APIs that return refresh tokens in the response body.
    For httpOnly-cookie refresh tokens, use TokenResponse instead.
    """

    refresh_token: str
