"""Tests for JWT token creation and validation."""

import uuid
from datetime import timedelta

import pytest

from b3dmar_auth.jwt import (
    DecodedToken,
    InvalidTokenError,
    TokenConfig,
    TokenExpiredError,
    create_access_token,
    create_refresh_token,
    decode_token,
)

SECRET = "test-secret-key-at-least-32-chars-long"


@pytest.fixture
def config() -> TokenConfig:
    return TokenConfig(
        secret_key=SECRET,
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
        issuer="test-app",
        audience="test-api",
    )


@pytest.fixture
def bare_config() -> TokenConfig:
    """Config without issuer/audience for minimal token tests."""
    return TokenConfig(secret_key=SECRET)


class TestTokenConfig:
    def test_empty_secret_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key must not be empty"):
            TokenConfig(secret_key="")

    def test_defaults(self) -> None:
        cfg = TokenConfig(secret_key=SECRET)
        assert cfg.access_token_expire_minutes == 15
        assert cfg.refresh_token_expire_days == 7
        assert cfg.algorithm == "HS256"
        assert cfg.issuer is None
        assert cfg.audience is None


class TestAccessToken:
    def test_create_and_decode(self, config: TokenConfig) -> None:
        user_id = uuid.uuid4()
        token = create_access_token(config, subject=user_id)
        decoded = decode_token(config, token, expected_type="access")

        assert decoded.sub == str(user_id)
        assert decoded.type == "access"
        assert decoded.jti is None

    def test_extra_claims(self, config: TokenConfig) -> None:
        user_id = uuid.uuid4()
        token = create_access_token(
            config, subject=user_id, extra_claims={"tenant_id": "t-123", "email": "a@b.com"}
        )
        decoded = decode_token(config, token, expected_type="access")

        assert decoded.extra["tenant_id"] == "t-123"
        assert decoded.extra["email"] == "a@b.com"

    def test_custom_expiry(self, config: TokenConfig) -> None:
        token = create_access_token(
            config, subject="user-1", expires_delta=timedelta(minutes=5)
        )
        decoded = decode_token(config, token)
        assert decoded.type == "access"

    def test_string_subject(self, bare_config: TokenConfig) -> None:
        token = create_access_token(bare_config, subject="user-abc")
        decoded = decode_token(bare_config, token)
        assert decoded.sub == "user-abc"


class TestRefreshToken:
    def test_create_and_decode(self, config: TokenConfig) -> None:
        user_id = uuid.uuid4()
        token = create_refresh_token(config, subject=user_id)
        decoded = decode_token(config, token, expected_type="refresh")

        assert decoded.sub == str(user_id)
        assert decoded.type == "refresh"
        assert decoded.jti is not None

    def test_jti_is_unique(self, config: TokenConfig) -> None:
        t1 = create_refresh_token(config, subject="u1")
        t2 = create_refresh_token(config, subject="u1")
        d1 = decode_token(config, t1)
        d2 = decode_token(config, t2)
        assert d1.jti != d2.jti

    def test_extra_claims(self, config: TokenConfig) -> None:
        token = create_refresh_token(
            config, subject="u1", extra_claims={"tenant_id": "t-456"}
        )
        decoded = decode_token(config, token)
        assert decoded.extra["tenant_id"] == "t-456"


class TestDecodeToken:
    def test_wrong_type_rejected(self, config: TokenConfig) -> None:
        token = create_access_token(config, subject="u1")
        with pytest.raises(InvalidTokenError, match="Expected token type 'refresh'"):
            decode_token(config, token, expected_type="refresh")

    def test_wrong_secret_rejected(self, config: TokenConfig) -> None:
        token = create_access_token(config, subject="u1")
        bad_config = TokenConfig(
            secret_key="wrong-secret-key-at-least-32chars",
            issuer=config.issuer,
            audience=config.audience,
        )
        with pytest.raises(InvalidTokenError):
            decode_token(bad_config, token)

    def test_expired_token(self, config: TokenConfig) -> None:
        token = create_access_token(
            config, subject="u1", expires_delta=timedelta(seconds=-1)
        )
        with pytest.raises(TokenExpiredError):
            decode_token(config, token)

    def test_no_type_check(self, config: TokenConfig) -> None:
        token = create_access_token(config, subject="u1")
        decoded = decode_token(config, token)
        assert decoded.type == "access"

    def test_issuer_audience_validation(self) -> None:
        config_a = TokenConfig(secret_key=SECRET, issuer="app-a", audience="api-a")
        config_b = TokenConfig(secret_key=SECRET, issuer="app-b", audience="api-b")

        token = create_access_token(config_a, subject="u1")
        with pytest.raises(InvalidTokenError):
            decode_token(config_b, token)
