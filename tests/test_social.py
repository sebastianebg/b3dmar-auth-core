"""Tests for b3dmar_auth.social — OAuth exchange, URL builders, account linking."""

import httpx
import pytest
import respx

from b3dmar_auth.social import (
    AccountAction,
    AccountResolution,
    GitHubOAuthConfig,
    GoogleOAuthConfig,
    NoVerifiedEmailError,
    OAuthExchangeError,
    OAuthUserInfo,
    github_authorization_url,
    github_exchange,
    google_authorization_url,
    google_exchange,
    resolve_account_linking,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GOOGLE_CFG = GoogleOAuthConfig(client_id="g-id", client_secret="g-secret")
GITHUB_CFG = GitHubOAuthConfig(client_id="gh-id", client_secret="gh-secret")


# ---------------------------------------------------------------------------
# Authorization URL builders
# ---------------------------------------------------------------------------


class TestAuthorizationUrls:
    def test_google_url_contains_params(self) -> None:
        url = google_authorization_url(GOOGLE_CFG, "https://app/callback", "state123")
        assert "client_id=g-id" in url
        assert "redirect_uri=https" in url
        assert "state=state123" in url
        assert "scope=openid+email+profile" in url
        assert url.startswith(GOOGLE_CFG.auth_url)

    def test_github_url_contains_params(self) -> None:
        url = github_authorization_url(GITHUB_CFG, "https://app/callback", "state456")
        assert "client_id=gh-id" in url
        assert "state=state456" in url
        assert "scope=read" in url
        assert url.startswith(GITHUB_CFG.auth_url)


# ---------------------------------------------------------------------------
# Google exchange
# ---------------------------------------------------------------------------


class TestGoogleExchange:
    @respx.mock
    async def test_happy_path(self) -> None:
        respx.post(GOOGLE_CFG.token_url).mock(
            return_value=httpx.Response(200, json={"access_token": "gat"})
        )
        respx.get(GOOGLE_CFG.userinfo_url).mock(
            return_value=httpx.Response(
                200, json={"email": "a@b.com", "sub": "g-123", "name": "Alice"}
            )
        )
        info = await google_exchange(GOOGLE_CFG, "code", "https://app/cb")
        assert info == OAuthUserInfo(
            email="a@b.com",
            provider_id="g-123",
            name="Alice",
            raw={"email": "a@b.com", "sub": "g-123", "name": "Alice"},
        )

    @respx.mock
    async def test_http_error(self) -> None:
        respx.post(GOOGLE_CFG.token_url).mock(
            return_value=httpx.Response(400, json={"error": "bad"})
        )
        with pytest.raises(OAuthExchangeError, match="Google authentication failed"):
            await google_exchange(GOOGLE_CFG, "bad-code", "https://app/cb")

    @respx.mock
    async def test_network_error(self) -> None:
        respx.post(GOOGLE_CFG.token_url).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(OAuthExchangeError, match="Could not reach Google"):
            await google_exchange(GOOGLE_CFG, "code", "https://app/cb")


# ---------------------------------------------------------------------------
# GitHub exchange
# ---------------------------------------------------------------------------


class TestGitHubExchange:
    @respx.mock
    async def test_happy_path(self) -> None:
        respx.post(GITHUB_CFG.token_url).mock(
            return_value=httpx.Response(200, json={"access_token": "ghat"})
        )
        respx.get(GITHUB_CFG.user_url).mock(
            return_value=httpx.Response(
                200, json={"id": 42, "email": "dev@gh.com", "name": "Bob", "login": "bob"}
            )
        )
        info = await github_exchange(GITHUB_CFG, "code", "https://app/cb")
        assert info.email == "dev@gh.com"
        assert info.provider_id == "42"
        assert info.name == "Bob"

    @respx.mock
    async def test_error_in_token_response(self) -> None:
        respx.post(GITHUB_CFG.token_url).mock(
            return_value=httpx.Response(
                200, json={"error": "bad_code", "error_description": "Code expired"}
            )
        )
        with pytest.raises(OAuthExchangeError, match="Code expired"):
            await github_exchange(GITHUB_CFG, "bad", "https://app/cb")

    @respx.mock
    async def test_fallback_to_emails_endpoint(self) -> None:
        respx.post(GITHUB_CFG.token_url).mock(
            return_value=httpx.Response(200, json={"access_token": "ghat"})
        )
        respx.get(GITHUB_CFG.user_url).mock(
            return_value=httpx.Response(
                200, json={"id": 99, "email": None, "login": "private-user"}
            )
        )
        respx.get(GITHUB_CFG.emails_url).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"email": "nope@gh.com", "primary": False, "verified": True},
                    {"email": "yes@gh.com", "primary": True, "verified": True},
                ],
            )
        )
        info = await github_exchange(GITHUB_CFG, "code", "https://app/cb")
        assert info.email == "yes@gh.com"
        assert info.name == "private-user"

    @respx.mock
    async def test_no_verified_email(self) -> None:
        respx.post(GITHUB_CFG.token_url).mock(
            return_value=httpx.Response(200, json={"access_token": "ghat"})
        )
        respx.get(GITHUB_CFG.user_url).mock(
            return_value=httpx.Response(200, json={"id": 1, "email": None, "login": "anon"})
        )
        respx.get(GITHUB_CFG.emails_url).mock(
            return_value=httpx.Response(
                200, json=[{"email": "x@y.com", "primary": True, "verified": False}]
            )
        )
        with pytest.raises(NoVerifiedEmailError, match="No verified email"):
            await github_exchange(GITHUB_CFG, "code", "https://app/cb")

    @respx.mock
    async def test_network_error(self) -> None:
        respx.post(GITHUB_CFG.token_url).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(OAuthExchangeError, match="Could not reach GitHub"):
            await github_exchange(GITHUB_CFG, "code", "https://app/cb")


# ---------------------------------------------------------------------------
# Account linking (pure function)
# ---------------------------------------------------------------------------


class TestResolveAccountLinking:
    def test_use_existing_by_provider(self) -> None:
        result = resolve_account_linking(
            existing_by_provider={"id": "user-1", "email": "a@b.com"},
            existing_by_email=None,
            provider="google",
        )
        assert result == AccountResolution(
            action=AccountAction.USE_EXISTING,
            existing_user_id="user-1",
            detail="Returning existing google user",
        )

    def test_link_to_email_account(self) -> None:
        result = resolve_account_linking(
            existing_by_provider=None,
            existing_by_email={"id": "user-2", "auth_provider": None},
            provider="github",
        )
        assert result.action == AccountAction.LINK_TO_EMAIL
        assert result.existing_user_id == "user-2"

    def test_conflict_different_provider(self) -> None:
        result = resolve_account_linking(
            existing_by_provider=None,
            existing_by_email={"id": "user-3", "auth_provider": "google"},
            provider="github",
        )
        assert result.action == AccountAction.CONFLICT
        assert "google" in result.detail

    def test_create_new(self) -> None:
        result = resolve_account_linking(
            existing_by_provider=None,
            existing_by_email=None,
            provider="google",
        )
        assert result.action == AccountAction.CREATE_NEW
        assert result.existing_user_id is None
