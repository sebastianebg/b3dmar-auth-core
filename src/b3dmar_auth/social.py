"""Social OAuth login primitives (Google, GitHub).

Provider-agnostic exchange functions, authorization URL builders, and
pure account-linking logic. No database access, no framework coupling.
"""

import enum
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SocialAuthError(Exception):
    """Base error for social auth operations."""


class OAuthExchangeError(SocialAuthError):
    """Raised when the OAuth token exchange or userinfo fetch fails."""


class NoVerifiedEmailError(SocialAuthError):
    """Raised when the provider account has no verified email."""


# ---------------------------------------------------------------------------
# Provider configs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoogleOAuthConfig:
    """Google OAuth 2.0 configuration."""

    client_id: str
    client_secret: str
    auth_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"
    userinfo_url: str = "https://www.googleapis.com/oauth2/v3/userinfo"
    scopes: str = "openid email profile"
    timeout: int = 10


@dataclass(frozen=True)
class GitHubOAuthConfig:
    """GitHub OAuth configuration."""

    client_id: str
    client_secret: str
    auth_url: str = "https://github.com/login/oauth/authorize"
    token_url: str = "https://github.com/login/oauth/access_token"
    user_url: str = "https://api.github.com/user"
    emails_url: str = "https://api.github.com/user/emails"
    scopes: str = "read:user user:email"
    timeout: int = 10


# ---------------------------------------------------------------------------
# Normalized user info
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OAuthUserInfo:
    """Normalized user information returned from any OAuth provider."""

    email: str
    provider_id: str
    name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Authorization URL builders (sync)
# ---------------------------------------------------------------------------


def google_authorization_url(
    config: GoogleOAuthConfig,
    callback_url: str,
    state: str,
) -> str:
    """Build the Google OAuth authorization redirect URL."""
    params = {
        "client_id": config.client_id,
        "redirect_uri": callback_url,
        "response_type": "code",
        "scope": config.scopes,
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return f"{config.auth_url}?{urlencode(params)}"


def github_authorization_url(
    config: GitHubOAuthConfig,
    callback_url: str,
    state: str,
) -> str:
    """Build the GitHub OAuth authorization redirect URL."""
    params = {
        "client_id": config.client_id,
        "redirect_uri": callback_url,
        "scope": config.scopes,
        "state": state,
    }
    return f"{config.auth_url}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Exchange functions (async)
# ---------------------------------------------------------------------------


async def google_exchange(
    config: GoogleOAuthConfig,
    code: str,
    callback_url: str,
) -> OAuthUserInfo:
    """Exchange a Google authorization code for user info.

    Raises:
        OAuthExchangeError: On HTTP or network failure.
    """
    try:
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            token_resp = await client.post(
                config.token_url,
                data={
                    "code": code,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "redirect_uri": callback_url,
                    "grant_type": "authorization_code",
                },
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()

            userinfo_resp = await client.get(
                config.userinfo_url,
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            userinfo_resp.raise_for_status()
            info: dict[str, Any] = userinfo_resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning("Google OAuth error: %s", e.response.text)
        raise OAuthExchangeError("Google authentication failed") from e
    except httpx.RequestError as e:
        logger.warning("Google OAuth network error: %s", e)
        raise OAuthExchangeError("Could not reach Google") from e

    return OAuthUserInfo(
        email=info["email"],
        provider_id=info["sub"],
        name=info.get("name"),
        raw=info,
    )


async def github_exchange(
    config: GitHubOAuthConfig,
    code: str,
    callback_url: str,
) -> OAuthUserInfo:
    """Exchange a GitHub authorization code for user info.

    Falls back to the emails endpoint when the user profile has no public email.

    Raises:
        OAuthExchangeError: On HTTP, network, or upstream error-in-token-response.
        NoVerifiedEmailError: When no verified primary email is found.
    """
    try:
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            token_resp = await client.post(
                config.token_url,
                data={
                    "code": code,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "redirect_uri": callback_url,
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            tokens: dict[str, Any] = token_resp.json()

            if "error" in tokens:
                detail = tokens.get("error_description", tokens["error"])
                raise OAuthExchangeError(f"GitHub OAuth error: {detail}")

            access_token: str = tokens["access_token"]
            auth_headers = {"Authorization": f"Bearer {access_token}"}

            user_resp = await client.get(config.user_url, headers=auth_headers)
            user_resp.raise_for_status()
            user_data: dict[str, Any] = user_resp.json()

            email: str | None = user_data.get("email")
            if not email:
                emails_resp = await client.get(config.emails_url, headers=auth_headers)
                emails_resp.raise_for_status()
                for entry in emails_resp.json():
                    if entry.get("primary") and entry.get("verified"):
                        email = entry["email"]
                        break
    except OAuthExchangeError:
        raise
    except httpx.HTTPStatusError as e:
        logger.warning("GitHub OAuth error: %s", e.response.text)
        raise OAuthExchangeError("GitHub authentication failed") from e
    except httpx.RequestError as e:
        logger.warning("GitHub OAuth network error: %s", e)
        raise OAuthExchangeError("Could not reach GitHub") from e

    if not email:
        raise NoVerifiedEmailError("No verified email found on GitHub account")

    return OAuthUserInfo(
        email=email,
        provider_id=str(user_data["id"]),
        name=user_data.get("name") or user_data.get("login"),
        raw=user_data,
    )


# ---------------------------------------------------------------------------
# Account linking (pure, sync)
# ---------------------------------------------------------------------------


class AccountAction(enum.Enum):
    """Possible outcomes of account resolution."""

    USE_EXISTING = "use_existing"
    LINK_TO_EMAIL = "link_to_email"
    CONFLICT = "conflict"
    CREATE_NEW = "create_new"


@dataclass(frozen=True)
class AccountResolution:
    """Result of resolve_account_linking()."""

    action: AccountAction
    existing_user_id: str | None = None
    detail: str = ""


def resolve_account_linking(
    existing_by_provider: dict[str, Any] | None,
    existing_by_email: dict[str, Any] | None,
    provider: str,
) -> AccountResolution:
    """Determine what to do when a social user authenticates.

    This is a pure function: it inspects lookup results and returns an action.
    The caller is responsible for performing the actual DB writes.

    Args:
        existing_by_provider: User row found by (auth_provider, auth_provider_id), or None.
        existing_by_email: User row found by email, or None.
        provider: The OAuth provider name (e.g. "google", "github").

    Returns:
        AccountResolution describing the action to take.
    """
    if existing_by_provider is not None:
        return AccountResolution(
            action=AccountAction.USE_EXISTING,
            existing_user_id=str(existing_by_provider["id"]),
            detail=f"Returning existing {provider} user",
        )

    if existing_by_email is not None:
        email_provider = existing_by_email.get("auth_provider")
        if email_provider is None:
            return AccountResolution(
                action=AccountAction.LINK_TO_EMAIL,
                existing_user_id=str(existing_by_email["id"]),
                detail=f"Linking {provider} to existing email+password account",
            )
        return AccountResolution(
            action=AccountAction.CONFLICT,
            existing_user_id=str(existing_by_email["id"]),
            detail=f"Email already registered with provider '{email_provider}'",
        )

    return AccountResolution(
        action=AccountAction.CREATE_NEW,
        detail=f"Creating new user via {provider}",
    )
