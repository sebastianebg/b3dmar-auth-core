"""Cookbook: Social login with Google/GitHub OAuth.

Shows how to wire up b3dmar-auth-core's social and state modules
in a FastAPI application. Adapt the DB lookups to your ORM/driver.
"""

from b3dmar_auth.social import (
    AccountAction,
    GitHubOAuthConfig,
    GoogleOAuthConfig,
    github_authorization_url,
    github_exchange,
    google_authorization_url,
    google_exchange,
    resolve_account_linking,
)
from b3dmar_auth.state import StateSigner, StateSignerConfig

# --- Configuration (from env in production) ---

google_cfg = GoogleOAuthConfig(client_id="GOOGLE_ID", client_secret="GOOGLE_SECRET")
github_cfg = GitHubOAuthConfig(client_id="GITHUB_ID", client_secret="GITHUB_SECRET")
state_signer = StateSigner(StateSignerConfig(secret_key="your-jwt-secret", salt="social-auth"))


# --- 1. Build authorization URL (redirect user here) ---

def get_login_url(provider: str, callback_url: str) -> str:
    state = state_signer.sign({"provider": provider})
    if provider == "google":
        return google_authorization_url(google_cfg, callback_url, state)
    return github_authorization_url(github_cfg, callback_url, state)


# --- 2. Handle OAuth callback ---

async def handle_callback(provider: str, code: str, state: str, callback_url: str) -> dict:
    # Verify state token (raises StateExpiredError / StateInvalidError)
    data = state_signer.unsign(state)
    assert data["provider"] == provider

    # Exchange code for user info
    if provider == "google":
        user_info = await google_exchange(google_cfg, code, callback_url)
    else:
        user_info = await github_exchange(github_cfg, code, callback_url)

    # Look up existing users (YOUR DB logic here)
    existing_by_provider = None  # db.find_by_provider(provider, user_info.provider_id)
    existing_by_email = None     # db.find_by_email(user_info.email)

    # Resolve what to do
    resolution = resolve_account_linking(existing_by_provider, existing_by_email, provider)

    match resolution.action:
        case AccountAction.USE_EXISTING:
            return {"user_id": resolution.existing_user_id}
        case AccountAction.LINK_TO_EMAIL:
            return {
                "user_id": resolution.existing_user_id,
                "linked": True,
                "provider_id": user_info.provider_id,
            }
        case AccountAction.CONFLICT:
            raise ValueError(resolution.detail)
        case AccountAction.CREATE_NEW:
            return {
                "email": user_info.email,
                "name": user_info.name,
                "created": True,
            }
