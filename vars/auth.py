"""Authentication for keymaker.

Two paths:
  * UI  — Bitbucket OAuth 2.0 (workspace-restricted), session-based. A dev-only
          shortcut (DEV_LOGIN) lets you in without Bitbucket configured.
  * API — bearer ApiToken, used by agents and the Dokku sync client.

The UI uses a lightweight session model (not django.contrib.auth's User): we
store the AppUser id in request.session and expose it via helpers below.
"""
import requests
from django.conf import settings
from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import ApiToken, AppUser

BITBUCKET_AUTHORIZE = "https://bitbucket.org/site/oauth2/authorize"
BITBUCKET_TOKEN = "https://bitbucket.org/site/oauth2/access_token"
BITBUCKET_API = "https://api.bitbucket.org/2.0"

SESSION_USER_KEY = "appuser_id"


# --- UI session helpers ---------------------------------------------------

def login_appuser(request, appuser: AppUser):
    appuser.last_login_at = timezone.now()
    appuser.save(update_fields=["last_login_at"])
    request.session[SESSION_USER_KEY] = appuser.id


def logout_appuser(request):
    request.session.pop(SESSION_USER_KEY, None)


def current_user(request):
    uid = request.session.get(SESSION_USER_KEY)
    if not uid:
        return None
    return AppUser.objects.filter(id=uid).first()


def is_admin_username(username: str) -> bool:
    return (username or "").lower() in settings.KEYMAKER_ADMIN_USERNAMES


# --- shared-account login (no per-user accounts yet) ----------------------

SHARED_USERNAME = "team"


def get_shared_user() -> AppUser:
    """The single shared account everyone uses until OAuth is wired up."""
    user, _ = AppUser.objects.get_or_create(
        username=SHARED_USERNAME,
        defaults={"display_name": "CiteMed Engineering", "is_admin": True},
    )
    if not user.is_admin:  # always an admin
        user.is_admin = True
        user.save(update_fields=["is_admin"])
    return user


def check_shared_password(password: str) -> bool:
    """Constant-time check against the configured shared password.

    If no password is configured, entry is allowed (fully trusting).
    """
    expected = settings.KEYMAKER_SHARED_PASSWORD
    if not expected:
        return True
    import hmac

    return hmac.compare_digest((password or "").encode(), expected.encode())


def upsert_appuser(*, bitbucket_uuid, username, display_name="", email="") -> AppUser:
    user, _ = AppUser.objects.update_or_create(
        username=username,
        defaults={
            "bitbucket_uuid": bitbucket_uuid,
            "display_name": display_name,
            "email": email,
            "is_admin": is_admin_username(username),
        },
    )
    return user


# --- Bitbucket OAuth ------------------------------------------------------

def authorize_url(state: str) -> str:
    return (
        f"{BITBUCKET_AUTHORIZE}?client_id={settings.BITBUCKET_CLIENT_ID}"
        f"&response_type=code&state={state}"
    )


def exchange_code(code: str) -> str:
    """Exchange an auth code for an access token."""
    resp = requests.post(
        BITBUCKET_TOKEN,
        data={"grant_type": "authorization_code", "code": code},
        auth=(settings.BITBUCKET_CLIENT_ID, settings.BITBUCKET_CLIENT_SECRET),
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_bitbucket_user(access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    user = requests.get(f"{BITBUCKET_API}/user", headers=headers, timeout=15)
    user.raise_for_status()
    data = user.json()
    email = ""
    emails = requests.get(f"{BITBUCKET_API}/user/emails", headers=headers, timeout=15)
    if emails.ok:
        primary = next(
            (e for e in emails.json().get("values", []) if e.get("is_primary")), None
        )
        if primary:
            email = primary.get("email", "")
    return {
        "uuid": data.get("uuid"),
        "username": data.get("username") or data.get("nickname"),
        "display_name": data.get("display_name", ""),
        "email": email,
    }


def is_workspace_member(access_token: str, username: str) -> bool:
    """Confirm the user belongs to the configured Bitbucket workspace."""
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(
        f"{BITBUCKET_API}/workspaces/{settings.BITBUCKET_WORKSPACE}/members/{username}",
        headers=headers,
        timeout=15,
    )
    return resp.status_code == 200


# --- DRF API token auth ---------------------------------------------------

class TokenIdentity:
    """A minimal authenticated principal for token-based API requests."""

    is_authenticated = True

    def __init__(self, token: ApiToken):
        self.token = token

    def __str__(self):
        return f"token:{self.token.name}"


class ApiTokenAuthentication(authentication.BaseAuthentication):
    """Authenticate ``Authorization: Bearer <token>`` against ApiToken."""

    keyword = "Bearer"

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header.startswith(self.keyword + " "):
            return None
        raw = header[len(self.keyword) + 1 :].strip()
        if not raw:
            return None
        try:
            token = ApiToken.objects.select_related("environment").get(
                token_hash=ApiToken.hash_token(raw)
            )
        except ApiToken.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid API token")
        if token.revoked:
            raise exceptions.AuthenticationFailed("Token revoked")
        ApiToken.objects.filter(pk=token.pk).update(last_used_at=timezone.now())
        return TokenIdentity(token), token

    def authenticate_header(self, request):
        # Makes DRF return 401 (not 403) when credentials are missing.
        return self.keyword
