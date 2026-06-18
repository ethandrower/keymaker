"""Authentication for Keymaker — one shared key for everything.

A single secret, ``KEYMAKER_KEY``, authenticates both:
  * the web UI — paste it as the password on the login page (session-based after), and
  * agents / the CLI clients — send it as ``Authorization: Bearer <key>``.

There are no per-agent tokens, scopes, or external identity providers. Everyone
who has the key has full read/write access. Rotate by changing the env var.

The UI uses a lightweight session model (not django.contrib.auth's User): we
store the AppUser id in request.session and expose it via the helpers below.
"""
import hmac

from django.conf import settings
from django.utils import timezone
from rest_framework import authentication

SESSION_USER_KEY = "appuser_id"
SHARED_USERNAME = "team"


# --- the single key -------------------------------------------------------

def check_key(provided: str) -> bool:
    """Constant-time check against KEYMAKER_KEY.

    If no key is configured, access is allowed (passwordless local dev only —
    production must set KEYMAKER_KEY, since the same key guards the API).
    """
    expected = settings.KEYMAKER_KEY
    if not expected:
        return True
    return hmac.compare_digest((provided or "").encode(), expected.encode())


# --- UI session helpers ---------------------------------------------------

def get_shared_user():
    """The single shared account everyone signs in as."""
    from .models import AppUser

    user, _ = AppUser.objects.get_or_create(
        username=SHARED_USERNAME,
        defaults={"display_name": "CiteMed Engineering", "is_admin": True},
    )
    if not user.is_admin:
        user.is_admin = True
        user.save(update_fields=["is_admin"])
    return user


def login_appuser(request, appuser):
    appuser.last_login_at = timezone.now()
    appuser.save(update_fields=["last_login_at"])
    request.session[SESSION_USER_KEY] = appuser.id


def logout_appuser(request):
    request.session.pop(SESSION_USER_KEY, None)


def current_user(request):
    from .models import AppUser

    uid = request.session.get(SESSION_USER_KEY)
    if not uid:
        return None
    return AppUser.objects.filter(id=uid).first()


# --- DRF API auth (same key, as a bearer token) ---------------------------

class ApiIdentity:
    """The authenticated principal for API requests (full access)."""

    is_authenticated = True

    def __str__(self):
        return "api"


class KeymakerKeyAuthentication(authentication.BaseAuthentication):
    """Authenticate ``Authorization: Bearer <KEYMAKER_KEY>``."""

    keyword = "Bearer"

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header.startswith(self.keyword + " "):
            return None
        raw = header[len(self.keyword) + 1 :].strip()
        if not raw or not check_key(raw):
            from rest_framework import exceptions

            raise exceptions.AuthenticationFailed("Invalid key")
        return ApiIdentity(), None

    def authenticate_header(self, request):
        # Makes DRF return 401 (not 403) when credentials are missing.
        return self.keyword
