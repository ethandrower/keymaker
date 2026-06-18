"""Django settings for the keymaker service."""
import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name, default=False):
    return os.environ.get(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _env_list(name, default=""):
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-change-me")
DEBUG = _env_bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

# --- keymaker-specific config ---
# Comma-separated Fernet keys. First is the primary (used for new writes); the rest
# are kept for decryption so keys can be rotated without downtime.
KEYMAKER_MASTER_KEYS = _env_list("KEYMAKER_MASTER_KEY")
KEYMAKER_ADMIN_USERNAMES = [u.lower() for u in _env_list("KEYMAKER_ADMIN_USERNAMES")]
# Simple shared-account auth: one password the whole team uses. Everyone who logs
# in is an admin. Leave blank to allow passwordless entry (fully trusting).
# (Bitbucket OAuth below stays dormant until BITBUCKET_CLIENT_ID is set.)
KEYMAKER_SHARED_PASSWORD = os.environ.get("KEYMAKER_SHARED_PASSWORD", "")
BITBUCKET_WORKSPACE = os.environ.get("BITBUCKET_WORKSPACE", "citemed")
BITBUCKET_CLIENT_ID = os.environ.get("BITBUCKET_CLIENT_ID", "")
BITBUCKET_CLIENT_SECRET = os.environ.get("BITBUCKET_CLIENT_SECRET", "")
KEYMAKER_BASE_URL = os.environ.get("KEYMAKER_BASE_URL", "http://localhost:8000").rstrip("/")

# Keys that Dokku manages itself — never synced, flagged read-only in the UI.
KEYMAKER_MANAGED_KEYS = _env_list("KEYMAKER_MANAGED_KEYS", "DATABASE_URL,REDIS_URL")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "vars",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "keymaker.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "keymaker.wsgi.application"

DATABASES = {
    "default": dj_database_url.config(
        default=os.environ.get("DATABASE_URL", "sqlite:///" + str(BASE_DIR / "db.sqlite3")),
        conn_max_age=600,
    )
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/login"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "vars.auth.ApiTokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    # Don't let DRF hijack the ?format= query param — we use it for dotenv output.
    "URL_FORMAT_OVERRIDE": None,
    "UNAUTHENTICATED_USER": None,
}

# Behind Dokku/nginx TLS in production.
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    CSRF_TRUSTED_ORIGINS = [KEYMAKER_BASE_URL]
