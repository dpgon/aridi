"""Settings of the aridi central component, read from environment variables.

Production is the default: ARIDI_SECRET_KEY is required unless ARIDI_DEBUG=1. TLS is
terminated by a reverse proxy in front of gunicorn (docs/CAMBIO.md).
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent


def _env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def _env_int(name, default):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        raise ImproperlyConfigured(f"{name} must be an integer, not {value!r}") from None


DEBUG = os.environ.get("ARIDI_DEBUG", "") == "1"

SECRET_KEY = os.environ.get("ARIDI_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured(
            "ARIDI_SECRET_KEY is not set (use ARIDI_DEBUG=1 only for development)")
    SECRET_KEY = "aridi-development-only-insecure-key"

ALLOWED_HOSTS = _env_list("ARIDI_ALLOWED_HOSTS", "localhost,127.0.0.1" if DEBUG else "")
CSRF_TRUSTED_ORIGINS = _env_list("ARIDI_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "aridi_central.inventory",
    "aridi_central.collection",
    "aridi_central.changes",
    "aridi_central.discovery",
    "aridi_central.web",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "aridi_central.web.middleware.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "aridi_central.urls"
WSGI_APPLICATION = "aridi_central.wsgi.application"

TEMPLATES = [{
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
}]

# SQLite. WAL, busy_timeout and foreign keys are set on every connection
# (inventory/apps.py); IMMEDIATE transactions avoid lock upgrades between the web and the
# worker.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("ARIDI_DB_PATH", "/data/aridi.db"),
        "OPTIONS": {"transaction_mode": "IMMEDIATE", "timeout": 20},
        # Tests use a file, not the in-memory default: the worker tests need real SQLite
        # locking between threads (tests/central/run.sh sets it).
        "TEST": {"NAME": os.environ.get("ARIDI_TEST_DB_PATH") or None},
    },
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "machine-list"
LOGOUT_REDIRECT_URL = "login"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# Behind the TLS proxy. The proxy must set X-Forwarded-Proto and strip it from clients.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SECURE_SSL_REDIRECT = not DEBUG and os.environ.get("ARIDI_SSL_REDIRECT", "1") == "1"
# The container healthcheck talks plain HTTP to gunicorn.
SECURE_REDIRECT_EXEMPT = [r"^healthz$"]
SECURE_HSTS_SECONDS = 0 if DEBUG else _env_int("ARIDI_HSTS_SECONDS", 31536000)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
# Subdomains and preload lists are decisions of the domain owner, not of aridi.
SILENCED_SYSTEM_CHECKS = ["security.W005", "security.W021"]

# Uploads of raw bundles (inventory/importing.py) are read into memory up to this size.
ARIDI_MAX_BUNDLE_BYTES = _env_int("ARIDI_MAX_BUNDLE_BYTES", 64 * 1024 * 1024)
DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = ARIDI_MAX_BUNDLE_BYTES

# Raw bundles kept (gzip) per machine: the most recent ones (decision of TODO.md 5.0).
ARIDI_RAW_RETENTION = _env_int("ARIDI_RAW_RETENTION", 10)

# SSH collection (collection/ssh.py). Credentials are never stored: ssh uses the agent
# (SSH_AUTH_SOCK) and a known_hosts file with strict checking.
ARIDI_COLLECTOR_SCRIPT = os.environ.get(
    "ARIDI_COLLECTOR_SCRIPT",
    str(BASE_DIR.parent.parent / "collector" / "aridi-collect.sh"))
ARIDI_SSH_CONFIG = os.environ.get("ARIDI_SSH_CONFIG", "")
ARIDI_KNOWN_HOSTS = os.environ.get("ARIDI_KNOWN_HOSTS", "")
ARIDI_SSH_CONNECT_TIMEOUT = _env_int("ARIDI_SSH_CONNECT_TIMEOUT", 15)
ARIDI_SSH_TIMEOUT = _env_int("ARIDI_SSH_TIMEOUT", 900)
ARIDI_MAX_SSH = _env_int("ARIDI_MAX_SSH", 4)
ARIDI_JOB_ATTEMPTS = _env_int("ARIDI_JOB_ATTEMPTS", 3)
# Alerts (changes/): links in the messages, webhooks and email (TODO.md 6.4). Secrets live
# here, never in the database: a webhook channel names one ARIDI_WEBHOOK_URL_<NAME>.
ARIDI_BASE_URL = os.environ.get("ARIDI_BASE_URL", "")
ARIDI_WEBHOOKS = {}
for _name, _url in os.environ.items():
    if _name.startswith("ARIDI_WEBHOOK_URL_") and _url:
        if not _url.startswith(("https://", "http://")):
            raise ImproperlyConfigured(f"{_name} must be an http(s) URL")
        ARIDI_WEBHOOKS[_name.removeprefix("ARIDI_WEBHOOK_URL_").lower()] = _url
ARIDI_WEBHOOK_TIMEOUT = _env_int("ARIDI_WEBHOOK_TIMEOUT", 10)
ARIDI_DELIVERY_ATTEMPTS = _env_int("ARIDI_DELIVERY_ATTEMPTS", 5)
EMAIL_HOST = os.environ.get("ARIDI_EMAIL_HOST", "")
EMAIL_PORT = _env_int("ARIDI_EMAIL_PORT", 587)
EMAIL_HOST_USER = os.environ.get("ARIDI_EMAIL_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("ARIDI_EMAIL_PASSWORD", "")
_email_security = os.environ.get("ARIDI_EMAIL_SECURITY", "starttls")
if _email_security not in ("starttls", "tls", "none"):
    raise ImproperlyConfigured("ARIDI_EMAIL_SECURITY must be starttls, tls or none")
EMAIL_USE_TLS = _email_security == "starttls"
EMAIL_USE_SSL = _email_security == "tls"
EMAIL_TIMEOUT = 20
DEFAULT_FROM_EMAIL = os.environ.get("ARIDI_EMAIL_FROM", "aridi@localhost")

# File the worker touches on every loop, for the container healthcheck ("" = none).
ARIDI_WORKER_HEARTBEAT = os.environ.get("ARIDI_WORKER_HEARTBEAT", "")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"stdout": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout",
                            "formatter": "plain"}},
    "root": {"handlers": ["stdout"], "level": os.environ.get("ARIDI_LOG_LEVEL", "INFO")},
}
