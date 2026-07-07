import os
import sys

_INSECURE_DEFAULTS = frozenset(
    {
        "change-me-to-a-random-value",
        "dev-insecure-secret-key",
        "change-me-to-a-secure-token",
        "password",
        "<generate-with-python3-secrets-token-hex-32>",
        "<generate-strong-password>",
        "<generate-with-openssl-rand-hex-32>",
    }
)


def _bool(value, default=False):
    if value is None:
        return default
    stripped = str(value).strip()
    if not stripped:
        return default
    return stripped.lower() in ("1", "true", "yes", "on")


def _is_insecure_secret(value):
    """Reject missing, blank, known-default, or .env.example placeholder values."""
    if value is None:
        return True
    stripped = str(value).strip()
    if not stripped:
        return True
    if stripped.lower() in _INSECURE_DEFAULTS:
        return True
    return stripped.startswith("<") and stripped.endswith(">")


def _session_cookie_secure_default():
    for key in ("PANEL_PUBLIC_URL", "LRTMP2_STATS_URL", "LRTMP2_API_URL"):
        value = os.environ.get(key, "").strip().lower()
        if value.startswith("https://"):
            return True
    return _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)


def _validate_config():
    """Fail fast on insecure or missing configuration at startup."""
    errors = []

    secret_key = os.environ.get("SECRET_KEY")
    if _is_insecure_secret(secret_key):
        errors.append(
            "SECRET_KEY is not set or uses an insecure default. "
            "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
        )

    password = os.environ.get("PASSWORD")
    require_login = _bool(os.environ.get("REQUIRE_LOGIN"), False)
    if require_login and _is_insecure_secret(password):
        errors.append(
            "PASSWORD is not set or uses an insecure default while REQUIRE_LOGIN=True. "
            "Set a strong password."
        )

    api_token = os.environ.get("LRTMP2_API_TOKEN")
    if _is_insecure_secret(api_token):
        errors.append(
            "LRTMP2_API_TOKEN is not set or uses the placeholder. "
            "Set the same token in librtmp2-server and panel (via LRTMP2_API_TOKEN env "
            "or the value stored in the server's SQLite database)."
        )

    if errors:
        for err in errors:
            print(f"CONFIG ERROR: {err}", file=sys.stderr)
        sys.exit(1)


# Validate on import — before the app can start with bad config.
_validate_config()


class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]

    REQUIRE_LOGIN = _bool(os.environ.get("REQUIRE_LOGIN"), False)
    USERNAME = os.environ.get("USERNAME", "admin")
    PASSWORD = os.environ.get("PASSWORD", "")

    LRTMP2_API_URL = os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")
    # Browser-reachable HTTP API base URL for copied stats links (defaults to LRTMP2_API_URL).
    LRTMP2_STATS_URL = os.environ.get("LRTMP2_STATS_URL", LRTMP2_API_URL).rstrip("/")
    LRTMP2_API_TOKEN = os.environ["LRTMP2_API_TOKEN"]

    LRTMP2_DOMAIN = os.environ.get("LRTMP2_DOMAIN", "localhost")
    LRTMP2_RTMP_PORT = os.environ.get("LRTMP2_RTMP_PORT", "1935")
    # Publicly-reachable RTMPS port. Only used when librtmp2-server reports
    # RTMPS as enabled (via /api/v1/health) — kept separate from RTMP_PORT
    # since RTMPS is a second listener, not a mode switch on the same port.
    LRTMP2_RTMPS_PORT = os.environ.get("LRTMP2_RTMPS_PORT", "1936")
    LRTMP2_APP = os.environ.get("LRTMP2_APP", "live")

    # Enable Secure cookies automatically when public URLs use HTTPS.
    SESSION_COOKIE_SECURE = _session_cookie_secure_default()

    # Shared limiter backend for multi-worker deployments (e.g. redis://redis:6379/0).
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
