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
    if value is None or not str(value).strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _is_insecure_secret(value):
    """Reject missing, blank, known-default, or .env.example placeholder values."""
    if not value or not value.strip():
        return True
    stripped = value.strip()
    if stripped in _INSECURE_DEFAULTS:
        return True
    return stripped.startswith("<") and stripped.endswith(">")


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
    require_login = _bool(os.environ.get("REQUIRE_LOGIN"), True)
    if require_login and _is_insecure_secret(password):
        errors.append(
            "PASSWORD is not set or uses an insecure default while REQUIRE_LOGIN=True. "
            "Set a strong password."
        )

    api_token = os.environ.get("LRTMP2_API_TOKEN")
    if _is_insecure_secret(api_token):
        errors.append(
            "LRTMP2_API_TOKEN is not set or uses the placeholder. "
            "Copy the token printed by librtmp2-server on first startup "
            "(stored in the server's SQLite database)."
        )

    if errors:
        for err in errors:
            print(f"CONFIG ERROR: {err}", file=sys.stderr)
        sys.exit(1)


# Validate on import — before the app can start with bad config.
_validate_config()


class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]

    REQUIRE_LOGIN = _bool(os.environ.get("REQUIRE_LOGIN"), True)
    USERNAME = os.environ.get("USERNAME", "admin")
    PASSWORD = os.environ.get("PASSWORD", "")

    LRTMP2_API_URL = os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")
    # Browser-reachable HTTP API base URL for copied stats links (defaults to LRTMP2_API_URL).
    LRTMP2_STATS_URL = os.environ.get("LRTMP2_STATS_URL", LRTMP2_API_URL).rstrip("/")
    LRTMP2_API_TOKEN = os.environ["LRTMP2_API_TOKEN"]

    LRTMP2_DOMAIN = os.environ.get("LRTMP2_DOMAIN", "localhost")
    LRTMP2_RTMP_PORT = os.environ.get("LRTMP2_RTMP_PORT", "1935")
    LRTMP2_APP = os.environ.get("LRTMP2_APP", "live")

    # Only enable Secure cookies when the panel is served over HTTPS.
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)

    # Shared limiter backend for multi-worker deployments (e.g. redis://redis:6379/0).
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
