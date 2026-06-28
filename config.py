import os
import sys


def _bool(value, default=False):
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _validate_config():
    """Fail fast on insecure or missing configuration at startup."""
    errors = []

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key or secret_key in ("change-me-to-a-random-value", "dev-insecure-secret-key"):
        errors.append(
            "SECRET_KEY is not set or uses an insecure default. "
            "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
        )

    password = os.environ.get("PASSWORD")
    require_login = _bool(os.environ.get("REQUIRE_LOGIN"), True)
    if require_login and (not password or password == "password"):
        errors.append(
            "PASSWORD is not set or uses an insecure default while REQUIRE_LOGIN=True. "
            "Set a strong password."
        )

    api_token = os.environ.get("LRTMP2_API_TOKEN")
    if not api_token or api_token == "change-me-to-a-secure-token":
        errors.append(
            "LRTMP2_API_TOKEN is not set or uses the placeholder. "
            "Set a secure token."
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
    PASSWORD = os.environ["PASSWORD"]

    LRTMP2_API_URL = os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")
    LRTMP2_API_TOKEN = os.environ["LRTMP2_API_TOKEN"]

    LRTMP2_DOMAIN = os.environ.get("LRTMP2_DOMAIN", "localhost")
    LRTMP2_RTMP_PORT = os.environ.get("LRTMP2_RTMP_PORT", "1935")
    LRTMP2_APP = os.environ.get("LRTMP2_APP", "live")

    PANEL_DB_PATH = os.environ.get("PANEL_DB_PATH", "panel.db")
