import os


def _bool(value, default=False):
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key")

    REQUIRE_LOGIN = _bool(os.environ.get("REQUIRE_LOGIN"), True)
    USERNAME = os.environ.get("USERNAME", "admin")
    PASSWORD = os.environ.get("PASSWORD", "")

    LRTMP2_API_URL = os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")
    LRTMP2_API_TOKEN = os.environ.get("LRTMP2_API_TOKEN", "")

    LRTMP2_DOMAIN = os.environ.get("LRTMP2_DOMAIN", "localhost")
    LRTMP2_RTMP_PORT = os.environ.get("LRTMP2_RTMP_PORT", "1935")
    LRTMP2_APP = os.environ.get("LRTMP2_APP", "live")

    PANEL_DB_PATH = os.environ.get("PANEL_DB_PATH", "panel.db")
