import os
from unittest.mock import patch

import pytest


def test_login_page_renders_without_session():
    with patch("app.Lrtmp2Client"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        client = application.test_client()
        r = client.get("/login")
        assert r.status_code == 200


def test_security_headers_on_html_responses():
    with patch("app.Lrtmp2Client"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        client = application.test_client()
        r = client.get("/login")
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Content-Security-Policy") == "frame-ancestors 'none'"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("Referrer-Policy") == "no-referrer"
        assert r.headers.get("Cache-Control") == "no-store"


def test_cache_control_no_store_on_json_responses(app_client):
    """JSON stats responses may carry stream keys and must not be cached."""
    client, mock_api = app_client
    mock_api.stream_stats_by_id.return_value = {"stats_key": "secret"}
    r = client.get("/streams/s1/stats.json")
    assert r.headers.get("Cache-Control") == "no-store"


def test_login_rejects_bad_password():
    with patch("app.Lrtmp2Client"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        r = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password-value"},
        )
        assert r.status_code == 200
        assert b"Invalid credentials" in r.data


def test_login_accepts_valid_credentials():
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        r = client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/")


def test_logout_clears_session():
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        r = client.post("/logout")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]

        r2 = client.get("/")
        assert r2.status_code == 302
        assert "/login" in r2.headers["Location"]


def test_index_requires_login_when_not_authenticated():
    with patch("app.Lrtmp2Client"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        client = application.test_client()
        r = client.get("/")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]


def test_stream_stats_json_returns_data(app_client):
    client, mock_api = app_client
    mock_api.stream_stats_by_id.return_value = {"id": "s1", "live": False}

    r = client.get("/streams/s1/stats.json")
    assert r.status_code == 200
    assert r.get_json()["id"] == "s1"
    mock_api.stream_stats_by_id.assert_called_once_with("s1")


def test_stream_stats_json_api_failure_returns_502(app_client):
    from lrtmp2_client import Lrtmp2ApiError

    client, mock_api = app_client
    mock_api.stream_stats_by_id.side_effect = Lrtmp2ApiError("down")

    r = client.get("/streams/s1/stats.json")
    assert r.status_code == 502
    assert r.get_json() == {"error": "Failed to fetch stats"}


def test_stream_stats_json_scoped_rate_limit_allows_polling(app_client):
    """scripts.js polls each stream every 3s; 300/min allows up to 15 streams."""
    client, mock_api = app_client
    mock_api.stream_stats_by_id.return_value = {"streams": []}

    for _ in range(110):
        r = client.get("/streams/s1/stats.json")
        assert r.status_code == 200


def test_create_stream_get_renders_form(app_client):
    client, _mock_api = app_client
    r = client.get("/streams/new")
    assert r.status_code == 200
