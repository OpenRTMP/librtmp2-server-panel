"""Integration tests against a live librtmp2-server (Docker in CI).

Run locally:
  RUN_INTEGRATION=1 LRTMP2_API_URL=http://localhost:8080 \\
    LRTMP2_API_TOKEN=<token> docker compose -f docker-compose.integration.yml up -d --build --wait
  RUN_INTEGRATION=1 LRTMP2_API_URL=http://localhost:8080 \\
    LRTMP2_API_TOKEN=<token> pytest -m integration -q
"""

import importlib
import os
import sys
import uuid

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_INTEGRATION") != "1",
        reason="set RUN_INTEGRATION=1 with a running librtmp2-server",
    ),
]

CI_API_TOKEN = (
    "c10123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
)
PUB_KEY = "pub_integration_key_with_sufficient_length01"
PLAY_KEY = "play_integration_key_with_sufficient_length01"
STATS_KEY = "st_integration_key_with_sufficient_length001"


@pytest.fixture(scope="module")
def api_base_url():
    return os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")


@pytest.fixture(scope="module")
def api_token():
    return os.environ.get("LRTMP2_API_TOKEN", CI_API_TOKEN)


@pytest.fixture(scope="module")
def live_client(api_base_url, api_token):
    from lrtmp2_client import Lrtmp2Client

    return Lrtmp2Client(api_base_url, api_token, timeout=10)


def test_live_health(api_base_url):
    import requests

    resp = requests.get(f"{api_base_url}/api/v1/health", timeout=10)
    resp.raise_for_status()
    body = resp.json()
    assert body.get("status") == "ok"
    assert body.get("rtmp_port") == 1935


def test_live_create_list_delete_stream(live_client):
    stream_id = f"ci{uuid.uuid4().hex[:8]}"
    created = live_client.create_stream(
        stream_id,
        "Integration Stream",
        "live",
        publish_key=PUB_KEY,
        play_key=PLAY_KEY,
        stats_key=STATS_KEY,
    )
    assert created["id"] == stream_id
    assert created["publish_key"] == PUB_KEY

    streams = live_client.list_streams()
    assert any(s.get("id") == stream_id for s in streams)

    live_client.delete_stream(stream_id)
    streams_after = live_client.list_streams()
    assert not any(s.get("id") == stream_id for s in streams_after)


def test_live_public_stats_offline(live_client, api_base_url):
    import requests

    stream_id = f"st{uuid.uuid4().hex[:8]}"
    stats_key = "st_stats_offline_key_with_sufficient_len01"
    live_client.create_stream(
        stream_id,
        "Stats Offline",
        "live",
        publish_key="pub_stats_offline_key_with_sufficient_len01",
        play_key="play_stats_offline_key_with_sufficient_len01",
        stats_key=stats_key,
    )
    try:
        resp = requests.get(
            f"{api_base_url}/stats",
            params={"key": stats_key},
            timeout=10,
        )
        assert resp.status_code == 200
        assert resp.text == "Stream offline"
    finally:
        live_client.delete_stream(stream_id)


def _integration_panel_env(api_base_url, api_token, monkeypatch):
    monkeypatch.setenv("LRTMP2_API_URL", api_base_url)
    monkeypatch.setenv("LRTMP2_API_TOKEN", api_token)
    monkeypatch.setenv("LRTMP2_STATS_URL", api_base_url)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("USERNAME", "admin")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)


def _fresh_flask_app(monkeypatch, api_base_url, api_token):
    _integration_panel_env(api_base_url, api_token, monkeypatch)
    sys.modules.pop("config", None)
    sys.modules.pop("app", None)
    import app as app_module

    importlib.reload(app_module)
    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    application = app_module.create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


def test_panel_lists_stream_from_live_server(live_client, api_base_url, api_token, monkeypatch):
    stream_id = f"ui{uuid.uuid4().hex[:8]}"
    live_client.create_stream(
        stream_id,
        "Panel Integration",
        "live",
        publish_key="pub_panel_live_key_with_sufficient_len01",
        play_key="play_panel_live_key_with_sufficient_len01",
        stats_key="st_panel_live_key_with_sufficient_len001",
    )
    try:
        application = _fresh_flask_app(monkeypatch, api_base_url, api_token)
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        resp = client.get("/")
        assert resp.status_code == 200
        assert stream_id.encode() in resp.data
        assert b"Panel Integration" in resp.data
    finally:
        live_client.delete_stream(stream_id)


def test_panel_create_stream_against_live_server(
    live_client, api_base_url, api_token, monkeypatch
):
    stream_id = f"new{uuid.uuid4().hex[:7]}"
    application = _fresh_flask_app(monkeypatch, api_base_url, api_token)
    client = application.test_client()
    client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )
    try:
        resp = client.post(
            "/streams/new",
            data={"id": stream_id, "name": "Created Via Panel", "app": "live"},
        )
        assert resp.status_code == 302
        assert f"/streams/created?stream_id={stream_id}" in resp.headers["Location"]

        streams = live_client.list_streams()
        assert any(s.get("id") == stream_id for s in streams)
    finally:
        live_client.delete_stream(stream_id)
