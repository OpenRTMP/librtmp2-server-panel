"""Regressions for the r18 panel UI findings (RTMPS badge, numeric ids, C1 controls)."""

import os
from unittest.mock import patch

import pytest
from flask_test_utils import configure_testing_app

import app as app_module
import lrtmp2_client


def _login_client(monkeypatch):
    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    application = app_module.create_app()
    configure_testing_app(application)
    client = application.test_client()
    client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )
    return client


def test_index_api_failure_keeps_health_reported_rtmps_badge(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": True, "rtmps_port": 1936}
        mock_client.list_streams.side_effect = lrtmp2_client.Lrtmp2ApiError(
            "list_streams failed: connection refused"
        )
        client = _login_client(monkeypatch)

        body = client.get("/").get_data(as_text=True)

    assert "RTMPS enabled" in body
    assert "RTMPS disabled" not in body


@pytest.mark.parametrize("upstream_id", [0, 42])
def test_stream_created_accepts_numeric_upstream_id(monkeypatch, upstream_id):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
        mock_client.create_stream.return_value = {"id": upstream_id}
        mock_client.list_streams.return_value = [
            {
                "id": upstream_id,
                "name": "Cam",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "players": [],
            }
        ]
        client = _login_client(monkeypatch)

        created = client.post("/streams/new", data={"name": "Cam"})
        page = client.get(created.headers["Location"])

    assert page.status_code == 200
    assert "Cam" in page.get_data(as_text=True)


@pytest.mark.parametrize("name", ["a\x85b", "cam\x9b1", "a\x9fb"])
def test_display_name_rejects_c1_controls(name):
    assert app_module._is_valid_display_name(name) is False


def test_display_name_keeps_printable_unicode():
    assert app_module._is_valid_display_name("Cámara 1") is True
