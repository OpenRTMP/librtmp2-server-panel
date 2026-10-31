import contextlib
import logging
import os
from unittest.mock import patch

import pytest
from flask_test_utils import configure_testing_app

from config import _parse_log_level
from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, ("INFO", True)),
        ("", ("INFO", True)),
        ("0", ("ERROR", True)),
        ("1", ("WARNING", True)),
        ("2", ("INFO", True)),
        ("3", ("DEBUG", True)),
        ("debug", ("DEBUG", True)),
        (" Warn ", ("WARNING", True)),
        ("verbose", ("INFO", False)),
        ("7", ("INFO", False)),
    ],
)
def test_parse_log_level(raw, expected):
    assert _parse_log_level(raw) == expected


def _app():
    import app as app_module

    application = app_module.create_app()
    configure_testing_app(application)
    application.config["REQUIRE_LOGIN"] = True
    return application


def test_login_success_and_failure_are_logged_without_credentials(caplog):
    with patch("app.Lrtmp2Client") as mock_client_cls, patch("app.create_session_store"):
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []
        client = _app().test_client()
        with caplog.at_level(logging.INFO):
            client.post("/login", data={"username": "admin", "password": "wrong-password-1"})
            client.post(
                "/login",
                data={"username": "admin", "password": os.environ["PASSWORD"]},
            )
    messages = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("Login failed (invalid credentials) from ") for m in messages)
    assert any(m.startswith("Login succeeded from ") for m in messages)
    assert not any("wrong-password-1" in m or os.environ["PASSWORD"] in m for m in messages)


def test_api_error_status_is_logged_without_url(caplog):
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = False
        mock_get.return_value.status_code = 500
        mock_get.return_value.json.return_value = {}
        with caplog.at_level(logging.WARNING, logger="lrtmp2_client"):
            with pytest.raises(Lrtmp2ApiError):
                client.stream_stats("secret-stats-key")
    messages = [r.getMessage() for r in caplog.records]
    assert any("stream_stats -> HTTP 500" in m for m in messages)
    assert not any("secret-stats-key" in m for m in messages)


def test_debug_level_does_not_enable_third_party_url_logging(monkeypatch):
    import app as app_module

    application = app_module.create_app()
    application.config["LOG_LEVEL"] = "DEBUG"
    app_module._configure_logging(application)
    try:
        assert logging.getLogger("lrtmp2_client").isEnabledFor(logging.DEBUG)
        assert application.logger.isEnabledFor(logging.DEBUG)
        # urllib3 logs "GET /stats?key=..." at debug.
        assert not logging.getLogger("urllib3.connectionpool").isEnabledFor(logging.DEBUG)
    finally:
        application.config["LOG_LEVEL"] = "INFO"
        app_module._configure_logging(application)


def test_login_is_not_logged_as_succeeded_when_the_session_backend_fails(caplog):
    from session_store import SessionBackendUnavailable

    with patch("app.Lrtmp2Client") as mock_client_cls, patch("app.create_session_store"):
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        client = _app().test_client()
        with patch(
            "app._PanelRuntime._establish_logged_in_session",
            side_effect=SessionBackendUnavailable("down"),
        ), caplog.at_level(logging.INFO):
            resp = client.post(
                "/login",
                data={"username": "admin", "password": os.environ["PASSWORD"]},
            )
    assert resp.status_code == 503
    messages = [r.getMessage() for r in caplog.records]
    assert not any(m.startswith("Login succeeded from ") for m in messages)


@pytest.mark.parametrize(
    ("call", "ok_404_expected"),
    [
        (lambda c: c.delete_player("s1", "p1"), True),
        (lambda c: c.health(), False),
    ],
)
def test_404_is_quiet_only_for_the_idempotent_deletes(caplog, call, ok_404_expected):
    client = Lrtmp2Client("http://example.test", "tok")
    resp = type("Resp", (), {"ok": False, "status_code": 404, "json": lambda self: {}})()
    with patch("lrtmp2_client.requests.get", return_value=resp), patch(
        "lrtmp2_client.requests.delete", return_value=resp
    ), caplog.at_level(logging.DEBUG, logger="lrtmp2_client"):
        # Only the log level matters here; a raised API error is expected.
        with contextlib.suppress(Lrtmp2ApiError):
            call(client)
    levels = [r.levelno for r in caplog.records if "HTTP 404" in r.getMessage()]
    assert levels == [logging.DEBUG if ok_404_expected else logging.WARNING]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://user:pw@api.test:8080/base", "http://api.test:8080/base"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("http://api.test:99999", "http://api.test"),
    ],
)
def test_api_url_for_log_drops_userinfo_and_survives_bad_ports(url, expected):
    import app as app_module

    assert app_module._api_url_for_log(url) == expected


def test_final_3xx_response_logs_at_warning(caplog):
    client = Lrtmp2Client("http://example.test", "tok")
    # requests' resp.ok is True for 3xx; the API log must still warn.
    resp = type("Resp", (), {"ok": True, "status_code": 304, "json": lambda self: {}})()
    with patch("lrtmp2_client.requests.get", return_value=resp), caplog.at_level(
        logging.DEBUG, logger="lrtmp2_client"
    ):
        # Only the log level matters here; a raised API error is expected.
        with contextlib.suppress(Lrtmp2ApiError):
            client.health()
    levels = [r.levelno for r in caplog.records if "HTTP 304" in r.getMessage()]
    assert levels == [logging.WARNING]
