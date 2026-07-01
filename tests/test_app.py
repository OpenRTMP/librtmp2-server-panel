import os
from unittest.mock import patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
os.environ.setdefault("PASSWORD", "test-password-for-ci-only")
os.environ.setdefault("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")


def test_session_cookie_secure_defaults_false(monkeypatch):
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.SESSION_COOKIE_SECURE is False


def test_session_cookie_secure_honors_env(monkeypatch):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.SESSION_COOKIE_SECURE is True


def test_config_loads_without_password_when_login_disabled(monkeypatch):
    monkeypatch.setenv("REQUIRE_LOGIN", "false")
    monkeypatch.delenv("PASSWORD", raising=False)
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is False
    assert config.Config.PASSWORD == ""


def test_create_stream_rolls_back_on_duplicate_id(tmp_path, monkeypatch):
    db_path = tmp_path / "panel.db"
    monkeypatch.setenv("PANEL_DB_PATH", str(db_path))

    mock_result = {
        "id": "dup-stream",
        "name": "Dup",
        "app": "live",
        "publish_key": "pk",
        "play_key": "plk",
        "stats_key": "stk",
    }

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.create_stream.return_value = mock_result

        import app as app_module

        monkeypatch.setattr(app_module.Config, "PANEL_DB_PATH", str(db_path))
        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r1 = client.post(
            "/streams/new",
            data={"id": "dup-stream", "name": "First", "app": "live"},
        )
        assert r1.status_code == 302

        r2 = client.post(
            "/streams/new",
            data={"id": "dup-stream", "name": "Second", "app": "live"},
        )
        assert r2.status_code == 200
        assert b"already exists" in r2.data
        assert mock_client.create_stream.call_count == 2
        mock_client.delete_stream.assert_called_once_with("dup-stream")


def test_delete_stream_keeps_local_row_when_api_fails(tmp_path, monkeypatch):
    db_path = tmp_path / "panel.db"
    monkeypatch.setenv("PANEL_DB_PATH", str(db_path))

    from store import Store

    store = Store(str(db_path))
    store.add_stream("keep-me", "Keep", "live", "pk", "plk", "stk")

    with patch("app.Lrtmp2Client") as mock_client_cls:
        from lrtmp2_client import Lrtmp2ApiError

        mock_client = mock_client_cls.return_value
        mock_client.delete_stream.side_effect = Lrtmp2ApiError("server down")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "PANEL_DB_PATH", str(db_path))
        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.post("/streams/keep-me/delete")
        assert r.status_code == 302
        assert store.get_stream("keep-me") is not None


def test_create_stream_rejects_path_unsafe_stream_id(tmp_path, monkeypatch):
    db_path = tmp_path / "panel.db"
    monkeypatch.setenv("PANEL_DB_PATH", str(db_path))

    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

        monkeypatch.setattr(app_module.Config, "PANEL_DB_PATH", str(db_path))
        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.post(
            "/streams/new",
            data={"id": "bad/id", "name": "Bad", "app": "live"},
        )
        assert r.status_code == 200
        assert b"Stream ID must be" in r.data
        mock_client_cls.return_value.create_stream.assert_not_called()


def test_delete_stream_url_encodes_stream_id():
    from lrtmp2_client import Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete:
        mock_delete.return_value.ok = True
        client.delete_stream("a/b?c")

    assert mock_delete.call_args.args[0] == "http://example.test/api/v1/streams/a%2Fb%3Fc"
