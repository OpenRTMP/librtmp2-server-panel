import os
from unittest.mock import patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
os.environ.setdefault("PASSWORD", "test-password-for-ci-only")
os.environ.setdefault("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
# Force panel login credentials for isolated tests (override host .env).
os.environ["USERNAME"] = "admin"
os.environ["PASSWORD"] = "test-password-for-ci-only"


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


def test_password_not_required_when_login_disabled(monkeypatch):
    original_password = os.environ.get("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "false")
    monkeypatch.delenv("PASSWORD", raising=False)
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is False
    assert config.Config.PASSWORD == ""

    monkeypatch.delenv("REQUIRE_LOGIN", raising=False)
    monkeypatch.setenv("PASSWORD", original_password)
    importlib.reload(config)


def test_index_lists_streams_from_api(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.list_streams.return_value = [
            {
                "id": "s1",
                "name": "Stream One",
                "app": "live",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "stats_key": "st_k",
                "players": [
                    {
                        "id": "vi_s1",
                        "name": "Player 1",
                        "play_key": "pl_k",
                    }
                ],
                "enabled": True,
                "created_at": 1,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.get("/")
        assert r.status_code == 200
        assert b"Stream One" in r.data
        assert b"s1" in r.data
        assert b"pub_k" in r.data
        mock_client.list_streams.assert_called_once()


def test_create_stream_shows_keys_without_session_storage(monkeypatch):
    mock_result = {
        "id": "new-stream",
        "name": "New",
        "app": "live",
        "publish_key": "pk",
        "play_key": "plk",
        "stats_key": "stk",
        "players": [
            {
                "id": "vi_new",
                "name": "Player 1",
                "play_key": "plk",
            }
        ],
    }

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.create_stream.return_value = mock_result
        mock_client.list_streams.return_value = [mock_result]

        import app as app_module

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
            data={"id": "new-stream", "name": "New", "app": "live"},
        )
        assert r.status_code == 302
        assert "/streams/created?stream_id=new-stream" in r.headers["Location"]

        with client.session_transaction() as sess:
            assert "created_stream" not in sess

        r2 = client.get("/streams/created?stream_id=new-stream")
        assert r2.status_code == 200
        assert b"pk" in r2.data
        assert b"plk" in r2.data


def test_delete_stream_surfaces_api_error(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        from lrtmp2_client import Lrtmp2ApiError

        mock_client = mock_client_cls.return_value
        mock_client.list_streams.return_value = []
        mock_client.delete_stream.side_effect = Lrtmp2ApiError("server down")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.post("/streams/gone/delete")
        assert r.status_code == 302

        r2 = client.get("/")
        assert r2.status_code == 200
        assert b"server down" in r2.data


def test_create_stream_rejects_path_unsafe_stream_id(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

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


def test_delete_stream_rejects_invalid_stream_id(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.post("/streams/bad%00id/delete")
        assert r.status_code == 302

        r2 = client.get("/")
        assert r2.status_code == 200
        assert b"Invalid stream ID" in r2.data
        mock_client_cls.return_value.delete_stream.assert_not_called()


def test_stream_stats_rejects_invalid_stream_id(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.get("/streams/bad%00id/stats.json")
        assert r.status_code == 400
        assert r.get_json() == {"error": "Invalid stream ID"}
        mock_client_cls.return_value.stream_stats_by_id.assert_not_called()


def test_delete_stream_url_encodes_stream_id():
    from lrtmp2_client import Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete:
        mock_delete.return_value.ok = True
        client.delete_stream("a/b?c")

    assert mock_delete.call_args.args[0] == "http://example.test/api/v1/streams/a%2Fb%3Fc"


def test_create_stream_rejects_invalid_display_name(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

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
            data={"id": "ok-stream", "name": "bad\nname", "app": "live"},
        )
        assert r.status_code == 200
        assert b"Name must be" in r.data
        mock_client_cls.return_value.create_stream.assert_not_called()


def test_delete_player_rejects_invalid_player_id(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        r = client.post("/streams/s1/players/not-a-real-id/delete")
        assert r.status_code == 302

        r2 = client.get("/")
        assert r2.status_code == 200
        assert b"Invalid player ID" in r2.data
        mock_client_cls.return_value.delete_player.assert_not_called()


def test_stream_stats_by_id_uses_bearer_auth():
    from lrtmp2_client import Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = {"streams": []}
        client.stream_stats_by_id("mystream")

    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer tok"
    assert mock_get.call_args.args[0] == "http://example.test/api/v1/streams/mystream/stats"


def test_request_timeout_raised_as_api_error():
    import requests

    from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get", side_effect=requests.exceptions.Timeout):
        with pytest.raises(Lrtmp2ApiError):
            client.list_streams()


def test_request_connection_error_raised_as_api_error():
    import requests

    from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch(
        "lrtmp2_client.requests.get",
        side_effect=requests.exceptions.ConnectionError,
    ):
        with pytest.raises(Lrtmp2ApiError):
            client.list_streams()


def test_malformed_json_response_raised_as_api_error():
    from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client

    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.side_effect = ValueError("not json")
        with pytest.raises(Lrtmp2ApiError):
            client.list_streams()
