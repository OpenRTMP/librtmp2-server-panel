import importlib
import os
import sys
from unittest.mock import patch

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
os.environ.setdefault("PASSWORD", "test-password-for-ci-only")
os.environ.setdefault("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
# Force panel login credentials for isolated tests (override host .env).
os.environ["USERNAME"] = "admin"
os.environ["PASSWORD"] = "test-password-for-ci-only"


def _forget_config_module():
    sys.modules.pop("config", None)


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


def test_config_rejects_env_example_placeholders(monkeypatch):
    valid = {
        "SECRET_KEY": "valid-test-secret-key-for-placeholder-check",
        "PASSWORD": "valid-test-password-for-placeholder-check",
        "LRTMP2_API_TOKEN": "valid-test-api-token-for-placeholder-check",
    }
    placeholders = {
        "SECRET_KEY": "<generate-with-python3-secrets-token-hex-32>",
        "PASSWORD": "<generate-strong-password>",
        "LRTMP2_API_TOKEN": "<generate-with-openssl-rand-hex-32>",
    }
    for key, placeholder in placeholders.items():
        for env_key, env_value in valid.items():
            monkeypatch.setenv(env_key, env_value)
        monkeypatch.setenv(key, placeholder)
        monkeypatch.setenv("REQUIRE_LOGIN", "true")

        _forget_config_module()
        try:
            with pytest.raises(SystemExit) as exc:
                importlib.import_module("config")
            assert exc.value.code == 1
        finally:
            _forget_config_module()


def test_config_rejects_insecure_defaults_case_insensitive(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-case-check")
    monkeypatch.setenv("PASSWORD", "PASSWORD")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-case-check")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_require_login_empty_string_defaults_to_true(monkeypatch):
    monkeypatch.setenv("REQUIRE_LOGIN", "")
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is True


def test_require_login_unset_defaults_to_true(monkeypatch):
    monkeypatch.delenv("REQUIRE_LOGIN", raising=False)
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is True


def test_require_login_false_string_disables_login(monkeypatch):
    monkeypatch.setenv("REQUIRE_LOGIN", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_LOGIN", "1")
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is False


def test_config_rejects_require_login_typo(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-require-login-typo")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-require-login-typo")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-require-login-typo")
    monkeypatch.setenv("REQUIRE_LOGIN", "Tru")

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_config_rejects_short_secret_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "abc")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-short-secret-key")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-short-secret-key")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_session_cookie_secure_from_panel_public_url(monkeypatch):
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("PANEL_PUBLIC_URL", "https://panel.example.com")
    import config

    importlib.reload(config)
    assert config.Config.SESSION_COOKIE_SECURE is True


def test_password_not_required_when_login_disabled(monkeypatch):
    original_password = os.environ.get("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "false")
    monkeypatch.setenv("ALLOW_INSECURE_NO_LOGIN", "1")
    monkeypatch.delenv("PASSWORD", raising=False)
    import importlib
    import config

    importlib.reload(config)
    assert config.Config.REQUIRE_LOGIN is False
    assert config.Config.PASSWORD == ""

    monkeypatch.delenv("REQUIRE_LOGIN", raising=False)
    monkeypatch.setenv("PASSWORD", original_password)
    importlib.reload(config)


def test_config_rejects_short_password_when_login_enabled(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-placeholder-check")
    monkeypatch.setenv("PASSWORD", "12345678")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-placeholder-check")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_config_rejects_require_login_false_without_ack(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-insecure-login")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-insecure-login")
    monkeypatch.setenv("REQUIRE_LOGIN", "false")
    monkeypatch.delenv("ALLOW_INSECURE_NO_LOGIN", raising=False)

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_config_rejects_memory_ratelimit_with_gunicorn_cmd_args_workers(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-gunicorn-workers-check")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-gunicorn-workers-check")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-gunicorn-workers-check")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "--bind=0.0.0.0:8000 --workers=3")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)

    _forget_config_module()
    try:
        with pytest.raises(SystemExit) as exc:
            importlib.import_module("config")
        assert exc.value.code == 1
    finally:
        _forget_config_module()


def test_detect_worker_count_parses_gunicorn_cmd_args(monkeypatch):
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    import config

    monkeypatch.setenv("GUNICORN_CMD_ARGS", "--bind=0.0.0.0:8000 -w 4")
    assert config._detect_worker_count() == 4


def test_config_accepts_long_password_when_login_enabled(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-placeholder-check")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-placeholder-check")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-placeholder-check")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")

    _forget_config_module()
    try:
        importlib.import_module("config")
    finally:
        _forget_config_module()


def test_index_lists_streams_from_api(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
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


def test_index_shows_rtmps_urls_when_server_reports_enabled(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "rtmp_port": 1935,
            "rtmps_enabled": True,
            "rtmps_port": 1936,
        }
        mock_client.list_streams.return_value = [
            {
                "id": "s1",
                "name": "Stream One",
                "app": "live",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "stats_key": "st_k",
                "players": [
                    {"id": "vi_s1", "name": "Player 1", "play_key": "pl_k"}
                ],
                "enabled": True,
                "created_at": 1,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        monkeypatch.setattr(app_module.Config, "LRTMP2_RTMPS_PORT", "1936")
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
        assert b"RTMPS enabled" in r.data
        assert b"rtmps://localhost:1936/live" in r.data


def test_index_prefers_public_rtmps_port_over_health_bind_port(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "rtmp_port": 1935,
            "rtmps_enabled": True,
            "rtmps_port": 1936,
        }
        mock_client.list_streams.return_value = [
            {
                "id": "s1",
                "name": "Stream One",
                "app": "live",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "stats_key": "st_k",
                "players": [
                    {"id": "vi_s1", "name": "Player 1", "play_key": "pl_k"}
                ],
                "enabled": True,
                "created_at": 1,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        monkeypatch.setattr(app_module.Config, "LRTMP2_RTMPS_PORT", "443")
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
        assert b"RTMPS enabled" in r.data
        assert b"rtmps://localhost:443/live" in r.data
        assert b"rtmps://localhost:1936/live" not in r.data


def test_index_hides_rtmps_urls_when_server_reports_disabled(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
        mock_client.list_streams.return_value = [
            {
                "id": "s1",
                "name": "Stream One",
                "app": "live",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "stats_key": "st_k",
                "players": [
                    {"id": "vi_s1", "name": "Player 1", "play_key": "pl_k"}
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
        assert b"RTMPS disabled" in r.data
        assert b"rtmps://" not in r.data


def test_index_treats_health_failure_as_rtmps_disabled(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        from lrtmp2_client import Lrtmp2ApiError

        mock_client = mock_client_cls.return_value
        mock_client.health.side_effect = Lrtmp2ApiError("unreachable")
        mock_client.list_streams.return_value = []

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
        assert b"RTMPS disabled" in r.data


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
        mock_client.health.return_value = {"rtmps_enabled": False}
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


def test_create_stream_forwards_custom_keys(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.create_stream.return_value = {
            "id": "custom",
            "name": "Custom",
            "app": "live",
            "publish_key": "my_pub",
            "play_key": "my_play",
            "stats_key": "my_stats",
            "players": [],
        }

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
            data={
                "id": "custom",
                "name": "Custom",
                "app": "live",
                "publish_key": "my_pub_key_with_sufficient_length_here01",
                "play_key": "my_play_key_with_sufficient_length_here01",
                "stats_key": "my_stats_key_with_sufficient_length_here01",
            },
        )
        assert r.status_code == 302
        mock_client.create_stream.assert_called_once_with(
            "custom",
            "Custom",
            "live",
            publish_key="my_pub_key_with_sufficient_length_here01",
            play_key="my_play_key_with_sufficient_length_here01",
            stats_key="my_stats_key_with_sufficient_length_here01",
        )


def test_create_stream_rejects_invalid_custom_key(monkeypatch):
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
            data={"id": "badkey", "name": "Bad", "app": "live", "publish_key": "bad/key"},
        )
        assert r.status_code == 200
        assert b"publish_key:" in r.data
        mock_client_cls.return_value.create_stream.assert_not_called()


def test_create_stream_rejects_duplicate_custom_keys(monkeypatch):
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
            data={
                "id": "dup",
                "name": "Dup",
                "app": "live",
                "publish_key": "same_custom_key_with_sufficient_length01",
                "play_key": "same_custom_key_with_sufficient_length01",
            },
        )
        assert r.status_code == 200
        assert b"must be distinct" in r.data
        mock_client_cls.return_value.create_stream.assert_not_called()


def test_add_player_forwards_custom_play_key(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
        mock_client.list_streams.return_value = []

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
            "/streams/s1/players/new",
            data={"name": "Guest", "play_key": "guest_play_key_with_sufficient_length01"},
        )
        assert r.status_code == 302
        mock_client.create_player.assert_called_once_with(
            "s1",
            name="Guest",
            play_key="guest_play_key_with_sufficient_length01",
        )


def test_delete_stream_surfaces_api_error(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        from lrtmp2_client import Lrtmp2ApiError

        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
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
