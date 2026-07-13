import os
from unittest.mock import patch

import pytest


@pytest.fixture
def login_required_app():
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        application.config["REQUIRE_LOGIN"] = True
        yield application.test_client()


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


def _attempt_login_rate_limit_in_subprocess(queue):
    """Run login attempts in a child process for memory:// rate-limit isolation tests."""
    with patch("app.Lrtmp2Client"), patch("app.Config.RATELIMIT_STORAGE_URI", "memory://"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        client = application.test_client()
        accepted = 0
        for i in range(8):
            r = client.post(
                "/login",
                data={"username": "admin", "password": f"wrong-password-{i}"},
            )
            if r.status_code == 200 and b"Invalid credentials" in r.data:
                accepted += 1
        queue.put(accepted)


def test_login_rate_limit_blocks_after_five_attempts():
    with patch("app.Lrtmp2Client"), patch("app.Config.RATELIMIT_STORAGE_URI", "memory://"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        client = application.test_client()
        for i in range(5):
            r = client.post(
                "/login",
                data={"username": "admin", "password": f"wrong-password-{i}"},
            )
            assert r.status_code == 200
            assert b"Invalid credentials" in r.data

        r = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password-final"},
        )
        assert r.status_code == 429


def test_login_rate_limit_is_per_process_with_memory_storage():
    """Documents why docker-compose defaults to a shared redis:// limiter backend."""
    from multiprocessing import Process, Queue

    queue = Queue()
    workers = [
        Process(target=_attempt_login_rate_limit_in_subprocess, args=(queue,))
        for _ in range(3)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)

    alive = [worker for worker in workers if worker.is_alive()]
    for worker in alive:
        worker.terminate()
        worker.join()

    assert not alive, "Login rate-limit workers timed out"
    assert all(worker.exitcode == 0 for worker in workers)

    accepted_per_worker = [queue.get(timeout=5) for _ in workers]
    assert accepted_per_worker == [5, 5, 5]
    assert sum(accepted_per_worker) == 15


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


def test_logout_clears_session(login_required_app):
    client = login_required_app
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


def test_index_requires_login_by_default():
    with patch("app.Lrtmp2Client"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        client = application.test_client()
        r = client.get("/")
        assert r.status_code == 302
        assert "/login" in r.headers["Location"]


def test_index_requires_login_when_not_authenticated(login_required_app):
    r = login_required_app.get("/")
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


def test_stream_stats_json_scoped_rate_limit_is_per_stream(app_client):
    """Each stream_id gets its own 25/min bucket (scripts.js polls every 3s)."""
    client, mock_api = app_client
    mock_api.stream_stats_by_id.return_value = {"streams": []}

    for stream_id in ("s1", "s2", "s3"):
        for _ in range(20):
            r = client.get(f"/streams/{stream_id}/stats.json")
            assert r.status_code == 200


def test_stats_rate_limit_key_collapses_invalid_stream_ids():
    from flask_limiter.util import get_remote_address

    with patch("app.Lrtmp2Client"), patch("app.Config.RATELIMIT_STORAGE_URI", "memory://"):
        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        with application.test_request_context("/streams/not-valid!/stats.json"):
            assert (
                app_module._stats_rate_limit_key()
                == f"{get_remote_address()}:_invalid_"
            )


def test_unauthenticated_stats_requests_do_not_consume_rate_limit():
    with patch("app.Lrtmp2Client") as mock_client_cls, patch(
        "app.Config.RATELIMIT_STORAGE_URI", "memory://"
    ):
        mock_api = mock_client_cls.return_value
        mock_api.health.return_value = {"rtmps_enabled": False}
        mock_api.list_streams.return_value = []
        mock_api.stream_stats_by_id.return_value = {"streams": []}

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        application.config["REQUIRE_LOGIN"] = True
        client = application.test_client()

        for _ in range(30):
            r = client.get("/streams/s1/stats.json")
            assert r.status_code == 302
            assert r.status_code != 429

        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        for _ in range(20):
            r = client.get("/streams/s1/stats.json")
            assert r.status_code == 200


def test_create_stream_get_renders_form(app_client):
    client, _mock_api = app_client
    r = client.get("/streams/new")
    assert r.status_code == 200
