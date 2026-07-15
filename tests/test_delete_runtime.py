import os
from pathlib import Path
from unittest.mock import patch


def test_container_uses_threaded_gunicorn_for_long_running_deletes():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert '"--worker-class", "gthread"' in dockerfile
    assert '"--threads", "4"' in dockerfile
    assert '"--timeout", "60"' in dockerfile


def test_delete_stream_logs_api_failure(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        from lrtmp2_client import Lrtmp2ApiError

        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
        mock_client.list_streams.return_value = []
        mock_client.delete_stream.side_effect = Lrtmp2ApiError("delete failed")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )

        with patch.object(application.logger, "warning") as log_warning:
            response = client.post("/streams/fail/delete")

        assert response.status_code == 302
        log_warning.assert_called_once_with(
            "Delete for stream %s failed: %s",
            "fail",
            mock_client.delete_stream.side_effect,
        )
