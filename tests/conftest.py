import os

import pytest
from flask_test_utils import configure_testing_app

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
os.environ.setdefault("PASSWORD", "test-password-for-ci-only")
os.environ.setdefault("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
os.environ["USERNAME"] = "admin"
os.environ["PASSWORD"] = "test-password-for-ci-only"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: tests requiring a live librtmp2-server (RUN_INTEGRATION=1)",
    )


@pytest.fixture
def app_client(monkeypatch):
    """Flask test client with login session and mocked API."""
    from unittest.mock import patch

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"rtmps_enabled": False}
        mock_client.list_streams.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        yield client, mock_client
