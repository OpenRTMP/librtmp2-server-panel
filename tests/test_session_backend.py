import os
from unittest.mock import patch

from session_store import SessionBackendUnavailable


def test_login_returns_503_without_mutating_session_when_backend_write_fails():
    with patch("app.Lrtmp2Client") as mock_client_cls, patch(
        "app.create_session_store"
    ) as create_store:
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []
        store = create_store.return_value
        store.replace_user_session.side_effect = SessionBackendUnavailable(
            "Session backend unavailable"
        )

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        client = application.test_client()

        with client.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["session_token"] = "existing-token"

        with patch.object(application.logger, "error") as log_error:
            response = client.post(
                "/login",
                data={"username": "admin", "password": os.environ["PASSWORD"]},
            )

        assert response.status_code == 503
        assert b"temporarily unavailable" in response.data
        log_error.assert_called_once()

        with client.session_transaction() as sess:
            assert sess["logged_in"] is True
            assert sess["username"] == "admin"
            assert sess["session_token"] == "existing-token"

        store.revoke.assert_not_called()
