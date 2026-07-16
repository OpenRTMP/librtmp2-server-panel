import os
from unittest.mock import patch

from session_store import SessionBackendUnavailable


def test_logout_validation_failure_preserves_session_and_reports_error():
    with patch("app.Lrtmp2Client") as mock_client_cls, patch(
        "app.create_session_store"
    ) as create_store:
        mock_client_cls.return_value.health.return_value = {"rtmps_enabled": False}
        mock_client_cls.return_value.list_streams.return_value = []
        store = create_store.return_value

        import app as app_module

        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False  # NOSONAR - test client posts without CSRF tokens
        application.config["REQUIRE_LOGIN"] = True
        client = application.test_client()

        client.post(
            "/login",
            data={"username": "admin", "password": os.environ["PASSWORD"]},
        )
        with client.session_transaction() as sess:
            token = sess["session_token"]

        store.is_valid.side_effect = SessionBackendUnavailable(
            "Session backend unavailable"
        )

        with patch.object(application.logger, "error") as log_error:
            response = client.post("/logout")

        assert response.status_code == 503
        assert b"still active" in response.data
        store.is_valid.assert_called_once_with("admin", token, fail_closed=True)
        store.revoke.assert_not_called()
        log_error.assert_called_once()

        with client.session_transaction() as sess:
            assert sess.get("logged_in") is True
            assert sess.get("username") == "admin"
            assert sess.get("session_token") == token
