import os
import re
import time
from unittest.mock import patch

import pytest


def _csrf_app(monkeypatch, *, require_login=True):
    import app as app_module

    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(app_module.Config, "REQUIRE_LOGIN", require_login)
    application = app_module.create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    return application


def _csrf_token(client, path="/login"):
    page = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match is not None
    return match.group(1)


def _login(client):
    token = _csrf_token(client)
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": os.environ["PASSWORD"],
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    # Login rotates the session, so forms rendered after it carry a new token.
    return _csrf_token(client, "/")


@pytest.fixture
def mock_client():
    with patch("app.Lrtmp2Client") as mock_client_cls:
        client = mock_client_cls.return_value
        client.health.return_value = {"rtmps_enabled": False}
        client.list_streams.return_value = []
        yield client


def test_csrf_tokens_live_as_long_as_the_login_session(monkeypatch, mock_client):
    application = _csrf_app(monkeypatch)

    assert application.config["WTF_CSRF_TIME_LIMIT"] == int(
        application.config["SESSION_LIFETIME"].total_seconds()
    )


def test_form_on_a_dashboard_open_longer_than_an_hour_still_works(
    monkeypatch, mock_client
):
    application = _csrf_app(monkeypatch)
    client = application.test_client()
    token = _login(client)

    two_hours_later = time.time() + 2 * 3600
    with patch("itsdangerous.timed.time.time", return_value=two_hours_later):
        response = client.post("/streams/demo/delete", data={"csrf_token": token})

    assert response.status_code == 302
    mock_client.delete_stream.assert_called_once_with("demo")


def test_rejected_form_redirects_with_message_instead_of_bare_400(
    monkeypatch, mock_client
):
    application = _csrf_app(monkeypatch)
    client = application.test_client()
    _login(client)

    response = client.post("/streams/demo/delete", data={"csrf_token": "stale"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    mock_client.delete_stream.assert_not_called()
    with client.session_transaction() as sess:
        assert "nothing was changed" in sess.get("flash_error", "")


def test_rejected_login_form_shows_the_login_page(monkeypatch, mock_client):
    application = _csrf_app(monkeypatch)
    client = application.test_client()

    response = client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )

    assert response.status_code == 400
    assert b"The login form expired" in response.data
    with client.session_transaction() as sess:
        assert not sess.get("logged_in")


def test_rejected_form_after_session_expiry_explains_on_login_page(
    monkeypatch, mock_client
):
    application = _csrf_app(monkeypatch)
    client = application.test_client()
    _login(client)
    with client.session_transaction() as sess:
        sess["session_token"] = "expired-or-revoked"

    response = client.post("/streams/demo/delete", data={"csrf_token": "stale"})

    assert response.status_code == 400
    assert b"Your session expired, so nothing was changed" in response.data
    mock_client.delete_stream.assert_not_called()


@pytest.mark.parametrize("page", ["/", "/cluster"])
def test_logout_button_only_when_login_is_required(monkeypatch, mock_client, page):
    mock_client.cluster_status.return_value = {"enabled": False}

    open_app = _csrf_app(monkeypatch, require_login=False)
    open_page = open_app.test_client().get(page).get_data(as_text=True)
    assert ">Logout<" not in open_page

    protected_app = _csrf_app(monkeypatch, require_login=True)
    client = protected_app.test_client()
    _login(client)
    protected_page = client.get(page).get_data(as_text=True)
    assert ">Logout<" in protected_page
