"""Every state-changing panel route is login- and CSRF-protected.

The panel authenticates browsers with a session cookie, so (unlike the
Bearer-only server API) CSRF protection is what keeps a foreign site from
driving it. These tests walk the live URL map instead of a hand-kept list, so
a newly added mutating route is covered automatically.
"""

import os
import re
from unittest.mock import patch

import pytest

# Client calls that only read. Anything else an unauthorised or forged request
# makes is counted as a mutation, so new client mutators are covered without
# having to be listed here.
READ_ONLY = {
    "health",
    "list_streams",
    "stream_stats",
    "stream_stats_by_id",
    "cluster_status",
    "cluster_nodes",
    "cluster_streams",
    "cluster_enabled_from_health",
}
VALID_PLAYER_ID = "vi_" + "0" * 32
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@pytest.fixture
def panel(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(app_module.Config, "REQUIRE_LOGIN", True)
    # Record every run of the panel's CSRF error handler, so the sweep proves
    # CSRF validation rejected a request instead of inferring it from the
    # status code (the handler turns Flask-WTF's 400 into a redirect).
    csrf_errors = []
    original_handler = app_module._PanelRuntime.handle_csrf_error

    def record_csrf_error(runtime, error):
        csrf_errors.append(error)
        return original_handler(runtime, error)

    with patch("app.Lrtmp2Client") as client_cls, patch.object(
        app_module._PanelRuntime, "handle_csrf_error", record_csrf_error
    ):
        upstream = client_cls.return_value
        upstream.health.return_value = {"rtmps_enabled": False}
        upstream.list_streams.return_value = []
        application = app_module.create_app()
        application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        application.extensions["test_csrf_errors"] = csrf_errors
        yield application, upstream


def _placeholder(name):
    """A syntactically valid id, so a missing guard would reach the upstream."""
    if "node" in name:
        return "1"
    if "player" in name:
        return VALID_PLAYER_ID
    return "demo"


def _mutating_urls(application):
    urls = []
    for rule in application.url_map.iter_rules():
        if rule.endpoint == "static" or not (rule.methods & UNSAFE):
            continue
        url = re.sub(r"<([^>]+)>", lambda m: _placeholder(m.group(1)), rule.rule)
        for method in sorted(rule.methods & UNSAFE):
            urls.append((method, url, rule.endpoint))
    return urls


def _token(client, path):
    page = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match is not None
    return match.group(1)


def _login(client):
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": os.environ["PASSWORD"],
            "csrf_token": _token(client, "/login"),
        },
    )
    assert response.status_code == 302


def _csrf_errors(application):
    return application.extensions["test_csrf_errors"]


def _mutations(upstream):
    return [c for c in upstream.method_calls if c[0] not in READ_ONLY]


def test_url_map_contains_the_expected_mutating_routes(panel):
    application, _ = panel
    endpoints = {e for _, _, e in _mutating_urls(application)}
    assert {
        "login",
        "logout",
        "create_stream",
        "delete_stream",
        "add_player",
        "delete_player",
        "cluster_drain_node",
        "cluster_resume_node",
        "cluster_remove_node",
    } <= endpoints


@pytest.mark.parametrize("content_type", [
    "application/x-www-form-urlencoded",
    "text/plain",
    "multipart/form-data; boundary=x",
])
def test_anonymous_forged_requests_cannot_mutate(panel, content_type):
    application, upstream = panel
    for method, url, endpoint in _mutating_urls(application):
        client = application.test_client()
        before = len(_csrf_errors(application))
        response = client.open(
            url,
            method=method,
            data="name=x&stream_name=x",
            content_type=content_type,
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code in (302, 400, 401, 403, 404, 415), (
            method,
            url,
            response.status_code,
        )
        assert len(_csrf_errors(application)) == before + 1, (
            f"CSRF validation did not reject {method} {url}"
        )
        assert "Access-Control-Allow-Origin" not in response.headers
    assert _mutations(upstream) == []


def test_anonymous_requests_with_a_valid_csrf_token_are_sent_to_login(panel):
    """Authentication is exercised on its own, not masked by the CSRF check."""
    application, upstream = panel
    for method, url, endpoint in _mutating_urls(application):
        if endpoint in ("login", "logout"):
            continue  # not login-protected by design
        client = application.test_client()
        token = _token(client, "/login")
        response = client.open(
            url,
            method=method,
            data={"csrf_token": token, "stream_name": "x"},
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 302, (method, url, response.status_code)
        assert "/login" in response.headers["Location"], (method, url)
    assert _mutations(upstream) == []
    assert _csrf_errors(application) == [], "a valid token must pass CSRF"


def test_logged_in_session_without_valid_csrf_token_cannot_mutate(panel):
    application, upstream = panel
    client = application.test_client()
    _login(client)
    good = _token(client, "/")
    forged_tokens = ({}, {"csrf_token": ""}, {"csrf_token": "forged"}, {"csrf_token": good[:-2] + "xx"})
    for method, url, endpoint in _mutating_urls(application):
        # /login is the login form itself; a forged /logout is checked below
        # because a successful one would end this session.
        if endpoint in ("login", "logout"):
            continue
        for data in forged_tokens:
            before = len(_csrf_errors(application))
            response = client.open(
                url,
                method=method,
                data=data,
                headers={"Origin": "https://evil.example"},
            )
            assert response.status_code in (302, 400, 403), (method, url, data)
            assert len(_csrf_errors(application)) == before + 1, (
                f"CSRF validation did not reject {method} {url} with {data}"
            )
    assert _mutations(upstream) == []

    for data in forged_tokens:
        before = len(_csrf_errors(application))
        assert client.post("/logout", data=data).status_code in (302, 400, 403)
        assert len(_csrf_errors(application)) == before + 1, "forged logout"
        assert client.get("/").status_code == 200, "forged logout ended the session"


def test_valid_csrf_token_still_allows_the_legitimate_mutation(panel):
    application, upstream = panel
    client = application.test_client()
    _login(client)
    response = client.post("/streams/demo/delete", data={"csrf_token": _token(client, "/")})
    assert response.status_code == 302
    upstream.delete_stream.assert_called_once_with("demo")
    assert _csrf_errors(application) == []


def test_session_cookie_is_httponly_and_samesite_strict(panel):
    application, _ = panel
    client = application.test_client()
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": os.environ["PASSWORD"],
            "csrf_token": _token(client, "/login"),
        },
    )
    cookies = [v for k, v in response.headers if k == "Set-Cookie"]
    assert cookies, "login must set a session cookie"
    for cookie in cookies:
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
