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

MUTATORS = {
    "create_stream",
    "delete_stream",
    "create_player",
    "delete_player",
    "cluster_drain_node",
    "cluster_resume_node",
    "cluster_remove_node",
}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@pytest.fixture
def panel(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(app_module.Config, "REQUIRE_LOGIN", True)
    with patch("app.Lrtmp2Client") as client_cls:
        upstream = client_cls.return_value
        upstream.health.return_value = {"rtmps_enabled": False}
        upstream.list_streams.return_value = []
        application = app_module.create_app()
        application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        yield application, upstream


def _mutating_urls(application):
    urls = []
    for rule in application.url_map.iter_rules():
        if rule.endpoint == "static" or not (rule.methods & UNSAFE):
            continue
        url = re.sub(
            r"<([^>]+)>", lambda m: "1" if "node" in m.group(1) else "demo", rule.rule
        )
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


def _mutations(upstream):
    return [c for c in upstream.method_calls if c[0] in MUTATORS]


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
        assert "Access-Control-Allow-Origin" not in response.headers
    assert _mutations(upstream) == []


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
            response = client.open(
                url,
                method=method,
                data=data,
                headers={"Origin": "https://evil.example"},
            )
            assert response.status_code in (302, 400, 403), (method, url, data)
    assert _mutations(upstream) == []

    for data in forged_tokens:
        assert client.post("/logout", data=data).status_code in (302, 400, 403)
        assert client.get("/").status_code == 200, "forged logout ended the session"


def test_valid_csrf_token_still_allows_the_legitimate_mutation(panel):
    application, upstream = panel
    client = application.test_client()
    _login(client)
    response = client.post("/streams/demo/delete", data={"csrf_token": _token(client, "/")})
    assert response.status_code == 302
    upstream.delete_stream.assert_called_once_with("demo")


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
