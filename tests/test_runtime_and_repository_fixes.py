import os
from pathlib import Path
from unittest.mock import patch

from flask import request

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
os.environ.setdefault("PASSWORD", "test-password-for-ci-only")
os.environ.setdefault("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
os.environ["RATELIMIT_STORAGE_URI"] = "memory://"


ROOT = Path(__file__).resolve().parents[1]


def test_url_host_formatter_brackets_ipv6_literals():
    import app as app_module

    assert app_module._format_url_host("2001:db8::1") == "[2001:db8::1]"
    assert app_module._format_url_host("[2001:db8::1]") == "[2001:db8::1]"
    assert app_module._format_url_host("192.0.2.10") == "192.0.2.10"
    assert app_module._format_url_host("rtmp.example.test") == "rtmp.example.test"


def _proxy_test_client(proxy_count):
    import app as app_module

    with patch.object(app_module.Config, "TRUSTED_PROXY_COUNT", proxy_count), patch.object(
        app_module.Config, "RATELIMIT_STORAGE_URI", "memory://"
    ), patch.object(app_module.Config, "SESSION_COOKIE_SECURE", False):
        application = app_module.create_app()

    application.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    @application.get("/_test/request-info")
    def request_info():
        return f"{request.scheme}|{request.remote_addr}"

    return application.test_client()


def test_forwarded_headers_are_ignored_by_default():
    client = _proxy_test_client(0)
    response = client.get(
        "/_test/request-info",
        headers={
            "X-Forwarded-For": "198.51.100.25",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.get_data(as_text=True) == "http|127.0.0.1"


def test_forwarded_headers_are_used_for_exact_trusted_proxy_count():
    client = _proxy_test_client(1)
    response = client.get(
        "/_test/request-info",
        headers={
            "X-Forwarded-For": "198.51.100.25",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.get_data(as_text=True) == "https|198.51.100.25"


def test_development_compose_uses_lowercase_registry_paths():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "ghcr.io/OpenRTMP" not in compose
    assert "ghcr.io/openrtmp/librtmp2-server-panel:latest" in compose
    assert "ghcr.io/openrtmp/librtmp2-server:latest" in compose


def test_manual_release_creates_tag_from_selected_source_commit_safely():
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    docker = (ROOT / ".github/workflows/docker-multiarch.yml").read_text(encoding="utf-8")

    assert "Version tag to create" in release
    assert release.count("ref: ${{ github.sha }}") == 2
    assert "group: release-${{ github.event.inputs.tag || github.ref_name }}" in release
    assert "REF: ${{ github.event.inputs.tag || github.ref_name }}" in release
    assert 'REF="${{ github.event.inputs.tag || github.ref_name }}"' not in release
    assert "Tag $TAG already exists" in release
    assert "Publish GitHub Release and create tag when missing" in release
    assert "target_commitish: ${{ steps.ver.outputs.source_sha }}" in release
    assert "ref: ${{ needs.package.outputs.source_sha }}" in release
    assert "ref: ${{ inputs.ref || github.ref }}" in docker
    assert "ref: ${{ github.event.inputs.tag || github.ref }}" not in release


def test_stats_polling_is_limited_to_visible_stream_and_times_out():
    scripts = (ROOT / "static/js/scripts.js").read_text(encoding="utf-8")

    assert "collapse.classList.contains('show')" in scripts
    assert "if (document.hidden)" in scripts
    assert "statsContainer.dataset.loading === 'true'" in scripts
    assert "new AbortController()" in scripts
    assert "controller.abort()" in scripts
    assert "clearTimeout(timeoutId)" in scripts
    assert "delete statsContainer.dataset.loading" in scripts


def test_https_csrf_keeps_same_origin_referrer():
    base = (ROOT / "templates/base.html").read_text(encoding="utf-8")

    assert '<meta name="referrer" content="same-origin">' in base
    assert '<meta name="referrer" content="no-referrer">' not in base


def test_proxy_docs_require_header_count_normalization():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "applies the configured count independently" in readme
    assert "must append or normalize both headers" in readme
