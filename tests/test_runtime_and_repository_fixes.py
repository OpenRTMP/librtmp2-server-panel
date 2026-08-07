import os
import re
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


def _proxy_test_client(proxy_count, trusted_proxy_ips="127.0.0.1"):
    import app as app_module

    trusted_networks = []
    if trusted_proxy_ips:
        import config as config_module

        trusted_networks = config_module._parse_trusted_proxy_networks(trusted_proxy_ips)

    with patch.object(app_module.Config, "TRUSTED_PROXY_COUNT", proxy_count), patch.object(
        app_module.Config, "TRUSTED_PROXY_NETWORKS", trusted_networks
    ), patch.object(
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


def test_manual_release_validates_and_pins_the_selected_source_commit():
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    docker = (ROOT / ".github/workflows/docker-multiarch.yml").read_text(encoding="utf-8")

    assert re.search(r"concurrency:\s+group:\s+release-", release)
    assert re.search(r"env:\s+REF:\s+\$\{\{ github\.event\.inputs\.tag", release)
    assert "git check-ref-format \"refs/tags/$REF\"" in release
    assert "(\\.[0-9]+){2,}" in release
    assert "(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?" in release
    assert "(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?" in release
    assert "v0.1.5.1" in release
    assert "v0.1.5+build.1" in release
    assert 'CHANGELOG_VERSION="${VERSION%%+*}"' in release
    assert 'awk -v ver="$CHANGELOG_VERSION"' in release
    assert "printf 'tag=%s\\n' \"$REF\" >> \"$GITHUB_OUTPUT\"" in release
    assert len(re.findall(r"ref:\s+\$\{\{ github\.sha \}\}", release)) == 2
    assert "target_commitish: ${{ steps.ver.outputs.source_sha }}" in release
    assert "ref: ${{ needs.package.outputs.source_sha }}" in release
    assert "ref: ${{ inputs.ref || github.ref }}" in docker
    assert 'REF="${{ github.event.inputs.tag || github.ref_name }}"' not in release


def test_stats_polling_is_limited_to_visible_stream_and_times_out():
    scripts = (ROOT / "static/js/scripts.js").read_text(encoding="utf-8")

    assert re.search(r"classList\.contains\(['\"]show['\"]\)", scripts)
    assert re.search(r"if\s*\(document\.hidden\)", scripts)
    assert "new AbortController()" in scripts
    assert "controller.abort()" in scripts
    assert "clearTimeout(timeoutId)" in scripts
    assert "delete statsContainer.dataset.loading" in scripts
    assert "relayRaw === null || relayRaw === undefined" in scripts
    assert "data.owner_node_id" in scripts
    assert "data.cluster_proxy" in scripts
    assert "data.cluster ||" not in scripts
    assert "'n/a'" in scripts or '"n/a"' in scripts
    assert "0.0 Mbps" not in scripts


def test_https_csrf_keeps_same_origin_referrer():
    base = (ROOT / "templates/base.html").read_text(encoding="utf-8")

    assert re.search(
        r'<meta\s+name=["\']referrer["\']\s+content=["\']same-origin["\']\s*/?>',
        base,
    )
    assert "no-referrer" not in base


def test_proxy_docs_require_header_count_normalization():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert re.search(r"configured count independently", readme, re.IGNORECASE)
    assert re.search(r"append or normalize both headers", readme, re.IGNORECASE)
