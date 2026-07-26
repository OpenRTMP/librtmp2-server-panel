import ipaddress

import pytest

from config import client_ip_for_rate_limit


def test_client_ip_for_rate_limit_ignores_spoofed_xff_from_untrusted_direct_clients():
    networks = [ipaddress.ip_network("203.0.113.0/24")]
    client_ip = client_ip_for_rate_limit(
        direct_addr="10.0.0.5",
        forwarded_addr="198.51.100.25",
        trusted_proxy_count=1,
        trusted_networks=networks,
    )
    assert client_ip == "10.0.0.5"


def test_client_ip_for_rate_limit_uses_forwarded_ip_from_trusted_proxy():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    client_ip = client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="198.51.100.25",
        trusted_proxy_count=1,
        trusted_networks=networks,
    )
    assert client_ip == "198.51.100.25"


def test_config_requires_trusted_proxy_ips_when_proxy_count_enabled(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)

    import importlib
    import sys

    sys.modules.pop("config", None)
    with pytest.raises(SystemExit) as exc:
        importlib.import_module("config")
    assert exc.value.code == 1


def test_session_cookie_secure_defaults_true_when_trusted_proxy_count_enabled(
    monkeypatch,
):
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("PANEL_PUBLIC_URL", raising=False)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "127.0.0.1")

    import importlib
    import sys

    sys.modules.pop("config", None)
    config = importlib.import_module("config")

    importlib.reload(config)
    assert config.Config.SESSION_COOKIE_SECURE is True
