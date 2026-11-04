import ipaddress

import pytest

import config


def test_client_ip_for_rate_limit_ignores_spoofed_xff_from_untrusted_direct_clients():
    networks = [ipaddress.ip_network("203.0.113.0/24")]
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.5",
        forwarded_addr="198.51.100.25",
        trusted_proxy_count=1,
        trusted_networks=networks,
    )
    assert client_ip == "10.0.0.5"


def test_client_ip_for_rate_limit_fails_closed_when_direct_peer_is_missing():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="",
        forwarded_addr="198.51.100.25",
        trusted_proxy_count=1,
        trusted_networks=networks,
    )
    assert client_ip == "unknown"


def test_client_ip_for_rate_limit_uses_forwarded_ip_from_trusted_proxy():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="198.51.100.25",
        trusted_proxy_count=1,
        trusted_networks=networks,
        xff_header="198.51.100.25",
    )
    assert client_ip == "198.51.100.25"


def test_client_ip_for_rate_limit_ignores_a_spoofable_xff_position():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    # An over-counted TRUSTED_PROXY_COUNT makes ProxyFix select the first
    # entry (5.6.7.8), which the client wrote. The limiter must use the
    # proxy-appended last entry instead.
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="5.6.7.8",
        trusted_proxy_count=2,
        trusted_networks=networks,
        xff_header="5.6.7.8, 198.51.100.25",
    )
    assert client_ip == "198.51.100.25"


def test_client_ip_for_rate_limit_prefers_the_configured_client_ip_header():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="5.6.7.8",
        trusted_proxy_count=1,
        trusted_networks=networks,
        xff_header="5.6.7.8",
        proxy_client_ip="198.51.100.25",
    )
    assert client_ip == "198.51.100.25"


def test_client_ip_for_rate_limit_ignores_an_unconfigured_client_header():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    # The caller only passes the header value when the operator configured it;
    # the X-Real-IP request header alone must not move the bucket.
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="5.6.7.8",
        trusted_proxy_count=1,
        trusted_networks=networks,
        xff_header="6.6.6.6, 198.51.100.25",
    )
    assert client_ip == "198.51.100.25"


def test_client_ip_for_rate_limit_falls_back_to_the_proxy_without_headers():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    client_ip = config.client_ip_for_rate_limit(
        direct_addr="10.0.0.2",
        forwarded_addr="5.6.7.8",
        trusted_proxy_count=1,
        trusted_networks=networks,
    )
    assert client_ip == "10.0.0.2"


def test_client_ip_for_rate_limit_uses_forwarded_ip_from_dual_stack_proxy():
    networks = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1/32")]
    assert config.ip_in_trusted_proxy_networks("::ffff:10.1.2.3", networks) is True
    assert config.ip_in_trusted_proxy_networks("::ffff:127.0.0.1", networks) is True
    assert config.ip_in_trusted_proxy_networks("::ffff:192.0.2.10", networks) is False
    assert (
        config.client_ip_for_rate_limit(
            direct_addr="::ffff:10.1.2.3",
            forwarded_addr="198.51.100.25",
            trusted_proxy_count=1,
            trusted_networks=networks,
            xff_header="198.51.100.25",
        )
        == "198.51.100.25"
    )


def test_ip_in_trusted_proxy_networks_matches_ipv4_peer_to_v4_mapped_range():
    networks = [ipaddress.ip_network("::ffff:10.0.0.0/104")]
    assert config.ip_in_trusted_proxy_networks("10.1.2.3", networks) is True
    assert config.ip_in_trusted_proxy_networks("11.1.2.3", networks) is False
    # An untrusted dual-stack peer is still not a proxy.
    assert config.ip_in_trusted_proxy_networks("::ffff:11.1.2.3", networks) is False


@pytest.mark.parametrize("trusted_proxy_ips", ["0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"])
def test_config_rejects_universal_trusted_proxy_ips(monkeypatch, trusted_proxy_ips):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", trusted_proxy_ips)

    import importlib
    import sys

    sys.modules.pop("config", None)
    with pytest.raises(SystemExit) as exc:
        importlib.import_module("config")
    assert exc.value.code == 1


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


def test_config_requires_proxy_count_for_a_client_ip_header(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("TRUSTED_PROXY_CLIENT_IP_HEADER", "X-Real-IP")
    monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)

    import importlib
    import sys

    sys.modules.pop("config", None)
    with pytest.raises(SystemExit) as exc:
        importlib.import_module("config")
    assert exc.value.code == 1


def test_config_accepts_a_client_ip_header_with_proxy_count(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-ci-validation-only-32chars")
    monkeypatch.setenv("PASSWORD", "test-password-for-ci-only")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "test-api-token-for-ci-only")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "127.0.0.1")
    monkeypatch.setenv("TRUSTED_PROXY_CLIENT_IP_HEADER", "X-Real-IP")

    import importlib
    import sys

    sys.modules.pop("config", None)
    config = importlib.import_module("config")
    assert config.Config.TRUSTED_PROXY_CLIENT_IP_HEADER == "X-Real-IP"
    importlib.reload(config)


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
