import importlib
import sys


def test_whitespace_ratelimit_storage_uri_falls_back_to_memory(monkeypatch):
    """A blank env value must not reach Flask-Limiter as an unknown scheme.

    config validation already normalizes the value for the worker-count gate;
    the Config attribute used by create_app() must use the same normalization,
    otherwise create_app() raises ConfigurationError from storage_from_string.
    """
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-storage-uri")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-storage-uri")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-storage-uri")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "   ")
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setattr(sys, "argv", ["pytest"])
    sys.modules.pop("config", None)
    try:
        config = importlib.import_module("config")
        assert config.Config.RATELIMIT_STORAGE_URI == config.RATELIMIT_MEMORY_URI
    finally:
        sys.modules.pop("config", None)
