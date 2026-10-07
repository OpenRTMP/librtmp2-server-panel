import ast
import importlib
import sys

import pytest


@pytest.fixture
def config_module(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-worker-regressions")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-worker-regressions")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-worker-regressions")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    monkeypatch.setattr(sys, "argv", ["pytest"])
    sys.modules.pop("config", None)
    module = importlib.import_module("config")
    try:
        yield module
    finally:
        sys.modules.pop("config", None)


# BUG-R8-P2-2: showwarning replacements inside compound blocks execute at import.
def test_showwarning_replacement_in_compound_block_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "if True:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_non_mutating_showwarning_replacement_in_compound_block_stays_static(
    config_module,
):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "if True:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)
