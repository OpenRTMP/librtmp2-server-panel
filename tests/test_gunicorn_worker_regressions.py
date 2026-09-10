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


def test_config_without_workers_preserves_web_concurrency(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text("bind = '0.0.0.0:8000'\n", encoding="utf-8")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (4, False)


def test_assignment_based_builtins_alias_fails_closed(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "bi = None\n"
        "bi = __import__('builtins')\n"
        "bi.exec('workers = 4')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_cli_workers_override_clears_config_assignment_dynamism(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import multiprocessing\nworkers = multiprocessing.cpu_count()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "--workers", "1", "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, False)


def test_cli_workers_override_keeps_runtime_hook_dynamism(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import multiprocessing\n"
        "workers = multiprocessing.cpu_count()\n"
        "def on_starting(server):\n"
        "    pass\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "--workers", "1", "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, True)


def test_actual_cwd_wins_over_stale_pwd(monkeypatch, tmp_path, config_module):
    stale_dir = tmp_path / "stale"
    launch_dir = tmp_path / "launch"
    stale_dir.mkdir()
    launch_dir.mkdir()
    (stale_dir / "gunicorn.conf.py").write_text("workers = 1\n", encoding="utf-8")
    (launch_dir / "gunicorn.conf.py").write_text("workers = 4\n", encoding="utf-8")

    monkeypatch.setenv("PWD", str(stale_dir))
    monkeypatch.chdir(launch_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config_module._detect_worker_settings() == (4, False)
