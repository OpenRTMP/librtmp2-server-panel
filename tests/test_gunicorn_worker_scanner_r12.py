"""Gunicorn worker scanner regressions for context-manager entry hooks.

A top-level ``with`` / ``async with`` runs ``__enter__`` / ``__aenter__`` at
config import time. Mutations there must mark the worker count as dynamic so
``memory://`` rate limits cannot pair with a hidden multi-worker Gunicorn
process.
"""

import ast
import sys

import pytest

_CONTEXT_MANAGER_CASES = [
    (
        "top-level with __enter__ rebinding workers is dynamic",
        "workers = 1\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with CM():\n"
        "    pass\n",
        (1, True),
    ),
    (
        "helper with __enter__ rebinding workers is dynamic",
        "workers = 1\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "def boot():\n"
        "    with CM():\n"
        "        pass\n"
        "boot()\n",
        (1, True),
    ),
    (
        "async with __aenter__ rebinding workers is dynamic",
        "workers = 1\n"
        "import asyncio\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "async def boot():\n"
        "    async with CM():\n"
        "        pass\n"
        "asyncio.run(boot())\n",
        (1, True),
    ),
    (
        "with body assignment changes workers dynamically",
        "workers = 1\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        return self\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with CM():\n"
        "    workers = 4\n",
        (1, True),
    ),
    (
        "with no mutating enter hook or body stays static",
        "workers = 1\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        return self\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with CM():\n"
        "    pass\n",
        (1, False),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CONTEXT_MANAGER_CASES],
    ids=[case[0] for case in _CONTEXT_MANAGER_CASES],
)
def test_context_manager_enter_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_context_manager_enter_rejects_memory_rate_limit(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with CM():\n"
        "    pass\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, True)
    assert config_module._ratelimit_storage_error() is not None
