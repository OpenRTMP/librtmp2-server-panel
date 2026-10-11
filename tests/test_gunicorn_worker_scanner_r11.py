"""Gunicorn worker scanner regressions from the round-11 review follow-up.

Two fail-open gaps in the worker-count gate are covered here: a
``global workers`` ``for``/``async for`` loop target, and a ``global workers``
walrus binding in an ``if``/``while`` test. Both rebind the module attribute at
import time, so ``_scan_gunicorn_config_workers`` must report them as dynamic
(``(1, True)``) rather than accepting the static count.

The shared ``config_module`` fixture lives in ``tests/conftest.py``.
"""

import ast
import sys

import pytest


_GLOBAL_BINDING_CASES = [
    (
        "global for-loop target rebinding workers is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    for workers in [4]:\n"
        "        pass\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "global tuple for-loop target rebinding workers is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    for workers, other in [(4, 5)]:\n"
        "        pass\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "global async for-loop target rebinding workers is dynamic",
        "workers = 1\n"
        "import asyncio\n"
        "async def configure_workers(stream):\n"
        "    global workers\n"
        "    async for workers in stream:\n"
        "        pass\n"
        "asyncio.run(configure_workers([]))\n",
        (1, True),
    ),
    (
        "global if-test walrus rebinding workers is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    if (workers := 8):\n"
        "        pass\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "global while-test walrus rebinding workers is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    while (workers := 8):\n"
        "        break\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "for-loop target without a global declaration stays static",
        "workers = 1\n"
        "def configure_workers():\n"
        "    for workers in [4]:\n"
        "        pass\n"
        "configure_workers()\n",
        (1, False),
    ),
    (
        "global for-loop target binding another name stays static",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    for other in [4]:\n"
        "        pass\n"
        "configure_workers()\n",
        (1, False),
    ),
    (
        "if-test walrus without a global declaration stays static",
        "workers = 1\n"
        "def configure_workers():\n"
        "    if (workers := 8):\n"
        "        pass\n"
        "configure_workers()\n",
        (1, False),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _GLOBAL_BINDING_CASES],
    ids=[case[0] for case in _GLOBAL_BINDING_CASES],
)
def test_global_for_and_walrus_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_global_for_loop_rebinding_rejects_memory_rate_limit(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    for workers in [4]:\n"
        "        pass\n"
        "configure_workers()\n",
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


# --- end of round-11 scanner regressions ---
