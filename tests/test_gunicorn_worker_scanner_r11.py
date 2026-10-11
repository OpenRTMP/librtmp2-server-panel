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
import textwrap

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
        "async def stream():\n"
        "    yield 4\n"
        "async def configure_workers(stream):\n"
        "    global workers\n"
        "    async for workers in stream:\n"
        "        pass\n"
        "asyncio.run(configure_workers(stream()))\n",
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
        "nested function default walrus rebinding workers is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    def inner(value=(workers := 4)):\n"
        "        pass\n"
        "    inner()\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "eager consumer of a workers walrus generator is dynamic",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    list((workers := 4) for _ in [0])\n"
        "configure_workers()\n",
        (1, True),
    ),
    (
        "unconsumed workers walrus generator stays static",
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    ((workers := 4) for _ in [0])\n"
        "configure_workers()\n",
        (1, False),
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



@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ("return sum((workers := 4) for _ in [0])", (1, True)),
        ("result = list((workers := 4) for _ in [0])", (1, True)),
        ("if list((workers := 4) for _ in [0]):\n    pass", (1, True)),
        ("for item in tuple((workers := 4) for _ in [0]):\n    pass", (1, True)),
        (
            "result = list(sum((workers := 4) for _ in [0]) for _ in [0])",
            (1, True),
        ),
        (
            "result = next((x for x in []), ((workers := 4) for _ in [0]))",
            (1, False),
        ),
        ("return ((workers := 4) for _ in [0])", (1, False)),
        ("if True:\n    class Holder:\n        (workers := 4)", (1, False)),
        ("def nested(value: (workers := 4)):\n    pass", (1, True)),
        ("def nested(*, value: (workers := 4)):\n    pass", (1, True)),
        ("def nested() -> (workers := 4):\n    pass", (1, True)),
    ],
)
def test_evaluated_worker_walruses(
    config_module, monkeypatch, snippet, expected
):
    if snippet.startswith("def nested"):
        # Model the eager evaluation used by Python <= 3.13 even when CI
        # executes on Python 3.14+ with PEP 649 deferred annotations.
        monkeypatch.setattr(config_module, "_config_defers_annotations", lambda tree: False)
    source = (
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        + textwrap.indent(snippet, "    ")
        + "\nconfigure_workers()\n"
    )
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_future_annotations_defer_nested_parameter_walrus(config_module):
    source = (
        "from __future__ import annotations\n"
        "workers = 1\n"
        "def configure_workers():\n"
        "    global workers\n"
        "    def nested(value: (workers := 4)):\n"
        "        pass\n"
        "configure_workers()\n"
    )
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)


def test_async_for_worker_fixture_executes():
    source = next(
        item[1]
        for item in _GLOBAL_BINDING_CASES
        if item[0] == "global async for-loop target rebinding workers is dynamic"
    )
    namespace = {}
    exec(compile(source, "<async for regression>", "exec"), namespace)
    assert namespace["workers"] == 4


# --- end of round-11 scanner regressions ---
