"""Gunicorn worker scanner regressions for closing(), async __aenter__, and enter_async_context."""

import ast
import sys

import pytest

_CASES = [
    (
        "contextlib closing close hook rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import closing\n"
        "class CM:\n"
        "    def close(self):\n"
        "        globals()['workers'] = 4\n"
        "with closing(CM()):\n"
        "    pass\n",
        (1, True),
    ),
    (
        "asyncio.run direct __aenter__ rebinding workers is dynamic",
        "workers = 1\n"
        "import asyncio\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "asyncio.run(CM().__aenter__())\n",
        (1, True),
    ),
    (
        "AsyncExitStack enter_async_context rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import AsyncExitStack\n"
        "import asyncio\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "async def main():\n"
        "    async with AsyncExitStack() as stack:\n"
        "        await stack.enter_async_context(CM())\n"
        "asyncio.run(main())\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_closing_and_async_context_entry_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


@pytest.mark.parametrize("source", [case[1] for case in _CASES], ids=[case[0] for case in _CASES])
def test_memory_storage_rejected_for_closing_and_async_entry_bypasses(
    monkeypatch, tmp_path, config_module, source
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings()[1] is True
    assert config_module._ratelimit_storage_error() is not None
