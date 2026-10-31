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
    (
        "AsyncExitStack push_async_callback rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import AsyncExitStack\n"
        "import asyncio\n"
        "async def main():\n"
        "    async with AsyncExitStack() as s:\n"
        "        async def cb():\n"
        "            globals().__setitem__('workers', 4)\n"
        "        s.push_async_callback(cb)\n"
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

_SAFE_CASES = [
    (
        "direct async entry does not execute a mutating exit hook",
        "workers = 1\n"
        "import asyncio\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        return self\n"
        "    async def __aexit__(self, *a):\n"
        "        globals()['workers'] = 4\n"
        "asyncio.run(CM().__aenter__())\n",
    ),
    (
        "unrelated enter_async_context method does not enter its argument",
        "workers = 1\n"
        "import asyncio\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "class Other:\n"
        "    async def enter_async_context(self, value):\n"
        "        return value\n"
        "asyncio.run(Other().enter_async_context(CM()))\n",
    ),
    (
        "async stack callback rebound to a harmless async function",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "async def main():\n"
        "    async with AsyncExitStack() as stack:\n"
        "        async def cb():\n"
        "            globals().__setitem__('workers', 4)\n"
        "        async def noop():\n"
        "            pass\n"
        "        cb = noop\n"
        "        stack.push_async_callback(cb)\n"
        "asyncio.run(main())\n",
    ),
    (
        "shadowed async stack receiver is not a real AsyncExitStack",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "class Other:\n"
        "    async def enter_async_context(self, value):\n"
        "        return value\n"
        "async def main():\n"
        "    async with AsyncExitStack() as stack:\n"
        "        stack = Other()\n"
        "        await stack.enter_async_context(CM())\n"
        "asyncio.run(main())\n",
    ),
    (
        "unclosed AsyncExitStack does not execute its registered exit hook",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        return self\n"
        "    async def __aexit__(self, *a):\n"
        "        globals()['workers'] = 4\n"
        "asyncio.run(AsyncExitStack().enter_async_context(CM()))\n",
    ),
]


_ADDITIONAL_DYNAMIC_CASES = [
    (
        "async with AsyncExitStack executes a mutating exit hook",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        return self\n"
        "    async def __aexit__(self, *a):\n"
        "        globals()['workers'] = 4\n"
        "async def main():\n"
        "    async with AsyncExitStack() as stack:\n"
        "        await stack.enter_async_context(CM())\n"
        "asyncio.run(main())\n",
    ),
    (
        "assigned AsyncExitStack performs a mutating async entry",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "class CM:\n"
        "    async def __aenter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    async def __aexit__(self, *a):\n"
        "        pass\n"
        "async def main():\n"
        "    stack = AsyncExitStack()\n"
        "    await stack.enter_async_context(CM())\n"
        "asyncio.run(main())\n",
    ),
    (
        "aliased local async callback still mutates workers",
        "workers = 1\n"
        "import asyncio\n"
        "from contextlib import AsyncExitStack\n"
        "async def main():\n"
        "    async with AsyncExitStack() as stack:\n"
        "        async def cb():\n"
        "            globals().__setitem__('workers', 4)\n"
        "        callback = cb\n"
        "        stack.push_async_callback(callback)\n"
        "asyncio.run(main())\n",
    ),
]


@pytest.mark.parametrize("source", [case[1] for case in _SAFE_CASES], ids=[case[0] for case in _SAFE_CASES])
def test_safe_async_context_patterns_remain_static(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)


@pytest.mark.parametrize("source", [case[1] for case in _ADDITIONAL_DYNAMIC_CASES], ids=[case[0] for case in _ADDITIONAL_DYNAMIC_CASES])
def test_async_context_regressions_remain_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)


@pytest.mark.parametrize("source", [case[1] for case in _SAFE_CASES], ids=[case[0] for case in _SAFE_CASES])
def test_memory_storage_allowed_for_safe_async_context_patterns(
    monkeypatch, tmp_path, config_module, source
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings()[1] is False
    assert config_module._ratelimit_storage_error() is None
