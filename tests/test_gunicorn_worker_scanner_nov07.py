"""Gunicorn worker scanner regressions from the 2026-11-07 security review."""

import ast

import pytest

_DYNAMIC_CASES = [
    (
        "pickle.dumps __getstate__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __getstate__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return {}\n"
        "pickle.dumps(Bump())\n",
    ),
    (
        "pickle.dumps __reduce__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dumps(Bump())\n",
    ),
    (
        "copy.deepcopy __reduce__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (Bump, ())\n"
        "copy.deepcopy(Bump())\n",
    ),
    (
        "asyncio.run async for __aiter__ dispatch",
        "workers = 1\n"
        "import asyncio\n"
        "class G:\n"
        "    def __aiter__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return self\n"
        "    async def __anext__(self):\n"
        "        raise StopAsyncIteration\n"
        "async def main():\n"
        "    async for _ in G():\n"
        "        pass\n"
        "asyncio.run(main())\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_nov07_serialization_and_async_iter_gaps_are_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)
