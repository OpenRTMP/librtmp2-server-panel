"""Gunicorn worker scanner regressions from the 2026-11-05 security review.

Covers implicit dispatch paths that still looked static after the implicit-dunder
and builtin-unary hardening: ``ClassName()()``, attribute reads on a fresh
instance, ``asyncio.run`` awaiting a custom ``__await__`` object, and numeric
``round()`` / ``math.trunc`` / ``math.floor`` / ``math.ceil`` hooks.
"""

import ast

import pytest

_DYNAMIC_CASES = [
    (
        "instance __call__ dispatch",
        "workers = 1\n"
        "class Bump:\n"
        "    def __call__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "Bump()()\n",
    ),
    (
        "instance __getattribute__ dispatch",
        "workers = 1\n"
        "class Bump:\n"
        "    def __getattribute__(self, name):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return object.__getattribute__(self, name)\n"
        "Bump().__class__\n",
    ),
    (
        "asyncio.run awaiting custom __await__",
        "workers = 1\n"
        "import asyncio\n"
        "class AwaitBump:\n"
        "    def __await__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        if False:\n"
        "            yield\n"
        "async def run():\n"
        "    await AwaitBump()\n"
        "asyncio.run(run())\n",
    ),
    (
        "round() dispatch through __round__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __round__(self, n=None):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "round(Bump())\n",
    ),
    (
        "math.trunc dispatch through __trunc__",
        "workers = 1\n"
        "import math\n"
        "class Bump:\n"
        "    def __trunc__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "math.trunc(Bump())\n",
    ),
    (
        "math.floor dispatch through __floor__",
        "workers = 1\n"
        "import math\n"
        "class Bump:\n"
        "    def __floor__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "math.floor(Bump())\n",
    ),
    (
        "math.ceil dispatch through __ceil__",
        "workers = 1\n"
        "import math\n"
        "class Bump:\n"
        "    def __ceil__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "math.ceil(Bump())\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_nov05_implicit_dispatch_gaps_are_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)
