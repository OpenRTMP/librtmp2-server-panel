"""Gunicorn worker scanner regressions from the round-9 review follow-up.

The shared ``config_module`` fixture lives in ``tests/conftest.py``.
"""

import ast

import pytest

_MUTATING_HELPER = (
    "def bump(value):\n"
    "    global workers\n"
    "    workers = 4\n"
)

_NAMED_CALLBACK_CASES = [
    (
        "named sorted key callback mutating workers is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "sorted([1], key=bump)\n",
        (1, True),
    ),
    (
        "named max key callback mutating workers is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "max([1], key=bump)\n",
        (1, True),
    ),
    (
        "named min key callback mutating workers is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "min([1], key=bump)\n",
        (1, True),
    ),
    (
        "named map callback mutating workers is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "list(map(bump, [1]))\n",
        (1, True),
    ),
    (
        "named filter callback mutating workers is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "list(filter(bump, [1]))\n",
        (1, True),
    ),
    (
        "named map callback joined by str.join is dynamic",
        "workers = 1\n" + _MUTATING_HELPER + "''.join(map(bump, [1]))\n",
        (1, True),
    ),
    (
        "named map callback drained by deque is dynamic",
        "workers = 1\n"
        "from collections import deque\n"
        + _MUTATING_HELPER
        + "deque(map(bump, [1]), maxlen=1)\n",
        (1, True),
    ),
    (
        "named key callback in heapq.nsmallest is dynamic",
        "workers = 1\n"
        "import heapq\n"
        + _MUTATING_HELPER
        + "heapq.nsmallest(2, [1], key=bump)\n",
        (1, True),
    ),
    (
        "builtin sorted key stays static",
        "workers = 1\nsorted([1], key=str)\n",
        (1, False),
    ),
    (
        "builtin map callback stays static",
        "workers = 1\nlist(map(int, ['1']))\n",
        (1, False),
    ),
    (
        "named non-mutating key callback stays static",
        "workers = 1\n"
        "def ident(value):\n"
        "    return value\n"
        "sorted([1], key=ident)\n",
        (1, False),
    ),
    (
        "named callback without global declaration stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    workers = 4\n"
        "    return value\n"
        "sorted([1], key=bump)\n",
        (1, False),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _NAMED_CALLBACK_CASES],
    ids=[case[0] for case in _NAMED_CALLBACK_CASES],
)
def test_named_builtin_consumer_callbacks(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


# --- end of round-9 scanner regressions ---
