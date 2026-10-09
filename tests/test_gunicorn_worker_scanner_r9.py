"""Gunicorn worker scanner regressions from the round-9 review follow-up.

The shared ``config_module`` fixture lives in ``tests/conftest.py``.
"""

import ast
import sys

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


_CONTEXT_MANAGER = (
    "from contextlib import contextmanager\n"
    "@contextmanager\n"
    "def cm():\n"
    "    yield 4\n"
)

_WITH_TARGET_CASES = [
    (
        "module with-statement target binding workers is dynamic",
        "workers = 1\n" + _CONTEXT_MANAGER + "with cm() as workers:\n    pass\n",
        (1, True),
    ),
    (
        "module with-statement tuple target binding workers is dynamic",
        "workers = 1\n"
        + _CONTEXT_MANAGER
        + "with cm() as (workers, other):\n"
        "    pass\n",
        (1, True),
    ),
    (
        "second with-statement item binding workers is dynamic",
        "workers = 1\n"
        + _CONTEXT_MANAGER
        + "with cm() as first, cm() as workers:\n"
        "    pass\n",
        (1, True),
    ),
    (
        "with-statement target binding another name stays static",
        "workers = 1\nwith open('/dev/null') as handle:\n    pass\n",
        (1, False),
    ),
    (
        "function-local with-statement target stays static",
        "workers = 1\n"
        "def f():\n"
        "    with open('/dev/null') as workers:\n"
        "        pass\n"
        "f()\n",
        (1, False),
    ),
    (
        "global-declaring function async with target is dynamic",
        "workers = 1\n"
        "import asyncio\n"
        "async def main():\n"
        "    global workers\n"
        "    async with asyncio.Lock() as workers:\n"
        "        pass\n"
        "asyncio.run(main())\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _WITH_TARGET_CASES],
    ids=[case[0] for case in _WITH_TARGET_CASES],
)
def test_with_statement_target_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


_MODULE_NAMESPACE_MAPPING_CASES = [
    (
        "locals update payload mutating workers is dynamic",
        "workers = 1\nlocals().update({'workers': 4})\n",
        (1, True),
    ),
    (
        "argument-less vars update payload mutating workers is dynamic",
        "workers = 1\nvars().update({'workers': 4})\n",
        (1, True),
    ),
    (
        "dict.update over locals is dynamic",
        "workers = 1\ndict.update(locals(), {'workers': 4})\n",
        (1, True),
    ),
    (
        "locals setitem payload mutating workers is dynamic",
        "workers = 1\nlocals().__setitem__('workers', 4)\n",
        (1, True),
    ),
    (
        "one-argument vars over the module namespace is still dynamic",
        "workers = 1\n"
        "import sys\n"
        "vars(sys.modules[__name__]).update({'workers': 4})\n",
        (1, True),
    ),
    (
        "saved locals mapping stays static",
        "workers = 1\nns = locals()\n",
        (1, False),
    ),
    (
        "locals update payload without workers stays static",
        "workers = 1\nlocals().update({'other': 4})\n",
        (1, False),
    ),
    (
        "one-argument vars over a class namespace stays static",
        "workers = 1\nclass C:\n    pass\nvars(C).update({'workers': 4})\n",
        (1, False),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _MODULE_NAMESPACE_MAPPING_CASES],
    ids=[case[0] for case in _MODULE_NAMESPACE_MAPPING_CASES],
)
def test_module_namespace_mapping_aliases(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


_MATCH_PATTERN_CASES = [
    (
        "mapping pattern capture of workers is dynamic",
        "workers = 1\n"
        "match {'workers': 4}:\n"
        "    case {'workers': workers}:\n"
        "        pass\n",
        (1, True),
    ),
    (
        "bare name pattern capture of workers is dynamic",
        "workers = 1\nmatch 4:\n    case workers:\n        pass\n",
        (1, True),
    ),
    (
        "star pattern capture of workers is dynamic",
        "workers = 1\nmatch [1]:\n    case [*workers]:\n        pass\n",
        (1, True),
    ),
    (
        "mapping rest pattern capture of workers is dynamic",
        "workers = 1\nmatch {'a': 1}:\n    case {**workers}:\n        pass\n",
        (1, True),
    ),
    (
        "class pattern capture of workers is dynamic",
        "workers = 1\nmatch 4:\n    case int(workers):\n        pass\n",
        (1, True),
    ),
    (
        "or-pattern capture of workers is dynamic",
        "workers = 1\nmatch 4:\n    case 1 | workers:\n        pass\n",
        (1, True),
    ),
    (
        "as-pattern capture of workers is dynamic",
        "workers = 1\nmatch 4:\n    case 4 as workers:\n        pass\n",
        (1, True),
    ),
    (
        "mapping pattern capture of another name stays static",
        "workers = 1\nmatch {'a': 1}:\n    case {'a': value}:\n        pass\n",
        (1, False),
    ),
    (
        "wildcard pattern stays static",
        "workers = 1\nmatch 4:\n    case _:\n        pass\n",
        (1, False),
    ),
    (
        "function-local pattern capture stays static",
        "workers = 1\n"
        "def f(value):\n"
        "    match value:\n"
        "        case workers:\n"
        "            return workers\n"
        "f(4)\n",
        (1, False),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _MATCH_PATTERN_CASES],
    ids=[case[0] for case in _MATCH_PATTERN_CASES],
)
def test_match_case_pattern_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


_ANNOTATION_CASES = [
    (
        "bare workers annotation stays static",
        "workers: int\n",
        (1, False),
    ),
    (
        "bare workers annotation after a static assignment stays static",
        "workers = 1\nworkers: int\n",
        (1, False),
    ),
    (
        "annotated static workers assignment stays static",
        "workers: int = 1\n",
        (1, False),
    ),
    (
        "annotated dynamic workers value stays dynamic",
        "workers: int = max(2, 3)\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _ANNOTATION_CASES],
    ids=[case[0] for case in _ANNOTATION_CASES],
)
def test_annotated_workers_assignments(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_bare_workers_annotation_keeps_web_concurrency(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text("workers: int\n", encoding="utf-8")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (4, False)

    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    assert config_module._ratelimit_storage_error() is not None


# --- end of round-9 scanner regressions ---
