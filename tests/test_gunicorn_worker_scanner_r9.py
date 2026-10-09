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


_NESTED_SCOPE_NAMESPACE_MAPPING_CASES = [
    (
        "function locals update stays static",
        "workers = 1\ndef f(cfg):\n    locals().update(cfg)\nf({})\n",
        (1, False),
    ),
    (
        "function argument-less vars update stays static",
        "workers = 1\ndef f(**cfg):\n    vars().update(cfg)\nf()\n",
        (1, False),
    ),
    (
        "function vars update with keyword payload stays static",
        "workers = 1\ndef f(cfg):\n    vars().update(workers=4)\n    return cfg\nf({})\n",
        (1, False),
    ),
    (
        "function dict.update over locals stays static",
        "workers = 1\ndef f(cfg):\n    dict.update(locals(), cfg)\nf({})\n",
        (1, False),
    ),
    (
        "function dict.__setitem__ over locals stays static",
        "workers = 1\n"
        "def f(cfg):\n"
        "    dict.__setitem__(locals(), 'workers', 4)\n"
        "f({})\n",
        (1, False),
    ),
    (
        "function locals ior stays static",
        "workers = 1\ndef f(cfg):\n    locals().__ior__(cfg)\nf({})\n",
        (1, False),
    ),
    (
        "function locals subscript store stays static",
        "workers = 1\n"
        "def f(name, value):\n"
        "    locals()[name] = value\n"
        "f('workers', 4)\n",
        (1, False),
    ),
    (
        "function subscript store in a loop stays static",
        "workers = 1\n"
        "def f(cfg):\n"
        "    for k, v in cfg.items():\n"
        "        locals()[k] = v\n"
        "f({})\n",
        (1, False),
    ),
    (
        "function try-block vars update stays static",
        "workers = 1\n"
        "def f(cfg):\n"
        "    try:\n"
        "        vars().update(cfg)\n"
        "    except Exception:\n"
        "        pass\n"
        "f({})\n",
        (1, False),
    ),
    (
        "async function locals update stays static",
        "workers = 1\nasync def f(cfg):\n    locals().update(cfg)\nf({})\n",
        (1, False),
    ),
    (
        "generator locals update stays static",
        "workers = 1\n"
        "def f(cfg):\n"
        "    yield 1\n"
        "    locals().update(cfg)\n"
        "list(f({}))\n",
        (1, False),
    ),
    (
        "nested function argument-less vars update stays static",
        "workers = 1\n"
        "def g():\n"
        "    def f(cfg):\n"
        "        vars().update(cfg)\n"
        "    f({})\n"
        "g()\n",
        (1, False),
    ),
    (
        "decorated helper locals update stays static",
        "workers = 1\n"
        "def deco(fn):\n"
        "    locals().update({'workers': 4})\n"
        "    return fn\n"
        "@deco\n"
        "def hook():\n"
        "    pass\n",
        (1, False),
    ),
    (
        "method locals update stays static",
        "workers = 1\nclass C:\n    def m(self):\n        locals().update(workers=4)\n",
        (1, False),
    ),
    (
        "method dict.update over locals stays static",
        "workers = 1\n"
        "class C:\n"
        "    def m(self, cfg):\n"
        "        dict.update(locals(), cfg)\n",
        (1, False),
    ),
    (
        "class body locals update stays static",
        "workers = 1\nclass C:\n    locals().update({'workers': 4})\n",
        (1, False),
    ),
    (
        "class body dict.update over locals stays static",
        "workers = 1\n"
        "class C:\n"
        "    dict.update(locals(), {'workers': 4})\n",
        (1, False),
    ),
    (
        "module-level dict.__setitem__ over locals stays dynamic",
        "workers = 1\ndict.__setitem__(locals(), 'workers', 4)\n",
        (1, True),
    ),
    (
        "module-level argument-less vars update with keywords stays dynamic",
        "workers = 1\nvars().update(workers=4)\n",
        (1, True),
    ),
    (
        "module-level locals update in a block stays dynamic",
        "workers = 1\nif True:\n    locals().update({'workers': 4})\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _NESTED_SCOPE_NAMESPACE_MAPPING_CASES],
    ids=[case[0] for case in _NESTED_SCOPE_NAMESPACE_MAPPING_CASES],
)
def test_nested_scope_namespace_mapping_aliases(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_nested_scope_locals_update_keeps_config_static(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def load(cfg):\n"
        "    vars().update(cfg)\n"
        "load({'debug': True})\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, False)
    assert config_module._ratelimit_storage_error() is None


_SHADOWED_NAMESPACE_ACCESSOR_CASES = [
    (
        "locals rebound to a lambda stays static",
        "workers = 1\nlocals = lambda: {}\nlocals().update({'workers': 4})\n",
        (1, False),
    ),
    (
        "vars rebound to a lambda stays static",
        "workers = 1\nvars = lambda: {}\nvars().update({'workers': 4})\n",
        (1, False),
    ),
    (
        "function rebound as locals stays static",
        "workers = 1\n"
        "def locals():\n"
        "    return {}\n"
        "locals().update({'workers': 4})\n",
        (1, False),
    ),
    (
        "class rebound as vars stays static",
        "workers = 1\nclass vars:\n    pass\nvars().update({'workers': 4})\n",
        (1, False),
    ),
    (
        "rebound locals ior stays static",
        "workers = 1\nlocals = dict\nlocals().__ior__({'workers': 4})\n",
        (1, False),
    ),
    (
        "unshadowed locals update stays dynamic",
        "workers = 1\nlocals().update({'workers': 4})\n",
        (1, True),
    ),
    (
        "unshadowed vars update stays dynamic",
        "workers = 1\nvars().update(workers=4)\n",
        (1, True),
    ),
    (
        "locals restored from the builtins module stays dynamic",
        "workers = 1\n"
        "import builtins\n"
        "locals = builtins.locals\n"
        "locals().update({'workers': 4})\n",
        (1, True),
    ),
    (
        "conditional locals rebinding stays dynamic",
        "workers = 1\n"
        "if True:\n"
        "    locals = lambda: {}\n"
        "locals().update({'workers': 4})\n",
        (1, True),
    ),
    (
        "rebound vars does not hide locals",
        "workers = 1\nvars = lambda: {}\nlocals().update({'workers': 4})\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _SHADOWED_NAMESPACE_ACCESSOR_CASES],
    ids=[case[0] for case in _SHADOWED_NAMESPACE_ACCESSOR_CASES],
)
def test_shadowed_namespace_accessors(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


_NESTED_EXPRESSION_SCOPE_CASES = [
    (
        "invoked lambda locals update stays static",
        "workers = 1\n(lambda: locals().update({'workers': 4}))()\n",
        (1, False),
    ),
    (
        "invoked lambda vars update stays static",
        "workers = 1\n(lambda: vars().update(workers=4))()\n",
        (1, False),
    ),
    (
        "lambda key callback locals update stays static",
        "workers = 1\n"
        "sorted([1], key=lambda item: locals().update({'workers': 4}))\n",
        (1, False),
    ),
    (
        "list comprehension locals update stays static",
        "workers = 1\n[locals().update({'workers': 4}) for _ in (0,)]\n",
        (1, False),
    ),
    (
        "set comprehension vars update stays static",
        "workers = 1\n{vars().update({'workers': 4}) for _ in (0,)}\n",
        (1, False),
    ),
    (
        "dict comprehension locals update stays static",
        "workers = 1\n{0: locals().update({'workers': 4}) for _ in (0,)}\n",
        (1, False),
    ),
    (
        "generator expression locals update stays static",
        "workers = 1\nlist(locals().update({'workers': 4}) for _ in (0,))\n",
        (1, False),
    ),
    (
        "comprehension condition locals update stays static",
        "workers = 1\n[1 for _ in (0,) if locals().update({'workers': 4})]\n",
        (1, False),
    ),
    (
        "lambda bound to a name and invoked stays static",
        "workers = 1\nfn = lambda: locals().update({'workers': 4})\nfn()\n",
        (1, False),
    ),
    (
        "comprehension outermost iterable locals update stays dynamic",
        "workers = 1\n[x for x in locals().update({'workers': 4})]\n",
        (1, True),
    ),
    (
        "invoked lambda globals update stays dynamic",
        "workers = 1\n(lambda: globals().update({'workers': 4}))()\n",
        (1, True),
    ),
    (
        "comprehension globals update stays dynamic",
        "workers = 1\n[globals().update({'workers': 4}) for _ in (0,)]\n",
        (1, True),
    ),
    (
        "comprehension walrus target stays dynamic",
        "workers = 1\n[workers := 4 for _ in (0,)]\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _NESTED_EXPRESSION_SCOPE_CASES],
    ids=[case[0] for case in _NESTED_EXPRESSION_SCOPE_CASES],
)
def test_nested_expression_scope_mutations(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


_CALL_SITE_CALLBACK_BINDING_CASES = [
    (
        "safe redefinition before the sorted call stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "bump = lambda value: value\n"
        "sorted([1], key=bump)\n",
        (1, False),
    ),
    (
        "safe redefinition before the map call stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "bump = lambda value: value\n"
        "list(map(bump, [1]))\n",
        (1, False),
    ),
    (
        "safe redefinition before the max call stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "bump = lambda value: value\n"
        "max([1], key=bump)\n",
        (1, False),
    ),
    (
        "mutating definition after the consumer call stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    return value\n"
        "sorted([1], key=bump)\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n",
        (1, False),
    ),
    (
        "safe definition then safe redefinition stays static",
        "workers = 1\n"
        "def bump(value):\n"
        "    return value\n"
        "bump = lambda value: value\n"
        "sorted([1], key=bump)\n",
        (1, False),
    ),
    (
        "named key callback without a rebinding stays dynamic",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "sorted([1], key=bump)\n",
        (1, True),
    ),
    (
        "redefinition after the consumer call stays dynamic",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "sorted([1], key=bump)\n"
        "bump = lambda value: value\n",
        (1, True),
    ),
    (
        "safe definition replaced by a mutating lambda stays dynamic",
        "workers = 1\n"
        "def bump(value):\n"
        "    return value\n"
        "bump = lambda value: globals().update({'workers': 4})\n"
        "sorted([1], key=bump)\n",
        (1, True),
    ),
    (
        "conditional mutating definition stays dynamic",
        "workers = 1\n"
        "if True:\n"
        "    def bump(value):\n"
        "        global workers\n"
        "        workers = 4\n"
        "sorted([1], key=bump)\n",
        (1, True),
    ),
    (
        "alias of a mutating definition stays dynamic",
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "alias = bump\n"
        "sorted([1], key=alias)\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CALL_SITE_CALLBACK_BINDING_CASES],
    ids=[case[0] for case in _CALL_SITE_CALLBACK_BINDING_CASES],
)
def test_call_site_callback_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_rebound_namespace_accessor_keeps_config_static(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "locals = lambda: {}\n"
        "locals().update({'workers': 4})\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, False)
    assert config_module._ratelimit_storage_error() is None


def test_comprehension_scope_keeps_config_static(monkeypatch, tmp_path, config_module):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "[locals().update({'workers': 4}) for _ in (0,)]\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, False)
    assert config_module._ratelimit_storage_error() is None


def test_rebound_callback_keeps_config_static(monkeypatch, tmp_path, config_module):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def bump(value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "bump = lambda value: value\n"
        "sorted([1], key=bump)\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, False)
    assert config_module._ratelimit_storage_error() is None


# --- end of round-9 scanner regressions ---
