import ast
import importlib
import sys

import pytest


@pytest.fixture
def config_module(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "valid-test-secret-key-for-worker-regressions")
    monkeypatch.setenv("PASSWORD", "valid-test-password-for-worker-regressions")
    monkeypatch.setenv("LRTMP2_API_TOKEN", "valid-test-api-token-for-worker-regressions")
    monkeypatch.setenv("REQUIRE_LOGIN", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    monkeypatch.setattr(sys, "argv", ["pytest"])
    sys.modules.pop("config", None)
    module = importlib.import_module("config")
    try:
        yield module
    finally:
        sys.modules.pop("config", None)


# BUG-R8-P2-2: showwarning replacements inside compound blocks execute at import.
def test_showwarning_replacement_in_compound_block_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "if True:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_non_mutating_showwarning_replacement_in_compound_block_stays_static(
    config_module,
):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "if True:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


# BUG-R8-P3-2: subclass construction runs an inherited mutating __init__.
def test_subclass_inheriting_mutating_init_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self):\n"
        "        globals().update({'workers': 4})\n"
        "class Child(Base):\n"
        "    pass\n"
        "Child()\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_subclass_overriding_mutating_init_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self):\n"
        "        globals().update({'workers': 4})\n"
        "class Child(Base):\n"
        "    def __init__(self):\n"
        "        pass\n"
        "Child()\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


# BUG-R8-P3-5: bare sum is an eager consumer of a mutating lazy iterator.
def test_bare_sum_consuming_mutating_map_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "sum(map(lambda _: globals().update({'workers': 4}), [1]))\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_shadowed_sum_consuming_mutating_map_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "def sum(values):\n"
        "    return 0\n"
        "sum(map(lambda _: globals().update({'workers': 4}), [1]))\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


# BUG-R8-P4-3: a second alias of a tracked f_globals mapping keeps its provenance.
def test_second_f_globals_alias_in_stack_loop_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = fi.frame.f_globals\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_alias_of_untracked_name_in_stack_loop_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = {}\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


# BUG-R8-F1: only definite safe replacements may clear a mutating hook.
def test_conditional_safe_replacement_after_mutating_hook_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "warnings.showwarning = w\n"
        "if False:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_conditional_mutating_replacement_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "if True:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_definite_safe_replacement_after_mutating_hook_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "warnings.showwarning = w\n"
        "warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


def test_conditional_safe_replacement_alone_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "if True:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


# BUG-R8-F2: class-local ``warnings`` names never touch the imported module.
def test_class_local_warnings_rebinding_keeps_mutating_hook(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "warnings.showwarning = w\n"
        "class C:\n"
        "    warnings = object()\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_class_local_mutating_warnings_replacement_alone_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "class Dummy:\n"
        "    pass\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "class C:\n"
        "    warnings = Dummy()\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


def test_class_body_warnings_replacement_without_rebinding_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "class C:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


# BUG-R8-F3: a class-local ``sum`` binding shadows the builtin consumer.
def test_class_local_sum_shadow_consuming_mutating_map_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "class C:\n"
        "    sum = lambda values: 0\n"
        "    sum(map(lambda _: globals().update({'workers': 4}), [1]))\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


def test_class_body_bare_sum_consuming_mutating_map_is_dynamic(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "class C:\n"
        "    sum(map(lambda _: globals().update({'workers': 4}), [1]))\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


# BUG-R8-F4: an import rebinding drops stale f_globals alias provenance.
def test_import_rebound_f_globals_alias_in_stack_loop_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = fi.frame.f_globals\n"
        "    from sys import modules as g\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


def test_import_rebound_module_f_globals_alias_stays_static(config_module):
    tree = ast.parse(
        "workers = 1\n"
        "import inspect\n"
        "fi = inspect.currentframe()\n"
        "g = fi.f_globals\n"
        "from sys import modules as g\n"
        "h = g\n"
        "h.update({'workers': 4})\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)
