"""Gunicorn scanner regressions for the PR #442 review findings.

Each case pins a regression introduced by the r18 worker-scan hardening:
loop-target invalidation, recursive class-attribute resolution, the pending
mutation flag surviving a ``del workers``, and definition-time expressions of a
``def`` binding in the enclosing scope.
"""

import ast

import pytest

_LOOP_CASES = [
    (
        "zero-iteration for target keeps the tracked dict subclass",
        "workers = 1\n"
        "class D(dict):\n"
        "    pass\n"
        "for D in ():\n"
        "    pass\n"
        "D.update(globals(), {'workers': 4})\n",
        (1, True),
    ),
    (
        "unresolvable loop iterable keeps the tracked dict subclass",
        "workers = 1\n"
        "import os\n"
        "class D(dict):\n"
        "    pass\n"
        "for D in os.listdir('.'):\n"
        "    pass\n"
        "D.update(globals(), {'workers': 4})\n",
        (1, True),
    ),
    (
        "for target proven to run replaces the tracked dict subclass",
        "workers = 1\n"
        "class D(dict):\n"
        "    pass\n"
        "class Plain:\n"
        "    pass\n"
        "for D in (Plain,):\n"
        "    pass\n"
        "D.update(globals(), {'workers': 4})\n",
        (1, False),
    ),
    (
        "plain assignment still replaces the tracked dict subclass",
        "workers = 1\n"
        "class D(dict):\n"
        "    pass\n"
        "D = {}\n"
        "D.update(globals(), {'workers': 4})\n",
        (1, False),
    ),
]

_CLASS_ATTRIBUTE_CASES = [
    (
        "self-referential class attribute hook does not recurse",
        "workers = 1\n"
        "import warnings\n"
        "class Hooks:\n"
        "    @staticmethod\n"
        "    def showwarning(*args, **kwargs):\n"
        "        return None\n"
        "class Hooks(Hooks):\n"
        "    showwarning = Hooks.showwarning\n"
        "warnings.showwarning = Hooks.showwarning\n"
        "warnings.warn('x')\n",
        (1, False),
    ),
    (
        "self-referential class attribute still resolves the mutating base",
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "class Hooks:\n"
        "    showwarning = staticmethod(w)\n"
        "class Hooks(Hooks):\n"
        "    showwarning = Hooks.showwarning\n"
        "warnings.showwarning = Hooks.showwarning\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "staticmethod class attribute reference stays detected",
        "workers = 1\n"
        "import warnings\n"
        "def w(*args, **kwargs):\n"
        "    globals().update({'workers': 4})\n"
        "class Hooks:\n"
        "    showwarning = staticmethod(w)\n"
        "warnings.showwarning = Hooks.showwarning\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
]

_THREAD_CASES = [
    (
        "deleting workers keeps the pending thread mutation",
        "workers = 1\n"
        "import threading\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "t = threading.Thread(target=bump)\n"
        "t.start()\n"
        "del workers\n",
        (None, True),
    ),
    (
        "a static reassignment keeps the pending thread mutation",
        "workers = 1\n"
        "import threading\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "t = threading.Thread(target=bump)\n"
        "t.start()\n"
        "del workers\n"
        "workers = 1\n",
        (1, True),
    ),
    (
        "deleting a computed workers setting without a thread stays static",
        "import multiprocessing\n"
        "workers = multiprocessing.cpu_count()\n"
        "del workers\n",
        (None, False),
    ),
    (
        "a static reassignment after a deleted computed setting is recorded",
        "import multiprocessing\n"
        "workers = multiprocessing.cpu_count()\n"
        "del workers\n"
        "workers = 1\n",
        (1, False),
    ),
]

_DEFINITION_TIME_CASES = [
    (
        "walrus in a function default binds the hook at module scope",
        "workers = 1\n"
        "def install(hook=(when_ready := lambda server: None)):\n"
        "    return hook\n",
        True,
    ),
    (
        "walrus in a class base binds at module scope",
        "workers = 1\n"
        "class Base((when_ready := lambda server: None) and object):\n"
        "    pass\n",
        True,
    ),
    (
        "walrus in a class keyword binds at module scope",
        "workers = 1\n"
        "class Holder(object, metaclass=(when_ready := type)):\n"
        "    pass\n",
        True,
    ),
    (
        "walrus inside a function body stays a local binding",
        "workers = 1\n"
        "def install():\n"
        "    when_ready = lambda server: None\n"
        "    return when_ready\n",
        False,
    ),
]

_EXCEPT_CASE = (
    "except handler rebinding reaches the mutating instance",
    "workers = 1\n"
    "class Safe:\n"
    "    def bump(self):\n"
    "        pass\n"
    "class Dangerous(Exception):\n"
    "    def bump(self):\n"
    "        globals()['workers'] = 4\n"
    "h = Safe()\n"
    "try:\n"
    "    raise Dangerous()\n"
    "except Dangerous as h:\n"
    "    h.bump()\n",
    (1, True),
)


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _LOOP_CASES],
    ids=[case[0] for case in _LOOP_CASES],
)
def test_loop_target_keeps_previous_binding_until_proven(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CLASS_ATTRIBUTE_CASES],
    ids=[case[0] for case in _CLASS_ATTRIBUTE_CASES],
)
def test_recursive_class_attribute_resolution_terminates(
    config_module, source, expected
):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _THREAD_CASES],
    ids=[case[0] for case in _THREAD_CASES],
)
def test_pending_mutation_survives_workers_removal(config_module, source, expected):
    count, dynamic = config_module._scan_gunicorn_config_workers(ast.parse(source))
    expected_count, expected_dynamic = expected
    assert (count if expected_count is not None else None) == expected_count
    assert dynamic is expected_dynamic


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _DEFINITION_TIME_CASES],
    ids=[case[0] for case in _DEFINITION_TIME_CASES],
)
def test_definition_time_expressions_bind_in_the_enclosing_scope(
    config_module, source, expected
):
    _, assignment_dynamic, runtime_dynamic = (
        config_module._scan_gunicorn_config_worker_details(ast.parse(source))
    )
    assert (assignment_dynamic or runtime_dynamic) is expected


def test_except_handler_instance_binding_is_reachable(config_module):
    source = _EXCEPT_CASE[1]
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)


def test_zero_iteration_loop_config_is_rejected_with_memory_storage(
    monkeypatch, tmp_path, config_module
):
    source = _LOOP_CASES[0][1]
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")

    import sys

    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings()[1] is True
    assert config_module._ratelimit_storage_error() is not None
