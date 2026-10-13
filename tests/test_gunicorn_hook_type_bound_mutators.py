"""Hook-gate regressions for type-bound namespace mutators (round-14 PAN-A-1).

``_gunicorn_config_has_runtime_hooks`` used to read the module namespace only
off the attribute receiver of a call, so the low-level mutator spellings that
pass the namespace as the *first argument* stayed invisible:

    dict.__setitem__(globals(), "on_starting", hook)
    object.__setattr__(sys.modules[__name__], "post_fork", hook)
    operator.setitem(globals(), "when_ready", hook)

The worker scan already treats those forms as dynamic. With a static
``workers = 1`` and ``RATELIMIT_STORAGE_URI=memory://`` the mismatch let the
panel start with per-process rate limits and session tokens. These tests pin
the hook gate to the same spellings, plus the negative controls that keep a
mutator on an unrelated dict from widening acceptance.

The shared ``config_module`` fixture lives in ``tests/conftest.py``.
"""

import ast
import sys

import pytest


_HOOK = "def hook(server, worker):\n    server.cfg.workers = 8\n"


def _hook_gate(config_module, source):
    """Run the hook gate the way the worker scan does, with its bindings.

    ``_gunicorn_config_has_runtime_hooks`` needs the aliases and shadow lines
    ``_collect_operator_setitem_bindings`` produces to tell a builtin ``dict``
    apart from a shadowed one; the production caller passes them along.
    """
    tree = ast.parse(source)
    bindings = config_module._collect_operator_setitem_bindings(tree)
    return config_module._gunicorn_config_has_runtime_hooks(tree, bindings[2], bindings)

_TYPE_BOUND_HOOK_CASES = [
    (
        "dict setitem on globals is dynamic",
        "import operator\n"
        "workers = 1\n"
        + _HOOK
        + "dict.__setitem__(globals(), 'on_starting', hook)\n",
    ),
    (
        "object setattr on the module object is dynamic",
        "import sys\n"
        "workers = 1\n"
        + _HOOK
        + "object.__setattr__(sys.modules[__name__], 'post_fork', hook)\n",
    ),
    (
        "operator setitem on globals is dynamic",
        "import operator\n"
        "workers = 1\n"
        + _HOOK
        + "operator.setitem(globals(), 'when_ready', hook)\n",
    ),
    (
        "aliased operator setitem on globals is dynamic",
        "import operator as op\n"
        "workers = 1\n"
        + _HOOK
        + "op.setitem(globals(), 'when_ready', hook)\n",
    ),
    (
        "imported operator setitem name is dynamic",
        "from operator import setitem\n"
        "workers = 1\n"
        + _HOOK
        + "setitem(globals(), 'when_ready', hook)\n",
    ),
    (
        "getattr dict setitem on globals is dynamic",
        "workers = 1\n"
        + _HOOK
        + "getattr(dict, '__setitem__')(globals(), 'on_starting', hook)\n",
    ),
    (
        "getattr object setattr on the module object is dynamic",
        "import sys\n"
        "workers = 1\n"
        + _HOOK
        + "getattr(object, '__setattr__')(sys.modules[__name__], 'post_fork', hook)\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _TYPE_BOUND_HOOK_CASES],
    ids=[case[0] for case in _TYPE_BOUND_HOOK_CASES],
)
def test_type_bound_hook_mutators_are_runtime_dynamic(config_module, source):
    tree = ast.parse(source)
    assert _hook_gate(config_module, source) is True
    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


_INERT_MUTATOR_CASES = [
    (
        "dict setitem on an unrelated mapping stays inert",
        "workers = 1\n"
        + _HOOK
        + "target = {}\n"
        "dict.__setitem__(target, 'on_starting', hook)\n",
    ),
    (
        "operator setitem on an unrelated mapping stays inert",
        "import operator\n"
        "workers = 1\n"
        + _HOOK
        + "target = {}\n"
        "operator.setitem(target, 'when_ready', hook)\n",
    ),
    (
        "object setattr on an unrelated object stays inert",
        "workers = 1\n"
        + _HOOK
        + "target = object()\n"
        "object.__setattr__(target, 'post_fork', hook)\n",
    ),
    (
        "a shadowed dict name is not the builtin",
        "workers = 1\n"
        + _HOOK
        + "dict = {}\n"
        "dict.__setitem__(globals(), 'on_starting', hook)\n",
    ),
    (
        "a shadowed object name is not the builtin",
        "workers = 1\n"
        + _HOOK
        + "object = type('object', (), {})\n"
        "object.__setattr__(globals(), 'on_starting', hook)\n",
    ),
    (
        "a shadowed getattr-object form is not the builtin",
        "workers = 1\n"
        + _HOOK
        + "object = type('object', (), {})\n"
        "getattr(object, '__setattr__')(globals(), 'on_starting', hook)\n",
    ),
    (
        "a shadowed getattr name is not the builtin",
        "workers = 1\n"
        + _HOOK
        + "def getattr(obj, name):\n"
        "    return None\n"
        "getattr(object, '__setattr__')(globals(), 'on_starting', hook)\n",
    ),
    (
        "a shadowed getattr does not fetch dict.__setitem__",
        "workers = 1\n"
        + _HOOK
        + "def getattr(obj, name):\n"
        "    return None\n"
        "getattr(dict, '__setitem__')(globals(), 'on_starting', hook)\n",
    ),
    (
        "operator rebinding makes the setitem spelling inert",
        "import operator\n"
        "workers = 1\n"
        + _HOOK
        + "operator = object()\n"
        "operator.setitem(globals(), 'on_starting', hook)\n",
    ),
    (
        "a rebound imported setitem name is inert",
        "from operator import setitem\n"
        "workers = 1\n"
        + _HOOK
        + "setitem = lambda *args: None\n"
        "setitem(globals(), 'on_starting', hook)\n",
    ),
    (
        "a rebound globals is not the module namespace",
        "workers = 1\n"
        + _HOOK
        + "globals = lambda: {}\n"
        "dict.__setitem__(globals(), 'on_starting', hook)\n",
    ),
    (
        "a rebound globals makes its alias inert",
        "workers = 1\n"
        + _HOOK
        + "globals = lambda: {}\n"
        "ns = globals()\n"
        "ns.__setitem__('on_starting', hook)\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _INERT_MUTATOR_CASES],
    ids=[case[0] for case in _INERT_MUTATOR_CASES],
)
def test_unrelated_type_bound_mutators_stay_inert(config_module, source):
    assert _hook_gate(config_module, source) is False


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "import operator\nworkers = 1\n" + _HOOK,
            (1, False),
        ),
        (
            "import operator\n"
            "workers = 1\n"
            + _HOOK
            + "operator.setitem(globals(), 'on_starting', hook)\n",
            (1, True),
        ),
    ],
    ids=["hook defined but never bound is inert", "operator setitem hook is dynamic"],
)
def test_hook_gate_matches_the_worker_gate(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


@pytest.mark.parametrize(
    "binding",
    [
        "dict.__setitem__(globals(), 'on_starting', hook)",
        "object.__setattr__(sys.modules[__name__], 'post_fork', hook)",
        "operator.setitem(globals(), 'when_ready', hook)",
    ],
    ids=["dict setitem", "object setattr", "operator setitem"],
)
def test_type_bound_hook_rejects_memory_rate_limit(
    binding, monkeypatch, tmp_path, config_module
):
    preamble = ""
    if "sys.modules" in binding:
        preamble += "import sys\n"
    if binding.startswith("operator."):
        preamble += "import operator\n"
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        preamble + "workers = 1\n" + _HOOK + binding + "\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings() == (1, True)
    assert config_module._ratelimit_storage_error() is not None
