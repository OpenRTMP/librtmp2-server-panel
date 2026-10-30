"""Gunicorn worker scanner regressions for ExitStack.enter_context and contextmanager methods."""

import ast
import sys

import pytest

_CASES = [
    (
        "ExitStack enter_context rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with ExitStack() as stack:\n"
        "    stack.enter_context(CM())\n",
        (1, True),
    ),
    (
        "assigned ExitStack enter_context rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "stack = ExitStack()\n"
        "stack.__enter__()\n"
        "stack.enter_context(CM())\n",
        (1, True),
    ),
    (
        "contextmanager instance method rebinding workers is dynamic",
        "workers = 1\n"
        "from contextlib import contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "with C().cm():\n"
        "    pass\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_exit_stack_and_contextmanager_method_bindings(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


def test_exit_stack_enter_context_rejects_memory_rate_limit(
    monkeypatch, tmp_path, config_module
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *a):\n"
        "        pass\n"
        "with ExitStack() as stack:\n"
        "    stack.enter_context(CM())\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_file), "app:app"],
    )

    assert config_module._detect_worker_settings() == (1, True)
    assert config_module._ratelimit_storage_error() is not None


_REGRESSION_CASES = [
    (
        "creating a contextmanager method does not execute its body",
        "workers = 1\n"
        "from contextlib import contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "pending = C().cm()\n",
        (1, False),
    ),
    (
        "entering a contextmanager method executes its body",
        "workers = 1\n"
        "from contextlib import contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "with C().cm():\n"
        "    pass\n",
        (1, True),
    ),
    (
        "entering an alias-decorated contextmanager method executes its body",
        "workers = 1\n"
        "from contextlib import contextmanager as cm_decorator\n"
        "class C:\n"
        "    @cm_decorator\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "with C().cm():\n"
        "    pass\n",
        (1, True),
    ),
    (
        "entering a stored contextmanager executes its body",
        "workers = 1\n"
        "from contextlib import contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "pending = C().cm()\n"
        "with pending:\n"
        "    pass\n",
        (1, True),
    ),
    (
        "entering a stored contextmanager through ExitStack executes it",
        "workers = 1\n"
        "from contextlib import ExitStack, contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "pending = C().cm()\n"
        "stack = ExitStack()\n"
        "stack.enter_context(pending)\n",
        (1, True),
    ),
    (
        "rebinding a stored contextmanager removes its deferred effect",
        "workers = 1\n"
        "from contextlib import contextmanager\n"
        "class C:\n"
        "    @contextmanager\n"
        "    def cm(self):\n"
        "        globals()['workers'] = 4\n"
        "        yield\n"
        "pending = C().cm()\n"
        "pending = None\n",
        (1, False),
    ),
    (
        "unclosed ExitStack does not run context exit hook",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        pass\n"
        "    def __exit__(self, *args):\n"
        "        globals()['workers'] = 4\n"
        "stack = ExitStack()\n"
        "stack.enter_context(CM())\n",
        (1, False),
    ),
    (
        "explicitly closed ExitStack runs context exit hook",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        pass\n"
        "    def __exit__(self, *args):\n"
        "        globals()['workers'] = 4\n"
        "stack = ExitStack()\n"
        "stack.enter_context(CM())\n"
        "stack.close()\n",
        (1, True),
    ),
    (
        "ExitStack with block runs context exit hook",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        pass\n"
        "    def __exit__(self, *args):\n"
        "        globals()['workers'] = 4\n"
        "with ExitStack() as stack:\n"
        "    stack.enter_context(CM())\n",
        (1, True),
    ),
    (
        "ExitStack context entry executes entry hook without a close",
        "workers = 1\n"
        "from contextlib import ExitStack\n"
        "class CM:\n"
        "    def __enter__(self):\n"
        "        globals()['workers'] = 4\n"
        "    def __exit__(self, *args):\n"
        "        pass\n"
        "stack = ExitStack()\n"
        "stack.enter_context(CM())\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _REGRESSION_CASES],
    ids=[case[0] for case in _REGRESSION_CASES],
)
def test_deferred_contextmanager_and_exitstack_hooks(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected


@pytest.mark.parametrize(
    ("source", "is_dynamic"),
    [
        (_REGRESSION_CASES[0][1], False),
        (_REGRESSION_CASES[3][1], False),
        (_REGRESSION_CASES[4][1], True),
    ],
)
def test_memory_storage_allowed_when_deferred_hooks_are_not_run(
    monkeypatch, tmp_path, config_module, source, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings() == (1, is_dynamic)
    assert (config_module._ratelimit_storage_error() is not None) is is_dynamic
