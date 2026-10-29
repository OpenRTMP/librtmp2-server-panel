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
