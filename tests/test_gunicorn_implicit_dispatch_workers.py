"""Regression tests for implicit worker mutations in Gunicorn configs.

The scanner must fail closed when a config reaches ``workers`` through an
implicit dispatch hook or installs a process-wide trace/profile callback.
Otherwise ``memory://`` is accepted while Gunicorn forks multiple workers, and
the login rate limit and panel sessions become per-process.
"""

import ast
import sys

import pytest

GETATTR_SOURCE = """
workers = 1
class _S:
    def __getattr__(self, name):
        globals()['workers'] = 8
        return None
_S().anything
"""

MISSING_SOURCE = """
workers = 1
class _S(dict):
    def __missing__(self, key):
        globals()['workers'] = 8
        return None
_S()['anything']
"""

SETTRACE_SOURCE = """
workers = 1
import sys
def _trace(frame, event, arg):
    if event == 'call':
        frame.f_globals['workers'] = 8
    return _trace
def _noop():
    pass
sys.settrace(_trace)
_noop()
"""


@pytest.mark.parametrize(
    "source",
    [GETATTR_SOURCE, MISSING_SOURCE, SETTRACE_SOURCE],
)
def test_implicit_dispatch_worker_mutation_is_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (
        1,
        True,
    )


def test_memory_ratelimit_rejects_a_trace_hook_config(
    config_module, monkeypatch, tmp_path
):
    config_path = tmp_path / "gunicorn.conf.py"
    config_path.write_text(SETTRACE_SOURCE, encoding="utf-8")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["gunicorn", "-c", str(config_path), "app:app"],
    )

    assert config_module._ratelimit_storage_error() is not None
