"""Gunicorn worker scanner regressions for the r18 Bug Hunter findings.

Covers the critical findings accepted for this scan: the import-time crash on a
nested class inside a class hook, delegated class hooks, class-base aliases,
frame-globals helpers, definition-time expressions, conditional alias
invalidation, launch-directory config selection, decorator-installed hooks and
non-attribute package imports.
"""

import ast
import sys

import pytest

_DYNAMIC_CASES = [
    (
        "class hook delegating to a module mutator is dynamic",
        "workers = 1\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "class H:\n"
        "    def __init__(self):\n"
        "        bump()\n"
        "H()\n",
    ),
    (
        "class method delegating to a module mutator is dynamic",
        "workers = 1\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "class H:\n"
        "    def go(self):\n"
        "        bump()\n"
        "H().go()\n",
    ),
    (
        "class base alias keeps the inherited constructor",
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "Alias = Base\n"
        "class Child(Alias):\n"
        "    pass\n"
        "Child()\n",
    ),
    (
        "class base alias keeps the inherited __class_getitem__",
        "workers = 1\n"
        "class Base:\n"
        "    def __class_getitem__(cls, item):\n"
        "        globals()['workers'] = 4\n"
        "Alias = Base\n"
        "class Child(Alias):\n"
        "    pass\n"
        "Child[0]\n",
    ),
    (
        "helper mutating through a live frame f_globals is dynamic",
        "import sys\n"
        "workers = 1\n"
        "def bump():\n"
        "    sys._getframe(1).f_globals.update({'workers': 8})\n"
        "bump()\n",
    ),
    (
        "decorator argument expression mutating workers is dynamic",
        "workers = 1\n"
        "def deco(x):\n"
        "    def wrap(fn):\n"
        "        return fn\n"
        "    return wrap\n"
        "@deco(globals().update({'workers': 4}))\n"
        "def f():\n"
        "    pass\n",
    ),
    (
        "class base expression mutating workers is dynamic",
        "workers = 1\n"
        "class C(globals().update({'workers': 4}) or object):\n"
        "    pass\n",
    ),
    (
        "class metaclass keyword expression mutating workers is dynamic",
        "workers = 1\n"
        "class C(metaclass=(globals().update({'workers': 4}) or type)):\n"
        "    pass\n",
    ),
    (
        "conditional rebinding keeps the imported thread alias",
        "workers = 1\n"
        "import os\n"
        "from threading import Thread\n"
        "if os.environ.get('LEGACY'):\n"
        "    Thread = None\n"
        "Thread(target=lambda: globals().update({'workers': 4})).start()\n",
    ),
    (
        "decorator that calls the decorated function installs a live hook",
        "workers = 1\n"
        "def hook(server, worker):\n"
        "    server.cfg.workers = 8\n"
        "def boot(fn):\n"
        "    fn()\n"
        "    return fn\n"
        "@boot\n"
        "def install():\n"
        "    global when_ready\n"
        "    when_ready = hook\n",
    ),
    (
        "conditional sched cancel keeps the pending mutation",
        "workers = 1\n"
        "import os, sched\n"
        "s = sched.scheduler()\n"
        "ev = s.enter(0, 1, lambda: globals().update({'workers': 4}))\n"
        "if os.environ.get('DEBUG'):\n"
        "    s.cancel(ev)\n"
        "s.run()\n",
    ),
    (
        "from concurrent import futures resolves the executor",
        "workers = 1\n"
        "from concurrent import futures\n"
        "futures.ThreadPoolExecutor(1).submit("
        "lambda: globals().update({'workers': 4})).result()\n",
    ),
    (
        "from multiprocessing import pool resolves the thread pool",
        "workers = 1\n"
        "from multiprocessing import pool\n"
        "pool.ThreadPool(1).apply(lambda: globals().update({'workers': 4}))\n",
    ),
]

_SAFE_CASES = [
    (
        "nested class inside a class hook body without a mutation stays static",
        "workers = 1\n"
        "class ConfigBuilder:\n"
        "    def build(self):\n"
        "        class Model:\n"
        "            class Meta:\n"
        "                pass\n"
        "        return Model\n",
    ),
    (
        "a helper that never touches workers stays static",
        "workers = 1\n"
        "def helper():\n"
        "    return 1\n"
        "class H:\n"
        "    def __init__(self):\n"
        "        helper()\n"
        "H()\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_r18_dynamic_bindings(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _SAFE_CASES],
    ids=[case[0] for case in _SAFE_CASES],
)
def test_r18_safe_bindings_stay_static(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _SAFE_CASES],
    ids=[case[0] for case in _SAFE_CASES],
)
def test_r18_scan_does_not_raise_on_nested_definitions(config_module, source):
    # The critical finding was an uncaught TypeError during the scan; the
    # nested definition itself proves no workers mutation, so the verdict is a
    # static single worker and the scan must simply complete.
    count, assignment_dynamic, runtime_dynamic = (
        config_module._scan_gunicorn_config_worker_details(ast.parse(source))
    )
    assert (count, assignment_dynamic or runtime_dynamic) == (1, False)


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_r18_memory_storage_rejected(monkeypatch, tmp_path, config_module, source):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "-c", str(config_file), "app:app"])

    assert config_module._detect_worker_settings()[1] is True
    assert config_module._ratelimit_storage_error() is not None


def test_r18_computed_chdir_prefers_the_launch_directory_config(
    monkeypatch, tmp_path, config_module
):
    launch_dir = tmp_path / "launch"
    served_dir = tmp_path / "served"
    launch_dir.mkdir()
    served_dir.mkdir()
    (launch_dir / "gunicorn.conf.py").write_text(
        "import os\n"
        "chdir = os.environ.get('APP_DIR')\n"
        "workers = 4\n",
        encoding="utf-8",
    )
    (served_dir / "gunicorn.conf.py").write_text("workers = 1\n", encoding="utf-8")

    monkeypatch.setenv("PWD", str(launch_dir))
    monkeypatch.chdir(served_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    paths, ambiguous = config_module._default_gunicorn_config_selection()

    # Gunicorn resolves the implicit config in its launch directory before it
    # applies chdir, so the launch file is the one it executed.
    assert [path.parent for path in paths] == [launch_dir]
    assert ambiguous is True
    assert config_module._detect_worker_settings() == (4, True)
