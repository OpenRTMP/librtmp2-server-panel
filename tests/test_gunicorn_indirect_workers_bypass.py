import sys

import pytest

import config


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\ngetattr(globals(), 'update')({'workers': 4})\n",
        "workers = 1\n__import__('builtins').exec('workers = 4')\n",
        "workers = 1\nfrom functools import partial\npartial(globals().__setitem__, 'workers')(4)\n",
        "workers = 1\nimport operator\noperator.ior(globals(), {'workers': 4})\n",
        "workers = 1\n(ns := globals())\nns |= {'workers': 4}\n",
        "workers = 1\nfrom operator import ior\nior(globals(), {'workers': 4})\n",
        "workers = 1\nimport functools\nfunctools.partial(globals().__setitem__, 'workers')(4)\n",
        "workers = 1\nns = globals()\nfrom functools import partial\npartial(ns.__setitem__, 'workers')(4)\n",
        "workers = 1\n(ns := globals()).update({'workers': 4})\n",
        "workers = 1\nupdate_workers = getattr(globals(), 'update')\nupdate_workers({'workers': 4})\n",
        "workers = 1\nupdate = globals().update\nglobals()['update']({'workers': 4})\n",
        "workers = 1\nns = globals()\nupdate = ns.update\nns['update']({'workers': 4})\n",
        "workers = 1\ngetattr(__import__('builtins'), 'exec')('workers = 4')\n",
        "workers = 1\nbuiltins = __import__('builtins')\nbuiltins.exec('workers = 4')\n",
        "workers = 1\n__import__('builtins').__dict__['exec']('workers = 4')\n",
        "workers = 1\nimport builtins\nbuiltins.exec('workers = 4')\n",
        "workers = 1\nimport builtins as bi\ngetattr(bi, 'exec')('workers = 4')\n",
        "workers = 1\nimport builtins as bi\nbi.__dict__['exec']('workers = 4')\n",
        "workers = 1\nresult = getattr(__import__('builtins'), 'exec')('workers = 4')\n",
        "workers = 1\nbi = None\nimport builtins as bi\nbi.exec('workers = 4')\n",
        "workers = 1\nimport operator\ngetattr(operator, 'setitem')(globals(), 'workers', 4)\n",
        "workers = 1\nimport operator\ngetattr(operator, 'ior')(globals(), {'workers': 4})\n",
        "workers = 1\nimport operator\noperator.attrgetter('update')(globals())({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\n(p := partial(globals().__setitem__, 'workers'))(4)\n",
        "workers = 1\nimport operator\noperator.attrgetter('update')(globals())(workers=4)\n",
        "workers = 1\nfrom operator import attrgetter\nattrgetter('update')(globals())({'workers': 4})\n",
        "workers = 1\nimport operator\nns = globals()\ngetattr(operator, 'setitem')(ns, 'workers', 4)\n",
        "workers = 1\nimport operator\nkey = 'workers'\ngetattr(operator, 'setitem')(globals(), key, 4)\n",
        "workers = 1\nimport operator\nmethod = 'ior'\ngetattr(operator, method)(globals(), {'workers': 4})\n",
        "workers = 1\nimport operator\n(update := operator.attrgetter('update')(globals()))({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\nsetter = partial(globals().__setitem__, 'workers')\nsetter(4)\n",
        "workers = 1\nfrom functools import partial\n(setter := partial(globals().__setitem__, 'workers'))\nsetter(4)\n",
        "workers = 1\n__builtins__['exec']('workers = 4')\n",
        "workers = 1\ngetattr(__builtins__, 'exec')('workers = 4')\n",
        "workers = 1\nimport sys\ngetattr(sys.modules[__name__], '__setattr__')('workers', 4)\n",
        "workers = 1\nfrom functools import partial\n(p := partial(globals().update, {'workers': 4}))()\n",
        "workers = 1\nfrom functools import partial\np = partial(globals().update, {'workers': 4})\np()\n",
        "workers = 1\nfrom functools import reduce\nreduce(lambda g, _: g.update({'workers': 4}) or g, [None], globals())\n",
    ],
)
def test_gunicorn_indirect_namespace_workers_mutations_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_unrelated_eval_exec_methods_do_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Helper:\n"
        "    def eval(self):\n"
        "        return None\n"
        "    def exec(self):\n"
        "        return None\n"
        "Helper().eval()\n"
        "Helper().exec()\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize("helper_name", ["eval", "exec"])
def test_shadowed_eval_exec_helpers_do_not_mark_workers_dynamic(tmp_path, helper_name):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        f"def {helper_name}(value):\n"
        "    return value\n"
        f"answer = {helper_name}(42)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_globals_update_entry_helper_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def update(payload):\n"
        "    return payload\n"
        "globals()['update']({'not_workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def _clear_worker_environment(monkeypatch):
    monkeypatch.delenv("GUNICORN_CMD_ARGS", raising=False)
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)


def test_default_config_uses_inherited_launch_pwd_after_chdir(monkeypatch, tmp_path):
    launch_dir = tmp_path / "launch"
    app_dir = tmp_path / "app"
    launch_dir.mkdir()
    app_dir.mkdir()
    (launch_dir / "gunicorn.conf.py").write_text(
        f"chdir = {str(app_dir)!r}\nworkers = 4\n",
        encoding="utf-8",
    )

    _clear_worker_environment(monkeypatch)
    monkeypatch.setenv("PWD", str(launch_dir))
    monkeypatch.chdir(app_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config._detect_worker_settings() == (4, False)


def test_cli_workers_override_implicit_config(monkeypatch, tmp_path):
    (tmp_path / "gunicorn.conf.py").write_text("workers = 4\n", encoding="utf-8")

    _clear_worker_environment(monkeypatch)
    monkeypatch.setenv("PWD", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "--workers", "1", "app:app"])

    assert config._detect_worker_settings() == (1, False)
