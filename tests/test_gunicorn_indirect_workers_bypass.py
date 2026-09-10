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
        "workers = 1\nglobals()['update']({'workers': 4})\n",
        "workers = 1\n(ns := globals())['update']({'workers': 4})\n",
        "workers = 1\ngetattr(__import__('builtins'), 'exec')('workers = 4')\n",
        "workers = 1\nbuiltins = __import__('builtins')\nbuiltins.exec('workers = 4')\n",
        "workers = 1\n__import__('builtins').__dict__['exec']('workers = 4')\n",
        "workers = 1\nimport builtins\nbuiltins.exec('workers = 4')\n",
        "workers = 1\nimport builtins as bi\ngetattr(bi, 'exec')('workers = 4')\n",
        "workers = 1\nimport builtins as bi\nbi.__dict__['exec']('workers = 4')\n",
        "workers = 1\nresult = getattr(__import__('builtins'), 'exec')('workers = 4')\n",
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
