import pytest

import config


@pytest.mark.parametrize(
    ("config_content", "expected"),
    [
        (
            "workers = 1\n"
            "from collections import ChainMap\n"
            "ChainMap({}, globals()).maps[0].update({'workers': 4})\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "from types import SimpleNamespace\n"
            "ns = SimpleNamespace(update=globals().update)\n"
            "ns = SimpleNamespace(update={}.update)\n"
            "ns.update({'workers': 4})\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "class dict:\n"
            "    @staticmethod\n"
            "    def __setitem__(*args):\n"
            "        return None\n"
            "dict.__setitem__(globals(), 'workers', 4)\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "from importlib import import_module\n"
            "import_module = lambda name: None\n"
            "import_module('builtins').exec('workers = 4')\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "from functools import reduce\n"
            "reduce(lambda g, _: g.__ior__({'workers': 4}), [None], initial=globals())\n",
            (1, True),
        ),
        (
            "workers = 1\n"
            "import builtins\n"
            "types_exec = builtins.exec\n"
            "types_exec('workers = 4')\n"
            "types_exec = lambda code: None\n",
            (1, True),
        ),
        (
            "workers = 1\n"
            "from functools import reduce\n"
            "reduce(lambda g, _: (lambda g: g.update({'workers': 4}))({}) or g, [None], globals())\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "import builtins\n"
            "types_exec = builtins.exec\n"
            "types_exec = lambda code: None\n"
            "types_exec('workers = 4')\n",
            (1, False),
        ),
        (
            "workers = 1\n"
            "(lambda g: g.update({'workers': 4}))(globals())\n",
            (1, True),
        ),
    ],
)
def test_codex_pr207_regressions(tmp_path, config_content, expected):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == expected
