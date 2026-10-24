import pytest

import config


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nif (ns := globals()):\n    ns.update({'workers': 4})\n",
        "workers = 1\nmatch globals():\n    case ns if ns.update({'workers': 4}) is None: pass\n",
        "workers = 1\nclass X:\n    def __init_subclass__(cls):\n        globals().update({'workers': 4})\nclass Y(X): pass\n",
        (
            "workers = 1\n"
            "from dataclasses import dataclass\n"
            "@dataclass\n"
            "class D:\n"
            "    x: int = 1\n"
            "    def __post_init__(self):\n"
            "        globals().update({'workers': 4})\n"
            "D()\n"
        ),
        (
            "workers = 1\n"
            "class Meta(type):\n"
            "    def __new__(mcls, name, bases, ns):\n"
            "        globals().update({'workers': 4})\n"
            "        return super().__new__(mcls, name, bases, ns)\n"
            "class X(metaclass=Meta): pass\n"
        ),
        (
            "workers = 1\n"
            "class D:\n"
            "    def __get__(self, obj, owner=None):\n"
            "        globals().update({'workers': 4})\n"
            "class X:\n"
            "    d = D()\n"
            "X().d\n"
        ),
        (
            "workers = 1\n"
            "class R:\n"
            "    def __getitem__(self, i):\n"
            "        globals()['workers'] = 4\n"
            "        return object\n"
            "R()[0]\n"
        ),
        (
            "workers = 1\n"
            "class R(type):\n"
            "    def __getitem__(cls, i):\n"
            "        globals()['workers'] = 4\n"
            "        return object\n"
            "class X(metaclass=R):\n"
            "    pass\n"
            "X[0]\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "from operator import call\n"
            "(call := call)(partial(globals().update, {'workers': 4}))\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "p = partial(globals().update, {'workers': 4})\n"
            "getattr(p, '__call__')()\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "object.__getattribute__(partial, '__call__')"
            "(partial(globals().update, {'workers': 4}))\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "import types\n"
            "bound = partial(globals().update, {'workers': 4})\n"
            "types.MethodType(partial.__call__, bound)()\n"
        ),
    ],
)
def test_security_review_worker_scan_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "from functools import partial\n"
            "import types\n"
            "bound = partial(globals().update, {'workers': 4})\n"
            "types.MethodType(partial.__repr__, bound)()\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "from operator import call\n"
            "def register(call):\n"
            "    (call := call)(partial(globals().update, {'workers': 4}))\n"
            "register(lambda callback: None)\n"
        ),
    ],
)
def test_security_review_non_invoking_partial_wrappers_are_static(
    tmp_path, config_content
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
