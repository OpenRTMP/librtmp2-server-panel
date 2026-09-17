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
    ],
)
def test_security_review_worker_scan_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)
