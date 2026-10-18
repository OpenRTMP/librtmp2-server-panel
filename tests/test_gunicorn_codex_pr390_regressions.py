"""Regression coverage for Codex findings on pull request #390."""

import pytest

import config


RISKY_CLASS = (
    "workers = 1\n"
    "class Risky:\n"
    "    def __init__(self):\n"
    "        globals()['workers'] = 4\n"
    "class Child(Risky):\n"
    "    pass\n"
)


@pytest.mark.parametrize(
    "dispatch",
    [
        "if True:\n    import inspect\n    inspect.getmro(Child)[1]()",
        "try:\n    from inspect import getmro\n    getmro(Child)[1]()\nexcept ImportError:\n    pass",
        "import inspect\ni = 1\ninspect.getmro(Child)[i]()",
        "from inspect import getmro\ni = 1\ngetmro(Child)[i]()",
        "object.__getattribute__(Child, '__bases__')[0]()",
        "from operator import attrgetter\nag = attrgetter\nag('__mro__')(Child)[1]()",
        "from operator import attrgetter\nname = '__mro__'\nattrgetter(name)(Child)[1]()",
        "from operator import attrgetter\nname = '__mro__'\nother = name\nattrgetter(other)(Child)[1]()",
        "getattr(getattr(Child, '__mro__'), '__getitem__')(1)()",
        "i = 1\ngetattr(getattr(Child, '__mro__'), '__getitem__')(i)()",
        "(lambda m, /: m[1])(Child.__mro__)()",
        "(lambda m, extra=None: m[1])(Child.__mro__)()",
        "(lambda *, m: m[1])(m=Child.__mro__)()",
        "(lambda m, /, extra=None: m[1])(Child.__mro__)()",
    ],
)
def test_pr390_mro_constructor_dispatch_is_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(RISKY_CLASS + dispatch + "\n", encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_pr390_shadowed_nested_getattr_is_not_a_builtin_mro_dispatch(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        RISKY_CLASS
        + "def getattr(obj, key):\n"
        + "    if key == '__mro__':\n"
        + "        return (lambda: None, lambda: None)\n"
        + "    if key == '__getitem__':\n"
        + "        return lambda index: (lambda: None)\n"
        + "getattr(getattr(Child, '__mro__'), '__getitem__')(1)()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_pr390_rebound_attrgetter_factory_is_not_treated_as_operator(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        RISKY_CLASS
        + "from operator import attrgetter\n"
        + "ag = attrgetter\n"
        + "ag = lambda name: lambda cls: (lambda: None, lambda: None)\n"
        + "ag('__mro__')(Child)[1]()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
