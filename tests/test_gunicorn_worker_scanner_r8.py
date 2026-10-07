"""Gunicorn worker scanner regressions from the round-8 review follow-up.

The shared ``config_module`` fixture lives in ``tests/conftest.py``.
"""

import ast

import pytest

_MUTATING_HOOK = (
    "def w(*args, **kwargs):\n"
    "    globals().update({'workers': 4})\n"
)
_MUTATING_INIT_BASE = (
    "class Base:\n"
    "    def __init__(self):\n"
    "        globals().update({'workers': 4})\n"
)
_BYPASS_METACLASS = (
    "class Meta(type):\n"
    "    def __call__(cls, *args, **kwargs):\n"
    "        return object()\n"
)
_DELEGATING_METACLASS = (
    "class Meta(type):\n"
    "    def __call__(cls, *args, **kwargs):\n"
    "        return super().__call__(*args, **kwargs)\n"
)

_CASES = [
    (
        "showwarning replacement in compound block is dynamic",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "if True:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "non-mutating showwarning replacement in compound block stays static",
        "workers = 1\n"
        "import warnings\n"
        "if True:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n",
        (1, False),
    ),
    (
        "subclass inheriting mutating init is dynamic",
        "workers = 1\n"
        + _MUTATING_INIT_BASE
        + "class Child(Base):\n"
        "    pass\n"
        "Child()\n",
        (1, True),
    ),
    (
        "subclass overriding mutating init stays static",
        "workers = 1\n"
        + _MUTATING_INIT_BASE
        + "class Child(Base):\n"
        "    def __init__(self):\n"
        "        pass\n"
        "Child()\n",
        (1, False),
    ),
    (
        "bare sum consuming mutating map is dynamic",
        "workers = 1\n"
        "sum(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        (1, True),
    ),
    (
        "shadowed sum consuming mutating map stays static",
        "workers = 1\n"
        "def sum(values):\n"
        "    return 0\n"
        "sum(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        (1, False),
    ),
    (
        "second f_globals alias in stack loop is dynamic",
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = fi.frame.f_globals\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n",
        (1, True),
    ),
    (
        "alias of untracked name in stack loop stays static",
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = {}\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n",
        (1, False),
    ),
    (
        "conditional safe replacement after mutating hook is dynamic",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "warnings.showwarning = w\n"
        "if False:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "conditional mutating replacement is dynamic",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "if True:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "definite safe replacement after mutating hook stays static",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "warnings.showwarning = w\n"
        "warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n",
        (1, False),
    ),
    (
        "conditional safe replacement alone stays static",
        "workers = 1\n"
        "import warnings\n"
        "if True:\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n",
        (1, False),
    ),
    (
        "class-local warnings rebinding keeps mutating hook",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "warnings.showwarning = w\n"
        "class C:\n"
        "    warnings = object()\n"
        "    warnings.showwarning = lambda *args, **kwargs: None\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "class-local mutating warnings replacement alone stays static",
        "workers = 1\n"
        "import warnings\n"
        "class Dummy:\n"
        "    pass\n"
        + _MUTATING_HOOK
        + "class C:\n"
        "    warnings = Dummy()\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n",
        (1, False),
    ),
    (
        "class body warnings replacement without rebinding is dynamic",
        "workers = 1\n"
        "import warnings\n"
        + _MUTATING_HOOK
        + "class C:\n"
        "    warnings.showwarning = w\n"
        "warnings.warn('x')\n",
        (1, True),
    ),
    (
        "class-local sum shadow consuming mutating map stays static",
        "workers = 1\n"
        "class C:\n"
        "    sum = lambda values: 0\n"
        "    sum(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        (1, False),
    ),
    (
        "class body bare sum consuming mutating map is dynamic",
        "workers = 1\n"
        "class C:\n"
        "    sum(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        (1, True),
    ),
    (
        "import rebinding drops stack-loop f_globals alias",
        "workers = 1\n"
        "import inspect\n"
        "for fi in inspect.stack():\n"
        "    g = fi.frame.f_globals\n"
        "    from sys import modules as g\n"
        "    h = g\n"
        "    h.update({'workers': 4})\n",
        (1, False),
    ),
    (
        "import rebinding drops module-level f_globals alias",
        "workers = 1\n"
        "import inspect\n"
        "fi = inspect.currentframe()\n"
        "g = fi.f_globals\n"
        "from sys import modules as g\n"
        "h = g\n"
        "h.update({'workers': 4})\n",
        (1, False),
    ),
    (
        "subclass of earlier base binding stays static",
        "workers = 1\n"
        "class Base:\n"
        "    pass\n"
        "class Child(Base):\n"
        "    pass\n"
        + _MUTATING_INIT_BASE
        + "Child()\n",
        (1, False),
    ),
    (
        "subclass of rebound safe base stays static",
        "workers = 1\n"
        + _MUTATING_INIT_BASE
        + "class Base:\n"
        "    pass\n"
        "class Child(Base):\n"
        "    pass\n"
        "Child()\n",
        (1, False),
    ),
    (
        "assigned object init barrier stays static",
        "workers = 1\n"
        + _MUTATING_INIT_BASE
        + "class Child(Base):\n"
        "    __init__ = object.__init__\n"
        "Child()\n",
        (1, False),
    ),
    (
        "metaclass bypassing initializer stays static",
        "workers = 1\n"
        + _BYPASS_METACLASS
        + _MUTATING_INIT_BASE
        + "class Child(Base, metaclass=Meta):\n"
        "    pass\n"
        "Child()\n",
        (1, False),
    ),
    (
        "delegating metaclass runs inherited mutating init",
        "workers = 1\n"
        + _DELEGATING_METACLASS
        + _MUTATING_INIT_BASE
        + "class Child(Base, metaclass=Meta):\n"
        "    pass\n"
        "Child()\n",
        (1, True),
    ),
    (
        "bypass metaclass rebound to plain class runs mutating init",
        "workers = 1\n"
        + _BYPASS_METACLASS
        + _MUTATING_INIT_BASE
        + "class Child(Base, metaclass=Meta):\n"
        "    pass\n"
        "class Child(Base):\n"
        "    pass\n"
        "Child()\n",
        (1, True),
    ),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_scan_gunicorn_config_workers(config_module, source, expected):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == expected
