"""Regression tests for implicit dunder dispatch on constructed config classes.

A Gunicorn config file is ordinary Python executed at import. A class whose
dunder hook rebinds ``workers`` therefore changes the worker count even when
the config never calls a method directly: ``Bump() + 1`` runs ``__add__``,
``f"{Bump()}"`` runs ``__format__``, ``for _ in Bump():`` runs ``__iter__``
and ``if Bump():`` runs ``__bool__``. The scanner must treat constructing such
a class as an import-time workers side effect; otherwise it reports
``workers = 1`` while Gunicorn forks the mutated count.
"""

import ast

import pytest

_DYNAMIC_CASES = [
    (
        "binary operator dispatch through __add__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __add__(self, other):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "Bump() + 1\n",
    ),
    (
        "reflected binary operator dispatch through __radd__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __radd__(self, other):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n"
        "1 + Bump()\n",
    ),
    (
        "f-string dispatch through __format__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __format__(self, spec):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return ''\n"
        "f'{Bump()}'\n",
    ),
    (
        "for-loop dispatch through __iter__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __iter__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return iter(())\n"
        "for _ in Bump():\n"
        "    pass\n",
    ),
    (
        "truth-test dispatch through __bool__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __bool__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return False\n"
        "if Bump():\n"
        "    pass\n",
    ),
    (
        "membership dispatch through __contains__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __contains__(self, item):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return False\n"
        "1 in Bump()\n",
    ),
    (
        "comparison dispatch through __eq__",
        "workers = 1\n"
        "class Bump:\n"
        "    def __eq__(self, other):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return False\n"
        "Bump() == 1\n",
    ),
    (
        "an inherited implicit hook is resolved through the MRO",
        "workers = 1\n"
        "class Bump:\n"
        "    def __iter__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return iter(())\n"
        "class Child(Bump):\n"
        "    pass\n"
        "for _ in Child():\n"
        "    pass\n",
    ),
]

_SAFE_CASES = [
    (
        "a mutating dunder that is never instantiated stays static",
        "workers = 1\n"
        "class Bump:\n"
        "    def __add__(self, other):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return 0\n",
    ),
    (
        "a constructed class with a non-mutating dunder stays static",
        "workers = 1\n"
        "class Helper:\n"
        "    def __add__(self, other):\n"
        "        return 0\n"
        "Helper() + 1\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_implicit_dunder_dispatch_is_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _SAFE_CASES],
    ids=[case[0] for case in _SAFE_CASES],
)
def test_implicit_dunder_scan_stays_static(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)
