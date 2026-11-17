"""Gunicorn worker scanner regressions from the 2026-11-07 security review."""

import ast

import pytest

_DYNAMIC_CASES = [
    (
        "pickle.dumps __getstate__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __getstate__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return {}\n"
        "pickle.dumps(Bump())\n",
    ),
    (
        "pickle.dumps __reduce__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dumps(Bump())\n",
    ),
    (
        "pickle module alias __reduce__ dispatch",
        "workers = 1\n"
        "import pickle as p\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "p.dumps(Bump())\n",
    ),
    (
        "from pickle import dumps __reduce__ dispatch",
        "workers = 1\n"
        "from pickle import dumps\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "dumps(Bump())\n",
    ),
    (
        "from pickle import dumps as alias __reduce__ dispatch",
        "workers = 1\n"
        "from pickle import dumps as d\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "d(Bump())\n",
    ),
    (
        "pickle.dumps protocol keyword __reduce__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dumps(Bump(), protocol=5)\n",
    ),
    (
        "pickle.dump __reduce__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dump(Bump(), None)\n",
    ),
    (
        "from pickle import dump as alias __reduce__ dispatch",
        "workers = 1\n"
        "from pickle import dump as d\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "d(Bump(), None)\n",
    ),
    (
        "copy.deepcopy __reduce__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (Bump, ())\n"
        "copy.deepcopy(Bump())\n",
    ),
    (
        "copy.deepcopy __deepcopy__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __deepcopy__(self, memo):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "copy.deepcopy(Bump())\n",
    ),
    (
        "copy.copy __copy__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __copy__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "copy.copy(Bump())\n",
    ),
    (
        "from copy import copy __copy__ dispatch",
        "workers = 1\n"
        "from copy import copy\n"
        "class Bump:\n"
        "    def __copy__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "copy(Bump())\n",
    ),
    (
        "from copy import copy as alias __copy__ dispatch",
        "workers = 1\n"
        "from copy import copy as duplicate\n"
        "class Bump:\n"
        "    def __copy__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "duplicate(Bump())\n",
    ),
    (
        "from copy import deepcopy as alias __deepcopy__ dispatch",
        "workers = 1\n"
        "from copy import deepcopy as clone\n"
        "class Bump:\n"
        "    def __deepcopy__(self, memo):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "clone(Bump())\n",
    ),
    (
        "import copy as alias __copy__ dispatch",
        "workers = 1\n"
        "import copy as pickle_copy\n"
        "class Bump:\n"
        "    def __copy__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "pickle_copy.copy(Bump())\n",
    ),
    (
        "copy.deepcopy memo keyword __deepcopy__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __deepcopy__(self, memo):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "copy.deepcopy(Bump(), memo={})\n",
    ),
    (
        "pickle.dumps obj keyword __reduce__ dispatch",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dumps(obj=Bump())\n",
    ),
    (
        "copy.deepcopy x keyword __deepcopy__ dispatch",
        "workers = 1\n"
        "import copy\n"
        "class Bump:\n"
        "    def __deepcopy__(self, memo):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return Bump()\n"
        "copy.deepcopy(x=Bump())\n",
    ),
    (
        "pickle alias self-assignment keeps the callable",
        "workers = 1\n"
        "from pickle import dumps as d\n"
        "d = d\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "d(Bump())\n",
    ),
    (
        "pickle same-line rebinding after the call",
        "workers = 1\n"
        "from pickle import dumps as p\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "p(Bump()); p = None\n",
    ),    (
        "pickle.dumps empty splat before obj keyword",
        "workers = 1\n"
        "import pickle\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "pickle.dumps(*(), obj=Bump())\n",
    ),    (
        "asyncio.run async for __aiter__ dispatch",
        "workers = 1\n"
        "import asyncio\n"
        "class G:\n"
        "    def __aiter__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return self\n"
        "    async def __anext__(self):\n"
        "        raise StopAsyncIteration\n"
        "async def main():\n"
        "    async for _ in G():\n"
        "        pass\n"
        "asyncio.run(main())\n",
    ),
]


@pytest.mark.parametrize(
    "source",
    [case[1] for case in _DYNAMIC_CASES],
    ids=[case[0] for case in _DYNAMIC_CASES],
)
def test_nov07_serialization_and_async_iter_gaps_are_dynamic(config_module, source):
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, True)


def test_nov07_unrelated_dumps_is_not_a_pickle_hook(config_module):
    source = (
        'workers = 1\n'
        'import json\n'
        'class Bump:\n'
        '    def __reduce__(self):\n'
        '        global workers\n'
        '        workers = 4\n'
        '        return (int, (0,))\n'
        'json.dumps(Bump())\n'
    )
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)

def test_reimported_name_is_not_treated_as_the_old_pickle_alias(config_module):
    source = (
        "workers = 1\n"
        "from pickle import dumps as d\n"
        "from json import dumps as d\n"
        "class Bump:\n"
        "    def __reduce__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return (int, (0,))\n"
        "d(Bump())\n"
    )
    assert config_module._scan_gunicorn_config_workers(ast.parse(source)) == (1, False)
