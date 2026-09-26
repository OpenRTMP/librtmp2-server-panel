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
        "workers = 1\nimport sys as s\ngetattr(s.modules[__name__], '__setattr__')('workers', 4)\n",
        "workers = 1\nfrom functools import partial\n(p := partial(globals().update, {'workers': 4}))()\n",
        "workers = 1\nfrom functools import partial\np = partial(globals().update, {'workers': 4})\np()\n",
        "workers = 1\nfrom functools import partial\npartial(globals().update, workers=4)()\n",
        "workers = 1\nfrom functools import partial\np = partial(globals().update, workers=4)\np()\n",
        "workers = 1\nfrom functools import partial\npayload = {'workers': 4}\npartial(globals().update, **payload)()\n",
        "workers = 1\n(lambda dict: dict.update({'workers': 4}))(globals())\n",
        "workers = 1\nfrom functools import reduce\nreduce(lambda g, _: g.update({'workers': 4}) or g, [None], globals())\n",
        "workers = 1\nimport builtins\ntypes_exec = getattr(builtins, 'exec')\ntypes_exec('workers = 4')\n",
        "workers = 1\nimport operator\noperator.methodcaller('exec', 'workers = 4')(__import__('builtins'))\n",
        "workers = 1\ngetattr(__import__('operator'), 'methodcaller')('exec', 'workers = 4')(__import__('builtins'))\n",
        "workers = 1\nfrom importlib import import_module\nimport_module('builtins').exec('workers = 4')\n",
        "workers = 1\ngetattr(dict, '__setitem__')(globals(), 'workers', 4)\n",
        "workers = 1\nfrom functools import reduce\nreduce(lambda g, _: g.__ior__({'workers': 4}), [None], globals())\n",
        "workers = 1\nfrom collections import ChainMap\nChainMap({}, globals()).maps[1].update({'workers': 4})\n",
        "workers = 1\nfrom types import SimpleNamespace\nns = SimpleNamespace(update=globals().update)\nns.update({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\ngetattr(partial, '__call__')(partial(globals().__setitem__, 'workers'), 4)\n",
        "workers = 1\ndict.__ior__(globals(), {'workers': 4})\n",
        "workers = 1\ngetattr(dict, '__ior__')(globals(), {'workers': 4})\n",
        "workers = 1\nfrom importlib import import_module\nimport_module('sys').modules[__name__].__dict__.update({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\n(p := partial(dict.update, globals(), {'workers': 4}))()\n",
        "workers = 1\nimport types\nf = types.FunctionType(compile('workers=4','','exec'), globals())\nf()\n",
        "workers = 1\nfrom importlib import import_module as im\nim('sys').modules[__name__].__dict__.update({'workers': 4})\n",
        "workers = 1\nimport importlib as il\nil.import_module('sys').modules[__name__].__dict__.update({'workers': 4})\n",
        "workers = 1\nmerge = dict.__ior__\nmerge(globals(), {'workers': 4})\n",
        "workers = 1\nmerge = dict.__ior__\nmerge2 = merge\nmerge2(globals(), {'workers': 4})\n",
        "workers = 1\nfrom types import FunctionType as FT\nFT(compile('workers=4','','exec'), globals())()\n",
        "workers = 1\nimport types as t\nt.FunctionType(code=compile('workers=4','','exec'), globals=globals())()\n",
        "workers = 1\nfrom functools import partial\npartial(dict.update, globals())({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\np = partial(dict.update, globals())\np({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\npartial(dict.__ior__, globals())({'workers': 4})\n",
        "workers = 1\nfrom functools import partial\np = partial(dict.__ior__, globals())\np({'workers': 4})\n",
        "workers = 1\nfrom collections import ChainMap\ncm = ChainMap(globals(), {})\ncm.maps[0].update({'workers': 4})\n",
        "workers = 1\nlist(map(lambda g: g.update({'workers': 4}), [globals()]))\n",
        "workers = 1\ndef dec(f):\n    globals()['workers'] = 4\n    return f\n@dec\ndef f(): pass\n",
        "workers = 1\nimport sys\nsys.modules['builtins'].exec('workers=4')\n",
        "workers = 1\nimport operator\noperator.call(globals().update, {'workers': 4})\n",
        "workers = 1\nfrom functools import partial\npartial(dict.__setitem__, globals(), 'workers')(4)\n",
        "workers = 1\nimport types\nc=compile('workers=4','','exec')\ngetattr(types, 'FunctionType')(c, globals())()\n",
        "workers = 1\nfrom functools import reduce\nreduce(lambda g, _: dict.__setitem__(g, 'workers', 4), [None], globals())\n",
        "workers = 1\ntype('X', (), {'__init__': lambda self: globals().update({'workers': 4})})()\n",
        "workers = 1\ngetattr(type(globals()), 'update')(globals(), {'workers': 4})\n",
        "workers = 1\n[__import__('builtins').exec][0]('workers=4')\n",
        "workers = 1\nimport importlib\nimportlib.import_module('builtins').exec('workers=4')\n",
        "workers = 1\nfrom functools import partial\nfrom operator import methodcaller\npartial(methodcaller('update', {'workers': 4}), globals())()\n",
        "workers = 1\ngetattr(__builtins__['dict'], 'update')(globals(), {'workers': 4})\n",
        "workers = 1\nfrom functools import partial, reduce\npartial(reduce, lambda g,_: g.update({'workers':4}), [None], globals())()\n",
    ],
)
def test_gunicorn_indirect_namespace_workers_mutations_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom importlib import import_module\nimport_module(name='sys').modules[__name__].__dict__.update({'workers': 4})\n",
        "workers = 1\nfrom types import FunctionType\ncode = compile('workers=4','','exec')\nFunctionType(code, globals())()\n",
        "workers = 1\nfrom types import FunctionType\ncode = compile('workers=4','','exec')\nf = FunctionType(code, globals())\nf()\n",
        "workers = 1\nfrom functools import partial\np = partial(dict.update, globals())\np({'workers': 4})\np = None\n",
        "workers = 1\nfrom importlib import import_module as im\ndict.update(im('sys').modules[__name__].__dict__, {'workers': 4})\n",
        "workers = 1\nfrom importlib import import_module as im\ndict.__ior__(im('sys').modules[__name__].__dict__, {'workers': 4})\n",
        "workers = 1\nfrom importlib import import_module as im\nvars(im('sys').modules[__name__]).update({'workers': 4})\n",
        "workers = 1\nfrom importlib import import_module as im\ngetattr(im('sys').modules[__name__], '__dict__').update({'workers': 4})\n",
        "workers = 1\nimport importlib as il\ndict.update(il.import_module('sys').modules[__name__].__dict__, {'workers': 4})\n",
        "workers = 1\nfrom importlib import import_module as im\nns = im('sys').modules[__name__].__dict__\nns.update({'workers': 4})\n",
    ],
)
def test_review_followup_namespace_mutations_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_dormant_functiontype_constructor_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "from types import FunctionType\n"
        "f = FunctionType(compile('workers=4','','exec'), globals())\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


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


@pytest.mark.parametrize(
    "exec_expression",
    [
        "__builtins__['exec']('workers = 4')",
        "getattr(__builtins__, 'exec')('workers = 4')",
    ],
)
def test_shadowed_builtins_exec_helpers_do_not_mark_workers_dynamic(
    tmp_path,
    exec_expression,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "__builtins__ = {'exec': lambda code: None}\n"
        f"{exec_expression}\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_uninvoked_lambda_update_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "transform = lambda d: d.update({'workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_builtin_dict_update_on_local_mapping_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "(lambda: dict.update({}, {'workers': 4}))()\n",
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


def test_shadowed_dict_update_partial_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class dict:\n"
        "    @staticmethod\n"
        "    def update(target, payload):\n"
        "        return target\n"
        "from functools import partial\n"
        "partial(dict.update, globals(), {'workers': 4})()\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_safe_partial_dict_update_payload_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "from functools import partial\n"
        "p = partial(dict.update, globals())\n"
        "p({'not_workers': 4})\n",
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



@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport operator\noperator.call(globals().update, workers=4)\n",
        "workers = 1\nlist(map(lambda _, g: g.update({'workers': 4}), [None], [globals()]))\n",
        "workers = 1\ndef dec(value):\n    globals()['workers'] = 4\n    return value\n@dec\nclass C:\n    pass\n",
        "workers = 1\n[None, __import__('builtins').exec][1]('workers=4')\n",
        "workers = 1\n(__import__('builtins').exec,)[0]('workers=4')\n",
        "workers = 1\n[None, __import__('builtins').exec][-1]('workers=4')\n",
        "workers = 1\nfrom functools import partial, reduce\npartial(reduce, lambda g, _: g.update({'workers': 4}) or g, [None], initial=globals())()\n",
        "workers = 1\ndict = object()\ngetattr(type(globals()), 'update')(globals(), {'workers': 4})\n",
    ],
)
def test_codex_followup_worker_mutations_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom collections import ChainMap\ncm = ChainMap({}, globals())\ncm.maps[0].update({'workers': 4})\n",
        "workers = 1\nT = type('X', (), {'__init__': lambda self: globals().update({'workers': 4})})\n",
        "workers = 1\nimport importlib\nclass Helper:\n    def import_module(self, name):\n        class Builtins:\n            @staticmethod\n            def exec(code):\n                return None\n        return Builtins()\nimportlib = Helper()\nimportlib.import_module('builtins').exec('workers=4')\n",
    ],
)
def test_codex_followup_safe_patterns_stay_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport operator\noperator.call(globals().__setitem__, 'workers', 4)\n",
        "workers = 1\n(globals().__class__.__dict__['update'])(globals(), {'workers': 4})\n",
        "workers = 1\nimport builtins\ngetattr(builtins.dict, 'update')(globals(), {'workers': 4})\n",
        "workers = 1\nclass D(dict): pass\nD.update(globals(), {'workers': 4})\n",
        "workers = 1\nfrom contextlib import contextmanager\n@contextmanager\ndef cm():\n    globals().update({'workers': 4})\n    yield\nwith cm(): pass\n",
        "workers = 1\nclass C:\n    def __init__(self):\n        globals().update({'workers': 4})\nC()\n",
        "workers = 1\nclass C:\n    @staticmethod\n    def f():\n        globals().update({'workers': 4})\nC.f()\n",
        "workers = 1\nclass C:\n    @classmethod\n    def f(cls):\n        globals().update({'workers': 4})\nC.f()\n",
        "workers = 1\nclass C:\n    @property\n    def p(self):\n        globals().update({'workers': 4})\n        return 0\nC().p\n",
        "workers = 1\nclass M(type):\n    def __init__(cls, name, bases, ns):\n        globals().update({'workers': 4})\nclass C(metaclass=M): pass\n",
        "workers = 1\nsorted([0], key=lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nlist(filter(lambda _: globals().update({'workers': 4}), [True]))\n",
        "workers = 1\nimport operator\ngetattr(operator, 'call')(operator.setitem, globals(), 'workers', 4)\n",
        "workers = 1\n__builtins__['dict'].update(globals(), {'workers': 4})\n",
        "workers = 1\nfrom functools import partial\ngetattr(partial(globals().update, {'workers': 4}), '__call__')()\n",
    ],
)
def test_security_review_worker_scan_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    'config_content',
    [
        "workers = 1\nbool(lambda: globals().update({'workers': 4}))\n",
        "workers = 1\nmap(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nfilter(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nclass C:\n    def __init__(self): globals().update({'workers': 4})\nC = lambda: None\nC()\n",
        "workers = 1\nclass dict:\n    @staticmethod\n    def update(target, payload): return target\nclass D(dict): pass\nD.update(globals(), {'workers': 4})\n",
        "workers = 1\nclass D(dict):\n    @staticmethod\n    def update(target, payload): return target\nD.update(globals(), {'workers': 4})\n",
        "workers = 1\nimport builtins\nclass Helper:\n    class Dict:\n        @staticmethod\n        def update(target, payload): return target\n    dict = Dict\nbuiltins = Helper()\ngetattr(builtins.dict, 'update')(globals(), {'workers': 4})\n",
        "workers = 1\nimport operator\nclass Helper:\n    @staticmethod\n    def call(*args): return None\noperator = Helper()\noperator.call(globals().__setitem__, 'workers', 4)\n",
        "workers = 1\nfrom functools import partial\ngetattr = lambda obj, name: (lambda: None)\ngetattr(partial(globals().update, {'workers': 4}), '__call__')()\n",
        "workers = 1\ndef staticmethod(fn):\n    return lambda *a, **k: None\nclass C:\n    @staticmethod\n    def f(): globals().update({'workers': 4})\nC.f()\n",
        "workers = 1\ndef globals():\n    class Mapping(dict):\n        @staticmethod\n        def update(target, payload): return target\n    return Mapping()\n(globals().__class__.__dict__['update'])(globals(), {'workers': 4})\n",
    ],
)
def test_codex_review_safe_patterns_remain_static(tmp_path, config_content):
    config_file = tmp_path / 'gunicorn.conf.py'
    config_file.write_text(config_content, encoding='utf-8')
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    'config_content',
    [
        "workers = 1\nclass C:\n    def __init__(self): globals().update({'workers': 4})\nprint(C())\n",
        "workers = 1\nclass C:\n    def __init__(self): globals().update({'workers': 4})\n(C(),)\n",
        "workers = 1\nif True:\n    class C:\n        def __init__(self): globals().update({'workers': 4})\nC()\n",
        "workers = 1\nclass C:\n    def __init__(self): globals().update({'workers': 4})\ndef helper():\n    return C()\nhelper()\n",
        "workers = 1\nclass D(dict): pass\ndef helper():\n    D.update(globals(), {'workers': 4})\nhelper()\n",
        "workers = 1\nimport builtins\nbuiltins.dict.update(globals(), {'workers': 4})\n",
        "workers = 1\ngetattr(globals().__class__.__dict__, 'update')(globals(), {'workers': 4})\n",
    ],
)
def test_codex_review_dynamic_patterns_are_detected(tmp_path, config_content):
    config_file = tmp_path / 'gunicorn.conf.py'
    config_file.write_text(config_content, encoding='utf-8')
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)



# Cursor lazy-consumer follow-up regressions
@pytest.mark.parametrize(
    'config_content',
    [
        "workers = 1\nsorted(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfor _ in map(lambda _: globals().update({'workers': 4}), [1]):\n    pass\n",
        "workers = 1\n[*map(lambda _: globals().update({'workers': 4}), [1])]\n",
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\nlist(it)\n",
        "workers = 1\nmax([1], key=lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nmin([1], key=lambda _: globals().update({'workers': 4}))\n",
    ],
)
def test_cursor_lazy_iterator_consumers_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / 'gunicorn.conf.py'
    config_file.write_text(config_content, encoding='utf-8')
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    'config_content',
    [
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nit = filter(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\nit = []\nlist(it)\n",
    ],
)
def test_cursor_unconsumed_or_rebound_lazy_iterators_stay_static(tmp_path, config_content):
    config_file = tmp_path / 'gunicorn.conf.py'
    config_file.write_text(config_content, encoding='utf-8')
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)



# Security review 2026-09-18: alternate lazy-iterator consumers
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom collections import deque\ndeque(map(lambda _: globals().update({'workers': 4}), [1]), maxlen=1)\n",
        "workers = 1\nlist(enumerate(map(lambda _: globals().update({'workers': 4}), [1])))\n",
        "workers = 1\nlist(zip(map(lambda _: globals().update({'workers': 4}), [1]), [1]))\n",
        "workers = 1\nfrozenset(x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfrom collections import Counter\nCounter(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\n''.join(map(lambda _: str(globals().update({'workers': 4})), [1]))\n",
        "workers = 1\nimport itertools\nlist(itertools.islice(map(lambda _: globals().update({'workers': 4}), [1]), 1))\n",
        "workers = 1\ndef g():\n    yield from map(lambda _: globals().update({'workers': 4}), [1])\nlist(g())\n",
        "workers = 1\nimport threading\nt = threading.Thread(target=lambda: globals().update({'workers': 4}))\nt.start(); t.join()\n",
    ],
)
def test_security_review_alternate_lazy_consumers_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Cursor consumed-generator follow-up regressions
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nlist(x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nany(x for x in filter(lambda _: globals().update({'workers': 4}), [True]))\n",
        "workers = 1\nsorted(x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfor _ in (x for x in map(lambda _: globals().update({'workers': 4}), [1])):\n    pass\n",
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\nlist(gen)\n",
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\ngen = (x for x in it)\nlist(gen)\n",
        "workers = 1\nlist(y for _ in [1] for y in map(lambda _: globals().update({'workers': 4}), [1]))\n",
    ],
)
def test_cursor_consumed_generator_over_mutating_lazy_iterator_is_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\ngen = (x for x in filter(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\ngen = ()\nlist(gen)\n",
    ],
)
def test_cursor_unconsumed_or_rebound_generator_stays_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)

# Codex review follow-up 2026-09-18: alias, generator, and Thread execution gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom collections import deque as consume\nconsume(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nimport collections as c\nc.Counter(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfrom itertools import islice as take\nlist(take(map(lambda _: globals().update({'workers': 4}), [1]), 1))\n",
        "workers = 1\nsep = ''\nsep.join(map(lambda _: str(globals().update({'workers': 4})), [1]))\n",
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\ndef g():\n    yield from it\nlist(g())\n",
        "workers = 1\ndef g():\n    yield from map(lambda _: globals().update({'workers': 4}), [1])\nh = g\nlist(h())\n",
        "workers = 1\nif True:\n    def g():\n        yield from map(lambda _: globals().update({'workers': 4}), [1])\nlist(g())\n",
        "workers = 1\nimport threading\ndef set_workers():\n    global workers\n    workers = 4\nt = threading.Thread(target=set_workers)\nt.start(); t.join()\n",
        "workers = 1\nfrom threading import Thread as T\nt = T(target=lambda: globals().update({'workers': 4}))\nt.start(); t.join()\n",
        "workers = 1\nfrom concurrent.futures import ThreadPoolExecutor\nwith ThreadPoolExecutor(1) as ex:\n    ex.submit(lambda: globals().update({'workers': 4})).result()\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).map(lambda _: globals().update({'workers': 4}), [1])\n",
    ],
)
def test_codex_review_alias_and_execution_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\ndef enumerate(it):\n    return []\nlist(enumerate(map(lambda _: globals().update({'workers': 4}), [1])))\n",
        "workers = 1\ndef zip(*items):\n    return []\nlist(zip(map(lambda _: globals().update({'workers': 4}), [1]), [1]))\n",
        "workers = 1\ndef iter(it):\n    return []\nlist(iter(map(lambda _: globals().update({'workers': 4}), [1])))\n",
        "workers = 1\ndef reversed(it):\n    return []\nlist(reversed(map(lambda _: globals().update({'workers': 4}), [1])))\n",
        "workers = 1\ndef frozenset(it):\n    return set()\nfrozenset(map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\ndef f():\n    def g():\n        yield from map(lambda _: globals().update({'workers': 4}), [1])\n    return []\nlist(f())\n",
        "workers = 1\nimport threading\nt = threading.Thread(target=lambda: globals().update({'workers': 4}))\n",
        "workers = 1\ndef g():\n    yield from map(lambda _: globals().update({'workers': 4}), [1])\nh = g\nh = lambda: []\nlist(h())\n",
    ],
)
def test_codex_review_safe_alias_and_thread_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)

# Codex PR #253 follow-up: thread-pool alias, receiver, callback, and initializer gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom multiprocessing.pool import ThreadPool as Pool\nPool(1).map(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\npool = ThreadPool(1)\npool.map(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nwith ThreadPool(1) as pool:\n    pool.map(lambda _: globals().update({'workers': 4}), [1])\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\ndef set_workers(_):\n    global workers\n    workers = 4\nThreadPool(1).map(set_workers, [1])\n",
        "workers = 1\nfrom concurrent.futures import ThreadPoolExecutor\nwith ThreadPoolExecutor(1) as ex:\n    ex.submit(lambda: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import ThreadPoolExecutor\nwith ThreadPoolExecutor(1) as ex:\n    future = ex.submit(lambda: globals().update({'workers': 4}))\n    future.result()\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).map(lambda value: value, map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1, initializer=lambda: globals().update({'workers': 4})).map(lambda value: value, [1])\n",
        "workers = 1\nfrom concurrent.futures import ThreadPoolExecutor\nwith ThreadPoolExecutor(1, initializer=lambda: globals().update({'workers': 4})) as ex:\n    ex.submit(lambda: None)\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).map(func=lambda _: globals().update({'workers': 4}), iterable=[1])\n",
        "workers = 1\nimport multiprocessing.pool as p\np.ThreadPool(1).map(lambda _: globals().update({'workers': 4}), [1])\nimport concurrent.futures as p\n",
    ],
)
def test_codex_pr253_thread_pool_followups_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-09-20: Thread.run, asyncio.to_thread, pool imap/starmap/apply_async
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport threading\nthreading.Thread(target=lambda: globals().update({'workers': 4})).run()\n",
        "workers = 1\nimport asyncio\nasyncio.run(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).apply_async(lambda: globals().update({'workers': 4})).get()\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nlist(ThreadPool(1).imap(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).starmap(lambda _: globals().update({'workers': 4}), [(1,)])\n",
    ],
)
def test_security_review_sep20_thread_asyncio_pool_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex review follow-up 2026-09-20: remaining Thread/asyncio/ThreadPool gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nlist(ThreadPool(1).imap_unordered(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\npool = ThreadPool(1)\nresult = pool.apply_async(lambda: globals().update({'workers': 4}))\nresult.get()\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).apply_async(lambda: 0, callback=lambda _: globals().update({'workers': 4})).get()\n",
        "workers = 1\nfrom asyncio import run, to_thread\nrun(to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport threading\nt = threading.Thread(target=lambda: globals().update({'workers': 4}))\nthreading.Thread.run(t)\n",
        "workers = 1\nimport asyncio\nasyncio.run(asyncio.to_thread(globals().update, {'workers': 4}))\n",
    ],
)
def test_codex_pr258_remaining_findings_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr253_custom_submitter_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Submitter:\n"
        "    def submit(self, fn):\n"
        "        class Future:\n"
        "            def result(self):\n"
        "                return None\n"
        "        return Future()\n"
        "Submitter().submit(lambda: globals().update({'workers': 4})).result()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-09-20: indirect asyncio.to_thread execution gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.run_until_complete(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nasyncio.get_event_loop().run_until_complete(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
    ],
)
def test_security_review_sep20_asyncio_to_thread_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)



# Codex PR #261 follow-up: asyncio wrapper and event-loop resolution gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nasync def main():\n    await to_thread(lambda: globals().update({'workers': 4}))\nfrom asyncio import to_thread\nimport asyncio\nasyncio.run(main())\n",
        "workers = 1\nasync def main():\n    await aio.to_thread(lambda: globals().update({'workers': 4}))\nimport asyncio as aio\naio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nloop = asyncio.new_event_loop()\nloop.run_until_complete(main())\n",
        "workers = 1\nimport asyncio\nasync def helper():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasync def main():\n    await helper()\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nif True:\n    async def main():\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.run_until_complete(future=asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nrunner = main\nasyncio.run(runner())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    pending = asyncio.to_thread(lambda: globals().update({'workers': 4}))\n    await pending\nasyncio.run(main())\n",
    ],
)
def test_codex_pr261_asyncio_execution_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport asyncio\nasync def main():\n    async def inner():\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nclass Runner:\n    def run_until_complete(self, future):\n        future.close()\nRunner().run_until_complete(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nasync def main():\n    await to_thread(lambda: globals().update({'workers': 4}))\nimport asyncio\nasyncio.run(main())\nfrom asyncio import to_thread\n",
    ],
)
def test_codex_pr261_nonexecuted_asyncio_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex PR #261 second follow-up: remaining asyncio binding and execution gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport asyncio\nasync def main():\n    from asyncio import to_thread\n    await to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    async with asyncio.timeout(1):\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    for _ in [1]:\n        pending = asyncio.to_thread(lambda: globals().update({'workers': 4}))\n        alias = pending\n        await alias\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nwith asyncio.Runner() as runner:\n    runner.run(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nclass Jobs:\n    @staticmethod\n    async def main():\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(Jobs.main())\n",
        "workers = 1\nimport asyncio\nasync def main(dispatch):\n    await dispatch(lambda: globals().update({'workers': 4}))\nasyncio.run(main(asyncio.to_thread))\n",
        "workers = 1\nimport asyncio\nfactory = asyncio.new_event_loop\nloop = factory()\nloop.run_until_complete(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nasync def main():\n    def mutate():\n        globals().update({'workers': 4})\n    await asyncio.to_thread(mutate)\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(*(main(),))\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(**{'main': main()})\n",
    ],
)
def test_codex_pr261_second_followup_dynamic_patterns(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nfrom asyncio import sleep as main\nasyncio.run(main(0))\n",
        "workers = 1\nimport asyncio\nclass Jobs:\n    async def main(self):\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\ntry:\n    asyncio.run(Jobs.main())\nexcept TypeError:\n    pass\n",
    ],
)
def test_codex_pr261_second_followup_safe_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex PR #261 third follow-up: compound Runner, loop else, same-line, shadowing, combinators
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport asyncio\nif True:\n    runner = asyncio.Runner()\nrunner.run(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
        "workers = 1\nimport asyncio\nasync def main():\n    for _ in []:\n        pass\n    else:\n        await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop(); loop.run_until_complete(asyncio.to_thread(lambda: globals().update({'workers': 4}))); loop = None\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.gather(asyncio.to_thread(lambda: globals().update({'workers': 4})))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.shield(asyncio.to_thread(lambda: globals().update({'workers': 4})))\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nasync def main():\n    await asyncio.wait_for(asyncio.to_thread(lambda: globals().update({'workers': 4})), 1)\nasyncio.run(main())\n",
        "workers = 1\nimport asyncio\nfrom asyncio import gather as consume\nasync def main():\n    await consume(asyncio.to_thread(lambda: globals().update({'workers': 4})))\nasyncio.run(main())\n",
    ],
)
def test_codex_pr261_third_followup_dynamic_patterns(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr261_local_to_thread_shadow_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "import asyncio\n"
        "from asyncio import to_thread\n"
        "async def main():\n"
        "    async def to_thread(callback):\n"
        "        return None\n"
        "    await to_thread(lambda: globals().update({'workers': 4}))\n"
        "asyncio.run(main())\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-09-23: concurrent.futures.Future.add_done_callback mutation
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.set_result(None)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future as CF\nf = CF()\nf.set_result(0)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
    ],
)
def test_security_review_sep23_future_add_done_callback_is_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #267 follow-up: Future receiver, completion, callback aliases, expansions
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.set_result(None)\ncb = lambda _: globals().update({'workers': 4})\nf.add_done_callback(cb)\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.set_result(None)\nf.add_done_callback(*(lambda _: globals().update({'workers': 4}),))\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.set_result(None)\ncb = lambda _: globals().update({'workers': 4})\nf.add_done_callback(**{'fn': cb})\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\ncb = lambda _: globals().update({'workers': 4})\nf.add_done_callback(cb)\nf.set_result(None)\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\ng = f\ng.set_result(None)\ng.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import ThreadPoolExecutor\nwith ThreadPoolExecutor(1) as ex:\n    f = ex.submit(lambda: None)\n    f.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
    ],
)
def test_codex_pr267_future_callback_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #267 second follow-up: import/alias/class-body/method-alias gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport concurrent.futures\nf = concurrent.futures.Future()\nf.set_result(None)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future; f = Future(); Future = object\nf.set_result(None)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nclass Complete:\n    f.set_result(None)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future\nF = Future\nf = F()\nf.set_result(None)\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.set_result(None)\nregister = f.add_done_callback\nregister(lambda _: globals().update({'workers': 4}))\n",
    ],
)
def test_codex_pr267_second_followup_future_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nclass Holder:\n    def add_done_callback(self, fn):\n        self.fn = fn\nHolder().add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
        "workers = 1\nfrom concurrent.futures import Future\nf = Future()\nf = object()\nf.add_done_callback(lambda _: globals().update({'workers': 4}))\n",
    ],
)
def test_codex_pr267_nonexecuting_callback_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-09-22: threading.Timer deferred workers mutation
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport threading\nthreading.Timer(0, lambda: globals().update({'workers': 4})).start()\n",
        "workers = 1\nfrom threading import Timer\nTimer(0, lambda: globals().update({'workers': 4})).start()\n",
        "workers = 1\nimport threading\nt = threading.Timer(0.0, lambda: globals().update({'workers': 4}))\nt.start()\n",
        "workers = 1\nimport threading\nthreading.Timer(interval=0, function=lambda: globals().update({'workers': 4})).start()\n",
        "workers = 1\nfrom threading import Timer as DeferredTimer\nDeferredTimer(interval=0, function=lambda: globals().update({'workers': 4})).start()\n",
    ],
)
def test_security_review_sep22_threading_timer_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-09-24: synchronous container dispatch workers mutation
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\nq.get()()\n",
        "workers = 1\nimport collections\nd = collections.deque()\nd.append(lambda: globals().update({'workers': 4}))\nd.popleft()()\n",
        "workers = 1\nlist(map(lambda f: f(), [lambda: globals().update({'workers': 4})]))\n",
        "workers = 1\nnext(iter([lambda: globals().update({'workers': 4})]))()\n",
    ],
)
def test_security_review_sep24_sync_container_dispatch_is_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_security_review_sep24_unrelated_get_result_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Holder:\n"
        "    def get(self):\n"
        "        return lambda: None\n"
        "Holder().get()()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex PR #271 follow-up: callback dispatch provenance and execution semantics
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: None)\nq.get()()\n",
        "workers = 1\nfor callback in [lambda: globals().update({'workers': 4})]:\n    pass\n",
        "workers = 1\nfor callback in iter([lambda: globals().update({'workers': 4})]):\n    pass\n",
        "workers = 1\nlist([lambda: globals().update({'workers': 4})])\n",
    ],
)
def test_codex_pr271_nonexecuted_callbacks_stay_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\nq.get(False)()\n",
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\nq.get(block=False)()\n",
        "workers = 1\nlist(map(lambda callback, _: callback(), [lambda: globals().update({'workers': 4})], [None]))\n",
        "workers = 1\ncallback = lambda: globals().update({'workers': 4})\nlist(map(lambda fn: fn(), [callback]))\n",
        "workers = 1\nlist(map(lambda fn: fn(), {lambda: globals().update({'workers': 4})}))\n",
        "workers = 1\ncallback = lambda: globals().update({'workers': 4})\nnext(iter([callback]))()\n",
        "workers = 1\ncallbacks = (lambda: globals().update({'workers': 4}),)\nnext(iter(callbacks))()\n",
    ],
)
def test_codex_pr271_executed_callbacks_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-09-25: direct callback invocation, getattr queue dispatch, asyncio scheduling
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfor callback in [lambda: globals().update({'workers': 4})]:\n    callback()\n",
        "workers = 1\nlst = [lambda: globals().update({'workers': 4})]\nlst[0]()\n",
        "workers = 1\ns = {lambda: globals().update({'workers': 4})}\ns.pop()()\n",
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\ngetattr(q, 'get')()()\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.call_soon(lambda: globals().update({'workers': 4}))\nloop.run_until_complete(asyncio.sleep(0))\n",
    ],
)
def test_security_review_sep25_callback_and_asyncio_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #276 follow-up: callback provenance, Queue.get arguments, asyncio aliases
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfor cb in [lambda: globals().update({'workers': 4})]:\n    result = cb()\n",
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\ngetattr(q, 'get')(False)()\n",
        "workers = 1\nimport queue\nq = queue.Queue()\nq.put(lambda: globals().update({'workers': 4}))\ngetattr(q, 'get')(block=False)()\n",
        "workers = 1\ncallbacks = [lambda: globals().update({'workers': 4})]\ncallback = callbacks[0]\ncallback()\n",
        "workers = 1\ncallback = lambda: globals().update({'workers': 4})\ncallback()\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.call_soon(lambda: globals().update({'workers': 4}))\nalias = loop\nalias.run_until_complete(asyncio.sleep(0))\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.call_soon_threadsafe(lambda: globals().update({'workers': 4}))\nloop.run_until_complete(asyncio.sleep(0))\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nloop.call_soon(lambda: globals().update({'workers': 4}))\nloop.call_soon(loop.stop)\nloop.run_forever()\n",
    ],
)
def test_codex_pr276_callback_and_asyncio_followups_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr276_standalone_callback_pop_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "callbacks = {lambda: globals().update({'workers': 4})}\n"
        "callbacks.pop()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug scan 2026-09-26: callback provenance and asyncio task scheduling gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "for cb in callbacks:\n",
            "    cb()\n",
        )),
        "".join((
            "workers = 1\n",
            "[callback() for callback in [lambda: globals().update({'workers': 4})]]\n",
        )),
        "".join((
            "workers = 1\n",
            "import operator\n",
            "operator.call(lambda: globals().update({'workers': 4}))\n",
        )),
        "".join((
            "workers = 1\n",
            "from operator import call as invoke\n",
            "invoke(lambda: globals().update({'workers': 4}))\n",
        )),
        "".join((
            "workers = 1\n",
            "from functools import partial\n",
            "partial(lambda: globals().update({'workers': 4}))()\n",
        )),
        "".join((
            "workers = 1\n",
            "from functools import partial\n",
            "cb = partial(lambda: globals().update({'workers': 4}))\n",
            "cb()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "results = [cb() for cb in callbacks]\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "tuple([cb() for cb in callbacks])\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "for cb in iter(callbacks):\n",
            "    cb()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "for cb in callbacks[:]:\n",
            "    cb()\n",
        )),
        "".join((
            "workers = 1\n",
            "import asyncio\n",
            "async def main():\n",
            "    asyncio.create_task(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
            "    await asyncio.sleep(0)\n",
            "asyncio.run(main())\n",
        )),
        "".join((
            "workers = 1\n",
            "import asyncio\n",
            "async def main():\n",
            "    task = asyncio.create_task(asyncio.to_thread(lambda: globals().update({'workers': 4})))\n",
            "    await asyncio.sleep(0)\n",
            "asyncio.run(main())\n",
        )),
    ],
)
def test_bugscan_sep26_callback_and_asyncio_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)
