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


# Security review 2026-09-27: additional import-time workers mutation gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport sched\ns = sched.scheduler()\ns.enter(0, 1, lambda: globals().update({'workers': 4}))\ns.run(blocking=False)\n",
        "workers = 1\nfrom functools import reduce\nreduce(lambda _, f: f(), [lambda: globals().update({'workers': 4})], None)\n",
        "workers = 1\nimport inspect\nframe = inspect.currentframe()\nframe.f_globals.update({'workers': 4})\n",
        "workers = 1\nany(cb() or True for cb in [lambda: globals().update({'workers': 4})])\n",
        "workers = 1\nsum(cb() or 0 for cb in [lambda: globals().update({'workers': 4})])\n",
        "workers = 1\nmatch [lambda: globals().update({'workers': 4})]:\n    case [cb]: cb()\n",
        "workers = 1\nfrom multiprocessing.pool import ThreadPool\nThreadPool(1).apply(lambda: globals().update({'workers': 4}))\n",
        "workers = 1\nimport builtins\nvars(builtins)['exec']('workers=4')\n",
        "workers = 1\n[(cb := lambda: globals().update({'workers': 4}))() for _ in [1]]\n",
        "workers = 1\nimport queue\nq = queue.PriorityQueue()\nq.put((0, lambda: globals().update({'workers': 4})))\nq.get()[1]()\n",
        "workers = 1\nimport heapq\nh = []\nheapq.heappush(h, (0, lambda: globals().update({'workers': 4})))\nheapq.heappop(h)[1]()\n",
        "workers = 1\nimport collections\nd = collections.UserList([lambda: globals().update({'workers': 4})])\nd.pop(0)()\n",
        "workers = 1\nit = iter([lambda: globals().update({'workers': 4})])\nwhile True:\n    try:\n        it.__next__()()\n    except StopIteration:\n        break\n",
        "workers = 1\nimport asyncio\nloop = asyncio.new_event_loop()\nasyncio.set_event_loop(loop)\nasync def coro():\n    await asyncio.to_thread(lambda: globals().update({'workers': 4}))\nloop.create_task(coro())\nloop.run_until_complete(asyncio.sleep(0))\n",
    ],
)
def test_security_review_sep27_worker_scan_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr290_direct_userlist_import_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "from collections import UserList\n"
        "d = UserList([lambda: globals().update({'workers': 4})])\n"
        "d.pop(0)()\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import builtins\n"
            "def vars(_):\n"
            "    return {'exec': lambda _: None}\n"
            "vars(builtins)['exec']('workers=4')\n"
        ),
        (
            "workers = 1\n"
            "class Frame:\n"
            "    pass\n"
            "frame = Frame()\n"
            "frame.f_globals = {}\n"
            "frame.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "any(True or cb() for cb in "
            "[lambda: globals().update({'workers': 4})])\n"
        ),
        (
            "workers = 1\n"
            "import queue\n"
            "q = queue.PriorityQueue()\n"
            "q.put((lambda: None, "
            "lambda: globals().update({'workers': 4})))\n"
            "q.get()[0]()\n"
        ),
        (
            "workers = 1\n"
            "import heapq\n"
            "h = []\n"
            "heapq.heappush(h, (lambda: None, "
            "lambda: globals().update({'workers': 4})))\n"
            "heapq.heappop(h)[0]()\n"
        ),
        (
            "workers = 1\n"
            "from functools import reduce\n"
            "reduce(lambda _, f: f(), "
            "[lambda: globals().update({'workers': 4})])\n"
        ),
        (
            "workers = 1\n"
            "match [lambda: globals().update({'workers': 4}), lambda: None]:\n"
            "    case [cb]: cb()\n"
        ),
        (
            "workers = 1\n"
            "match [lambda: globals().update({'workers': 4})]:\n"
            "    case [cb] if False: cb()\n"
        ),
        (
            "workers = 1\n"
            "import heapq\n"
            "class SafeHeap:\n"
            "    def heappush(self, *args):\n"
            "        return None\n"
            "    def heappop(self, *args):\n"
            "        return (0, lambda: None)\n"
            "heapq = SafeHeap()\n"
            "h = []\n"
            "heapq.heappush(h, (0, "
            "lambda: globals().update({'workers': 4})))\n"
            "heapq.heappop(h)[1]()\n"
        ),
        (
            "workers = 1\n"
            "import sched\n"
            "class SafeSched:\n"
            "    def scheduler(self):\n"
            "        return self\n"
            "    def enter(self, *args):\n"
            "        return object()\n"
            "    def run(self, *args, **kwargs):\n"
            "        return None\n"
            "sched = SafeSched()\n"
            "s = sched.scheduler()\n"
            "s.enter(0, 1, lambda: globals().update({'workers': 4}))\n"
            "s.run()\n"
        ),
        (
            "workers = 1\n"
            "import sched\n"
            "s = sched.scheduler()\n"
            "event = s.enter(0, 1, "
            "lambda: globals().update({'workers': 4}))\n"
            "s.cancel(event)\n"
            "s.run(blocking=False)\n"
        ),
        (
            "workers = 1\n"
            "import asyncio\n"
            "loop = asyncio.new_event_loop()\n"
            "asyncio.set_event_loop(loop)\n"
            "async def coro():\n"
            "    await asyncio.to_thread("
            "lambda: globals().update({'workers': 4}))\n"
            "task = loop.create_task(coro())\n"
            "task.cancel()\n"
            "loop.run_until_complete(asyncio.sleep(0))\n"
        ),
    ],
)
def test_codex_pr290_false_positive_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


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


# Codex PR #283: source-ordered callback provenance and consumer semantics
@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "import operator as op\n",
            "class Fake:\n",
            "    @staticmethod\n",
            "    def call(*args, **kwargs):\n",
            "        return None\n",
            "op = Fake()\n",
            "invoke = op.call\n",
            "invoke(globals().update, {'workers': 4})\n",
        )),
        "".join((
            "workers = 1\n",
            "import operator\n",
            "def cb():\n",
            "    globals().update({'workers': 4})\n",
            "cb = lambda: None\n",
            "operator.call(cb)\n",
        )),
        "".join((
            "workers = 1\n",
            "from functools import partial\n",
            "def cb():\n",
            "    globals().update({'workers': 4})\n",
            "cb = lambda: None\n",
            "partial(cb)()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "for name, cb in zip([lambda: None], callbacks):\n",
            "    name()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "max((cb() for cb in callbacks), object(), key=lambda _: 0)\n",
        )),
        "".join((
            "workers = 1\n",
            "def run(list):\n",
            "    list(cb() for cb in [lambda: globals().update({'workers': 4})])\n",
            "run(lambda gen: None)\n",
        )),
        "".join((
            "workers = 1\n",
            "any(cb() for cb in [lambda: True, lambda: globals().update({'workers': 4})])\n",
        )),
        "".join((
            "workers = 1\n",
            "all(cb() for cb in [lambda: False, lambda: globals().update({'workers': 4})])\n",
        )),
        "".join((
            "workers = 1\n",
            "next(cb() for cb in [lambda: None, lambda: globals().update({'workers': 4})])\n",
        )),
    ],
)
def test_codex_pr283_false_positive_patterns_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "import operator\n",
            "def cb():\n",
            "    globals().update({'workers': 4})\n",
            "operator.call(cb)\n",
        )),
        "".join((
            "workers = 1\n",
            "from functools import partial\n",
            "def cb():\n",
            "    globals().update({'workers': 4})\n",
            "partial(cb)()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "for name, cb in zip([lambda: None], callbacks):\n",
            "    cb()\n",
        )),
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "max(cb() for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "list(cb() for cb in [lambda: globals().update({'workers': 4})])\n",
        )),
        "".join((
            "workers = 1\n",
            "any(cb() for cb in [lambda: globals().update({'workers': 4}), lambda: True])\n",
        )),
        "".join((
            "workers = 1\n",
            "all(cb() for cb in [lambda: globals().update({'workers': 4}), lambda: False])\n",
        )),
        "".join((
            "workers = 1\n",
            "next(cb() for cb in [lambda: globals().update({'workers': 4}), lambda: None])\n",
        )),
    ],
)
def test_codex_pr283_positive_callback_patterns_remain_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# CodeRabbit PR #283 follow-up: a user-defined `sum` is not the eager builtin consumer
def test_coderabbit_pr283_shadowed_sum_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "".join((
            "workers = 1\n",
            "def sum(values):\n",
            "    return 0\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "answer = sum(cb() for cb in callbacks)\n",
        )),
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_coderabbit_pr283_builtin_sum_consumer_stays_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "".join((
            "workers = 1\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "answer = sum(cb() for cb in callbacks)\n",
        )),
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_coderabbit_pr292_sum_rebound_to_builtin_stays_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "".join((
            "import builtins\n",
            "workers = 1\n",
            "sum = lambda values: 0\n",
            "sum = builtins.sum\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "answer = sum(cb() for cb in callbacks)\n",
        )),
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-09-28: builtins-module eager consumer indirection
@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "builtins.sum(cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "builtins.any(cb() or True for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "getattr(builtins, 'sum')(cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "builtins.__dict__['sum'](cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "from importlib import import_module\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "import_module('builtins').sum(cb() or 0 for cb in callbacks)\n",
        )),
    ],
)
def test_security_review_sep28_builtins_module_consumers_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)



# Codex PR #294: source-ordered builtins/importlib resolution
@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "import importlib\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "importlib.import_module('builtins').sum(cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import importlib as il\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "il.import_module('builtins').sum(cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "builtins.getattr(builtins, 'sum')(cb() or 0 for cb in callbacks)\n",
        )),
    ],
)
def test_codex_pr294_builtin_module_resolution_is_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "getattr = lambda obj, name: (lambda values: 0)\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "getattr(builtins, 'sum')(cb() or 0 for cb in callbacks)\n",
        )),
        "".join((
            "workers = 1\n",
            "import builtins\n",
            "class Helper:\n",
            "    @staticmethod\n",
            "    def sum(values):\n",
            "        return 0\n",
            "builtins = Helper()\n",
            "callbacks = [lambda: globals().update({'workers': 4})]\n",
            "builtins.sum(cb() or 0 for cb in callbacks)\n",
        )),
    ],
)
def test_codex_pr294_shadowed_builtin_helpers_stay_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-09-29: import-time worker scanner follow-up gaps
@pytest.mark.parametrize(
    "config_content",
    [
        "".join(
            (
                "workers = 1\n",
                "import builtins\n",
                "callbacks = [lambda: globals().update({'workers': 4})]\n",
                "builtins.list(map(lambda cb: cb() or 0, callbacks))\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "import sys\n",
                "callbacks = [lambda: globals().update({'workers': 4})]\n",
                "sys.modules['builtins'].sum(cb() or 0 for cb in callbacks)\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "from contextlib import ExitStack\n",
                "with ExitStack() as stack:\n",
                "    stack.callback(lambda: globals().update({'workers': 4}))\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "import builtins\n",
                "callbacks = [lambda: globals().update({'workers': 4})]\n",
                "builtins.sorted(callbacks, key=lambda cb: cb() or 0)\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "import builtins\n",
                "callbacks = [lambda: globals().update({'workers': 4})]\n",
                "builtins.list(builtins.filter(lambda x: x, "
                "map(lambda cb: cb() or 0, callbacks)))\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "import heapq\n",
                "callbacks = [lambda: globals().update({'workers': 4})]\n",
                "heapq.nsmallest(1, callbacks, key=lambda cb: cb() or 0)\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "import itertools\n",
                "callbacks = [(lambda: globals().update({'workers': 4}),)]\n",
                "list(itertools.starmap(lambda f: f(), callbacks))\n",
            )
        ),
        "".join(
            (
                "workers = 1\n",
                "from collections import deque\n",
                "d = deque()\n",
                "d.append(lambda: globals().update({'workers': 4}))\n",
                "d[0]()\n",
            )
        ),
    ],
)
def test_security_review_sep29_worker_scan_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)

# Security review 2026-10-01: frame enumeration and sys._getframe f_globals gaps
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import sys\n"
            "sys._getframe(0).f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "frame = sys._getframe(0)\n"
            "frame.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "getattr(sys, '_getframe')(0).f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "from sys import _getframe as frame_getter\n"
            "frame_getter(0).f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "for fi in inspect.stack():\n"
            "    fi.frame.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "[fi.frame.f_globals.update({'workers': 4}) for fi in inspect.stack()[:1]]\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "for frame, *_ in inspect.getouterframes(inspect.currentframe()):\n"
            "    frame.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
    ],
)
def test_security_review_oct01_frame_globals_mutations_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-02: live-frame mutation paths
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import traceback\n"
            "for f, _ in traceback.walk_stack(None):\n"
            "    f.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
        (
            "workers = 1\n"
            "import traceback\n"
            "for item in traceback.walk_stack(None):\n"
            "    item[0].f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "sys._getframe(0).f_globals |= {'workers': 4}\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "inspect.stack()[0].frame.f_globals |= {'workers': 4}\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "fi = inspect.stack()[0]\n"
            "fi.frame.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "for fi in inspect.innerframes(inspect.currentframe()):\n"
            "    fi.frame.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "while (fi := inspect.stack()[0]).frame.f_globals.update({'workers': 4}) or False: break\n"
        ),
    ],
)
def test_security_review_oct02_frame_globals_mutations_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #310: reject non-config frames and stale/synthetic aliases
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import traceback\n"
            "try:\n"
            "    traceback.extract_stack()[0].frame.f_globals.update({'workers': 4})\n"
            "except AttributeError:\n"
            "    pass\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "sys._getframe(0).f_back.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "from types import SimpleNamespace\n"
            "fi = inspect.stack()[0]\n"
            "fi = SimpleNamespace(frame=SimpleNamespace(f_globals={}))\n"
            "fi.frame.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "def unused():\n"
            "    fi = inspect.stack()[0]\n"
            "    fi.frame.f_globals.update({'workers': 4})\n"
        ),
    ],
)
def test_codex_pr310_frame_provenance_false_positives_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class Holder:\n"
            "    pass\n"
            "obj = Holder()\n"
            "obj.frame = Holder()\n"
            "obj.frame.f_globals = {}\n"
            "obj.frame.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "class FakeFrame:\n"
            "    f_globals = {}\n"
            "_getframe = FakeFrame\n"
            "_getframe().f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "from sys import _getframe\n"
            "class FakeFrame:\n"
            "    f_globals = {}\n"
            "_getframe = FakeFrame\n"
            "_getframe().f_globals.update({'workers': 4})\n"
        ),
    ],
)
def test_codex_pr302_unrelated_frame_shapes_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter scan 2026-10-02: setdefault, getattr/f_globals __ior__, hooks
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nglobals().setdefault('workers', 8)\n",
        (
            "workers = 1\n"
            "import sys\n"
            "sys.modules[__name__].__dict__.setdefault('workers', 8)\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "inspect.currentframe().f_globals.__ior__({'workers': 8})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "frame = inspect.currentframe()\n"
            "getattr(frame, 'f_globals').update({'workers': 8})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "getattr(inspect.currentframe(), 'f_globals').__ior__({'workers': 8})\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "getattr(inspect.currentframe(), 'f_globals', {}).__ior__({'workers': 8})\n"
        ),
        "workers = 1\ngetattr(globals(), 'setdefault')('workers', 8)\n",
        "ns = globals()\ngetattr(ns, 'setdefault')('workers', 8)\n",
        (
            "workers = 1\n"
            "import operator\n"
            "operator.methodcaller('setdefault', 'workers', 8)(globals())\n"
        ),
    ],
)
def test_bughunter_oct02_indirect_workers_mutations_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nfrom hooks import when_ready\n",
        "workers = 1\nfrom hooks import ready as when_ready\n",
        "workers = 1\nfrom hooks import *\n",
        (
            "workers = 1\n"
            "import sys\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "setattr(sys.modules[__name__], 'when_ready', hook)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "sys.modules[__name__].when_ready = hook\n"
        ),
        (
            "workers = 1\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "globals()['when_ready'] = hook\n"
        ),
        (
            "workers = 1\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "globals().update({'when_ready': hook})\n"
        ),
        (
            "workers = 1\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "globals().setdefault('when_ready', hook)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "sys.modules[__name__].__dict__.setdefault('on_starting', hook)\n"
        ),
        (
            "workers = 1\n"
            "namespace = globals()\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "namespace.setdefault('on_starting', hook)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "key = 'on_starting'\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "setattr(sys.modules[__name__], key, hook)\n"
        ),
        (
            "workers = 1\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "globals().update(on_starting=hook)\n"
        ),
        (
            "workers = 1\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "class Holder:\n"
            "    globals()['on_starting'] = hook\n"
        ),
        (
            "workers = 1\n"
            "import sys as s\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "setattr(s.modules[__name__], 'on_starting', hook)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "class Install:\n"
            "    setattr(sys.modules[__name__], 'on_starting', hook)\n"
        ),
        (
            "workers = 1\n"
            "ns = globals()\n"
            "def hook(server):\n"
            "    server.cfg.workers = 8\n"
            "ns['on_starting'] = hook\n"
        ),
    ],
)
def test_bughunter_oct02_bound_runtime_hooks_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "def setup():\n"
            "    from hooks import when_ready\n"
            "setup()\n"
        ),
        (
            "workers = 1\n"
            "def setup():\n"
            "    import hooks\n"
            "setup()\n"
        ),
    ],
)
def test_bughunter_oct02_function_local_hook_import_stays_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-03: proven f_globals indirection and sys._current_frames
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import sys\n"
            "(fr := sys._getframe(0)).f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "fr = sys._getframe(0)\n"
            "getattr(fr.f_globals, 'update')({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "from functools import partial\n"
            "fr = sys._getframe(0)\n"
            "partial(fr.f_globals.update, {'workers': 4})()\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "fr = sys._getframe(0)\n"
            "dict.__setitem__(fr.f_globals, 'workers', 4)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "fr = sys._getframe(0)\n"
            "g = fr.f_globals\n"
            "g.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys, operator\n"
            "fr = sys._getframe(0)\n"
            "operator.methodcaller('update', {'workers': 4})(fr.f_globals)\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "fr = sys._getframe(0)\n"
            "fr.f_globals['workers'] = 4\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "for _fid, fr in sys._current_frames().items():\n"
            "    fr.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
    ],
)
def test_security_review_oct03_frame_globals_indirection_is_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Bug-hunter 2026-10-03: plain instance methods that mutate workers
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "Helper().bump()\n"
        ),
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "h = Helper()\n"
            "h.bump()\n"
        ),
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "Helper.bump(Helper())\n"
        ),
    ],
)
def test_instance_method_workers_mutation_is_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "h = Helper()\n"
            "h = None\n"
            "h.bump()\n"
        ),
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "Helper = lambda: None\n"
            "Helper().bump()\n"
        ),
        (
            "workers = 1\n"
            "class Helper:\n"
            "    def bump(self):\n"
            "        pass\n"
            "Helper().bump()\n"
        ),
    ],
)
def test_non_mutating_or_rebound_instance_calls_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex review 2026-10-03: instance provenance must survive a later rebinding
# of the class name, and class-local bindings must not be mistaken for module
# mutations.
def test_instance_provenance_survives_class_name_rebinding(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Helper:\n"
        "    def bump(self):\n"
        "        globals()['workers'] = 4\n"
        "h = Helper()\n"
        "Helper = None\n"
        "h.bump()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class Holder:\n"
            "    for workers in range(2):\n"
            "        pass\n"
        ),
        (
            "workers = 1\n"
            "class Holder:\n"
            "    from os import workers\n"
        ),
    ],
)
def test_class_local_workers_bindings_stay_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_class_body_global_workers_assignment_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Holder:\n"
        "    global workers\n"
        "    workers = 4\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# CodeRabbit review 2026-10-03: a conditional rebinding must keep the earlier
# instance class as a candidate, because the branch may not have run.
def test_conditional_instance_rebinding_keeps_both_candidates(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Helper:\n"
        "    def bump(self):\n"
        "        globals()['workers'] = 4\n"
        "class Other:\n"
        "    def bump(self):\n"
        "        pass\n"
        "h = Helper()\n"
        "if True:\n"
        "    h = Other()\n"
        "h.bump()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# CodeRabbit review 2026-10-04: a walrus after `global workers` in a class
# body binds the module name and must be treated as dynamic.
def test_class_body_global_workers_walrus_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Holder:\n"
        "    global workers\n"
        "    (workers := 4)\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_class_body_lambda_walrus_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Holder:\n"
        "    global workers\n"
        "    fn = lambda: (workers := 4)\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-04: frame and class-hook indirection gaps
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import sys\n"
            "fr = sys._getframe(0)\n"
            "object.__getattribute__(fr, 'f_globals').update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "getattr(object, '__getattribute__')(sys._getframe(0), 'f_globals').update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys, operator\n"
            "operator.attrgetter('f_globals')(sys._getframe(0)).update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "for fr in sys._current_frames().values():\n"
            "    fr.f_globals.update({'workers': 4})\n"
            "    break\n"
        ),
        (
            "workers = 1\n"
            "class D:\n"
            "    def __get__(self, obj, typ=None):\n"
            "        globals()['workers'] = 4\n"
            "class H:\n"
            "    d = D()\n"
            "H.d\n"
        ),
        (
            "workers = 1\n"
            "from enum import Enum\n"
            "class E(Enum):\n"
            "    A = 1\n"
            "    def f(self):\n"
            "        globals()['workers'] = 4\n"
            "E.A.f()\n"
        ),
        (
            "workers = 1\n"
            "class B:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "class H(B):\n"
            "    pass\n"
            "H().bump()\n"
        ),
        (
            "workers = 1\n"
            "import operator, sys\n"
            "operator.attrgetter('__dict__')(sys.modules[__name__]).update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import operator, sys\n"
            "g = operator.attrgetter('__dict__')(sys.modules[__name__])\n"
            "g.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "class B:\n"
            "    @staticmethod\n"
            "    def mut():\n"
            "        globals()['workers'] = 4\n"
            "class H(B):\n"
            "    pass\n"
            "H.mut()\n"
        ),
        (
            "workers = 1\n"
            "class B:\n"
            "    @classmethod\n"
            "    def mut(cls):\n"
            "        globals()['workers'] = 4\n"
            "class H(B):\n"
            "    pass\n"
            "H.mut()\n"
        ),
    ],
)
def test_security_review_oct04_workers_scan_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class M(type):\n"
            "    def __call__(cls, *a, **k):\n"
            "        globals()['workers'] = 4\n"
            "        return super().__call__(*a, **k)\n"
            "class C(metaclass=M):\n"
            "    pass\n"
            "C()\n"
        ),
        (
            "workers = 1\n"
            "class B:\n"
            "    def __init__(self):\n"
            "        globals()['workers'] = 4\n"
            "class D(B):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "D()\n"
        ),
        (
            "workers = 1\n"
            "class C:\n"
            "    def __class_getitem__(cls, item):\n"
            "        globals()['workers'] = 4\n"
            "        return cls\n"
            "C[int]\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "for fi in inspect.stack():\n"
            "    if (g := fi.frame.f_globals) is globals():\n"
            "        g.update({'workers': 4})\n"
            "        break\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "def g():\n"
            "    yield sys._getframe(0)\n"
            "for fr in g():\n"
            "    fr.f_globals.update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "from dataclasses import dataclass, field\n"
            "@dataclass\n"
            "class D:\n"
            "    x: int = field(\n"
            "        default_factory=lambda: (globals().update({'workers': 4}) or 1)\n"
            "    )\n"
            "D()\n"
        ),
        (
            "workers = 1\n"
            "import weakref\n"
            "class X:\n"
            "    pass\n"
            "weakref.finalize(X(), lambda: globals().update({'workers': 4}))\n"
        ),
        (
            "workers = 1\n"
            "import warnings\n"
            "def w(*a):\n"
            "    globals().update({'workers': 4})\n"
            "warnings.showwarning = w\n"
            "warnings.warn('x')\n"
        ),
    ],
)
def test_security_review_oct05_workers_scan_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class A:\n"
            "    def ping(self):\n"
            "        return None\n"
            "class A(A):\n"
            "    pass\n"
            "A().ping()\n"
        ),
        (
            "workers = 1\n"
            "class B:\n"
            "    def bump(self):\n"
            "        globals()['workers'] = 4\n"
            "class H(B):\n"
            "    def bump(self):\n"
            "        return None\n"
            "H().bump()\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "class FakeObject:\n"
            "    @staticmethod\n"
            "    def __getattribute__(frame, name):\n"
            "        return {}\n"
            "object = FakeObject\n"
            "object.__getattribute__(sys._getframe(0), 'f_globals').update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "def getattr(target, name):\n"
            "    return lambda *args: {}\n"
            "getattr(object, '__getattribute__')(sys._getframe(0), 'f_globals').update({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "class D:\n"
            "    def __get__(self, obj, typ=None):\n"
            "        globals()['workers'] = 4\n"
            "class H:\n"
            "    d = D()\n"
            "class Safe:\n"
            "    d = object()\n"
            "H = Safe\n"
            "H.d\n"
        ),
        (
            "workers = 1\n"
            "class H:\n"
            "    @property\n"
            "    def p(self):\n"
            "        globals()['workers'] = 4\n"
            "H.p\n"
        ),
        (
            "workers = 1\n"
            "class Item:\n"
            "    def f(self):\n"
            "        return None\n"
            "class E:\n"
            "    A = Item()\n"
            "    def f(self):\n"
            "        globals()['workers'] = 4\n"
            "E.A.f()\n"
        ),
        (
            "workers = 1\n"
            "import operator, sys\n"
            "try:\n"
            "    operator.attrgetter('f_globals')(sys._getframe(0))({'workers': 4})\n"
            "except TypeError:\n"
            "    pass\n"
        ),
    ],
)
def test_codex_review_oct04_false_positives_stay_static(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex review follow-up for PR #332.
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "from dataclasses import dataclass as dc, field\n"
            "@dc\n"
            "class C:\n"
            "    value: object = field(default_factory=lambda: globals().update({'workers': 4}))\n"
            "C()\n"
        ),
        (
            "workers = 1\n"
            "import sys as s\n"
            "def frames():\n"
            "    yield s._getframe(0)\n"
            "for frame in frames():\n"
            "    frame.f_globals['workers'] = 4\n"
        ),
        (
            "workers = 1\n"
            "from sys import _getframe as gf\n"
            "def frames():\n"
            "    yield gf(0)\n"
            "for frame in frames():\n"
            "    frame.f_globals['workers'] = 4\n"
        ),
        (
            "workers = 1\n"
            "from weakref import finalize\n"
            "class X: pass\n"
            "finalize(X(), lambda: globals().update({'workers': 4}))\n"
        ),
        (
            "workers = 1\n"
            "import warnings\n"
            "from warnings import warn\n"
            "def mutator(*args, **kwargs):\n"
            "    globals().update({'workers': 4})\n"
            "warnings.showwarning = mutator\n"
            "warn('x')\n"
        ),
        (
            "workers = 1\n"
            "class M(type):\n"
            "    def __call__(cls, *args, **kwargs):\n"
            "        globals().update({'workers': 4})\n"
            "class N(M):\n"
            "    pass\n"
            "class C(metaclass=N):\n"
            "    pass\n"
            "C()\n"
        ),
        (
            "workers = 1\n"
            "class Base:\n"
            "    def __class_getitem__(cls, item):\n"
            "        globals().update({'workers': 4})\n"
            "class Derived(Base):\n"
            "    pass\n"
            "Derived[int]\n"
        ),
        (
            "workers = 1\n"
            "class Mutating:\n"
            "    def __init__(self):\n"
            "        globals().update({'workers': 4})\n"
            "class Safe:\n"
            "    pass\n"
            "class D(Mutating, Safe):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "D()\n"
        ),
    ],
)
def test_codex_pr332_review_dynamic_patterns_are_detected(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class M(type):\n"
            "    def __call__(cls, *args, **kwargs):\n"
            "        globals().update({'workers': 4})\n"
            "class C(metaclass=M):\n"
            "    pass\n"
        ),
        (
            "workers = 1\n"
            "import warnings\n"
            "def mutator(*args, **kwargs):\n"
            "    globals().update({'workers': 4})\n"
            "warnings.warn('safe')\n"
            "warnings.showwarning = mutator\n"
        ),
        (
            "workers = 1\n"
            "import warnings\n"
            "def mutator(*args, **kwargs):\n"
            "    globals().update({'workers': 4})\n"
            "warnings.showwarning = mutator\n"
            "warnings.showwarning = lambda *args, **kwargs: None\n"
            "warnings.warn('safe')\n"
        ),
        (
            "workers = 1\n"
            "import inspect\n"
            "for fi in inspect.stack():\n"
            "    fi.frame.f_globals.update({'diagnostic': True})\n"
        ),
        (
            "workers = 1\n"
            "class Safe:\n"
            "    def __init__(self):\n"
            "        pass\n"
            "class Mutating:\n"
            "    def __init__(self):\n"
            "        globals().update({'workers': 4})\n"
            "class D(Safe, Mutating):\n"
            "    def __init__(self):\n"
            "        super().__init__()\n"
            "D()\n"
        ),
        (
            "workers = 1\n"
            "class Base:\n"
            "    def __class_getitem__(cls, item):\n"
            "        globals().update({'workers': 4})\n"
            "class Derived(Base):\n"
            "    def __class_getitem__(cls, item):\n"
            "        return item\n"
            "Derived[int]\n"
        ),
    ],
)
def test_codex_pr332_review_safe_patterns_remain_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-07: import hook indirection gaps
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import builtins\n"
            "_real = __import__\n"
            "def hook(name, *a, **k):\n"
            "    globals().update({'workers': 4})\n"
            "    return _real(name, *a, **k)\n"
            "builtins.__import__ = hook\n"
            "import os\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "class F:\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        globals()['workers'] = 4\n"
            "        return None\n"
            "sys.meta_path.insert(0, F())\n"
            "import json\n"
        ),
    ],
)
def test_security_review_oct07_import_hook_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)



# Codex review follow-up for PR #339: import-hook ordering and execution gaps.
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "import builtins\n"
            "_real = __import__\n"
            "def hook(name, *args, **kwargs):\n"
            "    globals()['workers'] = 4\n"
            "    return _real(name, *args, **kwargs)\n"
            "if True:\n"
            "    builtins.__import__ = hook\n"
            "import os\n"
        ),
        (
            "workers = 1\n"
            "import builtins\n"
            "_real = __import__\n"
            "def hook(name, *args, **kwargs):\n"
            "    globals()['workers'] = 4\n"
            "    return _real(name, *args, **kwargs)\n"
            "builtins.__import__ = hook\n"
            "__import__('os')\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "class F:\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        globals()['workers'] = 4\n"
            "        return None\n"
            "sys.meta_path = [F(), *sys.meta_path]\n"
            "import json\n"
        ),
        (
            "workers = 1\n"
            "import builtins\n"
            "_real = __import__\n"
            "def hook(name, *args, **kwargs):\n"
            "    globals()['workers'] = 4\n"
            "    return _real(name, *args, **kwargs)\n"
            "builtins.__import__ = hook; import os\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "class F:\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        globals()['workers'] = 4\n"
            "        return None\n"
            "sys.meta_path.insert(0, F()); import json\n"
        ),
        (
            "workers = 1\n"
            "import builtins\n"
            "_real = __import__\n"
            "def hook(name, *args, **kwargs):\n"
            "    globals()['workers'] = 4\n"
            "    return _real(name, *args, **kwargs)\n"
            "builtins.__import__ = hook\n"
            "class Holder:\n"
            "    import os\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "class F:\n"
            "    def find_spec(self, fullname, path, target=None):\n"
            "        globals()['workers'] = 4\n"
            "        return None\n"
            "sys.meta_path.insert(0, F())\n"
            "class Holder:\n"
            "    import json\n"
        ),
    ],
)
def test_codex_pr339_import_hook_gaps_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr339_noop_dunder_import_assignment_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "import builtins\n"
        "builtins.__import__ = builtins.__import__\n"
        "import os\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-08: module-level super() dispatch gaps
@pytest.mark.parametrize(
    "config_content",
    [
        (
            "workers = 1\n"
            "class Base:\n"
            "    @staticmethod\n"
            "    def m():\n"
            "        globals()['workers'] = 4\n"
            "class Child(Base):\n"
            "    pass\n"
            "super(Child, Child).m()\n"
        ),
        (
            "workers = 1\n"
            "class Base:\n"
            "    @classmethod\n"
            "    def m(cls):\n"
            "        globals()['workers'] = 4\n"
            "class Child(Base):\n"
            "    pass\n"
            "super(Child, Child).m()\n"
        ),
        (
            "workers = 1\n"
            "class Base:\n"
            "    @staticmethod\n"
            "    def m():\n"
            "        globals()['workers'] = 4\n"
            "class Child(Base):\n"
            "    pass\n"
            "getattr(super(Child, Child), 'm')()\n"
        ),
        (
            "workers = 1\n"
            "from functools import partial\n"
            "class Base:\n"
            "    @staticmethod\n"
            "    def m():\n"
            "        globals()['workers'] = 4\n"
            "class Child(Base):\n"
            "    pass\n"
            "partial(super(Child, Child).m)()\n"
        ),
    ],
)
def test_security_review_oct08_super_dispatch_gaps_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #342: super() dispatch, eager wrappers, and descriptor lookup
_SUPER_MUTATING_HOOK_CONFIG = (
    "workers = 1\n"
    "class Base:\n"
    "    @staticmethod\n"
    "    def m():\n"
    "        globals()['workers'] = 4\n"
    "class Child(Base):\n"
    "    pass\n"
)


@pytest.mark.parametrize(
    "dispatch",
    [
        "super(Child, Child).m()",
        "getattr(super(Child, Child), 'm')()",
        "partial(super(Child, Child).m)()",
        "partial(getattr(super(Child, Child), 'm'))()",
        "operator.call(super(Child, Child).m)",
        "operator.call(getattr(super(Child, Child), 'm'))",
        "def run():\n    partial(super(Child, Child).m)()\nrun()",
        "def run():\n    operator.call(super(Child, Child).m)\nrun()",
    ],
)
def test_codex_pr342_eager_super_callbacks_are_dynamic(tmp_path, dispatch):
    contents = (
        "from functools import partial\n"
        "import operator\n"
        + _SUPER_MUTATING_HOOK_CONFIG
        + dispatch
        + "\n"
    )
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(contents, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "super(B, C).m()",
        "partial(super(B, C).m)()",
        "operator.call(super(B, C).m)",
    ],
)
def test_codex_pr342_super_resolves_second_argument_mro(tmp_path, dispatch):
    contents = (
        "from functools import partial\n"
        "import operator\n"
        "workers = 1\n"
        "class A:\n"
        "    @staticmethod\n"
        "    def m():\n"
        "        globals()['workers'] = 4\n"
        "class B:\n"
        "    pass\n"
        "class C(B, A):\n"
        "    pass\n"
        + dispatch
        + "\n"
    )
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(contents, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "super(Child, Child).m",
        "super(Child, Child).m()",
        "getattr(super(Child, Child), 'm')",
        "partial(getattr(super(Child, Child), 'm'))()",
    ],
)
def test_codex_pr342_super_descriptor_get_is_dynamic(tmp_path, dispatch):
    contents = (
        "from functools import partial\n"
        "workers = 1\n"
        "class Descriptor:\n"
        "    def __get__(self, instance, owner):\n"
        "        globals()['workers'] = 4\n"
        "        return lambda: None\n"
        "class Base:\n"
        "    m = Descriptor()\n"
        "class Child(Base):\n"
        "    pass\n"
        + dispatch
        + "\n"
    )
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(contents, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr342_super_instance_property_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    @property\n"
        "    def m(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Base):\n"
        "    pass\n"
        "super(Child, Child()).m\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr342_shadowed_super_is_not_builtin(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _SUPER_MUTATING_HOOK_CONFIG
        + "class Safe:\n"
        "    def m(self):\n"
        "        pass\n"
        "def super(*args):\n"
        "    return Safe()\n"
        "super(Child, Child).m()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_codex_pr342_super_mro_safe_override_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    @staticmethod\n"
        "    def m():\n"
        "        globals()['workers'] = 4\n"
        "class Middle(Base):\n"
        "    @staticmethod\n"
        "    def m():\n"
        "        pass\n"
        "class Child(Middle):\n"
        "    pass\n"
        "super(Child, Child).m()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-09: indirect inherited-constructor instantiation gaps
_INHERITED_MUTATING_INIT_CONFIG = (
    "workers = 1\n"
    "class Base:\n"
    "    def __init__(self):\n"
    "        globals()['workers'] = 4\n"
    "class Child(Base):\n"
    "    pass\n"
)


@pytest.mark.parametrize(
    "dispatch",
    [
        "from functools import partial\npartial(Child)()",
        "import operator\noperator.call(Child)",
        "(lambda: Child())()",
        "[Child][0]()",
        "type('', (Child,), {})()",
    ],
)
def test_security_review_oct09_indirect_constructor_gaps_are_dynamic(
    tmp_path,
    dispatch,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #345: invoked lambda scope and inherited-constructor regressions.
@pytest.mark.parametrize(
    "dispatch",
    [
        "(lambda: (Child(), None)[1])()",
        "(lambda: [None, Child()][0])()",
        "(lambda: {'done': Child()}['done'])()",
    ],
)
def test_codex_pr345_nested_lambda_constructor_is_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("(lambda Child: Child())(Safe)", False),
        ("(lambda Child: Child())(Child)", True),
        ("(lambda *, Child: Child())(Child=Safe)", False),
        ("(lambda *, Child: Child())(Child=Child)", True),
    ],
)
def test_codex_pr345_lambda_shadowing_resolves_actual_argument(
    tmp_path, dispatch, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Safe:\n    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )


@pytest.mark.parametrize(
    "dispatch",
    [
        "[Child][0](1)",
        "(Child,)[0](1, named=True)",
    ],
)
def test_codex_pr345_literal_constructor_with_arguments_is_dynamic(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self, *args, **kwargs):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Base):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr345_dynamic_type_calls_init_subclass(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __init_subclass__(cls, **kwargs):\n"
        "        globals()['workers'] = 4\n"
        "type('Dynamic', (Base,), {})()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "import operator\noperator.call(Child)",
        "from functools import partial\npartial(Child)()",
        "Child()",
    ],
)
def test_codex_pr345_inherited_mutating_new_is_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __new__(cls, *args, **kwargs):\n"
        "        globals()['workers'] = 4\n"
        "        return object.__new__(cls)\n"
        "class Child(Base):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr345_overridden_inherited_new_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __new__(cls):\n"
        "        globals()['workers'] = 4\n"
        "        return object.__new__(cls)\n"
        "class Child(Base):\n"
        "    def __new__(cls):\n"
        "        return object.__new__(cls)\n"
        "Child()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("import operator\noperator.call(lambda Child: Child(), Safe)", False),
        ("import operator\noperator.call(lambda Child: Child(), Child)", True),
        ("from functools import partial\npartial(lambda Child: Child(), Safe)()", False),
        ("from functools import partial\npartial(lambda Child: Child(), Child)()", True),
    ],
)
def test_codex_pr345_indirect_lambda_class_argument_binding(
    tmp_path, dispatch, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Safe:\n    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )


@pytest.mark.parametrize(
    "dispatch",
    [
        "type('Dynamic', (Base,), {})",
        "type('Dynamic', (Base,), {'__init__': lambda self: None})()",
    ],
)
def test_codex_pr345_init_subclass_runs_during_class_creation(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __init_subclass__(cls, **kwargs):\n"
        "        globals()['workers'] = 4\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr345_dynamic_type_safe_init_ignores_inherited_init(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "type('Dynamic', (Child,), {'__init__': lambda self: None})()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, False
    )


# Security review 2026-10-10: class __call__ resolver and container subscript gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "getattr(Child, '__call__')()",
        "import operator\noperator.attrgetter('__call__')(Child)()",
        "object.__getattribute__(Child, '__call__')()",
        "(Child.__mro__[0])()",
        "from collections import deque\ndeque([Child], maxlen=1)[0]()",
        "import types\ntypes.new_class('X', (Child,))()",
    ],
)
def test_security_review_oct10_class_call_resolver_gaps_are_dynamic(
    tmp_path,
    dispatch,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #348: class-call semantics, MRO indexing, and bounded deque checks.
@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("Child.__mro__[1]()", True),
        ("Child.__mro__[-2]()", True),
        ("Child.__mro__[0]()", False),
    ],
)
def test_codex_pr348_mro_index_resolves_actual_class(tmp_path, dispatch, is_dynamic):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Base):\n"
        "    def __init__(self):\n"
        "        pass\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )


@pytest.mark.parametrize(
    "dispatch",
    [
        "getattr(Child, '__call__')(None)",
        "import operator\noperator.attrgetter('__call__')(Child)(None)",
        "object.__getattribute__(Child, '__call__')(None)",
        "Child.__call__(None)",
    ],
)
def test_codex_pr348_class_defined_call_mutates_workers(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Child:\n"
        "    def __call__(self, *args):\n"
        "        globals()['workers'] = 4\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "getattr(Child, '__call__')(None)",
        "import operator\noperator.attrgetter('__call__')(Child)(None)",
        "object.__getattribute__(Child, '__call__')(None)",
    ],
)
def test_codex_pr348_safe_class_call_does_not_invoke_mutating_init(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Base:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Base):\n"
        "    def __init__(self):\n"
        "        pass\n"
        "    def __call__(self):\n"
        "        return None\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("from collections import deque\ndeque([Safe, Child], maxlen=1)[0]()", True),
        ("from collections import deque\ndeque([Child, Safe], maxlen=1)[0]()", False),
        ("from collections import deque as q\nq([Safe, Child], maxlen=1)[0]()", True),
        ("import collections as c\nc.deque([Safe, Child], maxlen=1)[0]()", True),
        ("deque([Child], maxlen=1)[0]()", False),
        (
            "from collections import deque\n"
            "def deque(items, maxlen=None): return [lambda: None]\n"
            "deque([Child], maxlen=1)[0]()",
            False,
        ),
    ],
)
def test_codex_pr348_deque_requires_import_and_honors_maxlen(
    tmp_path, dispatch, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Safe:\n    pass\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )


@pytest.mark.parametrize("dispatch", ["types.new_class('X', (Base,))", "types.new_class('X', (Base,))()"])
def test_codex_pr348_new_class_runs_init_subclass_on_creation(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "import types\n"
        "class Base:\n"
        "    def __init_subclass__(cls, **kwargs):\n"
        "        globals()['workers'] = 4\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr348_shadowed_object_getattribute_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Helper:\n"
        "    @staticmethod\n"
        "    def __getattribute__(target, attr):\n"
        "        return lambda: None\n"
        "object = Helper\n"
        "object.__getattribute__(Child, '__call__')()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Security review 2026-10-11: __bases__ and mro() class-resolution gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "Child.__bases__[0]()",
        "Child.mro()[1]()",
        "list(Child.mro())[1]()",
        "getattr(Child.__bases__[0], '__call__')()",
        "Child.__bases__[0].__call__()",
        "object.__getattribute__(Child.__bases__[0], '__call__')()",
        "import operator\noperator.attrgetter('__call__')(Child.__bases__[0])()",
    ],
)
def test_security_review_oct11_bases_and_mro_gaps_are_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("Child.mro()[0]()", True),
        (
            "class SafeChild(Child):\n"
            "    def __init__(self):\n"
            "        pass\n"
            "SafeChild.mro()[0]()",
            False,
        ),
    ],
)
def test_security_review_oct11_mro_index_respects_constructor(
    tmp_path, dispatch, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )



@pytest.mark.parametrize(
    "dispatch",
    [
        "Safe.mro()[0]()",
        "list(Safe.mro())[0]()",
        "tuple(Safe.mro())[0]()",
        "getattr(Safe.mro()[0], '__call__')()",
    ],
)
def test_codex_pr355_overridden_mro_cannot_hide_mutating_constructor(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Safe:\n"
        "    @classmethod\n"
        "    def mro(cls):\n"
        "        return [Risky]\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "Child.__bases__[0]()",
        "Child.mro()[1]()",
        "tuple(Child.mro())[1]()",
        "getattr(Child.__bases__[0], '__call__')()",
        "Child.__bases__[0].__call__()",
    ],
)
def test_codex_pr355_captured_base_survives_name_rebinding(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        "class Safe:\n"
        "    pass\n"
        "Risky = Safe\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_codex_pr355_tuple_wrapped_mro_constructor_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + "tuple(Child.mro())[1]()\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    ("dispatch", "is_dynamic"),
    [
        ("Child.mro()[-1]()", False),
        ("Child.mro()[-2]()", True),
        ("tuple(Child.mro())[-1]()", False),
        ("tuple(Child.mro())[-2]()", True),
    ],
)
def test_codex_pr355_local_object_distinct_from_builtin_root(
    tmp_path, dispatch, is_dynamic
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class object:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(object):\n"
        "    pass\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (
        1, is_dynamic
    )


# Security review 2026-10-12: __mro__ sequence wrappers and __subclasses__ gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "tuple(Child.__mro__)[1]()",
        "list(Child.__mro__)[1]()",
        "[c for c in Child.__mro__][1]()",
        "Risky.__subclasses__()[0]()",
    ],
)
def test_security_review_oct12_mro_wrappers_and_subclasses_are_dynamic(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "case",
    [
        (
            "class Base:\n"
            "    @classmethod\n"
            "    def __subclasses__(cls):\n"
            "        return [Risky]\n"
            "class Child(Base):\n"
            "    pass\n"
            "Base.__subclasses__()[0]()\n"
        ),
        (
            "Alias = Risky\n"
            "class Child(Alias):\n"
            "    pass\n"
            "Risky.__subclasses__()[0]()\n"
        ),
        (
            "class Child(Risky):\n"
            "    pass\n"
            "class Safe:\n"
            "    pass\n"
            "Risky = Safe\n"
            "[c for c in Child.__mro__][1]()\n"
        ),
        (
            "class Base:\n"
            "    pass\n"
            "class Child(Risky, Base):\n"
            "    pass\n"
            "class Safe:\n"
            "    pass\n"
            "Child = Safe\n"
            "Base.__subclasses__()[0]()\n"
        ),
        (
            "if True:\n"
            "    class Child(Risky):\n"
            "        pass\n"
            "Risky.__subclasses__()[0]()\n"
        ),
        (
            "class Child(Risky):\n"
            "    pass\n"
            "[c for c in Child.__mro__ if True][1]()\n"
        ),
        (
            "class Meta(type):\n"
            "    def __getattribute__(cls, name):\n"
            "        if name == '__mro__':\n"
            "            return (cls, Risky, object)\n"
            "        return super().__getattribute__(name)\n"
            "class Safe(metaclass=Meta):\n"
            "    pass\n"
            "tuple(Safe.__mro__)[1]()\n"
        ),
    ],
)
def test_codex_pr360_dynamic_class_introspection_fails_closed(tmp_path, case):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        + case,
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-14: set/frozenset __mro__ wrappers around list/tuple gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "list(set(Child.__mro__))[1]()",
        "list(frozenset(Child.__mro__))[1]()",
        "tuple(set(Child.__mro__))[1]()",
    ],
)
def test_security_review_oct14_set_frozenset_mro_wrappers_are_dynamic(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "list(set(Child.mro()))[1]()",
        "list(frozenset(Child.mro()))[1]()",
        "tuple(set(Child.mro()))[1]()",
        "list(tuple(Child.mro()))[1]()",
    ],
)
def test_security_review_oct14_nested_mro_method_wrappers_are_dynamic(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-16: builtin reordering helpers and non-constant MRO slices
@pytest.mark.parametrize(
    "dispatch",
    [
        "list(filter(lambda c: True, Child.__mro__))[1]()",
        "list(map(lambda c: c, Child.__mro__))[1]()",
        "import itertools\nlist(itertools.chain(Child.__mro__))[1]()",
        "sorted(Child.__mro__, key=lambda c: 0)[1]()",
        "list(zip(Child.__mro__, Child.__mro__))[1][0]()",
        "list(enumerate(Child.__mro__))[1][1]()",
        "tuple(iter(Child.__mro__))[1]()",
        "from collections import deque\nlist(deque(Child.__mro__))[1]()",
        "Child.__mro__[1:2][0]()",
        "(Child.__mro__ + ())[1]()",
    ],
)
def test_security_review_oct16_mro_reordering_wrappers_are_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-17: alternate MRO element selection and constructor dispatch
@pytest.mark.parametrize(
    "dispatch",
    [
        "getattr(Child, '__mro__')[1]()",
        "import operator\noperator.getitem(Child.__mro__, 1)()",
        "from operator import itemgetter\nitemgetter(1)(Child.__mro__)()",
        "import copy\ncopy.copy(Child.__mro__)[1]()",
        "import heapq\nheapq.nlargest(2, Child.__mro__, key=lambda c: 0)[1]()",
        "Child.__mro__.__getitem__(1)()",
        "type(Child).mro(Child)[1]()",
    ],
)
def test_security_review_oct17_mro_selection_wrappers_are_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-18: remaining MRO constructor dispatch gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "import inspect\ninspect.getmro(Child)[1]()",
        "object.__getattribute__(Child, '__mro__')[1]()",
        "import operator\noperator.methodcaller('__getitem__', 1)(Child.__mro__)()",
        "from operator import attrgetter\nattrgetter('__mro__')(Child)[1]()",
        "getattr(getattr(Child, '__mro__'), '__getitem__')(1)()",
        "(lambda m: m[1])(Child.__mro__)()",
    ],
)
def test_security_review_oct18_mro_dispatch_gaps_are_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Security review 2026-10-19: builtins getattr and unbound type.mro MRO dispatch gaps
@pytest.mark.parametrize(
    "dispatch",
    [
        "import builtins\nbuiltins.getattr(Child, '__mro__')[1]()",
        "import builtins as b\nb.getattr(Child, '__mro__')[1]()",
        "from builtins import getattr as bg\nbg(Child, '__mro__')[1]()",
        "__import__('builtins').getattr(Child, '__mro__')[1]()",
        "import importlib\nimportlib.import_module('builtins').getattr(Child, '__mro__')[1]()",
        "import sys\nsys.modules['builtins'].getattr(Child, '__mro__')[1]()",
        "type.mro(Child)[1]()",
    ],
)
def test_security_review_oct19_builtins_getattr_and_type_mro_are_dynamic(
    tmp_path, dispatch
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Risky:\n"
        "    def __init__(self):\n"
        "        globals()['workers'] = 4\n"
        "class Child(Risky):\n"
        "    pass\n"
        + dispatch
        + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Codex PR #394: getattr aliases, bound builtins and unbound type.mro
@pytest.mark.parametrize(
    "dispatch",
    [
        "if True:\n    from builtins import getattr as bg\n" +
        "bg(Child, '__mro__')[1]()",
        "try:\n    from builtins import getattr as bg\n" +
        "except ImportError:\n    raise\n" +
        "bg(Child, '__mro__')[1]()",
        "if True:\n    import builtins as b\n" +
        "    bg = b.getattr\n" +
        "bg(Child, '__mro__')[1]()",
    ],
)
def test_codex_pr394_compound_getattr_aliases_are_dynamic(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "dispatch",
    [
        "from builtins import getattr as bg\n" +
        "def bg(cls, attr):\n    return (cls, Safe)\n" +
        "bg(Child, '__mro__')[1]()",
        "from builtins import getattr as bg\n" +
        "class bg:\n" +
        "    def __new__(cls, *_args):\n        return (Child, Safe)\n" +
        "bg(Child, '__mro__')[1]()",
        "class Facade:\n" +
        "    @staticmethod\n" +
        "    def mro(cls):\n        return (cls, Safe)\n" +
        "type = Facade\n" +
        "type.mro(Child)[1]()",
        "class Facade:\n" +
        "    @staticmethod\n" +
        "    def getattr(cls, name):\n        return (cls, Safe)\n" +
        "import builtins as b\n" +
        "b = Facade\n" +
        "bg = b.getattr\n" +
        "bg(Child, '__mro__')[1]()",
        "class Facade:\n" +
        "    @staticmethod\n" +
        "    def getattr(cls, name):\n        return (cls, Safe)\n" +
        "def __import__(name):\n    return Facade\n" +
        "__import__('builtins').getattr(Child, '__mro__')[1]()",
    ],
)
def test_codex_pr394_shadowed_builtins_stay_static(tmp_path, dispatch):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Safe:\n    pass\n"
        + dispatch + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


@pytest.mark.parametrize(
    "source",
    [
        "class Facade:\n" +
        "    @staticmethod\n" +
        "    def mro(cls):\n        return (cls, Safe)\n" +
        "if True:\n    type = Facade\n" +
        "type.mro(Child)[1]()",
        "class Facade:\n" +
        "    @staticmethod\n" +
        "    def getattr(cls, name):\n        return (cls, Safe)\n" +
        "if True:\n" +
        "    def __import__(name):\n        return Facade\n" +
        "__import__('builtins').getattr(Child, '__mro__')[1]()",
    ],
)
def test_codex_pr394_compound_shadowed_builtins_stay_static(tmp_path, source):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        _INHERITED_MUTATING_INIT_CONFIG
        + "class Safe:\n    pass\n"
        + source + "\n",
        encoding="utf-8",
    )
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# R15 AST-recognizer parity: each spelling resolves the same mutator as the
# already-covered literal form instead of being reported as a static config.
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nimport operator\nns = globals()\noperator.setitem(ns, 'workers', 4)\n",
        "workers = 1\nimport operator as op\nns = globals()\nop.setitem(ns, 'workers', 4)\n",
        "workers = 1\nfrom operator import setitem\nns = globals()\nsetitem(ns, 'workers', 4)\n",
        "workers = 1\nclass D(dict): pass\nD.mro()[1].update(globals(), {'workers': 4})\n",
        "workers = 1\nclass D(dict): pass\nD.__bases__[0].update(globals(), {'workers': 4})\n",
        "workers = 1\nclass D(dict): pass\nD.__mro__[1].update(globals(), {'workers': 4})\n",
        "workers = 1\nclass D(dict): pass\nD.__bases__[0].__setitem__(globals(), 'workers', 4)\n",
        "workers = 1\nimport collections\ncollections.ChainMap(globals()).maps[0].update({'workers': 4})\n",
        "workers = 1\nimport collections\ncm = collections.ChainMap({'a': 1}, globals())\ncm.maps[1].update({'workers': 4})\n",
        "workers = 1\nfrom collections import ChainMap as CM\nCM(globals()).maps[0].update({'workers': 4})\n",
        "workers = 1\nfrom collections import ChainMap\nCM = ChainMap\nCM(globals()).maps[0].update({'workers': 4})\n",
        "workers = 1\nimport builtins\nbuiltins.getattr(globals(), 'update')({'workers': 4})\n",
        "workers = 1\nimport builtins as bi\nbi.getattr(globals(), '__setitem__')('workers', 4)\n",
        "workers = 1\nfrom builtins import getattr as fetch\nfetch(globals(), 'update')({'workers': 4})\n",
        "workers = 1\nimport builtins\nbuiltins.getattr(builtins, 'dict').update(globals(), {'workers': 4})\n",
        "workers = 1\nimport builtins\nbuiltins.getattr(dict, 'update')(globals(), {'workers': 4})\n",
        "workers = 1\nimport builtins as b\nb.getattr(dict, 'update')(globals(), {'workers': 4})\n",
        "workers = 1\ntype(globals()).update(globals(), {'workers': 4})\n",
        "workers = 1\nglobals().__class__.update(globals(), {'workers': 4})\n",
        "workers = 1\ndict.__dict__['update'](globals(), {'workers': 4})\n",
    ],
)
def test_r15_resolved_indirect_worker_mutations_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        # The resolved mutator must still target the module namespace.
        "workers = 1\nclass D(dict): pass\nsettings = {}\n" +
        "D.mro()[1].update(settings, {'workers': 4})\n",
        "workers = 1\nclass D(dict): pass\nsettings = {}\n" +
        "D.__bases__[0].__setitem__(settings, 'workers', 4)\n",
        # ``type(globals())`` only reaches the namespace mutator when the
        # namespace itself is passed as the receiver.
        "workers = 1\nsettings = {}\ntype(globals()).update(settings, {'workers': 4})\n",
        # A shadowed collections module is not ChainMap.
        "workers = 1\nclass Helper:\n    @staticmethod\n    def ChainMap(*args):\n" +
        "        class Wrapper:\n            maps = [{} , {}]\n        return Wrapper()\n" +
        "collections = Helper()\n" +
        "collections.ChainMap(globals()).maps[0].update({'workers': 4})\n",
        # A shadowed namespace alias target is not the module namespace.
        "workers = 1\nimport operator\nns = {}\noperator.setitem(ns, 'workers', 4)\n",
    ],
)
def test_r15_resolved_mutator_spellings_stay_static_when_unresolved(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter r15 P2-001: metaclass bases reached through stdlib module aliases,
# direct imports, and ``Base = type`` aliases run mutating hooks at definition.
@pytest.mark.parametrize(
    "config_content",
    [
        "import abc\n" +
        "workers = 1\n" +
        "class Meta(abc.ABCMeta):\n" +
        "    def __new__(mcls, name, bases, ns):\n" +
        "        global workers\n" +
        "        workers = 4\n" +
        "        return super().__new__(mcls, name, bases, ns)\n" +
        "class C(metaclass=Meta):\n" +
        "    pass\n",
        "from abc import ABCMeta\n" +
        "workers = 1\n" +
        "class Meta(ABCMeta):\n" +
        "    def __init__(cls, name, bases, ns):\n" +
        "        global workers\n" +
        "        workers = 4\n" +
        "class C(metaclass=Meta):\n" +
        "    pass\n",
        "import builtins as b\n" +
        "workers = 1\n" +
        "class Meta(b.type):\n" +
        "    def __new__(mcls, name, bases, ns):\n" +
        "        global workers\n" +
        "        workers = 4\n" +
        "        return super().__new__(mcls, name, bases, ns)\n" +
        "class C(metaclass=Meta):\n" +
        "    pass\n",
        "workers = 1\n" +
        "Base = type\n" +
        "class Meta(Base):\n" +
        "    def __new__(mcls, name, bases, ns):\n" +
        "        global workers\n" +
        "        workers = 4\n" +
        "        return super().__new__(mcls, name, bases, ns)\n" +
        "class C(metaclass=Meta):\n" +
        "    pass\n",
        "from enum import EnumMeta\n" +
        "workers = 1\n" +
        "class Meta(EnumMeta):\n" +
        "    def __init__(cls, name, bases, ns, **kw):\n" +
        "        global workers\n" +
        "        workers = 4\n" +
        "        super().__init__(name, bases, ns, **kw)\n" +
        "class C(metaclass=Meta):\n" +
        "    pass\n",
    ],
    ids=[
        "abc-module-attribute",
        "abc-direct-import",
        "builtins-module-alias",
        "type-assignment-alias",
        "enum-direct-import",
    ],
)
def test_r15_metaclass_stdlib_base_spellings_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_metaclass_non_type_base_with_init_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import abc\n"
        "workers = 1\n"
        "class Meta(abc.ABC):\n"
        "    def __init__(cls, name, bases, ns):\n"
        "        global workers\n"
        "        workers = 4\n"
        "class C(metaclass=Meta):\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_explicit_metaclass_without_type_base_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Meta:\n"
        "    def __new__(mcls, name, bases, ns):\n"
        "        return type(name, bases, ns)\n"
        "    def __init__(cls, name, bases, ns):\n"
        "        global workers\n"
        "        workers = 4\n"
        "class C(metaclass=Meta):\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_chainmap_non_name_receiver_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "__import__('collections').ChainMap(globals()).maps[0].update("
        "{'workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Bug Hunter r15 P2-002: dict(generator) drains the generator and executes the
# callbacks; the callback must return a pair for the trigger to be real.
def test_r15_dict_generator_consumer_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "    return ('workers', 4)\n"
        "cbs = [bump]\n"
        "dict(cb() for cb in cbs)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_dict_lazy_iterator_consumer_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def bump(_):\n"
        "    global workers\n"
        "    workers = 4\n"
        "    return ('workers', 4)\n"
        "dict(map(bump, [1]))\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_shadowed_dict_generator_consumer_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def dict(value):\n"
        "    return value\n"
        "def bump():\n"
        "    global workers\n"
        "    workers = 4\n"
        "    return ('workers', 4)\n"
        "cbs = [bump]\n"
        "dict(cb() for cb in cbs)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter r15 P2-003: direct and aliased itertools.starmap imports.
@pytest.mark.parametrize(
    "config_content",
    [
        "from itertools import starmap\n" +
        "workers = 1\n" +
        "def bump(x):\n" +
        "    global workers\n" +
        "    workers = 4\n" +
        "pairs = [(1,)]\n" +
        "list(starmap(bump, pairs))\n",
        "from itertools import starmap as sm\n" +
        "workers = 1\n" +
        "def bump(x):\n" +
        "    global workers\n" +
        "    workers = 4\n" +
        "pairs = [(1,)]\n" +
        "list(sm(bump, pairs))\n",
    ],
    ids=["direct-import", "aliased-import"],
)
def test_r15_itertools_starmap_name_spellings_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_shadowed_itertools_starmap_name_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def starmap(*args):\n"
        "    return []\n"
        "def bump(x):\n"
        "    global workers\n"
        "    workers = 4\n"
        "pairs = [(1,)]\n"
        "list(starmap(bump, pairs))\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter r15 P2-004: functools.partial callbacks and starred map arguments.
@pytest.mark.parametrize(
    "config_content",
    [
        "from multiprocessing.pool import ThreadPool\n" +
        "from functools import partial\n" +
        "workers = 1\n" +
        "def bump(prefix, x):\n" +
        "    global workers\n" +
        "    workers = 4\n" +
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        "from multiprocessing.pool import ThreadPool\n" +
        "workers = 1\n" +
        "def bump(x):\n" +
        "    global workers\n" +
        "    workers = 4\n" +
        "args = (bump, [1, 2])\n" +
        "ThreadPool(2).map(*args)\n",
        "from multiprocessing.pool import ThreadPool\n" +
        "workers = 1\n" +
        "def bump(x):\n"
        "    global workers\n"
        "    workers = 4\n"
        "ThreadPool(2).map(*(bump, [1, 2]))\n",
    ],
    ids=["partial-callback", "unresolved-starred-args", "literal-starred-args"],
)
def test_r15_thread_pool_partial_and_starred_callbacks_are_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_thread_pool_partial_safe_callback_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "ThreadPool(2).map(partial(str, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter r15 P2-005: positional apply_async callback/error_callback slots.
@pytest.mark.parametrize(
    "call",
    [
        "ThreadPool(2).apply_async(lambda: 0, (), {}, bump).get()\n",
        "ThreadPool(2).apply_async(lambda: 0, (), {}, None, bump).get()\n",
    ],
    ids=["positional-callback", "positional-error-callback"],
)
def test_r15_thread_pool_apply_async_positional_callbacks_are_dynamic(
    tmp_path,
    call,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from multiprocessing.pool import ThreadPool\n"
        "workers = 1\n"
        "def bump(_):\n"
        "    global workers\n"
        "    workers = 4\n" + call,
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Bug Hunter r15 P2-006: class constructor reached through a module-level alias.
@pytest.mark.parametrize(
    "alias_statements",
    [
        "Alias = Helper\nAlias()\n",
        "Alias = Helper\nAlias2 = Alias\nAlias2()\n",
    ],
    ids=["direct-alias", "chained-alias"],
)
def test_r15_class_constructor_alias_spellings_are_dynamic(
    tmp_path,
    alias_statements,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Helper:\n"
        "    def __init__(self):\n"
        "        global workers\n"
        "        workers = 4\n" + alias_statements,
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Bug Hunter r15 P3-001: annotated and computed chdir values must not make the
# implicit PWD config disappear before the workers scan runs.
def test_r15_annotated_chdir_keeps_pwd_config_scannable(monkeypatch, tmp_path):
    launch_dir = tmp_path / "launch"
    app_dir = tmp_path / "app"
    launch_dir.mkdir()
    app_dir.mkdir()
    (launch_dir / "gunicorn.conf.py").write_text(
        f"chdir: str = {str(app_dir)!r}\nworkers = 4\n",
        encoding="utf-8",
    )

    _clear_worker_environment(monkeypatch)
    monkeypatch.setenv("PWD", str(launch_dir))
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.chdir(app_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config._detect_worker_settings() == (4, False)
    assert config._ratelimit_storage_error() is not None


def test_r15_computed_chdir_does_not_drop_pwd_config(monkeypatch, tmp_path):
    launch_dir = tmp_path / "launch"
    app_dir = tmp_path / "app"
    launch_dir.mkdir()
    app_dir.mkdir()
    (launch_dir / "gunicorn.conf.py").write_text(
        "import os\n"
        "chdir = os.environ.get('APP_DIR')\n"
        "workers = 4\n",
        encoding="utf-8",
    )

    _clear_worker_environment(monkeypatch)
    monkeypatch.setenv("PWD", str(launch_dir))
    monkeypatch.chdir(app_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    # The computed chdir cannot be verified, so the PWD fallback is scanned but
    # must stay dynamic: that keeps a shared limiter/session backend required.
    assert config._detect_worker_settings() == (4, True)


def test_r15_stale_pwd_static_workers_stays_dynamic(monkeypatch, tmp_path):
    """A stale PWD must not override WEB_CONCURRENCY with a static worker count."""
    stale_dir = tmp_path / "stale"
    app_dir = tmp_path / "app"
    stale_dir.mkdir()
    app_dir.mkdir()
    (stale_dir / "gunicorn.conf.py").write_text("workers = 1\n", encoding="utf-8")

    _clear_worker_environment(monkeypatch)
    monkeypatch.setenv("PWD", str(stale_dir))
    monkeypatch.setenv("WEB_CONCURRENCY", "8")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.chdir(app_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config._detect_worker_settings() == (8, True)
    assert config._ratelimit_storage_error() is not None


# Codex review (PR #395): captured aliases, conditional metaclass aliases,
# unrelated MRO-shaped subscripts, annotation-only chdir, and shadowed getattr.
def test_r15_captured_class_alias_survives_rebinding(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class Helper:\n"
        "    def __init__(self):\n"
        "        global workers\n"
        "        workers = 4\n"
        "Alias = Helper\n"
        "Helper = None\n"
        "Alias()\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_conditional_metaclass_module_rebinding_stays_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import abc\n"
        "workers = 1\n"
        "if False:\n"
        "    abc = None\n"
        "class Meta(abc.ABCMeta):\n"
        "    def __new__(mcls, name, bases, ns):\n"
        "        global workers\n"
        "        workers = 4\n"
        "        return super().__new__(mcls, name, bases, ns)\n"
        "class C(metaclass=Meta):\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_unrelated_subscript_receiver_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "helpers = {0: {}}\n"
        "key = 0\n"
        "helpers[key].update(globals(), {'workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_r15_annotation_only_chdir_keeps_literal_value():
    import ast

    tree = ast.parse("chdir = '/app'\nchdir: str\n")
    assert config._static_gunicorn_chdir(tree) == "/app"


def test_r15_shadowed_getattr_does_not_resolve_builtin_dict(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import builtins\n"
        "workers = 1\n"
        "getattr = lambda *args: {}\n"
        "getattr(builtins, 'dict').update(globals(), {'workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Bug Hunter r15 P3-002: handing the module namespace to an imported helper.
@pytest.mark.parametrize(
    "call",
    [
        "apply_settings(globals())\n",
        "apply_settings(vars())\n",
        "apply_settings(locals())\n",
        "apply_settings(**globals())\n",
        "__import__('settings').apply_settings(globals())\n",
        "import importlib\nimportlib.import_module('settings').apply_settings(globals())\n",
        "import sys\nsys.modules['settings'].apply_settings(globals())\n",
    ],
    ids=[
        "globals", "vars", "locals", "starred-globals",
        "import-builtin", "importlib-module", "sys-modules",
    ],
)
def test_r15_namespace_passed_to_imported_helper_is_dynamic(tmp_path, call):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from settings import apply_settings\n"
        + call,
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_namespace_passed_to_in_file_helper_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def helper(namespace):\n"
        "    return namespace\n"
        "helper(globals())\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


# Codex P2: a definite rebinding replaces the functools.partial alias.
def test_r15_rebound_partial_alias_callback_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "def safe_factory(func, value):\n"
        "    return lambda *args, **kwargs: None\n"
        "partial = safe_factory\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_r15_reimported_partial_alias_callback_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import functools\n"
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "partial = lambda *args, **kwargs: None\n"
        "partial = functools.partial\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


# Post-fix review: partial-restore expressions and conditional restores must
# stay fail-closed dynamic; only a proven local replacement may stay static.
def test_r15_partial_restore_via_getattr_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import functools\n"
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "def safe_factory(func, value):\n"
        "    return lambda *args, **kwargs: None\n"
        "partial = safe_factory\n"
        "partial = getattr(functools, 'partial')\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_partial_restore_via_copy_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import copy\n"
        "import functools\n"
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "partial = copy.copy(functools.partial)\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_conditional_partial_restore_stays_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "import functools\n"
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "def safe_factory(func, value):\n"
        "    return lambda *args, **kwargs: None\n"
        "partial = safe_factory\n"
        "if True:\n"
        "    partial = functools.partial\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_r15_partial_none_rebinding_stays_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from multiprocessing.pool import ThreadPool\n"
        "from functools import partial\n"
        "workers = 1\n"
        "def bump(prefix, value):\n"
        "    global workers\n"
        "    workers = 4\n"
        "partial = None\n"
        "ThreadPool(2).map(partial(bump, 1), [1, 2])\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
