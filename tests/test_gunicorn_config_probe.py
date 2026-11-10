"""Tests for the Gunicorn configuration probe used by the panel entrypoint."""

import pytest

import gunicorn_config_probe as probe


def _config_provides(path, mode="bind"):
    argv = ["-c", str(path)]
    return probe._probe(mode, argv, [], str(path.parent))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("--bind 127.0.0.1:8000", ["--bind", "127.0.0.1:8000"]),
        ("'--bind=127.0.0.1:8000'", ["--bind=127.0.0.1:8000"]),
        ('"-c" "conf.py"', ["-c", "conf.py"]),
        ("", []),
        (None, []),
    ],
)
def test_split_command_args_uses_shlex_rules(value, expected):
    assert probe.split_command_args(value) == expected


def test_split_command_args_reports_unparsable_env(monkeypatch):
    assert probe.split_command_args("'unbalanced") is None
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "'unbalanced")
    assert probe.main(["probe", "bind"]) == probe.UNKNOWN


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["--bind", "127.0.0.1:8000"], True),
        (["--bind=127.0.0.1:8000"], True),
        (["-b", "127.0.0.1:8000"], True),
        (["-b127.0.0.1:8000"], True),
        (["--workers", "2"], False),
        # A value that spells a bind option still counts: skipping the image
        # default is the safe direction.
        (["--name", "--bind"], True),
        ([], False),
    ],
)
def test_bind_option_supplied(tokens, expected):
    assert probe.bind_option_supplied(tokens) is expected


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["-c", "conf.py"], "conf.py"),
        (["--config", "conf.py"], "conf.py"),
        (["--config=conf.py"], "conf.py"),
        (["--confi=conf.py"], "conf.py"),
        (["-cconf.py"], "conf.py"),
        (["-c=conf.py"], "conf.py"),
        (["-c", "first.py", "-c", "second.py"], "second.py"),
        (["--workers", "2"], None),
    ],
)
def test_config_argument(tokens, expected):
    assert probe.config_argument(tokens) == expected


def test_config_path_precedence_prefers_argv_then_env(tmp_path):
    implicit = tmp_path / "gunicorn.conf.py"
    argv_config = tmp_path / "argv.conf.py"
    env_config = tmp_path / "env.conf.py"

    path, resolvable = probe.resolve_config_path(
        ["-c", str(argv_config)],
        ["-c", str(env_config)],
        str(tmp_path),
    )
    assert (path, resolvable) == (argv_config, True)

    path, resolvable = probe.resolve_config_path(
        [],
        ["--config", str(env_config)],
        str(tmp_path),
    )
    assert (path, resolvable) == (env_config, True)

    path, resolvable = probe.resolve_config_path([], [], str(tmp_path))
    assert (path, resolvable) == (implicit, True)


def test_config_path_python_reference_is_unresolvable(tmp_path):
    path, resolvable = probe.resolve_config_path(
        ["-c", "python:operator_config"],
        [],
        str(tmp_path),
    )
    assert path is None
    assert resolvable is False


def test_explicit_parent_relative_config_path_matches_gunicorn(tmp_path):
    """The probe must honor operator -c paths outside its working directory."""
    working_dir = tmp_path / "working"
    working_dir.mkdir()
    config_file = tmp_path / "operator.conf.py"
    config_file.write_text("bind = '127.0.0.1:9000'\n", encoding="utf-8")

    assert probe._probe(
        "bind", ["-c", "../operator.conf.py"], [], str(working_dir)
    ) == probe.SUPPLIED


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("bind = ['127.0.0.1:8000']\n", probe.SUPPLIED),
        ("bind: list = ['127.0.0.1:8000']\n", probe.SUPPLIED),
        ("bind: list\n", probe.ABSENT),
        ("if True:\n    bind = ['127.0.0.1:8000']\n", probe.SUPPLIED),
        ("for bind in [['127.0.0.1:8000']]:\n    pass\n", probe.SUPPLIED),
        ("with open('x') as bind:\n    pass\n", probe.SUPPLIED),
        ("bind, workers = ['127.0.0.1:8000'], 1\n", probe.SUPPLIED),
        ("(bind := ['127.0.0.1:8000'])\n", probe.SUPPLIED),
        ("bind += ['127.0.0.1:8000']\n", probe.SUPPLIED),
        ("workers = 1\n", probe.ABSENT),
        ("def configure():\n    bind = ['127.0.0.1:8000']\n", probe.ABSENT),
        # An imported binding is still a module global Gunicorn reads. The
        # probe cannot execute the import, so it must not claim ABSENT and let
        # the entrypoint prepend its 0.0.0.0 default over it.
        ("from settings import bind\n", probe.SUPPLIED),
        ("from settings import private_bind as bind\n", probe.SUPPLIED),
        ("from settings import bind as other\n", probe.ABSENT),
        ("from settings import *\n", probe.UNKNOWN),
        ("import settings as bind\n", probe.SUPPLIED),
        # Arbitrary namespace writes may define bind at import time. Returning
        # UNKNOWN keeps the image from overriding a value it cannot inspect.
        ("globals()['bind'] = ['127.0.0.1:8000']\n", probe.UNKNOWN),
        ("vars()['bind'] = ['127.0.0.1:8000']\n", probe.UNKNOWN),
        ("setattr(sys.modules[__name__], 'bind', [])\n", probe.UNKNOWN),
        ("sys.modules[__name__].bind = []\n", probe.UNKNOWN),
        (
            "sys.modules[__name__].bind, workers = [], 1\n",
            probe.UNKNOWN,
        ),
        # The config module's own __dict__ is another alias for its globals.
        (
            "import sys\n"
            "sys.modules[__name__].__dict__['bind'] = ['127.0.0.1:8000']\n",
            probe.UNKNOWN,
        ),
        (
            "import sys\n"
            "sys.modules[__name__].__dict__.update(bind=['127.0.0.1:8000'])\n",
            probe.UNKNOWN,
        ),
        # A definition evaluates its defaults while the module runs, so a
        # dynamic write there reaches globals even though the body is deferred.
        (
            "def configure(bind=globals().update(bind=['127.0.0.1:8000'])):\n"
            "    pass\n",
            probe.UNKNOWN,
        ),
        (
            "if True:\n"
            "    def configure(bind=globals().update(bind=['127.0.0.1:8000'])):\n"
            "        pass\n",
            probe.UNKNOWN,
        ),
        # A class body also runs at import time, but a plain class attribute is
        # not a module binding and a method body is still deferred.
        ("class Settings:\n    globals()['bind'] = ['127.0.0.1:8000']\n", probe.UNKNOWN),
        ("class Settings:\n    bind = ['127.0.0.1:8000']\n", probe.ABSENT),
        (
            "class Settings:\n    (bind := ['127.0.0.1:8000'])\n",
            probe.ABSENT,
        ),
        # A walrus in a function default runs at definition time in module scope.
        (
            "def configure(bind=(bind := ['127.0.0.1:8000'])):\n    pass\n",
            probe.SUPPLIED,
        ),
        (
            "class Settings:\n"
            "    def configure(self):\n"
            "        globals()['bind'] = ['127.0.0.1:8000']\n",
            probe.ABSENT,
        ),
        # A later explicit assignment is still proof even after a dynamic write.
        (
            "globals()['workers'] = 1\nbind = ['127.0.0.1:8000']\n",
            probe.SUPPLIED,
        ),
        # A dynamic write inside a function that the module never calls does
        # not run at import time; the probe must still see a plain ABSENT.
        ("def configure():\n    globals()['bind'] = []\n", probe.ABSENT),
        # A called helper runs at import time. If it can rebind the setting,
        # the probe must not claim ABSENT and let the image override it.
        (
            "def configure():\n"
            "    global bind\n"
            "    bind = ['127.0.0.1:9000']\n"
            "configure()\n",
            probe.UNKNOWN,
        ),
        (
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "def wrapper():\n"
            "    configure()\n"
            "wrapper()\n",
            probe.UNKNOWN,
        ),
        (
            "def deco(fn):\n"
            "    global bind\n"
            "    bind = []\n"
            "    return fn\n"
            "@deco\n"
            "def handler():\n"
            "    pass\n",
            probe.UNKNOWN,
        ),
        (
            "class Configure:\n"
            "    def __init__(self):\n"
            "        global bind\n"
            "        bind = []\n"
            "Configure()\n",
            probe.UNKNOWN,
        ),
        (
            "class Ctx:\n"
            "    def __enter__(self):\n"
            "        global bind\n"
            "        bind = []\n"
            "    def __exit__(self, *args):\n"
            "        pass\n"
            "with Ctx():\n"
            "    pass\n",
            probe.UNKNOWN,
        ),
        # A local-only assignment stays in the helper's namespace, and an
        # unrelated called helper cannot write the setting: both stay ABSENT.
        (
            "def configure():\n"
            "    bind = ['127.0.0.1:9000']\n"
            "configure()\n",
            probe.ABSENT,
        ),
        (
            "def helper():\n"
            "    return 1\n"
            "helper()\n"
            "workers = 1\n",
            probe.ABSENT,
        ),
        # A read-only namespace lookup does not bind the setting.
        (
            "value = globals().get('workers')\n",
            probe.ABSENT,
        ),
        # Definitions nested in an if/try block still run at import time.
        (
            "if True:\n"
            "    def deco(fn):\n"
            "        global bind\n"
            "        bind = []\n"
            "        return fn\n"
            "    @deco\n"
            "    def handler():\n"
            "        pass\n",
            probe.UNKNOWN,
        ),
        (
            "if True:\n"
            "    class Base:\n"
            "        def __init_subclass__(cls):\n"
            "            global bind\n"
            "            bind = []\n"
            "    class Child(Base):\n"
            "        pass\n",
            probe.UNKNOWN,
        ),
        # Aliases, partial wrappers and instance method calls can reach a
        # writer without spelling its name at the call site.
        (
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "f = configure\n"
            "f()\n",
            probe.UNKNOWN,
        ),
        (
            "from functools import partial\n"
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "partial(configure)()\n",
            probe.UNKNOWN,
        ),
        # An alias called inside a wrapper must still reach the writer.
        (
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "f = configure\n"
            "def wrapper():\n"
            "    f()\n"
            "wrapper()\n",
            probe.UNKNOWN,
        ),
        (
            "from functools import partial\n"
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "def wrapper():\n"
            "    partial(configure)()\n"
            "wrapper()\n",
            probe.UNKNOWN,
        ),
        (
            "class Configure:\n"
            "    def apply(self):\n"
            "        global bind\n"
            "        bind = []\n"
            "c = Configure()\n"
            "def wrapper():\n"
            "    c.apply()\n"
            "wrapper()\n",
            probe.UNKNOWN,
        ),
        # Constructing a partial is not invoking it; an unused partial leaves
        # the helper non-writing.
        (
            "from functools import partial\n"
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "p = partial(configure)\n"
            "def wrapper():\n"
            "    p\n"
            "wrapper()\n",
            probe.ABSENT,
        ),
        (
            "class Configure:\n"
            "    def apply(self):\n"
            "        global bind\n"
            "        bind = []\n"
            "Configure().apply()\n",
            probe.UNKNOWN,
        ),
        # A later redefinition that writes the setting must win over an
        # earlier read-only definition with the same name.
        (
            "def configure():\n"
            "    pass\n"
            "def configure():\n"
            "    global bind\n"
            "    bind = []\n"
            "configure()\n",
            probe.UNKNOWN,
        ),
        # Other binding forms in a called helper with a global declaration.
        (
            "def configure():\n"
            "    global bind\n"
            "    (bind := [])\n"
            "configure()\n",
            probe.UNKNOWN,
        ),
        (
            "def configure():\n"
            "    global bind\n"
            "    import os as bind\n"
            "configure()\n",
            probe.UNKNOWN,
        ),
        (
            "def configure(value):\n"
            "    global bind\n"
            "    match value:\n"
            "        case [bind]:\n"
            "            pass\n"
            "configure([1])\n",
            probe.UNKNOWN,
        ),
        # Positional __dict__.update arguments may contain the key.
        (
            "import sys\n"
            "def configure():\n"
            "    sys.modules[__name__].__dict__.update({'bind': []})\n"
            "configure()\n",
            probe.UNKNOWN,
        ),
        # Type-bound namespace stores match the worker scanner hook gate.
        ("dict.__setitem__(globals(), 'bind', [])\n", probe.UNKNOWN),
        (
            "import operator\n"
            "operator.setitem(globals(), 'bind', [])\n",
            probe.UNKNOWN,
        ),
        (
            "import sys\n"
            "object.__setattr__(sys.modules[__name__], 'bind', [])\n",
            probe.UNKNOWN,
        ),
        (
            "getattr(dict, '__setitem__')(globals(), 'bind', [])\n",
            probe.UNKNOWN,
        ),
        (
            "import builtins\n"
            "getattr(builtins.dict, '__setitem__')(globals(), 'bind', [])\n",
            probe.UNKNOWN,
        ),
        (
            "import operator\n"
            "operator.call(operator.setitem, globals(), 'bind', [])\n",
            probe.UNKNOWN,
        ),
        (
            "import builtins\n"
            "builtins.dict.update(globals(), {'bind': []})\n",
            probe.UNKNOWN,
        ),
        (
            "import builtins\n"
            "getattr(builtins.dict, 'update')(globals(), {'bind': []})\n",
            probe.UNKNOWN,
        ),
        (
            "import operator\n"
            "operator.call(getattr(__import__('builtins').dict, 'update'), globals(), {'bind': []})\n",
            probe.UNKNOWN,
        ),
        (
            "import builtins\n"
            "builtins.dict.update(globals(), {'workers': 1})\n",
            probe.ABSENT,
        ),
        (
            "import operator\n"
            "operator.methodcaller('__setitem__', 'bind', [])(globals())\n",
            probe.UNKNOWN,
        ),
        (
            "from functools import reduce\n"
            "reduce(lambda g, _: dict.__setitem__(g, 'bind', []), [None], globals())\n",
            probe.UNKNOWN,
        ),
        # A walrus inside a lambda or nested function binds that local scope,
        # not the module, so it must not suppress the image default bind.
        ("helper = lambda: (bind := ['127.0.0.1:9000'])\n", probe.ABSENT),
        (
            "if True:\n    def helper():\n        (bind := ['127.0.0.1:9000'])\n",
            probe.ABSENT,
        ),
        (
            "if True:\n    def helper():\n        globals()['bind'] = []\n",
            probe.ABSENT,
        ),
    ],
)
def test_config_provides_setting_reads_module_assignments(tmp_path, source, expected):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(source, encoding="utf-8")
    assert _config_provides(config_file) == expected


def test_dynamic_write_does_not_hide_a_later_explicit_wsgi_app_assignment(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "globals().update({'workers': 1})\nwsgi_app = 'custom:app'\n",
        encoding="utf-8",
    )
    assert _config_provides(config_file, "wsgi-app") == probe.SUPPLIED


def test_transitive_alias_writer_marks_wsgi_app_unknown(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "def configure():\n"
        "    global wsgi_app\n"
        "    wsgi_app = 'wrapper:app'\n"
        "f = configure\n"
        "def wrapper():\n"
        "    f()\n"
        "wrapper()\n",
        encoding="utf-8",
    )
    assert _config_provides(config_file, "wsgi-app") == probe.UNKNOWN


def test_wildcard_import_leaves_the_wsgi_app_unknown(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text("from base_config import *\n", encoding="utf-8")
    assert _config_provides(config_file, "wsgi-app") == probe.UNKNOWN


def test_config_provides_setting_reports_unreadable_and_unparsable_config(tmp_path):
    missing = tmp_path / "missing.conf.py"
    assert _config_provides(missing) == probe.ABSENT

    broken = tmp_path / "broken.conf.py"
    broken.write_text("bind = [\n", encoding="utf-8")
    assert _config_provides(broken) == probe.UNKNOWN


def test_wsgi_app_detection(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text('wsgi_app = "app:app"\n', encoding="utf-8")
    assert _config_provides(config_file, "wsgi-app") == probe.SUPPLIED
    assert _config_provides(config_file, "bind") == probe.ABSENT


def test_main_reads_env_args_and_implicit_config(monkeypatch, tmp_path):
    (tmp_path / "gunicorn.conf.py").write_text(
        'bind = ["127.0.0.1:18081"]\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    monkeypatch.setenv("GUNICORN_CMD_ARGS", "")
    assert probe.main(["probe", "bind"]) == probe.SUPPLIED

    monkeypatch.setenv("GUNICORN_CMD_ARGS", "'--bind=127.0.0.1:18082'")
    assert probe.main(["probe", "bind"]) == probe.SUPPLIED


def test_main_without_any_config_or_bind_reports_absent(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "")
    assert probe.main(["probe", "bind"]) == probe.ABSENT


def test_main_env_config_supplies_bind(monkeypatch, tmp_path):
    config_file = tmp_path / "operator.conf.py"
    config_file.write_text("bind: str = '127.0.0.1:18083'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUNICORN_CMD_ARGS", f"'-c' '{config_file}'")

    assert probe.main(["probe", "bind"]) == probe.SUPPLIED


def test_main_python_config_is_uninspectable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "")
    assert probe.main(["probe", "bind", "-c", "python:operator_config"]) == (
        probe.UNKNOWN
    )


def test_unknown_mode_is_uninspectable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "")
    assert probe.main(["probe", "something-else"]) == probe.UNKNOWN


def test_bom_prefixed_config_reports_absent_bind(tmp_path):
    """Gunicorn loads a BOM'd config through importlib; the probe must too."""
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 4\nloglevel = 'info'\n",
        encoding="utf-8-sig",
    )
    assert _config_provides(config_file) == probe.ABSENT


def test_crlf_config_is_still_parsed(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_bytes(b"bind = '0.0.0.0:8000'\r\nworkers = 2\r\n")
    assert _config_provides(config_file) == probe.SUPPLIED


def test_deep_expression_before_bind_reports_unknown(tmp_path):
    """A valid but too-deep expression must not make the probe exit with 1."""
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "x = " + " + ".join(["1"] * 2000) + "\nbind = ['127.0.0.1:8000']\n",
        encoding="utf-8",
    )
    assert _config_provides(config_file) == probe.UNKNOWN
