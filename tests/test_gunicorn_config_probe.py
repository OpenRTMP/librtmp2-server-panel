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
        ("from settings import *\n", probe.UNKNOWN),
        ("import settings as bind\n", probe.SUPPLIED),
        # Arbitrary namespace writes may define bind at import time. Returning
        # UNKNOWN keeps the image from overriding a value it cannot inspect.
        ("globals()['bind'] = ['127.0.0.1:8000']\n", probe.UNKNOWN),
        ("vars()['bind'] = ['127.0.0.1:8000']\n", probe.UNKNOWN),
        ("setattr(sys.modules[__name__], 'bind', [])\n", probe.UNKNOWN),
        ("sys.modules[__name__].bind = []\n", probe.UNKNOWN),
        # A later explicit assignment is still proof even after a dynamic write.
        (
            "globals()['workers'] = 1\nbind = ['127.0.0.1:8000']\n",
            probe.SUPPLIED,
        ),
        # A dynamic write inside a function that the module never calls does
        # not run at import time; the probe must still see a plain ABSENT.
        ("def configure():\n    globals()['bind'] = []\n", probe.ABSENT),
        # A walrus inside a lambda or nested function binds that local scope,
        # not the module, so it must not suppress the image default bind.
        ("helper = lambda: (bind := ['127.0.0.1:9000'])\n", probe.ABSENT),
        (
            "if True:\n    def helper():\n        (bind := ['127.0.0.1:9000'])\n",
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
