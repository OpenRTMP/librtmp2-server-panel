import pytest

import config


@pytest.mark.parametrize(
    "trusted_proxy_ips",
    [
        "0.0.0.0/2,64.0.0.0/2,128.0.0.0/2,192.0.0.0/2",
        "::/2,4000::/2,8000::/2,c000::/2",
    ],
)
def test_rejects_collectively_universal_trusted_proxy_networks(trusted_proxy_ips):
    with pytest.raises(SystemExit) as exc:
        config._parse_trusted_proxy_networks(trusted_proxy_ips)
    assert exc.value.code == 1


def test_accepts_non_universal_proxy_network_union():
    networks = config._parse_trusted_proxy_networks(
        "0.0.0.0/2,64.0.0.0/2,128.0.0.0/2"
    )
    assert len(networks) == 3


def test_reads_service_managed_gunicorn_config_outside_project_root(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text("workers = 4\n", encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (4, False)


def test_gunicorn_config_compound_assignment_makes_later_static_unknown(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 4\n"
        "if True:\n"
        "    workers = 9\n"
        "def configure():\n"
        "    workers = 8\n"
        "workers = 1\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (4, True)


def test_gunicorn_config_conditional_workers_assignment_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "bind = '0.0.0.0:8000'\n"
        "if True:\n"
        "    workers = 4\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_gunicorn_config_top_level_workers_literal_is_static(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text("workers = 4\n", encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (4, False)


def test_gunicorn_config_dynamic_final_override_is_unknown(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 4\nworkers = max(1, 2)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (4, True)


def test_gunicorn_config_configure_hook_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def configure(server):\n"
        "    server.cfg.workers = 8\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_gunicorn_config_on_starting_hook_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "def on_starting(server):\n"
        "    server.cfg.workers = 8\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\n[workers] = [8]\n",
        "workers = 1\n(workers := 8)\n",
        "workers = 1\nfor workers in [8]:\n    pass\n",
        "workers = 1\ndef set_workers():\n    global workers\n    workers = 8\nset_workers()\n",
        "workers = 1\nglobals()['workers'] = 8\n",
        "workers = 1\nexec('workers = 8')\n",
        "g = globals()\ng['workers'] = 4\n",
        "globals().update({'workers': 4})\n",
        "workers = 1\nimport sys\nsys.modules[__name__].__dict__.update({'workers': 4})\n",
        "workers = 1\nimport sys\nvars(sys.modules[__name__]).update({'workers': 4})\n",
        "workers = 1\nimport sys\ngetattr(sys.modules[__name__], '__dict__').update({'workers': 4})\n",
        "workers = 1\nmatch 1:\n    case 1:\n        workers = 4\n",
        "m = __import__('sys').modules[__name__].__dict__\nm['workers'] = 4\n",
        "workers = 1\n[globals().__setitem__('workers', 4)]\n",
        "from worker_settings import workers\n",
        "from worker_settings import worker_count as workers\n",
        "from settings import *\n",
        "workers = 1\nimport sys\nobject.__setattr__(sys.modules[__name__], 'workers', 8)\n",
        "workers = 1\n(lambda g: g.__setitem__('workers', 4))(globals())\n",
        "workers = 1\nimport operator\noperator.setitem(globals(), 'workers', 4)\n",
        "workers = 1\ngetattr(globals(), '__setitem__')('workers', 4)\n",
        "workers = 1\nimport operator\n(operator.setitem(globals(), 'workers', 4),)\n",
        "workers = 1\nimport operator as op\nop.setitem(globals(), 'workers', 4)\n",
        "workers = 1\nfrom operator import setitem as put\nput(globals(), 'workers', 4)\n",
        "\n".join(
            [
                "workers = 1",
                "import sys",
                "def _bump():",
                "    sys.modules[__name__].__dict__['workers'] = 8",
                "_bump()",
                "",
            ]
        ),
        "\n".join(
            [
                "workers = 1",
                "import sys",
                "def _bump():",
                "    sys.modules[__name__].workers = 8",
                "_bump()",
                "",
            ]
        ),
        "\n".join(
            [
                "workers = 1",
                "import sys",
                "def _bump():",
                "    sys.modules[__name__].__dict__['workers'] += 7",
                "_bump()",
                "",
            ]
        ),
        "\n".join(
            [
                "workers = 1",
                "import sys",
                "def _bump():",
                "    sys.modules[__name__].__dict__['workers'] = 8",
                "result = _bump()",
                "",
            ]
        ),
        "\n".join(
            [
                "workers = 1",
                "import sys",
                "def _bump():",
                "    sys.modules[__name__].__dict__['workers'] = 8",
                "def _wrapper():",
                "    return _bump()",
                "result = _wrapper()",
                "",
            ]
        ),
    ],
)
def test_gunicorn_config_alternate_workers_assignments_are_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    (tmp_path / "worker_settings.py").write_text(
        "workers = 4\nworker_count = 4\n", encoding="utf-8"
    )
    (tmp_path / "settings.py").write_text("workers = 4\n", encoding="utf-8")
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


def test_gunicorn_config_helper_local_workers_is_not_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "\n".join(
            [
                "workers = 1",
                "def helper():",
                "    workers = len([1])",
                "    return workers",
                "result = helper()",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_gunicorn_config_operator_setitem_on_other_mapping_is_not_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "import operator\n"
        "settings = {}\n"
        "operator.setitem(settings, 'workers', 4)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_gunicorn_config_import_aliased_away_from_workers_is_not_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "from worker_settings import workers as default_workers\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
