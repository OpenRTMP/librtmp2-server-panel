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
