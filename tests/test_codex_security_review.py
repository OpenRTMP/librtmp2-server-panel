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

    assert config._workers_from_gunicorn_config_path(str(config_file)) == 4


def test_gunicorn_config_uses_last_top_level_workers_assignment(tmp_path):
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

    assert config._workers_from_gunicorn_config_path(str(config_file)) == 1


def test_gunicorn_config_dynamic_final_override_is_unknown(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 4\nworkers = max(1, 2)\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == 1
