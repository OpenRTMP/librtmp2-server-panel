import pytest

import config


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nnamespace = globals()\n",
        (
            "workers = 1\n"
            "import sys\n"
            "module_dict = sys.modules[__name__].__dict__\n"
        ),
    ],
)
def test_gunicorn_namespace_alias_binding_is_not_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_gunicorn_namespace_merge_with_dict_unpack_is_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "namespace: dict = globals()\n"
        "namespace |= {**{'workers': 4}}\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nglobals().__ior__({'workers': 4})\n",
        (
            "workers = 1\n"
            "namespace = globals()\n"
            "namespace.__ior__({'workers': 4})\n"
        ),
        (
            "workers = 1\n"
            "import sys\n"
            "sys.modules[__name__].__dict__.__ior__({'workers': 4})\n"
        ),
    ],
)
def test_gunicorn_namespace_explicit_ior_is_dynamic(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)
