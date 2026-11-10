import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which("sh")


@pytest.mark.skipif(
    SH is None or os.name == "nt",
    reason="requires a POSIX shell (the Docker image runtime)",
)
def test_entrypoint_does_not_override_an_operator_bind(tmp_path):
    """The Docker CMD must not put --bind on Gunicorn's CLI.

    Gunicorn applies CLI arguments last, so a bind in CMD overrides both
    GUNICORN_CMD_ARGS and gunicorn.conf.py. The entrypoint probe decides
    whether to add the image default; this test executes the real script with
    a fake gunicorn that records its argv.
    """
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    args_file = tmp_path / "gunicorn-args"
    fake_gunicorn = fake_bin / "gunicorn"
    fake_gunicorn.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_GUNICORN_ARGS\"\n",
        encoding="utf-8",
    )
    fake_gunicorn.chmod(fake_gunicorn.stat().st_mode | stat.S_IXUSR)
    real_python = shutil.which("python3") or shutil.which("python")
    assert real_python is not None
    fake_python = fake_bin / "python3"
    fake_python.write_text(
        f'#!/bin/sh\nexec "{Path(real_python).as_posix()}" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(fake_python.stat().st_mode | stat.S_IXUSR)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import os, sys\n"
        "if sys.argv[1] == 'bind':\n"
        "    sys.exit(int(os.environ.get('PROBE_BIND_STATUS', '1')))\n"
        "if sys.argv[1] == 'wsgi-app':\n"
        "    sys.exit(int(os.environ.get('PROBE_WSGI_STATUS', '1')))\n"
        "sys.exit(2)\n",
        encoding="utf-8",
    )
    # The Windows checkout may have CRLF line endings; the image runs LF. Test
    # the same bytes the image executes, not the checkout's EOL style.
    script = tmp_path / "entrypoint.sh"
    script.write_bytes((ROOT / "entrypoint.sh").read_bytes().replace(b"\r\n", b"\n"))

    base_env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"GUNICORN_CMD_ARGS", "GUNICORN_WORKERS", "WEB_CONCURRENCY"}
    }
    base_env.update(
        {
            "PATH": str(fake_bin) + os.pathsep + base_env.get("PATH", ""),
            "OPENRTMP_CONFIG_PROBE": probe.as_posix(),
            "OPENRTMP_VERSION_FILE": (tmp_path / "missing-version").as_posix(),
            "FAKE_GUNICORN_ARGS": args_file.as_posix(),
        }
    )

    def run(probe_status, wsgi_status=1):
        env = dict(base_env)
        env["PROBE_BIND_STATUS"] = str(probe_status)
        env["PROBE_WSGI_STATUS"] = str(wsgi_status)
        args_file.unlink(missing_ok=True)
        subprocess.run(
            [SH, script.as_posix(), "app:app"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return args_file.read_text(encoding="utf-8").splitlines()

    # Probe says the effective config has no bind: the image default is added.
    default_args = run(probe_status=1)
    assert "--bind" in default_args
    assert "0.0.0.0:8000" in default_args
    assert "app:app" in default_args

    # Probe says a bind is configured: no default --bind may reach gunicorn.
    configured = run(probe_status=0)
    assert "0.0.0.0:8000" not in configured
    assert "--bind" not in configured

    # The image CMD is a default, not an operator choice: when the effective
    # Gunicorn configuration supplies ``wsgi_app``, the positional default must
    # be dropped or Gunicorn serves it instead of the configured app.
    config_app = run(probe_status=1, wsgi_status=0)
    assert "app:app" not in config_app
    assert "--worker-class" in config_app
