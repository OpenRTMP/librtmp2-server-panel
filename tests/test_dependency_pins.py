import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([^\s\\]+)")


def _pins(path):
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PIN.match(line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def test_compiled_requirements_match_the_declared_direct_pins():
    """A direct pin and its hashed lockfiles must not drift apart.

    A dependency bot that updates only a compiled file leaves the declared pin
    behind; regenerating per the README then silently downgrades it. Runtime
    pins are checked against both locks, development pins against the
    development lock.
    """
    checks = [
        ("requirements.in", "requirements.txt"),
        ("requirements.in", "requirements-dev.txt"),
        ("requirements-dev.in", "requirements-dev.txt"),
    ]
    for source, lockfile in checks:
        declared = _pins(ROOT / source)
        compiled = _pins(ROOT / lockfile)
        mismatch = {
            name: (version, compiled.get(name))
            for name, version in declared.items()
            if compiled.get(name) != version
        }
        assert mismatch == {}, f"{source} vs {lockfile}"
