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
    """A direct pin and its hashed lockfile must not drift apart.

    A dependency bot that updates only the compiled file leaves the declared
    pin behind; regenerating per the README then silently downgrades it.
    """
    declared = _pins(ROOT / "requirements.in")
    compiled = _pins(ROOT / "requirements.txt")
    mismatch = {
        name: (version, compiled.get(name))
        for name, version in declared.items()
        if compiled.get(name) != version
    }
    assert mismatch == {}
