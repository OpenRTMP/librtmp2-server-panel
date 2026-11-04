"""The builder and runtime stages must use the same Python interpreter.

``pip install --only-binary :all: --require-hashes`` runs in the builder and
selects wheels for that interpreter's ABI. Copying ``/install`` into a runtime
stage with a different Python minor ships ``cp3XX`` extensions that the runtime
cannot import, and the hash-pinned set no longer describes the running image.
"""

from pathlib import Path

import re

_DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def _python_tags(text):
    return re.findall(r"^FROM\s+python:([0-9]+\.[0-9]+)-", text, re.MULTILINE)


def test_dockerfile_builder_and_runtime_share_the_python_minor():
    tags = _python_tags(_DOCKERFILE.read_text(encoding="utf-8"))
    assert len(tags) >= 2, "expected a builder and a runtime python stage"
    assert len(set(tags)) == 1, (
        "builder and runtime stages must use the same Python minor: "
        f"found {tags}"
    )
