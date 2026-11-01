"""Answer Gunicorn configuration questions for the panel entrypoint.

The panel image injects ``--bind 0.0.0.0:8000`` and ``app:app`` when the
operator does not supply them.  Gunicorn reads its configuration from three
places, in this order:

1. the file named by ``-c``/``--config`` on the command line,
2. the file named by ``-c``/``--config`` in ``GUNICORN_CMD_ARGS`` (split with
   ``shlex.split``, exactly like ``Config.get_cmd_args_from_env``),
3. the implicit ``gunicorn.conf.py`` in the current working directory,

and then applies the environment arguments and finally the command line.
This helper mirrors that precedence so the entrypoint can answer "does the
effective configuration already provide the setting?" without importing or
executing the operator's configuration file.

Usage::

    python gunicorn_config_probe.py <bind|wsgi-app> [gunicorn args...]

Exit codes:

* ``0`` - the effective configuration provides the setting.
* ``1`` - it provably does not.
* ``2`` - it cannot be inspected (a ``python:MODULE`` config, an unreadable or
  unparsable config file, or unparsable ``GUNICORN_CMD_ARGS``).  Callers must
  treat this as "provided": the image never overrides an operator setting it
  could not read.
"""

import ast
import os
import shlex
import sys
from pathlib import Path

DEFAULT_CONFIG_NAME = "gunicorn.conf.py"

SUPPLIED = 0
ABSENT = 1
UNKNOWN = 2

_CONFIG_OPTIONS = ("-c", "--config", "--conf", "--confi")
_BIND_OPTIONS = ("-b", "--bind")
_TRY_STATEMENT_TYPES = (ast.Try,)
if hasattr(ast, "TryStar"):  # pragma: no cover - Python 3.11+
    _TRY_STATEMENT_TYPES = (ast.Try, ast.TryStar)


def split_command_args(value):
    """Split ``GUNICORN_CMD_ARGS`` with Gunicorn's ``shlex.split`` rules."""
    if not value:
        return []
    try:
        return shlex.split(value)
    except ValueError:
        return None


def _option_value(token, following):
    """Return ``(value, consumed_next)`` for one ``-c``/``--config`` token."""
    for name in _CONFIG_OPTIONS:
        if token == name:
            if following is None:
                return None, False
            return following, True
        if token.startswith(name + "="):
            return token[len(name) + 1 :], False
    if token.startswith("-c") and len(token) > 2:
        # argparse gives ``-c=prod.py`` the value ``=prod.py``.
        raw = token[2:]
        return (raw[1:] if raw.startswith("=") else raw), False
    return None, False


def config_argument(tokens):
    """Return the last config file named by one token list, if any."""
    value = None
    index = 0
    while index < len(tokens):
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        found, consumed = _option_value(tokens[index], following)
        if found is not None:
            value = found
            index += 2 if consumed else 1
            continue
        index += 1
    return value


def bind_option_supplied(tokens):
    """Return True when a token list carries a ``--bind``/``-b`` option.

    The scan is deliberately simple: a token that looks like a bind option
    counts even when another option's value happens to spell it, because the
    only consequence is that the image keeps its own default bind out of the
    way (the safe direction).
    """
    for token in tokens:
        if token in _BIND_OPTIONS:
            return True
        if token.startswith("--bind="):
            return True
        if token.startswith("-b") and len(token) > 2 and not token.startswith("--"):
            return True
    return False


def resolve_config_path(argv, env_args, cwd):
    """Return ``(path, resolvable)`` using Gunicorn's config precedence.

    ``resolvable`` is False for a ``python:MODULE`` reference: Gunicorn imports
    that module, and the entrypoint must not execute operator code to answer.
    """
    for tokens in (argv, env_args):
        argument = config_argument(tokens)
        if not argument:
            continue
        if argument.startswith("python:"):
            return None, False
        if argument.startswith("file:"):
            argument = argument[len("file:") :]
        return Path(cwd) / argument, True
    return Path(cwd) / DEFAULT_CONFIG_NAME, True


def _compound_statement_blocks(node):
    """Yield the statement lists of a compound statement's bodies."""
    if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        yield node.body
        yield node.orelse
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        yield node.body
    elif isinstance(node, _TRY_STATEMENT_TYPES):
        yield node.body
        for handler in node.handlers:
            yield handler.body
        yield node.orelse
        yield node.finalbody
    elif isinstance(node, ast.Match):
        for case in node.cases:
            yield case.body


def _iter_module_assignments(statements):
    """Yield module-scope statements without entering function or class bodies."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        for block in _compound_statement_blocks(node):
            yield from _iter_module_assignments(block)


def _assigned_target_names(node):
    """Return the simple names a module-scope statement binds."""
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        # ``bind: str`` only updates __annotations__; Gunicorn reads vars(mod).
        targets = [node.target]
    else:
        return ()
    return tuple(
        target.id for target in targets if isinstance(target, ast.Name)
    )


def config_provides_setting(path, name):
    """Return ``0``/``1``/``2`` for whether ``path`` assigns ``name``."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return UNKNOWN
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return UNKNOWN
    for node in _iter_module_assignments(tree.body):
        if name in _assigned_target_names(node):
            return SUPPLIED
    return ABSENT


def _probe(mode, argv, env_args, cwd):
    """Return the tri-state answer for one entrypoint question."""
    if mode == "bind":
        if bind_option_supplied(argv) or bind_option_supplied(env_args):
            return SUPPLIED
        setting = "bind"
    elif mode == "wsgi-app":
        # Gunicorn servers the first positional argument in preference to
        # ``wsgi_app``; the entrypoint's app-target check covers that spelling.
        setting = "wsgi_app"
    else:
        return UNKNOWN
    path, resolvable = resolve_config_path(argv, env_args, cwd)
    if not resolvable:
        return UNKNOWN
    if not path.is_file():
        return ABSENT
    return config_provides_setting(path, setting)


def main(arguments):
    """Run the probe and return its exit code."""
    if len(arguments) < 2:
        return UNKNOWN
    env_args = split_command_args(os.environ.get("GUNICORN_CMD_ARGS", ""))
    if env_args is None:
        return UNKNOWN
    return _probe(arguments[1], arguments[2:], env_args, os.getcwd())


if __name__ == "__main__":
    sys.exit(main(sys.argv))
