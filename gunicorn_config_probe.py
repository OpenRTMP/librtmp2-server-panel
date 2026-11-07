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
# Names whose call can write an arbitrary module global. The probe must not
# claim the setting is absent after one of these: the entrypoint only skips its
# default bind when the answer is not ABSENT, so a false UNKNOWN is safe while a
# false ABSENT would override the operator's bind.
_DYNAMIC_NAMESPACE_CALLS = frozenset(
    {"eval", "exec", "globals", "locals", "setattr", "vars"}
)


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
            # The definition itself runs at module scope: its decorators,
            # defaults and class body can write globals. The deferred function
            # body cannot, so it is not entered.
            yield node
            continue
        yield node
        for block in _compound_statement_blocks(node):
            yield from _iter_module_assignments(block)


def _target_names(target) -> list[str]:
    """Return every simple name bound by one assignment target."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [
            name
            for element in target.elts
            for name in _target_names(element)
        ]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _iter_module_scope_nodes(node):
    """Yield expression nodes evaluated in the enclosing module scope.

    ``ast.walk`` would descend into a lambda body or a nested ``def`` inside a
    compound statement; a walrus there binds the nested scope, not the module.
    Decorators, defaults, bases and class keywords still run while the
    definition executes, so they are visited.
    """
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        children = [
            *node.args.defaults,
            *(default for default in node.args.kw_defaults if default is not None),
        ]
        if not isinstance(node, ast.Lambda):
            children = [*node.decorator_list, *children]
        for child in children:
            yield from _iter_module_scope_nodes(child)
        return
    if isinstance(node, ast.ClassDef):
        for child in [*node.decorator_list, *node.bases, *node.keywords]:
            yield from _iter_module_scope_nodes(child)
        # A class body runs while the class definition executes, so a
        # ``globals()`` write there reaches the module namespace. Plain
        # class-body assignments stay class attributes; only the dynamic-write
        # scan sees them, never ``_assigned_target_names``.
        for statement in node.body:
            yield from _iter_module_scope_nodes(statement)
        return
    for child in ast.iter_child_nodes(node):
        yield from _iter_module_scope_nodes(child)


def _iter_definition_header_nodes(node):
    """Yield expressions a ``def``/``class`` evaluates in the enclosing scope."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        children = [
            *getattr(node, "decorator_list", ()),
            *node.args.defaults,
            *(default for default in node.args.kw_defaults if default is not None),
        ]
    elif isinstance(node, ast.ClassDef):
        children = [*node.decorator_list, *node.bases, *node.keywords]
    else:
        return
    for child in children:
        yield from _iter_module_scope_nodes(child)


def _assigned_target_names(node):
    """Return the simple names a module-scope statement binds.

    Besides plain assignments this covers the other module-scope binding forms
    Gunicorn sees in ``vars(module)``: loop targets, context-manager targets,
    augmented assignments and walrus expressions.
    """
    targets = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        # ``bind: str`` only updates __annotations__; Gunicorn reads vars(mod).
        targets = [node.target]
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        targets = [node.target]
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        targets = [
            item.optional_vars
            for item in node.items
            if item.optional_vars is not None
        ]
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
    names = [name for target in targets for name in _target_names(target)]
    # A walrus can bind the module name inside an otherwise unrelated
    # expression; it is rare but Gunicorn still reads the resulting global.
    # Only expressions the definition evaluates in the enclosing scope count:
    # a class body or function body has its own namespace.
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        scope_nodes = _iter_definition_header_nodes(node)
    else:
        scope_nodes = _iter_module_scope_nodes(node)
    names.extend(
        child.target.id
        for child in scope_nodes
        if isinstance(child, ast.NamedExpr)
        and isinstance(child.target, ast.Name)
    )
    return tuple(names)


def _import_binding_kind(node, name):
    """Return ``"explicit"``, ``"wildcard"`` or ``None`` for an import."""
    if isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            return "wildcard"
        if any((alias.asname or alias.name) == name for alias in node.names):
            return "explicit"
    elif isinstance(node, ast.Import) and any(
        (alias.asname or alias.name.split(".", 1)[0]) == name
        for alias in node.names
    ):
        return "explicit"
    return None


def _is_module_dict_reference(node):
    """Return True for ``sys.modules[...].__dict__``."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        and isinstance(node.value, ast.Subscript)
        and isinstance(node.value.value, ast.Attribute)
        and node.value.value.attr == "modules"
        and isinstance(node.value.value.value, ast.Name)
        and node.value.value.value.id == "sys"
    )


def _subscript_may_name(slice_node, name):
    """Return False only when a literal subscript key is another name."""
    if isinstance(slice_node, ast.Tuple):
        return any(_subscript_may_name(element, name) for element in slice_node.elts)
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        return slice_node.value == name
    return True


def _target_writes_name(target, name):
    """Return True when an assignment target writes module attribute ``name``."""
    if isinstance(target, ast.Attribute):
        return target.attr == name
    if isinstance(target, ast.Subscript):
        return _is_module_dict_reference(target.value) and _subscript_may_name(
            target.slice, name
        )
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_writes_name(element, name) for element in target.elts)
    if isinstance(target, ast.Starred):
        return _target_writes_name(target.value, name)
    return False


def _module_dict_update_may_name(node, name):
    """Return True for a module ``__dict__`` update that may set ``name``."""
    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and child.func.attr == "update"
        and _is_module_dict_reference(child.func.value)
        and (
            bool(child.args)
            or any(
                keyword.arg is None or keyword.arg == name
                for keyword in child.keywords
            )
        )
        for child in _iter_module_scope_nodes(node)
    )


def _statement_writes_named_attribute(node, name):
    """Return True for ``obj.bind = ...`` or a module ``__dict__`` write."""
    targets = ()
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
    return any(_target_writes_name(target, name) for target in targets) or (
        _module_dict_update_may_name(node, name)
    )


def _has_dynamic_namespace_write(node):
    """Return True when a module-scope statement can write any global name."""
    return any(
        isinstance(child, ast.Call)
        and (
            (isinstance(child.func, ast.Name)
             and child.func.id in _DYNAMIC_NAMESPACE_CALLS)
            or (
                isinstance(child.func, ast.Attribute)
                and child.func.attr in _DYNAMIC_NAMESPACE_CALLS
            )
        )
        for child in _iter_module_scope_nodes(node)
    )


def _module_local_definitions(statements):
    """Map module-scope local function/class names to their definition."""
    definitions = {}
    for node in _iter_module_assignments(statements):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions.setdefault(node.name, node)
    return definitions


def _called_local_names(statements, definitions):
    """Return local definitions invoked while the config module is imported.

    This covers direct calls, decorator names, local base classes and calls in
    a class body. Calls inside a deferred function body only count when that
    function is invoked, which the transitive writer check below models.
    """
    called = set()
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in statement.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id in definitions:
                    called.add(decorator.id)
            if isinstance(statement, ast.ClassDef):
                # A local base runs its __init_subclass__/metaclass hooks.
                for base in statement.bases:
                    if isinstance(base, ast.Name) and base.id in definitions:
                        called.add(base.id)
        for node in _iter_module_scope_nodes(statement):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in definitions
            ):
                called.add(node.func.id)
    return called


def _assignment_target_names(node):
    """Return the simple names bound by one assignment-like node."""
    targets = ()
    if isinstance(node, ast.Assign):
        targets = tuple(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
        targets = (node.target,)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        targets = tuple(
            item.optional_vars for item in node.items if item.optional_vars is not None
        )
    elif isinstance(node, ast.Delete):
        targets = tuple(node.targets)
    return {name for target in targets for name in _target_names(target)}


def _body_writes_global_name(node, name):
    """Return True when executing ``node`` can rebind the module global ``name``.

    A plain assignment inside a function is local unless the function declares
    ``global <name>``; attribute writes and dynamic namespace writes can reach
    the module regardless.
    """
    declares_global = any(
        isinstance(child, ast.Global) and name in child.names
        for child in ast.walk(node)
    )
    if declares_global:
        assignment_nodes = (
            ast.Assign,
            ast.AnnAssign,
            ast.AugAssign,
            ast.For,
            ast.AsyncFor,
            ast.With,
            ast.AsyncWith,
            ast.Delete,
        )
        if any(
            name in _assignment_target_names(child)
            for child in ast.walk(node)
            if isinstance(child, assignment_nodes)
        ):
            return True
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if (
                isinstance(func, ast.Name)
                and func.id in _DYNAMIC_NAMESPACE_CALLS
            ) or (
                isinstance(func, ast.Attribute)
                and func.attr in _DYNAMIC_NAMESPACE_CALLS
            ):
                return True
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "update"
                and _is_module_dict_reference(func.value)
                and (not child.args or any(
                    keyword.arg is None or keyword.arg == name
                    for keyword in child.keywords
                ))
            ):
                return True
        if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = child.targets if isinstance(child, ast.Assign) else (child.target,)
            if any(_target_writes_name(target, name) for target in targets):
                return True
    return False


def _definition_writes_setting(node, name):
    """Return True when defining or invoking ``node`` can write the setting."""
    if isinstance(node, ast.ClassDef):
        # Class-body statements run at import time. Method bodies only run when
        # that specific method is invoked, so only lifecycle hooks that a
        # constructor/context-manager call can reach are considered.
        bodies = [
            child
            for child in node.body
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        lifecycle = {
            "__init__",
            "__new__",
            "__post_init__",
            "__enter__",
            "__exit__",
            "__call__",
            "__init_subclass__",
            "__set_name__",
        }
        bodies.extend(
            child
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name in lifecycle
        )
        return any(_body_writes_global_name(body, name) for body in bodies)
    return _body_writes_global_name(node, name)


def _local_writer_names(definitions, name):
    """Return local definitions that can write ``name``, including transitively."""
    writers = set()
    changed = True
    while changed:
        changed = False
        for definition_name, node in definitions.items():
            if definition_name in writers:
                continue
            called = {
                child.func.id
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
            }
            if _definition_writes_setting(node, name) or called & writers:
                writers.add(definition_name)
                changed = True
    return writers


def config_provides_setting(path, name):
    """Return ``0``/``1``/``2`` for whether ``path`` assigns ``name``."""
    try:
        # Gunicorn loads the file through importlib, which strips a UTF-8 BOM;
        # `utf-8-sig` gives the probe the same view instead of a bogus
        # SyntaxError that the entrypoint reads as "config supplies bind".
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return UNKNOWN
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, RecursionError):
        return UNKNOWN
    dynamic = False
    definitions = _module_local_definitions(tree.body)
    try:
        for node in _iter_module_assignments(tree.body):
            binding_kind = _import_binding_kind(node, name)
            if binding_kind == "explicit":
                return SUPPLIED
            if binding_kind == "wildcard":
                # A wildcard may or may not export this setting. The bind caller
                # treats UNKNOWN as supplied (safe), while the app caller keeps its
                # default because it only accepts SUPPLIED.
                dynamic = True
            if name in _assigned_target_names(node):
                return SUPPLIED
            if _statement_writes_named_attribute(node, name):
                dynamic = True
            if _has_dynamic_namespace_write(node):
                dynamic = True
        # A local helper invoked at import time can assign the setting even
        # though its body is not module scope. Only report uncertainty when the
        # called helper can actually write it; an unrelated helper stays ABSENT.
        if _called_local_names(tree.body, definitions) & _local_writer_names(
            definitions, name
        ):
            dynamic = True
    except RecursionError:
        # A deeply nested expression is valid Python but beyond this walk.
        # Never claim ABSENT: the entrypoint would override the bind.
        return UNKNOWN
    # Keep scanning after a dynamic write: an explicit assignment later in the
    # file still proves the setting is supplied. Only report uncertainty when
    # no explicit binding was found.
    return UNKNOWN if dynamic else ABSENT


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
