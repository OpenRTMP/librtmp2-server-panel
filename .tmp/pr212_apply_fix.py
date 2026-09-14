from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.py"
TESTS = ROOT / "tests/test_gunicorn_indirect_workers_bypass.py"


def replace_function(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
    )
    lines = source.splitlines(keepends=True)
    new = replacement.strip("\n") + "\n\n"
    return "".join(lines[: node.lineno - 1]) + new + "".join(lines[node.end_lineno :])


def insert_before_function(source: str, name: str, block: str) -> str:
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
    )
    lines = source.splitlines(keepends=True)
    new = block.strip("\n") + "\n\n"
    return "".join(lines[: node.lineno - 1]) + new + "".join(lines[node.lineno - 1 :])


source = CONFIG.read_text(encoding="utf-8")

source = replace_function(
    source,
    "_is_import_module_sys_call",
    r'''
def _is_import_module_sys_call(
    node,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Return True for a proven ``importlib.import_module('sys')`` call."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    module_arg = node.args[0]
    if not (isinstance(module_arg, ast.Constant) and module_arg.value == "sys"):
        return False
    if importlib_aliases is None:
        importlib_aliases = {"import_module"}
    if importlib_module_aliases is None:
        importlib_module_aliases = {"importlib"}
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in importlib_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_module_aliases
    )
''',
)

source = replace_function(
    source,
    "_is_current_module_reference",
    r'''
def _is_current_module_reference(
    node,
    sys_aliases=None,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Return True for expressions that resolve to this config module."""
    if sys_aliases is None:
        sys_aliases = {"sys"}
    if not isinstance(node, ast.Subscript):
        return False
    if not isinstance(node.slice, ast.Name) or node.slice.id != "__name__":
        return False
    modules = node.value
    if not isinstance(modules, ast.Attribute) or modules.attr != "modules":
        return False
    root = modules.value
    if isinstance(root, ast.Name) and root.id in sys_aliases:
        return True
    if _is_import_module_sys_call(
        root,
        importlib_aliases,
        importlib_module_aliases,
    ):
        return True
    return (
        isinstance(root, ast.Call)
        and isinstance(root.func, ast.Name)
        and root.func.id == "__import__"
        and len(root.args) == 1
        and isinstance(root.args[0], ast.Constant)
        and root.args[0].value == "sys"
        and not root.keywords
    )
''',
)

source = replace_function(
    source,
    "_is_dict_type_update_callable",
    r'''
def _is_dict_type_update_callable(
    func,
    aliases=None,
    *,
    reference_line=0,
    dict_shadow_line=None,
):
    """Return True for builtin ``dict.update`` or a proven alias of it."""
    if aliases is None:
        aliases = set()
    if isinstance(func, ast.Name):
        return func.id in aliases
    if not _dict_name_is_builtin_at_line(reference_line, dict_shadow_line):
        return False
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "update"
            and isinstance(func.value, ast.Name)
            and func.value.id == "dict"
        )
    return (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[0], ast.Name)
        and func.args[0].id == "dict"
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == "update"
    )
''',
)

source = replace_function(
    source,
    "_values_are_dict_update_aliases",
    r'''
def _values_are_dict_update_aliases(values, aliases, dict_shadow_line=None):
    """Return True when every assignment resolves to builtin ``dict.update``."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_dict_type_update_callable(
            value,
            aliases,
            reference_line=getattr(value, "lineno", 0),
            dict_shadow_line=dict_shadow_line,
        )
        for value in resolved_values
    )
''',
)

source = replace_function(
    source,
    "_collect_dict_update_aliases",
    r'''
def _collect_dict_update_aliases(tree, dict_shadow_line=None):
    """Collect transitive aliases that are always bound to builtin ``dict.update``."""
    if dict_shadow_line is None:
        dict_shadow_line = _collect_definite_name_shadow_line(tree, "dict")
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_dict_update_aliases(
                assignments[name],
                aliases,
                dict_shadow_line,
            )
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases
''',
)

source = replace_function(
    source,
    "_call_is_dict_type_update_on_module_namespace",
    r'''
def _call_is_dict_type_update_on_module_namespace(
    call,
    namespace_aliases=None,
    update_aliases=None,
    dict_shadow_line=None,
):
    """Return True for builtin ``dict.update(globals(), ...)`` style mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    if not _is_dict_type_update_callable(
        call.func,
        update_aliases,
        reference_line=getattr(call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _update_payload_may_set_workers(call, start_index=1)
''',
)

source = replace_function(
    source,
    "_is_dict_type_ior_callable",
    r'''
def _is_dict_type_ior_callable(
    func,
    *,
    aliases=None,
    reference_line=0,
    dict_shadow_line=None,
):
    """Return True for builtin ``dict.__ior__`` variants or proven aliases."""
    if aliases is None:
        aliases = set()
    if isinstance(func, ast.Name):
        return func.id in aliases
    if not _dict_name_is_builtin_at_line(reference_line, dict_shadow_line):
        return False
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "__ior__"
            and isinstance(func.value, ast.Name)
            and func.value.id == "dict"
        )
    return (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[0], ast.Name)
        and func.args[0].id == "dict"
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == "__ior__"
    )
''',
)

source = insert_before_function(
    source,
    "_call_is_dict_type_ior_on_module_namespace",
    r'''
def _values_are_dict_ior_aliases(values, aliases, dict_shadow_line=None):
    """Return True when every assignment resolves to builtin ``dict.__ior__``."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_dict_type_ior_callable(
            value,
            aliases=aliases,
            reference_line=getattr(value, "lineno", 0),
            dict_shadow_line=dict_shadow_line,
        )
        for value in resolved_values
    )


def _collect_dict_ior_aliases(tree, dict_shadow_line=None):
    """Collect transitive aliases always bound to builtin ``dict.__ior__``."""
    if dict_shadow_line is None:
        dict_shadow_line = _collect_definite_name_shadow_line(tree, "dict")
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_dict_ior_aliases(
                assignments[name],
                aliases,
                dict_shadow_line,
            )
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases
''',
)

source = replace_function(
    source,
    "_call_is_dict_type_ior_on_module_namespace",
    r'''
def _call_is_dict_type_ior_on_module_namespace(
    call,
    namespace_aliases=None,
    dict_shadow_line=None,
    ior_aliases=None,
):
    """Return True for builtin ``dict.__ior__(globals(), ...)`` mutations."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    if not _is_dict_type_ior_callable(
        call.func,
        aliases=ior_aliases,
        reference_line=getattr(call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _dict_merge_payload_may_set_workers(call.args[1])
''',
)

source = insert_before_function(
    source,
    "_is_types_functiontype_callable",
    r'''
def _collect_types_functiontype_aliases(statements):
    """Collect ``types`` module aliases and imported ``FunctionType`` aliases."""
    module_aliases = set()
    callable_aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "types":
                    module_aliases.add(imported.asname or imported.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "types":
            for imported in node.names:
                if imported.name == "FunctionType":
                    callable_aliases.add(imported.asname or imported.name)
        for block in _compound_statement_blocks(node):
            nested_modules, nested_callables = _collect_types_functiontype_aliases(block)
            module_aliases.update(nested_modules)
            callable_aliases.update(nested_callables)
    return module_aliases, callable_aliases
''',
)

source = replace_function(
    source,
    "_is_types_functiontype_callable",
    r'''
def _is_types_functiontype_callable(
    func,
    module_aliases=None,
    callable_aliases=None,
):
    """Return True for a proven ``types.FunctionType`` callable."""
    if module_aliases is None:
        module_aliases = {"types"}
    if callable_aliases is None:
        callable_aliases = {"FunctionType"}
    if isinstance(func, ast.Name):
        return func.id in callable_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "FunctionType"
        and isinstance(func.value, ast.Name)
        and func.value.id in module_aliases
    )
''',
)

source = insert_before_function(
    source,
    "_call_is_functiontype_namespace_code",
    r'''
def _call_argument_value(call, position, keyword_name):
    """Return a positional-or-keyword argument from a call, if present."""
    if len(call.args) > position:
        return call.args[position]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == keyword_name),
        None,
    )
''',
)

source = replace_function(
    source,
    "_call_is_functiontype_namespace_code",
    r'''
def _call_is_functiontype_namespace_code(
    call,
    namespace_aliases=None,
    types_module_aliases=None,
    functiontype_aliases=None,
):
    """Return True for ``FunctionType(compile(...), globals())`` calls."""
    if not isinstance(call, ast.Call):
        return False
    if not _is_types_functiontype_callable(
        call.func,
        types_module_aliases,
        functiontype_aliases,
    ):
        return False
    code_arg = _call_argument_value(call, 0, "code")
    globals_arg = _call_argument_value(call, 1, "globals")
    return (
        code_arg is not None
        and globals_arg is not None
        and _is_compile_call(code_arg)
        and _is_module_namespace_mapping(globals_arg, namespace_aliases)
    )
''',
)

source = replace_function(
    source,
    "_call_is_invoked_functiontype_namespace_code",
    r'''
def _call_is_invoked_functiontype_namespace_code(
    call,
    namespace_aliases=None,
    types_module_aliases=None,
    functiontype_aliases=None,
):
    """Return True for immediate ``FunctionType(..., globals())()`` calls."""
    if not isinstance(call, ast.Call):
        return False
    inner = call.func
    return isinstance(inner, ast.Call) and _call_is_functiontype_namespace_code(
        inner,
        namespace_aliases,
        types_module_aliases,
        functiontype_aliases,
    )
''',
)

source = replace_function(
    source,
    "_collect_functiontype_namespace_aliases",
    r'''
def _collect_functiontype_namespace_aliases(
    tree,
    namespace_aliases,
    types_module_aliases=None,
    functiontype_aliases=None,
):
    """Collect names bound to ``FunctionType(compile(...), globals())``."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if assignments[name]
            and all(
                value is not None
                and _call_is_functiontype_namespace_code(
                    value,
                    namespace_aliases,
                    types_module_aliases,
                    functiontype_aliases,
                )
                for value in assignments[name]
            )
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases
''',
)

source = insert_before_function(
    source,
    "_partial_uses_unbound_dict_namespace_mutation",
    r'''
def _partial_unbound_dict_namespace_method(
    partial_call,
    namespace_aliases,
    dict_update_aliases,
    dict_ior_aliases,
    dict_shadow_line=None,
):
    """Return the dict mutator bound by ``partial(..., globals())``."""
    if partial_call is None or len(partial_call.args) < 2:
        return None
    if not _is_module_namespace_mapping(partial_call.args[1], namespace_aliases):
        return None
    target = partial_call.args[0]
    if _is_dict_type_update_callable(
        target,
        dict_update_aliases,
        reference_line=getattr(partial_call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return "update"
    if _is_dict_type_ior_callable(
        target,
        aliases=dict_ior_aliases,
        reference_line=getattr(partial_call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return "__ior__"
    return None


def _call_payload_may_set_workers(method, call, start_index=0):
    """Inspect arguments supplied to a dict mutator invocation."""
    if method == "update":
        return _update_payload_may_set_workers(call, start_index=start_index)
    if method == "__ior__":
        return (
            len(call.args) > start_index
            and _dict_merge_payload_may_set_workers(call.args[start_index])
        )
    return False
''',
)

source = replace_function(
    source,
    "_partial_uses_unbound_dict_namespace_mutation",
    r'''
def _partial_uses_unbound_dict_namespace_mutation(
    partial_call,
    namespace_aliases,
    dict_update_aliases,
    dict_shadow_line=None,
    dict_ior_aliases=None,
    invocation_call=None,
    invocation_start_index=0,
):
    """Return True when a bound dict mutator can set ``workers``."""
    if dict_ior_aliases is None:
        dict_ior_aliases = set()
    method = _partial_unbound_dict_namespace_method(
        partial_call,
        namespace_aliases,
        dict_update_aliases,
        dict_ior_aliases,
        dict_shadow_line,
    )
    if method is None:
        return False
    if _call_payload_may_set_workers(method, partial_call, start_index=2):
        return True
    return invocation_call is not None and _call_payload_may_set_workers(
        method,
        invocation_call,
        start_index=invocation_start_index,
    )
''',
)

source = replace_function(
    source,
    "_partial_value_is_workers_setter",
    r'''
def _partial_value_is_workers_setter(
    value,
    namespace_aliases,
    partial_aliases,
    known_aliases,
    dict_update_aliases=None,
    dict_shadow_line=None,
    dict_ior_aliases=None,
):
    """Return True when a value resolves to a partial workers setter."""
    if dict_update_aliases is None:
        dict_update_aliases = set()
    if dict_ior_aliases is None:
        dict_ior_aliases = set()
    if isinstance(value, ast.Name):
        return value.id in known_aliases
    partial_call = _partial_factory_call(value, partial_aliases)
    if partial_call is None or not partial_call.args:
        return False
    if _partial_uses_unbound_dict_namespace_mutation(
        partial_call,
        namespace_aliases,
        dict_update_aliases,
        dict_shadow_line,
        dict_ior_aliases,
    ):
        return True
    if (
        len(partial_call.args) >= 2
        and _attribute_is_namespace_setitem(partial_call.args[0], namespace_aliases)
        and _constant_is_workers(partial_call.args[1])
    ):
        return True
    return (
        _attribute_is_namespace_update(partial_call.args[0], namespace_aliases)
        and _update_payload_may_set_workers(partial_call, start_index=1)
    )
''',
)

source = replace_function(
    source,
    "_values_are_partial_workers_setters",
    r'''
def _values_are_partial_workers_setters(
    values,
    namespace_aliases,
    partial_aliases,
    known_aliases,
    dict_update_aliases=None,
    dict_shadow_line=None,
    dict_ior_aliases=None,
):
    """Return True when every resolved assignment is a workers setter."""
    resolved = [value for value in values if value is not None]
    return bool(resolved) and all(
        _partial_value_is_workers_setter(
            value,
            namespace_aliases,
            partial_aliases,
            known_aliases,
            dict_update_aliases,
            dict_shadow_line,
            dict_ior_aliases,
        )
        for value in resolved
    )
''',
)

source = replace_function(
    source,
    "_collect_partial_workers_setter_aliases",
    r'''
def _collect_partial_workers_setter_aliases(
    tree,
    namespace_aliases,
    partial_aliases,
    dict_update_aliases=None,
    dict_shadow_line=None,
    dict_ior_aliases=None,
):
    """Collect names bound to partials that always set ``workers``."""
    if dict_shadow_line is None:
        dict_shadow_line = _collect_definite_name_shadow_line(tree, "dict")
    if dict_update_aliases is None:
        dict_update_aliases = _collect_dict_update_aliases(tree, dict_shadow_line)
    if dict_ior_aliases is None:
        dict_ior_aliases = _collect_dict_ior_aliases(tree, dict_shadow_line)
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_partial_workers_setters(
                assignments[name],
                namespace_aliases,
                partial_aliases,
                aliases,
                dict_update_aliases,
                dict_shadow_line,
                dict_ior_aliases,
            )
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases
''',
)

source = insert_before_function(
    source,
    "_call_is_getattr_partial_invocation",
    r'''
def _partial_value_dict_namespace_method(
    value,
    namespace_aliases,
    partial_aliases,
    known_aliases,
    dict_update_aliases,
    dict_ior_aliases,
    dict_shadow_line,
):
    """Resolve a saved partial to its bound dict namespace mutator."""
    if isinstance(value, ast.Name):
        return known_aliases.get(value.id)
    partial_call = _partial_factory_call(value, partial_aliases)
    return _partial_unbound_dict_namespace_method(
        partial_call,
        namespace_aliases,
        dict_update_aliases,
        dict_ior_aliases,
        dict_shadow_line,
    )


def _collect_partial_dict_namespace_mutator_aliases(
    tree,
    namespace_aliases,
    partial_aliases,
    dict_update_aliases,
    dict_ior_aliases,
    dict_shadow_line,
):
    """Collect saved partials bound to builtin dict mutators on globals()."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = {}
    unresolved = set(assignments)
    while unresolved:
        discovered = {}
        for name in unresolved:
            methods = [
                _partial_value_dict_namespace_method(
                    value,
                    namespace_aliases,
                    partial_aliases,
                    aliases,
                    dict_update_aliases,
                    dict_ior_aliases,
                    dict_shadow_line,
                )
                for value in assignments[name]
                if value is not None
            ]
            if methods and methods[0] is not None and all(
                method == methods[0] for method in methods
            ):
                discovered[name] = methods[0]
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases
''',
)

source = insert_before_function(
    source,
    "_call_is_partial_bound_workers_setitem",
    r'''
def _resolve_partial_invocation(call, partial_aliases):
    """Return an invoked partial factory and where invocation payloads begin."""
    partial_call = _partial_factory_call(call.func, partial_aliases)
    if partial_call is not None:
        return partial_call, 0
    if not _call_is_getattr_partial_invocation(call, partial_aliases) or not call.args:
        return None, 0
    return _partial_factory_call(call.args[0], partial_aliases), 1


def _partial_call_binds_namespace_workers_setter(partial_call, namespace_aliases):
    """Return True for non-dict partial forms that already bind workers."""
    if (
        len(partial_call.args) >= 2
        and _attribute_is_namespace_setitem(partial_call.args[0], namespace_aliases)
        and _constant_is_workers(partial_call.args[1])
    ):
        return True
    return (
        _attribute_is_namespace_update(partial_call.args[0], namespace_aliases)
        and _update_payload_may_set_workers(partial_call, start_index=1)
    )
''',
)

source = replace_function(
    source,
    "_call_is_partial_bound_workers_setitem",
    r'''
def _call_is_partial_bound_workers_setitem(call, operator_bindings):
    """Return True for direct or saved partial workers setters."""
    if not isinstance(call, ast.Call):
        return False
    _, _, namespace_aliases, _, partial_aliases = _unpack_operator_bindings(
        operator_bindings
    )
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    saved_aliases = operator_bindings[12] if len(operator_bindings) > 12 else set()
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_ior_aliases = operator_bindings[23] if len(operator_bindings) > 23 else set()
    partial_mutator_aliases = (
        operator_bindings[27] if len(operator_bindings) > 27 else {}
    )
    if isinstance(call.func, ast.Name):
        if call.func.id in saved_aliases:
            return True
        saved_method = partial_mutator_aliases.get(call.func.id)
        if saved_method is not None:
            return _call_payload_may_set_workers(saved_method, call)
    partial_call, invocation_start = _resolve_partial_invocation(call, partial_aliases)
    if partial_call is None or not partial_call.args:
        return False
    if _partial_uses_unbound_dict_namespace_mutation(
        partial_call,
        namespace_aliases,
        dict_update_aliases,
        dict_shadow_line,
        dict_ior_aliases,
        call,
        invocation_start,
    ):
        return True
    return _partial_call_binds_namespace_workers_setter(
        partial_call,
        namespace_aliases,
    )
''',
)

source = insert_before_function(
    source,
    "_importlib_import_module_aliases",
    r'''
def _collect_importlib_module_aliases(statements):
    """Collect aliases introduced by ``import importlib`` statements."""
    aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "importlib":
                    aliases.add(imported.asname or imported.name)
        for block in _compound_statement_blocks(node):
            aliases.update(_collect_importlib_module_aliases(block))
    return aliases
''',
)

source = insert_before_function(
    source,
    "_call_mutates_workers_via_indirection",
    r'''
def _call_is_importlib_sys_namespace_mutation(call, operator_bindings):
    """Detect mutators reached through aliased ``import_module('sys')``."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    namespace = call.func.value
    if not isinstance(namespace, ast.Attribute) or namespace.attr != "__dict__":
        return False
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else {"sys"}
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    importlib_module_aliases = (
        operator_bindings[24] if len(operator_bindings) > 24 else set()
    )
    if not _is_current_module_reference(
        namespace.value,
        sys_aliases,
        importlib_aliases,
        importlib_module_aliases,
    ):
        return False
    method = call.func.attr
    if method == "update":
        return _update_payload_may_set_workers(call)
    if method == "__ior__":
        return bool(call.args) and _dict_merge_payload_may_set_workers(call.args[0])
    if method == "__setitem__":
        return bool(call.args) and _key_may_be_workers(call.args[0])
    return False
''',
)

source = replace_function(
    source,
    "_call_is_getattr_bound_module_setattr_workers",
    r'''
def _call_is_getattr_bound_module_setattr_workers(
    call,
    sys_aliases=None,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Return True for ``getattr(module, '__setattr__')('workers', ...)`` calls."""
    if not isinstance(call, ast.Call) or len(call.args) < 1:
        return False
    func = call.func
    if not isinstance(func, ast.Call):
        return False
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return False
    if len(func.args) < 2 or not _is_current_module_reference(
        func.args[0],
        sys_aliases,
        importlib_aliases,
        importlib_module_aliases,
    ):
        return False
    setattr_key = func.args[1]
    if not isinstance(setattr_key, ast.Constant) or setattr_key.value != "__setattr__":
        return False
    worker_key = call.args[0]
    return isinstance(worker_key, ast.Constant) and worker_key.value == "workers"
''',
)

source = replace_function(
    source,
    "_call_sets_workers_attribute",
    r'''
def _call_sets_workers_attribute(
    call,
    sys_aliases=None,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Return True for setattr/object.__setattr__ calls that bind ``workers``."""
    if _call_is_getattr_bound_module_setattr_workers(
        call,
        sys_aliases,
        importlib_aliases,
        importlib_module_aliases,
    ):
        return True
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    key = call.args[1]
    if not isinstance(key, ast.Constant) or key.value != "workers":
        return False
    func = call.func
    if isinstance(func, ast.Name) and func.id == "setattr":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "__setattr__"
''',
)

source = replace_function(
    source,
    "_call_mutates_workers_via_indirection",
    r'''
def _call_mutates_workers_via_indirection(call, operator_bindings):
    """Return True for indirect import-time ``workers`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else {"sys"}
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_ior_aliases = operator_bindings[23] if len(operator_bindings) > 23 else set()
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    importlib_module_aliases = (
        operator_bindings[24] if len(operator_bindings) > 24 else set()
    )
    if (
        _call_sets_workers_via_setitem(call)
        or _call_is_operator_setitem_workers(call, operator_bindings)
        or _call_is_getattr_setitem_workers(call)
        or _call_is_dict_type_setitem_on_module_namespace(
            call,
            namespace_aliases,
            dict_shadow_line,
        )
        or _call_sets_workers_attribute(
            call,
            sys_aliases,
            importlib_aliases,
            importlib_module_aliases,
        )
        or _call_is_dict_type_update_on_module_namespace(
            call,
            namespace_aliases,
            dict_update_aliases,
            dict_shadow_line,
        )
        or _call_is_dict_type_ior_on_module_namespace(
            call,
            namespace_aliases,
            dict_shadow_line,
            dict_ior_aliases,
        )
        or _call_is_importlib_sys_namespace_mutation(call, operator_bindings)
        or _call_is_subscript_namespace_workers_update(
            call,
            namespace_aliases,
            mutator_aliases,
        )
        or _call_is_operator_methodcaller_on_module_namespace(
            call,
            operator_bindings,
            namespace_aliases,
        )
    ):
        return True
    if not isinstance(call.func, ast.Lambda):
        return False
    lambda_node = call.func
    if _lambda_mutates_workers(lambda_node, operator_bindings):
        return True
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    for param, value in zip(positional_params, call.args):
        if (
            _is_module_namespace_mapping(value, namespace_aliases)
            and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        ):
            return True
    keyword_values = {
        keyword.arg: keyword.value
        for keyword in call.keywords
        if keyword.arg is not None
    }
    return any(
        param.arg in keyword_values
        and _is_module_namespace_mapping(
            keyword_values[param.arg],
            namespace_aliases,
        )
        and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        for param in (*positional_params, *lambda_node.args.kwonlyargs)
    )
''',
)

source = insert_before_function(
    source,
    "_expression_mutates_workers",
    r'''
def _call_expression_mutates_workers(expr, operator_bindings):
    """Return True when one call expression can mutate module workers."""
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    exec_eval_shadow_lines = operator_bindings[9] if len(operator_bindings) > 9 else {}
    direct_exec_eval_aliases = operator_bindings[10] if len(operator_bindings) > 10 else set()
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    direct_exec_eval_alias_events = operator_bindings[18] if len(operator_bindings) > 18 else {}
    importlib_alias_events = operator_bindings[19] if len(operator_bindings) > 19 else {}
    delegated_update_alias_events = operator_bindings[20] if len(operator_bindings) > 20 else {}
    functiontype_namespace_aliases = operator_bindings[22] if len(operator_bindings) > 22 else set()
    types_module_aliases = operator_bindings[25] if len(operator_bindings) > 25 else set()
    functiontype_aliases = operator_bindings[26] if len(operator_bindings) > 26 else set()
    return (
        _call_is_dynamic_exec_eval(
            expr,
            builtins_aliases,
            exec_eval_shadow_lines,
            direct_exec_eval_aliases,
            importlib_aliases,
            direct_exec_eval_alias_events,
            importlib_alias_events,
        )
        or _call_is_operator_methodcaller_exec_on_builtins(expr, operator_bindings)
        or _call_is_module_namespace_workers_update(expr, namespace_aliases)
        or _call_is_module_namespace_workers_ior(expr, namespace_aliases)
        or _call_is_getattr_namespace_workers_mutation(
            expr, namespace_aliases, mutator_aliases
        )
        or _call_is_operator_namespace_ior(expr, operator_bindings)
        or _call_is_getattr_operator_namespace_mutation(expr, operator_bindings)
        or _call_is_operator_attrgetter_namespace_mutation(expr, operator_bindings)
        or _call_is_partial_bound_workers_setitem(expr, operator_bindings)
        or _call_is_known_reduce_lambda_mutation(expr, operator_bindings)
        or _call_is_functiontype_namespace_code(
            expr,
            namespace_aliases,
            types_module_aliases,
            functiontype_aliases,
        )
        or _call_is_invoked_functiontype_namespace_code(
            expr,
            namespace_aliases,
            types_module_aliases,
            functiontype_aliases,
        )
        or (
            isinstance(expr.func, ast.Name)
            and expr.func.id in functiontype_namespace_aliases
        )
        or _call_mutates_workers_via_indirection(expr, operator_bindings)
        or _call_is_chainmap_maps_update(expr, namespace_aliases)
        or _call_is_delegated_simplenamespace_update(
            expr,
            operator_bindings[17] if len(operator_bindings) > 17 else set(),
            delegated_update_alias_events,
        )
    )
''',
)

source = replace_function(
    source,
    "_expression_mutates_workers",
    r'''
def _expression_mutates_workers(expr, operator_bindings):
    """Return True when an evaluated expression mutates ``workers`` indirectly."""
    if isinstance(expr, ast.Lambda):
        return False
    if isinstance(expr, ast.Call) and _call_expression_mutates_workers(
        expr,
        operator_bindings,
    ):
        return True
    return any(
        _expression_mutates_workers(child, operator_bindings)
        for child in ast.iter_child_nodes(expr)
    )
''',
)

source = replace_function(
    source,
    "_collect_operator_setitem_bindings",
    r'''
def _collect_operator_setitem_bindings(tree):
    """Collect aliases used by operator and module-namespace mutation scans."""
    module_aliases = set()
    setitem_aliases = set()
    ior_aliases = set()
    partial_aliases = set()
    methodcaller_aliases = set()
    attrgetter_aliases = set()
    _collect_operator_bindings_from_statements(
        tree.body,
        module_aliases,
        setitem_aliases,
        ior_aliases,
        partial_aliases,
        methodcaller_aliases,
        attrgetter_aliases,
    )
    namespace_aliases = _collect_module_namespace_aliases(tree)
    mutator_aliases = _collect_namespace_mutator_aliases(tree, namespace_aliases)
    dict_shadow_line = _collect_definite_name_shadow_line(tree, "dict")
    dict_update_aliases = _collect_dict_update_aliases(tree, dict_shadow_line)
    dict_ior_aliases = _collect_dict_ior_aliases(tree, dict_shadow_line)
    builtins_aliases = _collect_builtins_aliases(tree)
    exec_eval_shadow_lines = _collect_definite_exec_eval_shadow_lines(tree)
    direct_exec_eval_aliases = _collect_builtins_exec_eval_aliases(
        tree.body,
        builtins_aliases,
    )
    direct_exec_eval_alias_events = _collect_builtins_exec_eval_alias_events(
        tree,
        builtins_aliases,
    )
    importlib_aliases = _collect_importlib_import_module_aliases(tree.body)
    importlib_alias_events = _collect_importlib_import_module_alias_events(tree)
    importlib_module_aliases = _collect_importlib_module_aliases(tree.body)
    partial_workers_setter_aliases = _collect_partial_workers_setter_aliases(
        tree,
        namespace_aliases,
        partial_aliases,
        dict_update_aliases,
        dict_shadow_line,
        dict_ior_aliases,
    )
    partial_dict_mutator_aliases = _collect_partial_dict_namespace_mutator_aliases(
        tree,
        namespace_aliases,
        partial_aliases,
        dict_update_aliases,
        dict_ior_aliases,
        dict_shadow_line,
    )
    sys_aliases = _collect_sys_import_aliases(tree.body)
    functools_aliases, reduce_aliases = _collect_functools_reduce_aliases(tree.body)
    delegated_update_aliases = _collect_delegated_update_namespace_aliases(
        tree,
        namespace_aliases,
    )
    delegated_update_alias_events = _collect_delegated_update_alias_events(
        tree,
        namespace_aliases,
    )
    types_module_aliases, functiontype_aliases = _collect_types_functiontype_aliases(
        tree.body
    )
    functiontype_namespace_aliases = _collect_functiontype_namespace_aliases(
        tree,
        namespace_aliases,
        types_module_aliases,
        functiontype_aliases,
    )
    return (
        module_aliases,
        setitem_aliases,
        namespace_aliases,
        ior_aliases,
        partial_aliases,
        mutator_aliases,
        methodcaller_aliases,
        dict_update_aliases,
        builtins_aliases,
        exec_eval_shadow_lines,
        direct_exec_eval_aliases,
        attrgetter_aliases,
        partial_workers_setter_aliases,
        sys_aliases,
        functools_aliases,
        reduce_aliases,
        importlib_aliases,
        delegated_update_aliases,
        direct_exec_eval_alias_events,
        importlib_alias_events,
        delegated_update_alias_events,
        dict_shadow_line,
        functiontype_namespace_aliases,
        dict_ior_aliases,
        importlib_module_aliases,
        types_module_aliases,
        functiontype_aliases,
        partial_dict_mutator_aliases,
    )
''',
)

ast.parse(source)
CONFIG.write_text(source, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
needle = '''        "workers = 1\\nimport types\\nf = types.FunctionType(compile('workers=4','','exec'), globals())\\nf()\\n",\n'''
if needle not in tests:
    raise RuntimeError("test insertion sentinel not found")
extra_cases = '''        "workers = 1\\nfrom importlib import import_module as im\\nim('sys').modules[__name__].__dict__.update({'workers': 4})\\n",\n        "workers = 1\\nimport importlib as il\\nil.import_module('sys').modules[__name__].__dict__.update({'workers': 4})\\n",\n        "workers = 1\\nmerge = dict.__ior__\\nmerge(globals(), {'workers': 4})\\n",\n        "workers = 1\\nmerge = dict.__ior__\\nmerge2 = merge\\nmerge2(globals(), {'workers': 4})\\n",\n        "workers = 1\\nfrom types import FunctionType as FT\\nFT(compile('workers=4','','exec'), globals())()\\n",\n        "workers = 1\\nimport types as t\\nt.FunctionType(code=compile('workers=4','','exec'), globals=globals())()\\n",\n        "workers = 1\\nfrom functools import partial\\npartial(dict.update, globals())({'workers': 4})\\n",\n        "workers = 1\\nfrom functools import partial\\np = partial(dict.update, globals())\\np({'workers': 4})\\n",\n        "workers = 1\\nfrom functools import partial\\npartial(dict.__ior__, globals())({'workers': 4})\\n",\n        "workers = 1\\nfrom functools import partial\\np = partial(dict.__ior__, globals())\\np({'workers': 4})\\n",\n'''
tests = tests.replace(needle, needle + extra_cases, 1)

tests = insert_before_function(
    tests,
    "_clear_worker_environment",
    r'''
def test_shadowed_dict_update_partial_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "class dict:\n"
        "    @staticmethod\n"
        "    def update(target, payload):\n"
        "        return target\n"
        "from functools import partial\n"
        "partial(dict.update, globals(), {'workers': 4})()\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)


def test_safe_partial_dict_update_payload_does_not_mark_workers_dynamic(tmp_path):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(
        "workers = 1\n"
        "from functools import partial\n"
        "p = partial(dict.update, globals())\n"
        "p({'not_workers': 4})\n",
        encoding="utf-8",
    )

    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
''',
)

ast.parse(tests)
TESTS.write_text(tests, encoding="utf-8")
