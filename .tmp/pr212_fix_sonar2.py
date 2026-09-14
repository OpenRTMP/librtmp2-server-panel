from __future__ import annotations

import ast
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "config.py"


def replace_function(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
    )
    lines = source.splitlines(keepends=True)
    return (
        "".join(lines[: node.lineno - 1])
        + replacement.strip("\n")
        + "\n\n"
        + "".join(lines[node.end_lineno :])
    )


def insert_before_function(source: str, name: str, block: str) -> str:
    tree = ast.parse(source)
    node = next(
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
    )
    lines = source.splitlines(keepends=True)
    return (
        "".join(lines[: node.lineno - 1])
        + block.strip("\n")
        + "\n\n"
        + "".join(lines[node.lineno - 1 :])
    )


source = CONFIG.read_text(encoding="utf-8")

source = insert_before_function(
    source,
    "_collect_types_functiontype_aliases",
    r'''
def _types_functiontype_aliases_from_import(node):
    """Return aliases introduced by one ``types`` import statement."""
    if isinstance(node, ast.Import):
        return (
            {
                imported.asname or imported.name
                for imported in node.names
                if imported.name == "types"
            },
            set(),
        )
    if isinstance(node, ast.ImportFrom) and node.module == "types":
        return (
            set(),
            {
                imported.asname or imported.name
                for imported in node.names
                if imported.name == "FunctionType"
            },
        )
    return set(), set()
''',
)

source = replace_function(
    source,
    "_collect_types_functiontype_aliases",
    r'''
def _collect_types_functiontype_aliases(statements):
    """Collect ``types`` module aliases and imported ``FunctionType`` aliases."""
    module_aliases = set()
    callable_aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        node_modules, node_callables = _types_functiontype_aliases_from_import(node)
        module_aliases.update(node_modules)
        callable_aliases.update(node_callables)
        for block in _compound_statement_blocks(node):
            nested_modules, nested_callables = _collect_types_functiontype_aliases(block)
            module_aliases.update(nested_modules)
            callable_aliases.update(nested_callables)
    return module_aliases, callable_aliases
''',
)

source = insert_before_function(
    source,
    "_call_mutates_workers_via_indirection",
    r'''
def _call_has_direct_worker_indirection(call, operator_bindings):
    """Return True for non-lambda indirect namespace mutation calls."""
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else {"sys"}
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_ior_aliases = operator_bindings[23] if len(operator_bindings) > 23 else set()
    importlib_module_aliases = operator_bindings[24] if len(operator_bindings) > 24 else set()
    return (
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
    )


def _lambda_invocation_mutates_workers(call, operator_bindings):
    """Return True when an invoked lambda mutates a namespace argument."""
    if not isinstance(call.func, ast.Lambda):
        return False
    lambda_node = call.func
    if _lambda_mutates_workers(lambda_node, operator_bindings):
        return True
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    if any(
        _is_module_namespace_mapping(value, namespace_aliases)
        and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        for param, value in zip(positional_params, call.args)
    ):
        return True
    keyword_values = {
        keyword.arg: keyword.value
        for keyword in call.keywords
        if keyword.arg is not None
    }
    return any(
        param.arg in keyword_values
        and _is_module_namespace_mapping(keyword_values[param.arg], namespace_aliases)
        and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        for param in (*positional_params, *lambda_node.args.kwonlyargs)
    )
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
    if _call_has_direct_worker_indirection(call, operator_bindings):
        return True
    return _lambda_invocation_mutates_workers(call, operator_bindings)
''',
)

ast.parse(source)
CONFIG.write_text(source, encoding="utf-8")
