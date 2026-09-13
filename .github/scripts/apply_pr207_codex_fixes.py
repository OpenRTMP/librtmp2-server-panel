import ast
import textwrap
from pathlib import Path


CONFIG_PATH = Path("config.py")


def replace_function(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    node = next(
        (
            item
            for item in tree.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == name
        ),
        None,
    )
    if node is None or node.end_lineno is None:
        raise SystemExit(f"Could not locate top-level function {name}")
    lines = source.splitlines(keepends=True)
    new_source = textwrap.dedent(replacement).strip("\n") + "\n\n"
    return "".join(lines[: node.lineno - 1]) + new_source + "".join(lines[node.end_lineno :])


def main() -> None:
    source = CONFIG_PATH.read_text(encoding="utf-8")

    source = replace_function(
        source,
        "_call_is_attribute_instance_update_workers",
        r'''
        def _call_is_attribute_instance_update_workers(call, shadowed_names=None):
            """Return True for instance ``mapping.update({...})`` with a workers payload."""
            if not isinstance(call, ast.Call):
                return False
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
                return False
            if shadowed_names is None:
                shadowed_names = set()
            receiver = call.func.value
            if isinstance(receiver, ast.Name):
                if receiver.id in shadowed_names:
                    return False
                if receiver.id == "dict":
                    return False
            return _update_payload_may_set_workers(call)
        ''',
    )

    source = replace_function(
        source,
        "_collect_delegated_update_namespace_aliases",
        r'''
        def _collect_delegated_update_namespace_aliases(tree, namespace_aliases):
            """Collect names ever bound to ``SimpleNamespace(update=globals().update)``."""
            assignments = {}
            _record_module_namespace_assignments(tree.body, assignments)
            aliases = set()
            for name, values in assignments.items():
                for value in values:
                    if value is not None and _simple_namespace_call_delegates_update(
                        value,
                        namespace_aliases,
                    ):
                        aliases.add(name)
                        break
            return aliases


        def _binding_state_at_line(events, name, line):
            """Return the latest known boolean binding state at ``line``."""
            state = None
            for event_line, active in events.get(name, ()):
                if line and event_line > line:
                    break
                state = active
            return state


        def _collect_delegated_update_alias_events(tree, namespace_aliases):
            """Track top-level delegated SimpleNamespace aliases by source position."""
            events = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                line = getattr(node, "lineno", 0)
                for name, value in _namespace_assignment_values(node):
                    active = bool(
                        value is not None
                        and _simple_namespace_call_delegates_update(
                            value,
                            namespace_aliases,
                        )
                    )
                    events.setdefault(name, []).append((line, active))
            return events
        ''',
    )

    source = replace_function(
        source,
        "_call_is_chainmap_maps_update",
        r'''
        def _chainmap_selected_entry_is_namespace(receiver, namespace_aliases=None):
            """Return whether a selected ChainMap entry can be the module namespace."""
            if not isinstance(receiver, ast.Subscript):
                return False
            maps_attr = receiver.value
            if not isinstance(maps_attr, ast.Attribute) or maps_attr.attr != "maps":
                return False
            chainmap_call = maps_attr.value
            if not _chainmap_call_includes_namespace(chainmap_call, namespace_aliases):
                return False
            if any(isinstance(arg, ast.Starred) for arg in chainmap_call.args):
                return True
            index_node = receiver.slice
            index = None
            if isinstance(index_node, ast.Constant) and isinstance(index_node.value, int):
                index = index_node.value
            elif (
                isinstance(index_node, ast.UnaryOp)
                and isinstance(index_node.op, ast.USub)
                and isinstance(index_node.operand, ast.Constant)
                and isinstance(index_node.operand.value, int)
            ):
                index = -index_node.operand.value
            if index is None:
                return True
            if index < 0:
                index += len(chainmap_call.args)
            if index < 0 or index >= len(chainmap_call.args):
                return False
            return _is_module_namespace_mapping(
                chainmap_call.args[index],
                namespace_aliases,
            )


        def _call_is_chainmap_maps_update(call, namespace_aliases=None):
            """Return True for ``ChainMap(..., globals()).maps[i].update(...)`` mutations."""
            if not isinstance(call, ast.Call):
                return False
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
                return False
            if not _chainmap_selected_entry_is_namespace(
                call.func.value,
                namespace_aliases,
            ):
                return False
            return _update_payload_may_set_workers(call)
        ''',
    )

    source = replace_function(
        source,
        "_call_is_delegated_simplenamespace_update",
        r'''
        def _call_is_delegated_simplenamespace_update(
            call,
            delegated_update_aliases=None,
            delegated_update_alias_events=None,
        ):
            """Return True for ``ns.update(...)`` when ``ns`` delegates to ``globals().update``."""
            if not isinstance(call, ast.Call):
                return False
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
                return False
            receiver = call.func.value
            if not isinstance(receiver, ast.Name):
                return False
            if delegated_update_alias_events and receiver.id in delegated_update_alias_events:
                state = _binding_state_at_line(
                    delegated_update_alias_events,
                    receiver.id,
                    getattr(call, "lineno", 0),
                )
                if state is not None:
                    return state and _update_payload_may_set_workers(call)
            if receiver.id not in (delegated_update_aliases or set()):
                return False
            return _update_payload_may_set_workers(call)
        ''',
    )

    source = replace_function(
        source,
        "_is_dict_type_setitem_callable",
        r'''
        def _dict_name_is_builtin_at_line(reference_line, dict_shadow_line=None):
            """Return whether ``dict`` still resolves to the builtin at a source line."""
            return dict_shadow_line is None or (
                reference_line and reference_line < dict_shadow_line
            )


        def _is_dict_type_setitem_callable(
            func,
            *,
            reference_line=0,
            dict_shadow_line=None,
        ):
            """Return True for builtin ``dict.__setitem__`` variants."""
            if not _dict_name_is_builtin_at_line(reference_line, dict_shadow_line):
                return False
            if isinstance(func, ast.Attribute):
                return (
                    func.attr == "__setitem__"
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
                and func.args[1].value == "__setitem__"
            )
        ''',
    )

    source = replace_function(
        source,
        "_call_is_dict_type_setitem_on_module_namespace",
        r'''
        def _call_is_dict_type_setitem_on_module_namespace(
            call,
            namespace_aliases=None,
            dict_shadow_line=None,
        ):
            """Return True for ``dict.__setitem__(globals(), 'workers', ...)`` mutations."""
            if not isinstance(call, ast.Call) or len(call.args) < 2:
                return False
            if not _is_dict_type_setitem_callable(
                call.func,
                reference_line=getattr(call, "lineno", 0),
                dict_shadow_line=dict_shadow_line,
            ):
                return False
            if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
                return False
            return _key_may_be_workers(call.args[1])
        ''',
    )

    source = replace_function(
        source,
        "_update_builtins_exec_eval_assignment_aliases",
        r'''
        def _update_builtins_exec_eval_assignment_aliases(node, aliases, builtins_aliases):
            """Update direct exec/eval aliases for assignments in one statement."""
            for name, value in _namespace_assignment_values(node):
                if value is None:
                    aliases.discard(name)
                    continue
                if isinstance(value, ast.Name) and value.id in aliases:
                    aliases.add(name)
                elif _value_yields_exec_eval_resolver(value, builtins_aliases):
                    aliases.add(name)
                else:
                    aliases.discard(name)


        def _collect_builtins_exec_eval_alias_events(tree, builtins_aliases):
            """Track direct exec/eval aliases by source position."""
            aliases = set()
            events = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                line = getattr(node, "lineno", 0)
                for name in _builtins_exec_eval_import_aliases(node):
                    aliases.add(name)
                    events.setdefault(name, []).append((line, True))
                for name, value in _namespace_assignment_values(node):
                    active = bool(
                        value is not None
                        and (
                            (isinstance(value, ast.Name) and value.id in aliases)
                            or _value_yields_exec_eval_resolver(value, builtins_aliases)
                        )
                    )
                    if active:
                        aliases.add(name)
                        events.setdefault(name, []).append((line, True))
                    elif name in aliases or name in events:
                        aliases.discard(name)
                        events.setdefault(name, []).append((line, False))
            return events
        ''',
    )

    source = replace_function(
        source,
        "_collect_definite_exec_eval_shadow_lines",
        r'''
        def _collect_definite_exec_eval_shadow_lines(tree):
            """Return first top-level helper definition line shadowing builtin exec/eval."""
            shadows = {}
            for node in tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if node.name in _DYNAMIC_EXEC_EVAL_NAMES:
                    shadows.setdefault(node.name, node.lineno)
            return shadows


        def _collect_definite_name_shadow_line(tree, name):
            """Return the first unconditional top-level binding line for ``name``."""
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if node.name == name:
                        return getattr(node, "lineno", None)
                    continue
                if any(
                    bound_name == name
                    for bound_name, _value in _namespace_assignment_values(node)
                ):
                    return getattr(node, "lineno", None)
            return None
        ''',
    )

    source = replace_function(
        source,
        "_direct_name_is_builtin_exec_eval",
        r'''
        def _direct_name_is_builtin_exec_eval(
            func,
            call,
            shadow_lines,
            direct_aliases=None,
            direct_alias_events=None,
        ):
            """Return True when a direct name resolves to builtin exec/eval."""
            if not isinstance(func, ast.Name):
                return False
            if direct_alias_events and func.id in direct_alias_events:
                state = _binding_state_at_line(
                    direct_alias_events,
                    func.id,
                    getattr(call, "lineno", 0),
                )
                if state is not None:
                    return state
            if direct_aliases and func.id in direct_aliases:
                return True
            if func.id not in _DYNAMIC_EXEC_EVAL_NAMES:
                return False
            shadow_line = shadow_lines.get(func.id)
            call_line = getattr(call, "lineno", 0)
            return shadow_line is None or not call_line or shadow_line > call_line
        ''',
    )

    source = replace_function(
        source,
        "_collect_importlib_import_module_aliases",
        r'''
        def _collect_importlib_import_module_aliases(statements):
            """Collect names introduced by ``from importlib import import_module``."""
            aliases = set()
            for node in statements:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                aliases.update(_importlib_import_module_aliases(node))
                for block in _compound_statement_blocks(node):
                    aliases.update(_collect_importlib_import_module_aliases(block))
            return aliases


        def _collect_importlib_import_module_alias_events(tree):
            """Track top-level import_module aliases by source position."""
            active_aliases = set()
            events = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                line = getattr(node, "lineno", 0)
                for name in _importlib_import_module_aliases(node):
                    active_aliases.add(name)
                    events.setdefault(name, []).append((line, True))
                for name, _value in _namespace_assignment_values(node):
                    if name in active_aliases or name in events:
                        active_aliases.discard(name)
                        events.setdefault(name, []).append((line, False))
            return events
        ''',
    )

    source = replace_function(
        source,
        "_call_is_importlib_builtins_exec_eval",
        r'''
        def _call_is_importlib_builtins_exec_eval(
            call,
            importlib_aliases,
            importlib_alias_events=None,
        ):
            """Return True for ``import_module('builtins').exec/eval(...)`` calls."""
            if not isinstance(call, ast.Call):
                return False
            func = call.func
            if not isinstance(func, ast.Attribute) or func.attr not in _DYNAMIC_EXEC_EVAL_NAMES:
                return False
            base = func.value
            if not isinstance(base, ast.Call) or not isinstance(base.func, ast.Name):
                return False
            is_alias = base.func.id in importlib_aliases
            if importlib_alias_events and base.func.id in importlib_alias_events:
                state = _binding_state_at_line(
                    importlib_alias_events,
                    base.func.id,
                    getattr(call, "lineno", 0),
                )
                if state is not None:
                    is_alias = state
            if not is_alias or not base.args:
                return False
            module_name = base.args[0]
            return (
                isinstance(module_name, ast.Constant)
                and module_name.value == "builtins"
            )
        ''',
    )

    source = replace_function(
        source,
        "_call_is_dynamic_exec_eval",
        r'''
        def _call_is_dynamic_exec_eval(
            call,
            builtins_aliases=None,
            exec_eval_shadow_lines=None,
            direct_aliases=None,
            importlib_aliases=None,
            direct_alias_events=None,
            importlib_alias_events=None,
        ):
            """Return True for direct built-ins or known builtins-module calls."""
            if not isinstance(call, ast.Call):
                return False
            if builtins_aliases is None:
                builtins_aliases = set()
            if exec_eval_shadow_lines is None:
                exec_eval_shadow_lines = {}
            if direct_aliases is None:
                direct_aliases = set()
            if importlib_aliases is None:
                importlib_aliases = set()
            func = call.func
            return (
                _direct_name_is_builtin_exec_eval(
                    func,
                    call,
                    exec_eval_shadow_lines,
                    direct_aliases,
                    direct_alias_events,
                )
                or _getattr_is_dynamic_exec_eval(func, builtins_aliases)
                or _subscript_is_dynamic_exec_eval(func, builtins_aliases)
                or _attribute_is_dynamic_exec_eval(func, builtins_aliases)
                or _call_is_importlib_builtins_exec_eval(
                    call,
                    importlib_aliases,
                    importlib_alias_events,
                )
            )
        ''',
    )

    source = replace_function(
        source,
        "_lambda_param_namespace_mutation",
        r'''
        def _target_binds_name(target, name):
            """Return True when an assignment/comprehension target binds ``name``."""
            if isinstance(target, ast.Name):
                return target.id == name
            if isinstance(target, (ast.Tuple, ast.List)):
                return any(_target_binds_name(element, name) for element in target.elts)
            if isinstance(target, ast.Starred):
                return _target_binds_name(target.value, name)
            return False


        def _comprehension_param_namespace_mutation(node, param_name):
            """Scan a comprehension without crossing a target that shadows the parameter."""
            for generator in node.generators:
                if _lambda_param_namespace_mutation(generator.iter, param_name):
                    return True
                if _target_binds_name(generator.target, param_name):
                    return False
                if any(
                    _lambda_param_namespace_mutation(condition, param_name)
                    for condition in generator.ifs
                ):
                    return True
            if isinstance(node, ast.DictComp):
                return (
                    _lambda_param_namespace_mutation(node.key, param_name)
                    or _lambda_param_namespace_mutation(node.value, param_name)
                )
            return _lambda_param_namespace_mutation(node.elt, param_name)


        def _lambda_param_namespace_mutation(body, param_name):
            """Return True when a lambda body mutates ``param_name`` with a workers payload."""
            if isinstance(body, ast.Lambda):
                return False
            if isinstance(body, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                return _comprehension_param_namespace_mutation(body, param_name)
            if isinstance(body, ast.Call):
                func = body.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == param_name
                ):
                    if func.attr == "update":
                        return _update_payload_may_set_workers(body)
                    if func.attr in {"__ior__", "ior"}:
                        return bool(body.args) and _dict_merge_payload_may_set_workers(
                            body.args[0]
                        )
                    if func.attr == "__setitem__" and body.args:
                        return _key_may_be_workers(body.args[0])
                if isinstance(func, ast.Lambda):
                    if any(
                        _lambda_param_namespace_mutation(arg, param_name)
                        for arg in body.args
                    ) or any(
                        _lambda_param_namespace_mutation(keyword.value, param_name)
                        for keyword in body.keywords
                    ):
                        return True
                    if param_name in _lambda_bound_names(func):
                        return False
                    return _lambda_param_namespace_mutation(func.body, param_name)
            return any(
                _lambda_param_namespace_mutation(child, param_name)
                for child in ast.iter_child_nodes(body)
                if isinstance(child, ast.AST) and not isinstance(child, ast.Lambda)
            )
        ''',
    )

    source = replace_function(
        source,
        "_call_is_known_reduce_lambda_mutation",
        r'''
        def _call_is_known_reduce_lambda_mutation(call, operator_bindings):
            """Return True when a known ``functools.reduce`` invocation runs a risky lambda."""
            if (
                not isinstance(call, ast.Call)
                or not call.args
                or not isinstance(call.args[0], ast.Lambda)
            ):
                return False
            functools_aliases = operator_bindings[14] if len(operator_bindings) > 14 else set()
            reduce_aliases = operator_bindings[15] if len(operator_bindings) > 15 else set()
            func = call.func
            if isinstance(func, ast.Name):
                is_reduce = func.id in reduce_aliases
            else:
                is_reduce = (
                    isinstance(func, ast.Attribute)
                    and func.attr == "reduce"
                    and isinstance(func.value, ast.Name)
                    and func.value.id in functools_aliases
                )
            if not is_reduce:
                return False
            if _lambda_mutates_workers(call.args[0], operator_bindings):
                return True
            initializer = call.args[2] if len(call.args) >= 3 else None
            if initializer is None:
                initializer = next(
                    (
                        keyword.value
                        for keyword in call.keywords
                        if keyword.arg == "initial"
                    ),
                    None,
                )
            if initializer is None:
                return False
            namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
            if not _is_module_namespace_mapping(initializer, namespace_aliases):
                return False
            lambda_args = call.args[0].args.args
            if not lambda_args:
                return False
            return _lambda_param_namespace_mutation(
                call.args[0].body,
                lambda_args[0].arg,
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
            namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
            mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
            builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
            exec_eval_shadow_lines = operator_bindings[9] if len(operator_bindings) > 9 else {}
            direct_exec_eval_aliases = (
                operator_bindings[10] if len(operator_bindings) > 10 else set()
            )
            importlib_aliases = (
                operator_bindings[16] if len(operator_bindings) > 16 else set()
            )
            direct_exec_eval_alias_events = (
                operator_bindings[18] if len(operator_bindings) > 18 else {}
            )
            importlib_alias_events = (
                operator_bindings[19] if len(operator_bindings) > 19 else {}
            )
            delegated_update_alias_events = (
                operator_bindings[20] if len(operator_bindings) > 20 else {}
            )
            if isinstance(expr, ast.Call) and (
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
                or _call_mutates_workers_via_indirection(expr, operator_bindings)
                or _call_is_chainmap_maps_update(expr, namespace_aliases)
                or _call_is_delegated_simplenamespace_update(
                    expr,
                    operator_bindings[17] if len(operator_bindings) > 17 else set(),
                    delegated_update_alias_events,
                )
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
            if (
                _call_sets_workers_via_setitem(call)
                or _call_is_operator_setitem_workers(call, operator_bindings)
                or _call_is_getattr_setitem_workers(call)
                or _call_is_dict_type_setitem_on_module_namespace(
                    call,
                    namespace_aliases,
                    dict_shadow_line,
                )
                or _call_sets_workers_attribute(call, sys_aliases)
                or _call_is_dict_type_update_on_module_namespace(
                    call,
                    namespace_aliases,
                    dict_update_aliases,
                )
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
            dict_update_aliases = _collect_dict_update_aliases(tree)
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
            partial_workers_setter_aliases = _collect_partial_workers_setter_aliases(
                tree,
                namespace_aliases,
                partial_aliases,
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
            dict_shadow_line = _collect_definite_name_shadow_line(tree, "dict")
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
            )
        ''',
    )

    ast.parse(source)
    CONFIG_PATH.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    main()
