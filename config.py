import ast
import ipaddress
import os
import re
import shlex
import sys
from datetime import timedelta
from pathlib import Path

from session_store import shared_session_store_supported

_INSECURE_DEFAULTS = frozenset(
    {
        "change-me-to-a-random-value",
        "dev-insecure-secret-key",
        "change-me-to-a-secure-token",
        "password",
        "<generate-with-python3-secrets-token-hex-32>",
        "<generate-strong-password>",
        "<generate-with-openssl-rand-hex-32>",
    }
)
_MIN_SECRET_KEY_LEN = 32
_REQUIRE_LOGIN_TRUE = frozenset({"1", "true", "yes", "on"})
_REQUIRE_LOGIN_FALSE = frozenset({"0", "false", "no", "off"})

MIN_PASSWORD_LEN = 12
RATELIMIT_MEMORY_URI = "memory://"
_PROJECT_ROOT = Path(__file__).resolve().parent


def _bool(value, default=False):
    if value is None:
        return default
    stripped = str(value).strip()
    if not stripped:
        return default
    return stripped.lower() in _REQUIRE_LOGIN_TRUE


def _parse_require_login(value, default=True):
    """Parse REQUIRE_LOGIN; blank/unset uses default (True).

    Returns None when the value is set but not a recognized true/false token so
    startup validation can fail closed instead of silently disabling login.
    """
    if value is None:
        return default
    stripped = str(value).strip()
    if not stripped:
        return default
    lower = stripped.lower()
    if lower in _REQUIRE_LOGIN_TRUE:
        return True
    if lower in _REQUIRE_LOGIN_FALSE:
        return False
    return None


def _is_insecure_secret(value, *, min_length=0):
    """Reject missing, blank, known-default, or .env.example placeholder values."""
    if value is None:
        return True
    stripped = str(value).strip()
    if not stripped:
        return True
    if min_length and len(stripped) < min_length:
        return True
    if stripped.lower() in _INSECURE_DEFAULTS:
        return True
    return stripped.startswith("<") and stripped.endswith(">")


def _is_weak_panel_password(value):
    """Reject short or otherwise weak panel passwords when login is required."""
    if _is_insecure_secret(value):
        return True
    return len(str(value).strip()) < MIN_PASSWORD_LEN


def _parse_optional_bool(value):
    """Parse explicit true/false tokens; return None when unrecognized."""
    if value is None:
        return None
    stripped = str(value).strip()
    if not stripped:
        return None
    lower = stripped.lower()
    if lower in _REQUIRE_LOGIN_TRUE:
        return True
    if lower in _REQUIRE_LOGIN_FALSE:
        return False
    return None


_MIN_TRUSTED_PROXY_PREFIXLEN = {
    4: 2,  # reject /0 and /1 (split catch-alls that cover all of IPv4)
    6: 2,  # reject ::/0 and ::/1 (split catch-alls that cover all of IPv6)
}


def _is_overly_broad_proxy_network(network):
    """Return True for CIDR ranges broad enough to trust arbitrary clients."""
    min_prefix = _MIN_TRUSTED_PROXY_PREFIXLEN.get(network.version)
    if min_prefix is None:
        return False
    return network.prefixlen < min_prefix


def _proxy_networks_cover_entire_address_space(networks):
    """Return True when the configured union covers all of IPv4 or all of IPv6."""
    for version in (4, 6):
        same_version = [network for network in networks if network.version == version]
        if not same_version:
            continue
        if any(
            network.prefixlen == 0
            for network in ipaddress.collapse_addresses(same_version)
        ):
            return True
    return False


def _parse_trusted_proxy_entry(entry):
    """Parse and validate one TRUSTED_PROXY_IPS entry."""
    try:
        if "/" in entry:
            network = ipaddress.ip_network(entry, strict=False)
        else:
            parsed = ipaddress.ip_address(entry)
            prefix = 128 if parsed.version == 6 else 32
            network = ipaddress.ip_network(f"{parsed}/{prefix}", strict=False)
    except ValueError:
        _emit_config_error(
            "TRUSTED_PROXY_IPS contains an invalid IP address or CIDR range."
        )
        sys.exit(1)

    if _is_overly_broad_proxy_network(network):
        _emit_config_error(
            "TRUSTED_PROXY_IPS must list specific proxy IPs or CIDR ranges, "
            "not catch-all networks such as 0.0.0.0/0, 0.0.0.0/1, or ::/0. "
            "Overly broad ranges treat every direct client as a trusted proxy "
            "and allow X-Forwarded-For spoofing to bypass per-IP rate limits."
        )
        sys.exit(1)
    return network


def _validate_trusted_proxy_union(networks):
    """Reject trusted proxy networks whose union covers an entire IP version."""
    if not _proxy_networks_cover_entire_address_space(networks):
        return
    _emit_config_error(
        "TRUSTED_PROXY_IPS must not collectively cover the entire IPv4 or IPv6 "
        "address space. Trusting every direct client allows X-Forwarded-For "
        "spoofing to bypass per-IP rate limits."
    )
    sys.exit(1)


def _parse_trusted_proxy_networks(value):
    """Parse TRUSTED_PROXY_IPS into ip_network objects (IPs or CIDR ranges)."""
    if value is None:
        return []
    entries = (token.strip() for token in str(value).split(","))
    networks = [_parse_trusted_proxy_entry(entry) for entry in entries if entry]
    _validate_trusted_proxy_union(networks)
    return networks


def ip_in_trusted_proxy_networks(address, networks):
    """Return True when address belongs to a configured trusted proxy network."""
    if not address or not networks:
        return False
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def client_ip_for_rate_limit(
    *,
    direct_addr,
    forwarded_addr,
    trusted_proxy_count,
    trusted_networks,
):
    """Choose the client IP bucket for rate limiting.

    When forwarded headers are trusted only from known proxy IPs, direct clients
    cannot pick arbitrary X-Forwarded-For values to bypass per-IP limits.
    """
    if not trusted_proxy_count:
        return forwarded_addr
    if direct_addr and ip_in_trusted_proxy_networks(direct_addr, trusted_networks):
        return forwarded_addr
    if direct_addr:
        return direct_addr
    return forwarded_addr


def _session_cookie_secure_default():
    """Auto-detect from the panel's own public URL only — the API/stats URLs
    say nothing about whether the panel itself is served over HTTPS, and an
    explicit SESSION_COOKIE_SECURE always takes precedence over detection.
    """
    explicit = os.environ.get("SESSION_COOKIE_SECURE")
    if explicit is not None and explicit.strip() != "":
        parsed = _parse_optional_bool(explicit)
        if parsed is None:
            _emit_config_error(
                "SESSION_COOKIE_SECURE has an unrecognized value. "
                "Use True/False (or 1/0, yes/no, on/off)."
            )
            sys.exit(1)
        return parsed
    public_url = os.environ.get("PANEL_PUBLIC_URL", "").strip().lower()
    if public_url.startswith("https://"):
        return True
    if public_url.startswith("http://"):  # NOSONAR python:S5332 -- scheme check, not a network call
        return False
    trusted_proxy_count = _parse_positive_int(
        os.environ.get("TRUSTED_PROXY_COUNT"),
        default=0,
        min_value=0,
        max_value=10,
        name="TRUSTED_PROXY_COUNT",
    )
    return trusted_proxy_count > 0


def _parse_positive_int(value, default, *, min_value=1, max_value=10_000, name="value"):
    if value is None:
        return default
    stripped = str(value).strip()
    if not stripped:
        return default
    try:
        parsed = int(stripped)
    except ValueError:
        _emit_config_error(f"{name} must be an integer between {min_value} and {max_value}.")
        sys.exit(1)
    if not min_value <= parsed <= max_value:
        _emit_config_error(f"{name} must be between {min_value} and {max_value}.")
        sys.exit(1)
    return parsed


def _emit_config_error(message: str) -> None:
    """Emit a startup config error without interpolating sensitive env values."""
    sys.stderr.write("CONFIG ERROR: ")
    sys.stderr.write(message)
    sys.stderr.write("\n")


def _parse_worker_count(value):
    """Return a positive integer-looking worker count, or None."""
    return int(value) if value.isdigit() else None


def _worker_count_from_compact_token(token):
    """Parse --workers=N, -w=N, and -wN forms."""
    if token.startswith(("--workers=", "-w=")):
        return _parse_worker_count(token.split("=", 1)[1])
    if token.startswith("-w") and len(token) > 2:
        return _parse_worker_count(token[2:])
    return None


def _worker_count_override_from_tokens(tokens: list[str]) -> int | None:
    """Return the last explicit Gunicorn workers setting in ``tokens``."""
    count = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in ("--workers", "-w") and i + 1 < len(tokens):
            parsed = _parse_worker_count(tokens[i + 1])
            if parsed is not None:
                count = parsed
                i += 2
                continue
        parsed = _worker_count_from_compact_token(token)
        if parsed is not None:
            count = parsed
        i += 1
    return count


def _workers_from_command_tokens(tokens: list[str]) -> int:
    """Parse Gunicorn `-w` / `--workers` flags from a token list."""
    return _worker_count_override_from_tokens(tokens) or 1


def _static_int_from_ast(node):
    """Return an integer literal from a gunicorn config assignment, if static."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _resolve_gunicorn_config_path(config_path: str) -> Path | None:
    """Return the exact Gunicorn config path when it resolves to a regular file."""
    if not config_path or "\0" in config_path:
        return None
    try:
        candidate = Path(config_path)
        resolved = (
            (_PROJECT_ROOT / candidate).resolve()
            if not candidate.is_absolute()
            else candidate.resolve()
        )
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _target_assigns_workers(node):
    """Return True when an assignment target binds the ``workers`` name."""
    if isinstance(node, ast.Name):
        return node.id == "workers"
    if isinstance(node, ast.Tuple):
        return any(_target_assigns_workers(element) for element in node.elts)
    if isinstance(node, ast.List):
        return any(_target_assigns_workers(element) for element in node.elts)
    if isinstance(node, ast.Starred):
        return _target_assigns_workers(node.value)
    return False


def _subscript_slice_is_workers(node):
    """Return True when a subscript uses the literal ``'workers'`` key."""
    if not isinstance(node, ast.Subscript):
        return False
    slice_node = node.slice
    if isinstance(slice_node, ast.Constant):
        return slice_node.value == "workers"
    return False


def _subscript_slice_is_update(node):
    """Return True when a subscript uses the literal ``'update'`` key."""
    if not isinstance(node, ast.Subscript):
        return False
    slice_node = node.slice
    if isinstance(slice_node, ast.Constant):
        return slice_node.value == "update"
    return False


def _subscript_base_node(node):
    """Return the mapping/base expression behind a subscript lookup."""
    if not isinstance(node, ast.Subscript):
        return None
    value = node.value
    if isinstance(value, ast.NamedExpr):
        return value.value
    return value


def _is_globals_call(node):
    """Return True for a direct ``globals()`` call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "globals"
        and not node.args
        and not node.keywords
    )


def _globals_workers_subscript(node):
    """Return True for ``globals()['workers']``-style subscript targets."""
    return _subscript_slice_is_workers(node) and _is_globals_call(node.value)


def _dict_literal_sets_workers(node):
    """Return True when a dict literal may introduce a ``workers`` key."""
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values):
        if key is None:
            if not isinstance(value, ast.Dict) or _dict_literal_sets_workers(value):
                return True
            continue
        if not isinstance(key, ast.Constant):
            # A computed key cannot be proven different from ``workers``.
            return True
        if key.value == "workers":
            return True
    return False


def _dict_merge_payload_may_set_workers(node):
    """Return True when a dict-merge RHS may introduce a ``workers`` binding."""
    if isinstance(node, ast.Dict):
        return _dict_literal_sets_workers(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (
            _dict_merge_payload_may_set_workers(node.left)
            or _dict_merge_payload_may_set_workers(node.right)
        )
    return True


def _namespace_mapping_may_gain_workers_via_merge(node, namespace_aliases):
    """Return True for ``namespace |= {{...}}`` / ``__dict__ |= {{...}}`` patterns."""
    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr):
        target = node.target
        if _is_module_namespace_mapping(target, namespace_aliases):
            return _dict_merge_payload_may_set_workers(node.value)
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "__dict__"
                and _is_current_module_reference(target.value)
            ):
                return _dict_merge_payload_may_set_workers(node.value)
    return False


def _is_current_module_reference(node):
    """Return True for expressions that resolve to this config module."""
    if not isinstance(node, ast.Subscript):
        return False
    if not isinstance(node.slice, ast.Name) or node.slice.id != "__name__":
        return False
    modules = node.value
    if not isinstance(modules, ast.Attribute) or modules.attr != "modules":
        return False
    root = modules.value
    if isinstance(root, ast.Name) and root.id == "sys":
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


def _is_module_namespace_mapping(node, namespace_aliases=None):
    """Return True for mappings known to be the current module namespace."""
    if namespace_aliases is None:
        namespace_aliases = set()
    if isinstance(node, ast.Name) and node.id in namespace_aliases:
        return True
    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        return _is_module_namespace_mapping(node.value, namespace_aliases)
    if _is_globals_call(node):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _is_current_module_reference(node.value)
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id == "vars":
        return (
            len(node.args) == 1
            and not node.keywords
            and _is_current_module_reference(node.args[0])
        )
    if node.func.id == "getattr":
        return (
            len(node.args) == 2
            and not node.keywords
            and _is_current_module_reference(node.args[0])
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "__dict__"
        )
    return False


def _update_payload_may_set_workers(call, start_index=0):
    """Return True when an update payload may assign the ``workers`` key."""
    for arg in call.args[start_index:]:
        if isinstance(arg, ast.Dict):
            if _dict_literal_sets_workers(arg):
                return True
            continue
        # Mapping/call/iterable payloads cannot be proven to omit workers.
        return True
    for keyword in call.keywords:
        if keyword.arg is None or keyword.arg == "workers":
            return True
    return False


def _call_is_module_namespace_workers_update(call, namespace_aliases=None):
    """Return True when module namespace ``update`` may change workers."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
        return False
    if not _is_module_namespace_mapping(call.func.value, namespace_aliases):
        return False
    return _update_payload_may_set_workers(call)


def _call_is_module_namespace_workers_ior(call, namespace_aliases=None):
    """Return True when module namespace ``__ior__`` may change workers."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "__ior__":
        return False
    if not _is_module_namespace_mapping(call.func.value, namespace_aliases):
        return False
    if not call.args:
        return False
    return _dict_merge_payload_may_set_workers(call.args[0])


def _is_dict_type_update_callable(func, aliases=None):
    """Return True for ``dict.update`` or a proven alias of it."""
    if aliases is None:
        aliases = set()
    if isinstance(func, ast.Name):
        return func.id in aliases
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


def _values_are_dict_update_aliases(values, aliases):
    """Return True when every assignment resolves to unbound ``dict.update``."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_dict_type_update_callable(value, aliases) for value in resolved_values
    )


def _collect_dict_update_aliases(tree):
    """Collect transitive aliases that are always bound to ``dict.update``."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_dict_update_aliases(assignments[name], aliases)
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases


def _call_is_dict_type_update_on_module_namespace(
    call,
    namespace_aliases=None,
    update_aliases=None,
):
    """Return True for ``dict.update(globals(), ...)`` style mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    if not _is_dict_type_update_callable(call.func, update_aliases):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _update_payload_may_set_workers(call, start_index=1)


def _methodcaller_method_name(call):
    """Return the method name passed to ``operator.methodcaller``, if static."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    method = call.args[0]
    if isinstance(method, ast.Constant) and isinstance(method.value, str):
        return method.value
    return None


def _is_operator_methodcaller_factory(call, module_aliases, methodcaller_aliases):
    """Return True for an imported ``operator.methodcaller(...)`` factory call."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in methodcaller_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "methodcaller"
        and isinstance(func.value, ast.Name)
        and func.value.id in module_aliases
    )


def _key_may_be_workers(node):
    """Return True unless a literal key is provably different from ``workers``."""
    return not isinstance(node, ast.Constant) or node.value == "workers"


def _call_is_operator_methodcaller_on_module_namespace(
    call,
    operator_bindings,
    namespace_aliases=None,
):
    """Return True for ``operator.methodcaller(...)(globals())`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    module_aliases, _, _, _, _ = _unpack_operator_bindings(operator_bindings)
    methodcaller_aliases = operator_bindings[6] if len(operator_bindings) > 6 else set()
    factory = call.func
    if not _is_operator_methodcaller_factory(
        factory,
        module_aliases,
        methodcaller_aliases,
    ):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    method = _methodcaller_method_name(factory)
    if method == "update":
        return _update_payload_may_set_workers(factory, start_index=1)
    if method == "__ior__":
        return len(factory.args) >= 2 and _dict_merge_payload_may_set_workers(
            factory.args[1]
        )
    if method == "__setitem__":
        return len(factory.args) >= 3 and _key_may_be_workers(factory.args[1])
    return method is None


def _namedexpr_assignment_values(expr):
    """Return evaluated walrus name/value pairs, excluding lambda scopes."""
    if isinstance(expr, ast.Lambda):
        return []
    values = []
    if isinstance(expr, ast.NamedExpr) and isinstance(expr.target, ast.Name):
        values.append((expr.target.id, expr.value))
    for child in ast.iter_child_nodes(expr):
        values.extend(_namedexpr_assignment_values(child))
    return values


def _namespace_assignment_values(node):
    """Return simple name assignments relevant to namespace alias tracking."""
    if isinstance(node, ast.Assign):
        values = [
            (target.id, node.value)
            for target in node.targets
            if isinstance(target, ast.Name)
        ]
        values.extend(_namedexpr_assignment_values(node.value))
        return values
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        values = [(node.target.id, node.value)]
        if node.value is not None:
            values.extend(_namedexpr_assignment_values(node.value))
        return values
    if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        return [(node.target.id, None), *_namedexpr_assignment_values(node.value)]
    if isinstance(node, ast.Expr):
        return _namedexpr_assignment_values(node.value)
    return []


def _record_module_namespace_assignments(statements, assignments):
    """Collect module-level assignments, including compound statement bodies."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for name, value in _namespace_assignment_values(node):
            assignments.setdefault(name, []).append(value)
        for block in _compound_statement_blocks(node):
            _record_module_namespace_assignments(block, assignments)


def _values_are_module_namespace_aliases(values, aliases):
    """Return True when every assignment resolves to the module namespace."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_module_namespace_mapping(value, aliases) for value in resolved_values
    )


def _resolve_module_namespace_aliases(assignments):
    """Resolve aliases transitively until no additional names can be proven."""
    aliases = set()
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_module_namespace_aliases(assignments[name], aliases)
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases


def _collect_module_namespace_aliases(tree):
    """Collect names that are always assigned a module namespace mapping."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    return _resolve_module_namespace_aliases(assignments)


def _constant_is_workers(node):
    return isinstance(node, ast.Constant) and node.value == "workers"


def _call_sets_workers_via_setitem(call):
    """Return True for ``__setitem__('workers', ...)`` style mutations."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "__setitem__":
        return False
    if not call.args:
        return False
    return _constant_is_workers(call.args[0])


def _call_is_operator_setitem_workers(call, operator_bindings):
    """Return True for imported ``operator.setitem(globals(), 'workers', ...)``."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    if not _is_globals_call(call.args[0]) or not _constant_is_workers(call.args[1]):
        return False

    module_aliases, setitem_aliases = operator_bindings[:2]
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "setitem":
        return isinstance(func.value, ast.Name) and func.value.id in module_aliases
    return isinstance(func, ast.Name) and func.id in setitem_aliases


def _call_is_getattr_setitem_workers(call):
    """Return True for ``getattr(globals(), '__setitem__')('workers', ...)``."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    func = call.func
    if not isinstance(func, ast.Call) or len(func.args) < 2:
        return False
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return False
    if not _is_globals_call(func.args[0]):
        return False
    attr = func.args[1]
    if not isinstance(attr, ast.Constant) or attr.value != "__setitem__":
        return False
    return _constant_is_workers(call.args[0])


_NAMESPACE_GETATTR_METHODS = frozenset({"update", "__ior__", "__setitem__"})
_DYNAMIC_EXEC_EVAL_NAMES = frozenset({"exec", "eval"})


def _unpack_operator_bindings(operator_bindings):
    """Return operator/functools aliases and module namespace aliases."""
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    setitem_aliases = operator_bindings[1] if len(operator_bindings) > 1 else set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    ior_aliases = operator_bindings[3] if len(operator_bindings) > 3 else set()
    partial_aliases = operator_bindings[4] if len(operator_bindings) > 4 else set()
    return (
        module_aliases,
        setitem_aliases,
        namespace_aliases,
        ior_aliases,
        partial_aliases,
    )


def _is_builtins_import(node):
    """Return True for ``__import__('builtins')``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "builtins"
        and not node.keywords
    )


def _values_are_builtins_aliases(values, aliases):
    """Return True when any assignment may bind the name to builtins."""
    resolved_values = [value for value in values if value is not None]
    return any(
        _is_builtins_import(value)
        or (isinstance(value, ast.Name) and value.id in aliases)
        for value in resolved_values
    )


def _collect_builtins_import_aliases(statements):
    """Collect import-time names introduced by ``import builtins``."""
    aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "builtins":
                    aliases.add(imported.asname or imported.name)
        for block in _compound_statement_blocks(node):
            aliases.update(_collect_builtins_import_aliases(block))
    return aliases


def _collect_builtins_exec_eval_aliases(statements):
    """Collect direct aliases that may resolve to builtin exec/eval."""
    aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for imported in node.names:
                if imported.name in _DYNAMIC_EXEC_EVAL_NAMES:
                    aliases.add(imported.asname or imported.name)
        for name, value in _namespace_assignment_values(node):
            if value is not None and isinstance(value, ast.Name) and value.id in aliases:
                aliases.add(name)
            elif name in aliases:
                aliases.discard(name)
        for block in _compound_statement_blocks(node):
            aliases.update(_collect_builtins_exec_eval_aliases(block))
    return aliases


def _collect_builtins_aliases(tree):
    """Collect names that can resolve to the builtins module at import time."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    # Keep explicit import aliases even when the same name was assigned too. Mixed
    # bindings are intentionally treated conservatively so dynamic exec/eval cannot
    # evade the multi-worker guard through assignment ordering.
    aliases = _collect_builtins_import_aliases(tree.body)
    unresolved = set(assignments)
    while unresolved:
        discovered = {
            name
            for name in unresolved
            if _values_are_builtins_aliases(assignments[name], aliases)
        }
        if not discovered:
            break
        aliases.update(discovered)
        unresolved.difference_update(discovered)
    return aliases


def _collect_definite_exec_eval_shadow_lines(tree):
    """Return first top-level helper definition line shadowing builtin exec/eval."""
    shadows = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.name in _DYNAMIC_EXEC_EVAL_NAMES:
            shadows.setdefault(node.name, node.lineno)
    return shadows


def _is_known_builtins_module(node, builtins_aliases):
    """Return True when an expression is known to resolve to ``builtins``."""
    return _is_builtins_import(node) or (
        isinstance(node, ast.Name) and node.id in builtins_aliases
    )


def _constant_is_exec_eval(node):
    """Return True for a literal ``exec`` or ``eval`` lookup key."""
    return isinstance(node, ast.Constant) and node.value in _DYNAMIC_EXEC_EVAL_NAMES


def _getattr_is_dynamic_exec_eval(func, builtins_aliases):
    """Return True for ``getattr(builtins, 'exec'/'eval')`` callables."""
    return (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and _is_known_builtins_module(func.args[0], builtins_aliases)
        and _constant_is_exec_eval(func.args[1])
    )


def _subscript_is_dynamic_exec_eval(func, builtins_aliases):
    """Return True for ``builtins.__dict__['exec'/'eval']`` callables."""
    if not isinstance(func, ast.Subscript):
        return False
    base = _subscript_base_node(func)
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "__dict__"
        and _is_known_builtins_module(base.value, builtins_aliases)
        and _constant_is_exec_eval(func.slice)
    )


def _attribute_is_dynamic_exec_eval(func, builtins_aliases):
    """Return True for ``builtins.exec`` / ``builtins.eval`` callables."""
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _DYNAMIC_EXEC_EVAL_NAMES
        and _is_known_builtins_module(func.value, builtins_aliases)
    )


def _direct_name_is_builtin_exec_eval(
    func,
    call,
    shadow_lines,
    direct_aliases=None,
):
    """Return True when a direct name resolves to builtin exec/eval."""
    if not isinstance(func, ast.Name):
        return False
    if direct_aliases and func.id in direct_aliases:
        return True
    if func.id not in _DYNAMIC_EXEC_EVAL_NAMES:
        return False
    shadow_line = shadow_lines.get(func.id)
    call_line = getattr(call, "lineno", 0)
    return shadow_line is None or not call_line or shadow_line > call_line


def _call_is_dynamic_exec_eval(
    call,
    builtins_aliases=None,
    exec_eval_shadow_lines=None,
    direct_aliases=None,
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
    func = call.func
    return (
        _direct_name_is_builtin_exec_eval(
            func,
            call,
            exec_eval_shadow_lines,
            direct_aliases,
        )
        or _getattr_is_dynamic_exec_eval(func, builtins_aliases)
        or _subscript_is_dynamic_exec_eval(func, builtins_aliases)
        or _attribute_is_dynamic_exec_eval(func, builtins_aliases)
    )


def _attribute_is_namespace_setitem(node, namespace_aliases=None):
    """Return True for a module namespace ``__setitem__`` attribute."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__setitem__"
        and _is_module_namespace_mapping(node.value, namespace_aliases)
    )


def _getattr_namespace_mutator_method(func, namespace_aliases=None):
    """Return a recognized mutator name from a module namespace callable."""
    if isinstance(func, ast.Attribute):
        if (
            func.attr in _NAMESPACE_GETATTR_METHODS
            and _is_module_namespace_mapping(func.value, namespace_aliases)
        ):
            return func.attr
        return None
    if not isinstance(func, ast.Call):
        return None
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return None
    if len(func.args) < 2 or not _is_module_namespace_mapping(
        func.args[0], namespace_aliases
    ):
        return None
    key = func.args[1]
    if not isinstance(key, ast.Constant) or key.value not in _NAMESPACE_GETATTR_METHODS:
        return None
    return key.value


def _namespace_mutator_call_may_set_workers(method, call):
    """Return True when the namespace mutator call may bind workers."""
    if method == "update":
        return _update_payload_may_set_workers(call)
    if method == "__ior__":
        return bool(call.args) and _dict_merge_payload_may_set_workers(call.args[0])
    if method == "__setitem__":
        return len(call.args) >= 2 and _constant_is_workers(call.args[0])
    return False


def _call_is_getattr_namespace_workers_mutation(
    call,
    namespace_aliases=None,
    mutator_aliases=None,
):
    """Return True for direct or saved namespace mutator callables."""
    if not isinstance(call, ast.Call):
        return False
    method = None
    if isinstance(call.func, ast.Name) and mutator_aliases:
        method = mutator_aliases.get(call.func.id)
    if method is None:
        method = _getattr_namespace_mutator_method(call.func, namespace_aliases)
    return method is not None and _namespace_mutator_call_may_set_workers(
        method, call
    )


def _collect_namespace_mutator_aliases(tree, namespace_aliases):
    """Collect names that are always bound to one namespace mutator."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = {}
    for name, values in assignments.items():
        methods = [
            _getattr_namespace_mutator_method(value, namespace_aliases)
            if value is not None
            else None
            for value in values
        ]
        if methods and methods[0] is not None and all(
            method == methods[0] for method in methods
        ):
            aliases[name] = methods[0]
    return aliases


def _call_is_operator_namespace_ior(call, operator_bindings):
    """Return True for ``operator.ior(globals(), {'workers': ...})`` style calls."""
    module_aliases, _, namespace_aliases, ior_aliases, _ = _unpack_operator_bindings(
        operator_bindings
    )
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    func = call.func
    if isinstance(func, ast.Name):
        if func.id not in ior_aliases:
            return False
    elif isinstance(func, ast.Attribute) and func.attr in {"ior", "__ior__"}:
        if not isinstance(func.value, ast.Name) or func.value.id not in module_aliases:
            return False
    else:
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _dict_merge_payload_may_set_workers(call.args[1])


def _call_is_partial_bound_workers_setitem(call, operator_bindings):
    """Return True for ``partial(namespace.__setitem__, 'workers')(value)``."""
    _, _, namespace_aliases, _, partial_aliases = _unpack_operator_bindings(
        operator_bindings
    )
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not isinstance(func, ast.Call):
        return False
    partial_func = func.func
    if isinstance(partial_func, ast.Name):
        is_partial = partial_func.id in partial_aliases
    else:
        is_partial = (
            isinstance(partial_func, ast.Attribute)
            and partial_func.attr == "partial"
            and isinstance(partial_func.value, ast.Name)
            and partial_func.value.id in partial_aliases
        )
    if not is_partial or len(func.args) < 2:
        return False
    if not _attribute_is_namespace_setitem(func.args[0], namespace_aliases):
        return False
    return _constant_is_workers(func.args[1])


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
    if isinstance(expr, ast.Call) and (
        _call_is_dynamic_exec_eval(
            expr,
            builtins_aliases,
            exec_eval_shadow_lines,
            direct_exec_eval_aliases,
        )
        or _call_is_module_namespace_workers_update(expr, namespace_aliases)
        or _call_is_module_namespace_workers_ior(expr, namespace_aliases)
        or _call_is_getattr_namespace_workers_mutation(
            expr, namespace_aliases, mutator_aliases
        )
        or _call_is_operator_namespace_ior(expr, operator_bindings)
        or _call_is_partial_bound_workers_setitem(expr, operator_bindings)
        or _call_mutates_workers_via_indirection(expr, operator_bindings)
    ):
        return True
    return any(
        _expression_mutates_workers(child, operator_bindings)
        for child in ast.iter_child_nodes(expr)
    )


def _lambda_mutates_workers(lambda_node, operator_bindings):
    """Return True when an invoked lambda body mutates ``workers`` indirectly."""
    return isinstance(lambda_node, ast.Lambda) and _expression_mutates_workers(
        lambda_node.body, operator_bindings
    )


def _call_is_subscript_namespace_workers_update(
    call,
    namespace_aliases=None,
    mutator_aliases=None,
):
    """Return True for a proven namespace-update alias read through a subscript."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not isinstance(func, ast.Subscript) or not _subscript_slice_is_update(func):
        return False
    if not mutator_aliases or mutator_aliases.get("update") != "update":
        return False
    base = _subscript_base_node(func)
    if not _is_module_namespace_mapping(base, namespace_aliases):
        return False
    return _update_payload_may_set_workers(call)


def _call_mutates_workers_via_indirection(call, operator_bindings):
    """Return True for indirect import-time ``workers`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    if (
        _call_sets_workers_via_setitem(call)
        or _call_is_operator_setitem_workers(call, operator_bindings)
        or _call_is_getattr_setitem_workers(call)
        or _call_sets_workers_attribute(call)
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
    return isinstance(call.func, ast.Lambda) and _lambda_mutates_workers(
        call.func, operator_bindings
    )


def _call_sets_workers_attribute(call):
    """Return True for setattr/object.__setattr__ calls that bind ``workers``."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    key = call.args[1]
    if not isinstance(key, ast.Constant) or key.value != "workers":
        return False
    func = call.func
    if isinstance(func, ast.Name) and func.id == "setattr":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "__setattr__"


def _import_from_binds_workers(node):
    """Return True when an import statement may define ``workers`` indirectly."""
    if not isinstance(node, ast.ImportFrom):
        return False
    return any(
        alias.name == "*" or (alias.asname or alias.name) == "workers"
        for alias in node.names
    )


def _worker_assignment_value(node):
    """Return whether node assigns workers and its static value when available."""
    if isinstance(node, ast.Assign):
        targets_workers = any(
            _target_assigns_workers(target) or _globals_workers_subscript(target)
            for target in node.targets
        )
        if not targets_workers:
            return False, None
        return True, _static_int_from_ast(node.value)

    if isinstance(node, ast.AnnAssign) and node.target and (
        _target_assigns_workers(node.target) or _globals_workers_subscript(node.target)
    ):
        return True, _static_int_from_ast(node.value)

    if isinstance(node, ast.AugAssign) and (
        _target_assigns_workers(node.target) or _globals_workers_subscript(node.target)
    ):
        return True, None

    if isinstance(node, ast.NamedExpr) and _target_assigns_workers(node.target):
        return True, _static_int_from_ast(node.value)

    return False, None


def _indirect_workers_assignment_target(node):
    """Return True when an assignment target may mutate a ``workers`` binding indirectly."""
    return _subscript_slice_is_workers(node) or (
        isinstance(node, ast.Attribute) and node.attr == "workers"
    )


def _is_dynamic_workers_mutation(node, operator_bindings):
    """Return True for import-time mutations the AST scan cannot treat as static."""
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if _namespace_mapping_may_gain_workers_via_merge(node, namespace_aliases):
        return True

    if any(
        isinstance(child, ast.expr)
        and _expression_mutates_workers(child, operator_bindings)
        for child in ast.iter_child_nodes(node)
    ):
        return True

    if isinstance(node, ast.Assign):
        return any(_indirect_workers_assignment_target(target) for target in node.targets)

    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return _indirect_workers_assignment_target(node.target)

    return False


def _statements_declare_global_workers(statements):
    """Return True when this function scope declares ``global workers``."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Global) and "workers" in node.names:
            return True
        for block in _compound_statement_blocks(node):
            if _statements_declare_global_workers(block):
                return True
    return False


def _expression_invokes_function(expr, func_names):
    """Return True when an evaluated expression invokes a named helper."""
    if not func_names or isinstance(expr, ast.Lambda):
        return False
    if isinstance(expr, ast.Call):
        if _call_invokes_function(expr, func_names):
            return True
        if isinstance(expr.func, ast.Lambda) and _expression_invokes_function(
            expr.func.body, func_names
        ):
            return True
    return any(
        _expression_invokes_function(child, func_names)
        for child in ast.iter_child_nodes(expr)
    )


def _statement_invokes_function(node, func_names):
    """Return True when expressions evaluated by this statement invoke a helper."""
    if not func_names:
        return False
    return any(
        isinstance(child, ast.expr)
        and _expression_invokes_function(child, func_names)
        for child in ast.iter_child_nodes(node)
    )


def _statement_mutates_workers(
    node,
    operator_bindings,
    *,
    global_workers,
    mutator_names,
):
    """Return True when one statement may mutate the module ``workers`` binding."""
    if _statement_invokes_function(node, mutator_names):
        return True
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if _is_dynamic_workers_mutation(node, operator_bindings):
        return True
    assigns_workers, _ = _worker_assignment_value(node)
    if global_workers and assigns_workers:
        return True
    return any(
        _statements_mutate_workers(
            block,
            operator_bindings,
            global_workers=global_workers,
            mutator_names=mutator_names,
        )
        for block in _compound_statement_blocks(node)
    )


def _statements_mutate_workers(
    statements,
    operator_bindings,
    *,
    global_workers=False,
    mutator_names=None,
):
    """Return True when statements may mutate the module ``workers`` binding."""
    if mutator_names is None:
        mutator_names = set()
    return any(
        _statement_mutates_workers(
            node,
            operator_bindings,
            global_workers=global_workers,
            mutator_names=mutator_names,
        )
        for node in statements
    )


def _function_mutates_workers(func_node, operator_bindings, mutator_names=None):
    """Return True when a function may mutate the module ``workers`` binding."""
    has_global_workers = _statements_declare_global_workers(func_node.body)
    return _statements_mutate_workers(
        func_node.body,
        operator_bindings,
        global_workers=has_global_workers,
        mutator_names=mutator_names,
    )


def _call_invokes_function(call_node, func_names):
    """Return True when ``call_node`` invokes one of ``func_names``."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id in func_names
    return False


def _collect_import_time_workers_mutators(tree, operator_bindings):
    """Return function names that may mutate ``workers`` when called at import time."""
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    mutators = set()
    changed = True
    while changed:
        changed = False
        for name, node in functions.items():
            if name in mutators:
                continue
            if _function_mutates_workers(node, operator_bindings, mutators):
                mutators.add(name)
                changed = True
    return mutators


def _parse_gunicorn_config_tree(path):
    """Parse a Gunicorn config file into an AST, or return None if unreadable."""
    try:
        # The path comes only from Gunicorn's process startup arguments/environment,
        # not from an HTTP request. Service-managed absolute configs (for example
        # /etc/gunicorn.conf.py) must be inspected to enforce multi-worker guards.
        source = path.read_text(encoding="utf-8")  # NOSONAR pythonsecurity:S8707
        return ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return None


class _GunicornWorkersScanState:
    """Mutable scan state for gunicorn config worker assignments."""

    count = 1
    dynamic = False
    found = False

    def record_workers_assignment(self, value, *, in_compound: bool) -> None:
        self.found = True
        if in_compound or value is None or value < 1:
            self.dynamic = True
        elif not self.dynamic:
            self.count = value


def _compound_statement_blocks(node):
    """Yield statement lists from compound statement bodies."""
    if isinstance(node, ast.If):
        yield node.body
        yield node.orelse
    elif isinstance(node, ast.For):
        yield node.body
    elif isinstance(node, ast.While):
        yield node.body
    elif isinstance(node, ast.With):
        yield node.body
    elif isinstance(node, ast.Try):
        yield node.body
        for handler in node.handlers:
            yield handler.body
        yield node.orelse
        yield node.finalbody
    elif isinstance(node, ast.Match):
        for case in node.cases:
            yield case.body


def _record_relevant_import_aliases(names, destinations):
    """Record matching import aliases into their destination sets."""
    for alias in names:
        destination = destinations.get(alias.name)
        if destination is not None:
            destination.add(alias.asname or alias.name)


def _record_operator_import(
    node,
    module_aliases,
    setitem_aliases,
    ior_aliases,
    partial_aliases,
    methodcaller_aliases,
):
    """Record operator/functools aliases introduced by one statement."""
    if isinstance(node, ast.Import):
        _record_relevant_import_aliases(
            node.names,
            {
                "operator": module_aliases,
                "functools": partial_aliases,
            },
        )
        return
    if not isinstance(node, ast.ImportFrom):
        return
    destinations = {
        "operator": {
            "setitem": setitem_aliases,
            "ior": ior_aliases,
            "methodcaller": methodcaller_aliases,
        },
        "functools": {"partial": partial_aliases},
    }.get(node.module)
    if destinations is None:
        return
    _record_relevant_import_aliases(node.names, destinations)


def _collect_operator_bindings_from_statements(
    statements,
    module_aliases,
    setitem_aliases,
    ior_aliases,
    partial_aliases,
    methodcaller_aliases,
):
    """Walk import-time statements and collect operator/functools aliases."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        _record_operator_import(
            node,
            module_aliases,
            setitem_aliases,
            ior_aliases,
            partial_aliases,
            methodcaller_aliases,
        )
        for block in _compound_statement_blocks(node):
            _collect_operator_bindings_from_statements(
                block,
                module_aliases,
                setitem_aliases,
                ior_aliases,
                partial_aliases,
                methodcaller_aliases,
            )


def _collect_operator_setitem_bindings(tree):
    """Collect aliases used by operator and module-namespace mutation scans."""
    module_aliases = set()
    setitem_aliases = set()
    ior_aliases = set()
    partial_aliases = set()
    methodcaller_aliases = set()
    _collect_operator_bindings_from_statements(
        tree.body,
        module_aliases,
        setitem_aliases,
        ior_aliases,
        partial_aliases,
        methodcaller_aliases,
    )
    namespace_aliases = _collect_module_namespace_aliases(tree)
    mutator_aliases = _collect_namespace_mutator_aliases(tree, namespace_aliases)
    dict_update_aliases = _collect_dict_update_aliases(tree)
    builtins_aliases = _collect_builtins_aliases(tree)
    exec_eval_shadow_lines = _collect_definite_exec_eval_shadow_lines(tree)
    direct_exec_eval_aliases = _collect_builtins_exec_eval_aliases(tree.body)
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
    )


def _node_has_dynamic_workers_effect(node, global_workers_mutators, operator_bindings):
    """Return True when one statement makes the worker value non-static."""
    if _statement_invokes_function(node, global_workers_mutators):
        return True
    if isinstance(node, ast.For) and _target_assigns_workers(node.target):
        return True
    if _is_dynamic_workers_mutation(node, operator_bindings):
        return True
    return _import_from_binds_workers(node)


def _record_walrus_workers_assignment(node, state, *, in_compound):
    """Record a top-level expression using ``workers := ...`` when present."""
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.NamedExpr):
        return
    walrus = node.value
    if not _target_assigns_workers(walrus.target):
        return
    state.dynamic = True
    state.record_workers_assignment(
        _static_int_from_ast(walrus.value),
        in_compound=in_compound,
    )


def _record_direct_workers_assignment(node, state, *, in_compound):
    """Record direct assignments to workers."""
    assigns_workers, value = _worker_assignment_value(node)
    if assigns_workers:
        state.record_workers_assignment(value, in_compound=in_compound)


def _walk_gunicorn_workers_statements(
    statements,
    state,
    *,
    in_compound: bool,
    global_workers_mutators=None,
    operator_bindings=None,
) -> None:
    if global_workers_mutators is None:
        global_workers_mutators = set()
    if operator_bindings is None:
        operator_bindings = (set(), set())

    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if _node_has_dynamic_workers_effect(
            node,
            global_workers_mutators,
            operator_bindings,
        ):
            state.dynamic = True
        _record_walrus_workers_assignment(node, state, in_compound=in_compound)
        _record_direct_workers_assignment(node, state, in_compound=in_compound)
        for block in _compound_statement_blocks(node):
            _walk_gunicorn_workers_statements(
                block,
                state,
                in_compound=True,
                global_workers_mutators=global_workers_mutators,
                operator_bindings=operator_bindings,
            )


_GUNICORN_RUNTIME_HOOK_NAMES = frozenset(
    {
        "configure",
        "on_starting",
        "when_ready",
        "post_fork",
        "pre_exec",
        "on_reload",
    }
)


def _gunicorn_config_has_runtime_hooks(tree):
    """Return True when the config defines hooks that can mutate workers at runtime."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _GUNICORN_RUNTIME_HOOK_NAMES:
                return True
    return False


def _scan_gunicorn_config_worker_details(tree):
    """Return configured count, assignment dynamism, and runtime-hook dynamism."""
    state = _GunicornWorkersScanState()
    runtime_dynamic = _gunicorn_config_has_runtime_hooks(tree)
    operator_bindings = _collect_operator_setitem_bindings(tree)
    import_time_workers_mutators = _collect_import_time_workers_mutators(
        tree, operator_bindings
    )
    _walk_gunicorn_workers_statements(
        tree.body,
        state,
        in_compound=False,
        global_workers_mutators=import_time_workers_mutators,
        operator_bindings=operator_bindings,
    )
    configured_count = state.count if state.found else None
    return configured_count, state.dynamic, runtime_dynamic


def _scan_gunicorn_config_workers(tree):
    """Return worker count and dynamic flag from a gunicorn config module AST."""
    count, assignment_dynamic, runtime_dynamic = _scan_gunicorn_config_worker_details(
        tree
    )
    return (count if count is not None else 1), (
        assignment_dynamic or runtime_dynamic
    )


def _gunicorn_config_worker_details_from_path(
    config_path: str,
) -> tuple[int | None, bool, bool]:
    """Return worker details while preserving an omitted workers setting."""
    path = _resolve_gunicorn_config_path(config_path)
    if path is None:
        return None, False, False
    tree = _parse_gunicorn_config_tree(path)
    if tree is None:
        return None, False, False
    return _scan_gunicorn_config_worker_details(tree)


def _workers_from_gunicorn_config_path(config_path: str) -> tuple[int, bool]:
    """Parse worker count and whether the effective assignment is dynamic."""
    count, assignment_dynamic, runtime_dynamic = (
        _gunicorn_config_worker_details_from_path(config_path)
    )
    return (count if count is not None else 1), (
        assignment_dynamic or runtime_dynamic
    )


def _gunicorn_config_path_from_tokens(tokens: list[str]) -> str | None:
    """Return the last explicit Gunicorn config path in ``tokens``."""
    config_path = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in ("-c", "--config") and i + 1 < len(tokens):
            config_path = tokens[i + 1]
            i += 2
            continue
        if token.startswith("--config="):
            config_path = token.split("=", 1)[1]
        i += 1
    return config_path


def _argv_specifies_gunicorn_config(tokens: list[str]) -> bool:
    """Return True when argv tokens pass an explicit Gunicorn config path."""
    return _gunicorn_config_path_from_tokens(tokens) is not None


def _is_gunicorn_process(tokens: list[str]) -> bool:
    """Return True when the current process is running under Gunicorn."""
    if tokens:
        executable = Path(str(tokens[0])).name.lower()
        if executable in {"gunicorn", "gunicorn.exe"}:
            return True
    return "gunicorn" in sys.modules


def _gunicorn_launch_directories() -> list[Path]:
    """Return likely launch directories, preferring the actual current cwd."""
    directories = []
    try:
        cwd_path = Path.cwd().resolve()
    except (OSError, RuntimeError):
        cwd_path = None
    if cwd_path is not None:
        directories.append(cwd_path)

    inherited_pwd = os.environ.get("PWD", "").strip()
    if inherited_pwd:
        try:
            pwd_path = Path(inherited_pwd).resolve()
            if pwd_path.is_dir() and pwd_path not in directories:
                directories.append(pwd_path)
        except (OSError, RuntimeError):
            # Invalid/stale PWD is non-fatal; the actual cwd remains authoritative.
            pass
    return directories


def _static_gunicorn_chdir(tree):
    """Return a literal top-level Gunicorn chdir value when it is unambiguous."""
    value = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "chdir" for target in node.targets):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return None
        value = node.value.value
    return value


def _gunicorn_config_chdir_matches(config_path: Path, cwd: Path) -> bool:
    """Verify that a launch config's literal chdir resolves to the current cwd."""
    tree = _parse_gunicorn_config_tree(config_path)
    if tree is None:
        return False
    raw_chdir = _static_gunicorn_chdir(tree)
    if raw_chdir is None:
        return False
    try:
        target = Path(raw_chdir)
        if not target.is_absolute():
            target = config_path.parent / target
        return target.resolve() == cwd
    except (OSError, RuntimeError):
        return False


def _default_gunicorn_config_paths() -> list[Path]:
    """Return the implicit config, accepting PWD only when chdir proves it."""
    directories = _gunicorn_launch_directories()
    if not directories:
        return []
    cwd = directories[0]
    try:
        cwd_config = (cwd / "gunicorn.conf.py").resolve()
    except (OSError, RuntimeError):
        cwd_config = None

    if len(directories) > 1:
        try:
            pwd_config = (directories[1] / "gunicorn.conf.py").resolve()
        except (OSError, RuntimeError):
            pwd_config = None
        if (
            pwd_config is not None
            and pwd_config.is_file()
            and _gunicorn_config_chdir_matches(pwd_config, cwd)
        ):
            return [pwd_config]

    if cwd_config is not None and cwd_config.is_file():
        return [cwd_config]
    return []


def _workers_from_gunicorn_config_flag(tokens: list[str]) -> tuple[int, bool]:
    """Read the effective ``-c/--config`` path from a token list."""
    config_path = _gunicorn_config_path_from_tokens(tokens)
    if config_path is None:
        return 1, False
    return _workers_from_gunicorn_config_path(config_path)


def _worker_count_from_environment() -> int:
    """Return the largest safety-relevant environment worker count."""
    counts = [1]
    for env_key in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        raw = os.environ.get(env_key, "").strip()
        if raw.isdigit():
            counts.append(int(raw))
    return max(counts)


def _selected_gunicorn_config_path(
    cmd_tokens: list[str],
    argv: list[str],
) -> str | None:
    """Return the explicit config path using Gunicorn option precedence."""
    argv_path = _gunicorn_config_path_from_tokens(argv)
    if argv_path is not None:
        return argv_path
    return _gunicorn_config_path_from_tokens(cmd_tokens)


def _apply_gunicorn_config_worker_details(
    count: int,
    config_path: str,
) -> tuple[int, bool, bool]:
    """Apply config workers while preserving defaults when workers is omitted."""
    configured_count, assignment_dynamic, runtime_dynamic = (
        _gunicorn_config_worker_details_from_path(config_path)
    )
    if configured_count is not None:
        count = configured_count
    return count, assignment_dynamic, runtime_dynamic


def _detect_worker_settings() -> tuple[int, bool]:
    """Best-effort worker count and dynamic-config flag for Gunicorn deployments."""
    count = _worker_count_from_environment()
    assignment_dynamic = False
    runtime_dynamic = False
    cmd_args = os.environ.get("GUNICORN_CMD_ARGS", "")
    cmd_tokens = shlex.split(cmd_args) if cmd_args.strip() else []

    config_path = _selected_gunicorn_config_path(cmd_tokens, sys.argv)
    if config_path is not None:
        count, assignment_dynamic, runtime_dynamic = (
            _apply_gunicorn_config_worker_details(count, config_path)
        )
    elif _is_gunicorn_process(sys.argv):
        default_paths = _default_gunicorn_config_paths()
        if default_paths:
            count, assignment_dynamic, runtime_dynamic = (
                _apply_gunicorn_config_worker_details(count, str(default_paths[0]))
            )

    cmd_override = _worker_count_override_from_tokens(cmd_tokens)
    if cmd_override is not None:
        count = cmd_override
        assignment_dynamic = False
    argv_override = _worker_count_override_from_tokens(sys.argv)
    if argv_override is not None:
        count = argv_override
        assignment_dynamic = False

    return count, assignment_dynamic or runtime_dynamic


def _detect_worker_count() -> int:
    """Best-effort worker count for multi-process Gunicorn deployments."""
    count, _dynamic = _detect_worker_settings()
    return count


def _ratelimit_storage_error():
    """Return a startup error when the limiter URI cannot share panel sessions."""
    ratelimit_uri = (
        os.environ.get("RATELIMIT_STORAGE_URI", RATELIMIT_MEMORY_URI).strip()
        or RATELIMIT_MEMORY_URI
    )
    worker_count, dynamic_workers_config = _detect_worker_settings()
    needs_shared_backend = worker_count > 1 or dynamic_workers_config
    if not needs_shared_backend or shared_session_store_supported(ratelimit_uri):
        return None
    if ratelimit_uri == RATELIMIT_MEMORY_URI:
        if dynamic_workers_config:
            return (
                "The Gunicorn config file sets workers using a dynamic or conditional "
                "assignment (for example workers = multiprocessing.cpu_count() or "
                "workers = N inside an if/for block). Startup cannot verify a "
                f"single-worker deployment, so {RATELIMIT_MEMORY_URI} would bypass "
                "login rate limits across worker processes. Set a single static "
                "top-level workers = N in the config file, configure WEB_CONCURRENCY, "
                "or use a shared backend such as redis://redis:6379/0."
            )
        return (
            f"RATELIMIT_STORAGE_URI={RATELIMIT_MEMORY_URI} is per worker process and "
            "bypasses login rate limits with multiple Gunicorn workers. Set a shared "
            "backend (e.g. redis://redis:6379/0) or run with a single worker."
        )
    return (
        "RATELIMIT_STORAGE_URI cannot back shared panel sessions across "
        "multiple Gunicorn workers. Use redis://, rediss://, or redis+unix://. "
        "Schemes such as redis+cluster:// and redis+sentinel:// are supported "
        "by the rate limiter only; the panel would otherwise fall back to "
        "per-worker in-memory sessions, breaking logout and session rotation."
    )


def _validate_config():
    """Fail fast on insecure or missing configuration at startup."""
    had_error = False

    if _is_insecure_secret(os.environ.get("SECRET_KEY"), min_length=_MIN_SECRET_KEY_LEN):
        _emit_config_error(
            "SECRET_KEY is not set, is shorter than 32 characters, or uses an "
            "insecure default. Generate one with: python3 -c 'import secrets; "
            "print(secrets.token_hex(32))'"
        )
        had_error = True

    require_login = _parse_require_login(os.environ.get("REQUIRE_LOGIN"), True)
    if require_login is None:
        _emit_config_error(
            "REQUIRE_LOGIN has an unrecognized value. "
            "Use True/False (or 1/0, yes/no, on/off)."
        )
        had_error = True
    elif require_login and _is_weak_panel_password(os.environ.get("PASSWORD")):
        _emit_config_error(
            "PASSWORD is not set, uses an insecure default, or is shorter than "
            "12 characters while REQUIRE_LOGIN=True. Set a strong password."
        )
        had_error = True
    elif not require_login and not _bool(os.environ.get("ALLOW_INSECURE_NO_LOGIN"), False):
        _emit_config_error(
            "REQUIRE_LOGIN=False exposes the full admin panel without authentication. "
            "Set ALLOW_INSECURE_NO_LOGIN=1 to acknowledge this risk."
        )
        had_error = True

    ratelimit_error = _ratelimit_storage_error()
    if ratelimit_error:
        _emit_config_error(ratelimit_error)
        had_error = True

    if _is_insecure_secret(os.environ.get("LRTMP2_API_TOKEN")):
        _emit_config_error(
            "LRTMP2_API_TOKEN is not set or uses the placeholder. "
            "Set the same token in librtmp2-server and panel (via LRTMP2_API_TOKEN env "
            "or the value stored in the server's SQLite database)."
        )
        had_error = True

    trusted_proxy_count = _parse_positive_int(
        os.environ.get("TRUSTED_PROXY_COUNT"),
        default=0,
        min_value=0,
        max_value=10,
        name="TRUSTED_PROXY_COUNT",
    )
    trusted_proxy_networks = _parse_trusted_proxy_networks(
        os.environ.get("TRUSTED_PROXY_IPS")
    )
    if trusted_proxy_count > 0 and not trusted_proxy_networks:
        _emit_config_error(
            "TRUSTED_PROXY_COUNT is enabled but TRUSTED_PROXY_IPS is not set. "
            "List the proxy IP addresses or CIDR ranges that may append "
            "X-Forwarded-* headers (for example TRUSTED_PROXY_IPS=172.18.0.0/16) "
            "so direct clients cannot spoof forwarded headers to bypass rate limits."
        )
        had_error = True

    if had_error:
        sys.exit(1)


# Validate on import — before the app can start with bad config.
_validate_config()


class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]

    REQUIRE_LOGIN = _parse_require_login(os.environ.get("REQUIRE_LOGIN"), True)
    USERNAME = os.environ.get("USERNAME", "admin")
    PASSWORD = os.environ.get("PASSWORD", "")
    SESSION_LIFETIME = timedelta(hours=8)

    LRTMP2_API_URL = os.environ.get("LRTMP2_API_URL", "http://localhost:8080").rstrip("/")
    # Browser-reachable HTTP API base URL for copied stats links (defaults to LRTMP2_API_URL).
    LRTMP2_STATS_URL = os.environ.get("LRTMP2_STATS_URL", LRTMP2_API_URL).rstrip("/")
    LRTMP2_API_TOKEN = os.environ["LRTMP2_API_TOKEN"]

    LRTMP2_DOMAIN = os.environ.get("LRTMP2_DOMAIN", "localhost")
    LRTMP2_RTMP_PORT = os.environ.get("LRTMP2_RTMP_PORT", "1935")
    # Publicly-reachable RTMPS port. Only used when librtmp2-server reports
    # RTMPS as enabled (via /api/v1/health) — kept separate from RTMP_PORT
    # since RTMPS is a second listener, not a mode switch on the same port.
    LRTMP2_RTMPS_PORT = os.environ.get("LRTMP2_RTMPS_PORT", "1936")
    LRTMP2_APP = os.environ.get("LRTMP2_APP", "live")

    # Enable Secure cookies automatically when public URLs use HTTPS.
    SESSION_COOKIE_SECURE = _session_cookie_secure_default()

    # Number of trusted reverse proxies in front of the panel. Zero keeps
    # X-Forwarded-For/X-Forwarded-Proto ignored so direct clients cannot spoof
    # their source IP or scheme. Configure the exact hop count when the panel is
    # reachable only through a trusted proxy chain.
    TRUSTED_PROXY_COUNT = _parse_positive_int(
        os.environ.get("TRUSTED_PROXY_COUNT"),
        default=0,
        min_value=0,
        max_value=10,
        name="TRUSTED_PROXY_COUNT",
    )
    TRUSTED_PROXY_NETWORKS = _parse_trusted_proxy_networks(
        os.environ.get("TRUSTED_PROXY_IPS")
    )

    # Shared limiter backend for multi-worker deployments (e.g. redis://redis:6379/0).
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", RATELIMIT_MEMORY_URI)

    # Live stats polling limits for /streams/<id>/stats.json (Flask-Limiter).
    STATS_RATE_LIMIT_PER_IP = _parse_positive_int(
        os.environ.get("STATS_RATE_LIMIT_PER_IP"),
        default=600,
        min_value=60,
        max_value=10_000,
        name="STATS_RATE_LIMIT_PER_IP",
    )
    STATS_RATE_LIMIT_PER_STREAM = _parse_positive_int(
        os.environ.get("STATS_RATE_LIMIT_PER_STREAM"),
        default=25,
        min_value=5,
        max_value=1_000,
        name="STATS_RATE_LIMIT_PER_STREAM",
    )