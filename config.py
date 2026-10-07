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
    """Return an integer-looking worker count, or None.

    Gunicorn parses these values with plain ``int()``, so the panel must too:
    an ``isdigit()`` gate both rejects what Gunicorn accepts (``1_6``, ``+16``)
    and accepts what ``int()`` rejects (U+00B2), which raised an unhandled
    ``ValueError`` during startup validation.
    """
    try:
        count = int(value)
    except ValueError:
        return None
    # Gunicorn's validate_pos_int rejects negatives, so they are never live.
    return count if count >= 0 else None


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


def _gunicorn_config_path_candidates(config_path: str) -> list[Path]:
    """Filesystem locations Gunicorn may load for a PATH or file:PATH spec."""
    spec = config_path.strip()
    if spec.startswith("file:"):
        spec = spec[5:]
    if not spec or spec.startswith("python:"):
        return []
    try:
        candidate = Path(spec)
    except (OSError, RuntimeError, ValueError):
        return []
    search = []
    if candidate.is_absolute():
        search.append(candidate)
    else:
        # Relative -c/--config is resolved at launch, before Gunicorn chdir.
        # Reuse the implicit-config lookup; if that cannot identify the loaded
        # file, return no candidates so the scanner fails closed.
        search.extend(
            _gunicorn_relative_config_paths(
                candidate, fail_closed_if_ambiguous=True
            )
        )
    resolved = []
    seen = set()
    for path in search:
        try:
            full = path.resolve()
        except (OSError, RuntimeError):
            # Broken symlink or inaccessible path; try the next candidate.
            continue
        if full in seen:
            continue
        seen.add(full)
        resolved.append(full)
    return resolved


def _resolve_gunicorn_config_path(config_path: str) -> Path | None:
    """Return the exact Gunicorn config path when it resolves to a regular file."""
    if not config_path or "\0" in config_path:
        return None
    for resolved in _gunicorn_config_path_candidates(config_path):
        if resolved.is_file():
            return resolved
    return None


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


def _globals_workers_subscript(node, operator_bindings=None):
    """Return True for ``globals()['workers']``-style subscript targets."""
    if not _subscript_slice_is_workers(node):
        return False
    base = _subscript_base_node(node)
    if not _globals_name_is_unshadowed_at(base, operator_bindings):
        return False
    namespace_aliases = (
        operator_bindings[2]
        if operator_bindings is not None and len(operator_bindings) > 2
        else set()
    )
    return _is_module_namespace_mapping(base, namespace_aliases)


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
                and _namespace_aliases_reference_current_module(
                    target.value, namespace_aliases
                )
            ):
                return _dict_merge_payload_may_set_workers(node.value)
    return False


def _is_import_module_sys_call(
    node,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Return True for a proven ``importlib.import_module('sys')`` call."""
    if not isinstance(node, ast.Call):
        return False
    module_arg = node.args[0] if node.args else next(
        (
            keyword.value
            for keyword in node.keywords
            if keyword.arg == "name"
        ),
        None,
    )
    if module_arg is None:
        return False
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



class _ModuleNamespaceAliases(set):
    """Namespace aliases plus imports needed to recognize module references."""

    def __init__(
        self,
        values=(),
        *,
        sys_aliases=None,
        importlib_aliases=None,
        importlib_module_aliases=None,
    ):
        super().__init__(values)
        self.sys_aliases = (
            {"sys"} if sys_aliases is None else set(sys_aliases)
        )
        self.importlib_aliases = (
            {"import_module"}
            if importlib_aliases is None
            else set(importlib_aliases)
        )
        self.importlib_module_aliases = (
            {"importlib"}
            if importlib_module_aliases is None
            else set(importlib_module_aliases)
        )

    def __eq__(self, other):
        """Compare alias members and the module-reference metadata."""
        if not isinstance(other, _ModuleNamespaceAliases):
            return set.__eq__(self, other)
        return (
            set.__eq__(self, other)
            and self.sys_aliases == other.sys_aliases
            and self.importlib_aliases == other.importlib_aliases
            and self.importlib_module_aliases == other.importlib_module_aliases
        )


def _namespace_aliases_reference_current_module(node, namespace_aliases):
    """Resolve current-module references using aliases collected for the scan."""
    return _is_current_module_reference(
        node,
        getattr(namespace_aliases, "sys_aliases", None),
        getattr(namespace_aliases, "importlib_aliases", None),
        getattr(namespace_aliases, "importlib_module_aliases", None),
    )


def _is_structural_operator_attrgetter_factory(factory_call):
    """Return True for syntactic ``operator.attrgetter`` / imported ``attrgetter``."""
    if not isinstance(factory_call, ast.Call):
        return False
    func = factory_call.func
    if isinstance(func, ast.Attribute) and func.attr == "attrgetter":
        return isinstance(func.value, ast.Name)
    return isinstance(func, ast.Name) and func.id == "attrgetter"


def _is_structural_attrgetter_module_namespace_mapping(
    node, namespace_aliases
):
    """Return True when attrgetter resolves the current module's ``__dict__``."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    factory_call = node.func
    if not isinstance(factory_call, ast.Call) or not factory_call.args:
        return False
    return (
        isinstance(factory_call.args[0], ast.Constant)
        and factory_call.args[0].value == "__dict__"
        and _is_structural_operator_attrgetter_factory(factory_call)
        and _namespace_aliases_reference_current_module(
            node.args[0], namespace_aliases
        )
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
        return _namespace_aliases_reference_current_module(
            node.value, namespace_aliases
        )
    if _is_structural_attrgetter_module_namespace_mapping(
        node, namespace_aliases
    ):
        return True
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id == "vars":
        return (
            len(node.args) == 1
            and not node.keywords
            and _namespace_aliases_reference_current_module(
                node.args[0], namespace_aliases
            )
        )
    if node.func.id == "getattr":
        return (
            len(node.args) == 2
            and not node.keywords
            and _namespace_aliases_reference_current_module(
                node.args[0], namespace_aliases
            )
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



def _expression_is_namespace_update_reference(expr, namespace_aliases=None):
    """Return True for expressions that reference ``globals().update`` or an alias."""
    if isinstance(expr, ast.Attribute) and expr.attr == "update":
        return _is_module_namespace_mapping(expr.value, namespace_aliases)
    return False


def _simple_namespace_call_delegates_update(call, namespace_aliases=None):
    """Return True when ``SimpleNamespace(update=globals().update)`` is constructed."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Name) or call.func.id != "SimpleNamespace":
        return False
    return any(
        keyword.arg == "update"
        and _expression_is_namespace_update_reference(keyword.value, namespace_aliases)
        for keyword in call.keywords
    )


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


def _instance_binding_candidates_at_line(events, name, line):
    """Return ``(event_line, class_name)`` instance candidates visible at ``line``.

    The latest unconditional binding is the base; conditional bindings after it
    are kept as additional candidates because the branch may or may not have
    run, so the worker scan must fail closed for any of them.
    """
    base = None
    conditionals = []
    for event in events.get(name, ()):
        event_line = event[0]
        if line and event_line > line:
            break
        if len(event) == 3:
            conditionals.append((event_line, event[1]))
        else:
            value = event[1]
            base = (event_line, value) if value else None
            conditionals = []
    candidates = ([base] if base else []) + conditionals
    return [(event_line, class_name) for event_line, class_name in candidates if class_name]


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



def _chainmap_call_includes_namespace(chainmap_call, namespace_aliases=None):
    """Return True when a ``ChainMap`` call includes the module namespace."""
    if not isinstance(chainmap_call, ast.Call):
        return False
    if not isinstance(chainmap_call.func, ast.Name) or chainmap_call.func.id != "ChainMap":
        return False
    return any(
        _is_module_namespace_mapping(arg, namespace_aliases) for arg in chainmap_call.args
    )


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


def _call_is_chainmap_maps_update(call, namespace_aliases=None, chainmap_aliases=None):
    """Return True for ``ChainMap(..., globals()).maps[i].update(...)`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
        return False
    if not _chainmap_selected_entry_is_namespace(
        call.func.value,
        namespace_aliases,
    ):
        return _call_is_chainmap_alias_maps_update(
            call,
            chainmap_aliases,
            namespace_aliases,
        )
    return _update_payload_may_set_workers(call)


def _collect_chainmap_namespace_aliases(tree, namespace_aliases):
    """Collect ChainMap aliases and retain their constructor arguments."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = {}
    for name, values in assignments.items():
        calls = [
            value
            for value in values
            if value is not None
            and isinstance(value, ast.Call)
            and _chainmap_call_includes_namespace(value, namespace_aliases)
        ]
        if calls:
            aliases[name] = calls
    return aliases


def _call_is_chainmap_alias_maps_update(
    call,
    chainmap_aliases=None,
    namespace_aliases=None,
):
    """Return True when an alias selects its module-namespace ChainMap entry."""
    if not chainmap_aliases or not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Subscript):
        return False
    maps_attr = receiver.value
    if not isinstance(maps_attr, ast.Attribute) or maps_attr.attr != "maps":
        return False
    base = maps_attr.value
    if not isinstance(base, ast.Name):
        return False
    chainmap_calls = chainmap_aliases.get(base.id, ())
    if not chainmap_calls:
        return False
    for chainmap_call in chainmap_calls:
        selected = ast.Subscript(
            value=ast.Attribute(
                value=chainmap_call,
                attr="maps",
                ctx=ast.Load(),
            ),
            slice=receiver.slice,
            ctx=ast.Load(),
        )
        if _chainmap_selected_entry_is_namespace(
            selected,
            namespace_aliases,
        ):
            return _update_payload_may_set_workers(call)
    return False


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



def _expression_has_risky_instance_update(expr, shadowed_names=None):
    """Return True when an expression calls instance ``.update()`` with workers."""
    if shadowed_names is None:
        shadowed_names = set()
    if isinstance(expr, ast.Lambda):
        return False
    if isinstance(expr, ast.Call) and _call_is_attribute_instance_update_workers(
        expr,
        shadowed_names,
    ):
        return True
    return any(
        _expression_has_risky_instance_update(child, shadowed_names)
        for child in ast.iter_child_nodes(expr)
    )


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


def _is_direct_dict_update_attribute(func):
    """Return True for a direct builtin ``dict.update`` attribute."""
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "update"
        and isinstance(func.value, ast.Name)
        and func.value.id == "dict"
    )


def _getattr_target_for_method(func, method):
    """Return the target of ``getattr(target, method)`` when static."""
    if not isinstance(func, ast.Call) or not isinstance(func.func, ast.Name):
        return None
    if func.func.id != "getattr" or len(func.args) < 2:
        return None
    method_arg = func.args[1]
    if not isinstance(method_arg, ast.Constant) or method_arg.value != method:
        return None
    return func.args[0]


def _is_type_of_globals_call(node):
    """Return True for ``type(globals())``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and bool(node.args)
        and _is_globals_call(node.args[0])
    )


def _is_builtins_dict_subscript(node):
    """Return True for ``__builtins__['dict']`` style references."""
    return (
        isinstance(node, ast.Subscript)
        and _is_builtins_reference(node.value)
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == "dict"
    )


def _module_alias_active_at_line(node, aliases, events, reference_line=0):
    """Return whether a name still resolves to a proven imported module."""
    if not isinstance(node, ast.Name):
        return False
    if events and node.id in events:
        state = _binding_state_at_line(events, node.id, reference_line or getattr(node, 'lineno', 0))
        if state is not None:
            return bool(state)
    return node.id in (aliases or set())


def _name_is_unshadowed_builtin(name, reference_line, shadow_lines=None):
    """Return whether a builtin name is still visible at one source line."""
    shadow_state = (shadow_lines or {}).get(name)
    if shadow_state is None or not reference_line:
        return True
    if isinstance(shadow_state, list):
        is_shadowed = False
        for event_line, event_is_shadowed in shadow_state:
            if event_line > reference_line:
                break
            is_shadowed = event_is_shadowed
        return not is_shadowed
    return reference_line < shadow_state


def _is_builtins_dict_attribute(
    node,
    builtins_aliases=None,
    builtins_alias_events=None,
    reference_line=0,
):
    """Return True for proven ``builtins.dict`` attribute references."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == 'dict'
        and _module_alias_active_at_line(
            node.value,
            builtins_aliases,
            builtins_alias_events,
            reference_line or getattr(node, 'lineno', 0),
        )
    )



def _globals_name_is_unshadowed_at(node, operator_bindings=None):
    """Return True when a rebound ``globals`` has not hidden the builtin yet.

    ``_is_globals_call`` only checks the call syntax, so a config that binds its
    own ``globals`` would otherwise be read as mutating the module namespace
    when it only touches a temporary mapping. An alias bound from that rebound
    name is no more trustworthy, so the same shadow state is consulted for
    every receiver.
    """
    builtin_shadow_lines = (
        operator_bindings[32]
        if operator_bindings is not None and len(operator_bindings) > 32
        else {}
    )
    return _name_is_unshadowed_builtin(
        "globals",
        getattr(node, "lineno", 0),
        builtin_shadow_lines,
    )


def _globals_call_is_unshadowed(node, operator_bindings=None):
    """Return True for a ``globals()`` call that still names the builtin."""
    return _is_globals_call(node) and _globals_name_is_unshadowed_at(
        node,
        operator_bindings,
    )


def _is_globals_class_dict_reference(node, shadow_lines=None):
    """Return True for builtin ``globals().__class__.__dict__`` prefixes."""
    original = node
    if isinstance(node, ast.Attribute) and node.attr == '__dict__':
        node = node.value
    reference_line = getattr(original, 'lineno', 0)
    return (
        _name_is_unshadowed_builtin('globals', reference_line, shadow_lines)
        and isinstance(node, ast.Attribute)
        and node.attr == '__class__'
        and _is_globals_call(node.value)
    )



def _is_globals_type_dict_update_subscript(node, shadow_lines=None):
    """Return True for ``globals().__class__.__dict__['update']`` lookups."""
    if not isinstance(node, ast.Subscript):
        return False
    if not isinstance(node.slice, ast.Constant) or node.slice.value != 'update':
        return False
    return _is_globals_class_dict_reference(node.value, shadow_lines)



def _is_builtins_dict_update_attribute(
    func,
    builtins_aliases=None,
    builtins_alias_events=None,
    reference_line=0,
):
    """Return True for proven builtins-dict ``update`` attribute references."""
    if not isinstance(func, ast.Attribute) or func.attr != 'update':
        return False
    if _is_builtins_dict_subscript(func.value):
        return True
    return _is_builtins_dict_attribute(
        func.value,
        builtins_aliases,
        builtins_alias_events,
        reference_line or getattr(func, 'lineno', 0),
    )



def _is_dict_type_update_callable(
    func,
    aliases=None,
    *,
    reference_line=0,
    dict_shadow_line=None,
    builtins_aliases=None,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Return True for builtin ``dict.update`` or a proven alias of it."""
    if aliases is None:
        aliases = set()
    if isinstance(func, ast.Name):
        return func.id in aliases
    if _is_direct_dict_update_attribute(func):
        return _dict_name_is_builtin_at_line(reference_line, dict_shadow_line)
    if _is_builtins_dict_update_attribute(
        func,
        builtins_aliases,
        builtins_alias_events,
        reference_line,
    ):
        return True
    if _is_globals_type_dict_update_subscript(func, builtin_shadow_lines):
        return True
    if not _name_is_unshadowed_builtin('getattr', reference_line, builtin_shadow_lines):
        return False
    target = _getattr_target_for_method(func, 'update')
    if target is None:
        return False
    if isinstance(target, ast.Name) and target.id == 'dict':
        return _dict_name_is_builtin_at_line(reference_line, dict_shadow_line)
    return (
        (
            _name_is_unshadowed_builtin('type', reference_line, builtin_shadow_lines)
            and _name_is_unshadowed_builtin('globals', reference_line, builtin_shadow_lines)
            and _is_type_of_globals_call(target)
        )
        or _is_builtins_dict_subscript(target)
        or _is_builtins_dict_attribute(
            target,
            builtins_aliases,
            builtins_alias_events,
            reference_line,
        )
        or _is_globals_class_dict_reference(target, builtin_shadow_lines)
    )



def _values_are_dict_update_aliases(
    values,
    aliases,
    dict_shadow_line=None,
    builtins_aliases=None,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Return True when every assignment resolves to builtin ``dict.update``."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_dict_type_update_callable(
            value,
            aliases,
            reference_line=getattr(value, 'lineno', 0),
            dict_shadow_line=dict_shadow_line,
            builtins_aliases=builtins_aliases,
            builtins_alias_events=builtins_alias_events,
            builtin_shadow_lines=builtin_shadow_lines,
        )
        for value in resolved_values
    )




def _collect_dict_update_aliases(
    tree,
    dict_shadow_line=None,
    builtins_aliases=None,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Collect transitive aliases always bound to builtin ``dict.update``."""
    if dict_shadow_line is None:
        dict_shadow_line = _collect_definite_name_shadow_line(tree, 'dict')
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
                builtins_aliases,
                builtins_alias_events,
                builtin_shadow_lines,
            )
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
    dict_shadow_line=None,
    operator_bindings=None,
):
    """Return True for builtin ``dict.update(globals(), ...)`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    builtins_aliases = operator_bindings[8] if operator_bindings and len(operator_bindings) > 8 else set()
    builtins_alias_events = operator_bindings[30] if operator_bindings and len(operator_bindings) > 30 else {}
    builtin_shadow_lines = operator_bindings[32] if operator_bindings and len(operator_bindings) > 32 else {}
    if not _is_dict_type_update_callable(
        call.func,
        update_aliases,
        reference_line=getattr(call, 'lineno', 0),
        dict_shadow_line=dict_shadow_line,
        builtins_aliases=builtins_aliases,
        builtins_alias_events=builtins_alias_events,
        builtin_shadow_lines=builtin_shadow_lines,
    ):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _update_payload_may_set_workers(call, start_index=1)




def _dict_name_is_builtin_at_line(reference_line, dict_shadow_line=None):
    """Return whether ``dict`` still resolves to the builtin at a source line.

    ``dict`` bound at module scope and later restored from a proven
    ``builtins`` alias yields the whole shadow EVENT list, which
    ``_name_is_unshadowed_builtin`` already reads line by line.
    """
    if isinstance(dict_shadow_line, list):
        return _name_is_unshadowed_builtin(
            'dict',
            reference_line,
            {'dict': dict_shadow_line},
        )
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
    if (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[0], ast.Name)
        and func.args[0].id in module_aliases
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == "FunctionType"
    ):
        return True
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "FunctionType"
        and isinstance(func.value, ast.Name)
        and func.value.id in module_aliases
    )



def _is_compile_call(node):
    """Return True for a direct ``compile(...)`` call."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id == "compile":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "compile"


def _call_argument_value(call, position, keyword_name):
    """Return a positional-or-keyword argument from a call, if present."""
    if len(call.args) > position:
        return call.args[position]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == keyword_name),
        None,
    )

def _call_is_functiontype_namespace_code(
    call,
    namespace_aliases=None,
    types_module_aliases=None,
    functiontype_aliases=None,
):
    """Return True for ``FunctionType(..., globals())`` constructors."""
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
        and _is_module_namespace_mapping(globals_arg, namespace_aliases)
    )



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
    if _is_dict_type_setitem_callable(
        target,
        reference_line=getattr(partial_call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return "__setitem__"
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
    if method == "__setitem__":
        return (
            len(call.args) > start_index
            and _key_may_be_workers(call.args[start_index])
        )
    return False

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



def _methodcaller_method_name(call):
    """Return the method name passed to ``operator.methodcaller``, if static."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    method = call.args[0]
    if isinstance(method, ast.Constant) and isinstance(method.value, str):
        return method.value
    return None


def _is_operator_import(node):
    """Return True for ``__import__('operator')``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "operator"
        and not node.keywords
    )


def _is_operator_module_reference(node, module_aliases):
    """Return True when an expression resolves to the operator module."""
    return (
        isinstance(node, ast.Name)
        and node.id in module_aliases
    ) or _is_operator_import(node)


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
        and _is_operator_module_reference(func.value, module_aliases)
    )


def _key_may_be_workers(node):
    """Return True unless a literal key is provably different from ``workers``."""
    return not isinstance(node, ast.Constant) or node.value == "workers"


def _resolve_operator_methodcaller_factory(call, operator_bindings):
    """Return the ``methodcaller(...)`` factory for direct or getattr-bound calls."""
    module_aliases, _, _, _, _ = _unpack_operator_bindings(operator_bindings)
    methodcaller_aliases = operator_bindings[6] if len(operator_bindings) > 6 else set()
    factory = call.func
    if _is_operator_methodcaller_factory(
        factory,
        module_aliases,
        methodcaller_aliases,
    ):
        return factory
    if not isinstance(factory, ast.Call):
        return None
    getattr_call = factory.func
    if not isinstance(getattr_call, ast.Call):
        return None
    if _getattr_operator_method_name(getattr_call, module_aliases) != "methodcaller":
        return None
    if len(factory.args) < 1:
        return None
    method = factory.args[0]
    if not isinstance(method, ast.Constant) or not isinstance(method.value, str):
        return None
    return factory


def _call_is_operator_methodcaller_on_module_namespace(
    call,
    operator_bindings,
    namespace_aliases=None,
):
    """Return True for ``operator.methodcaller(...)(globals())`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    factory = _resolve_operator_methodcaller_factory(call, operator_bindings)
    if factory is None:
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
    if method == "setdefault":
        return len(factory.args) >= 2 and _key_may_be_workers(factory.args[1])
    return method is None


def _call_is_operator_methodcaller_exec_on_builtins(call, operator_bindings):
    """Return True for ``methodcaller('exec'/'eval', ...)(builtins)`` calls."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    factory = _resolve_operator_methodcaller_factory(call, operator_bindings)
    if factory is None:
        return False
    method = _methodcaller_method_name(factory)
    if method not in _DYNAMIC_EXEC_EVAL_NAMES:
        return False
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    return _is_known_builtins_module(call.args[0], builtins_aliases)


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


def _match_capture_name(pattern):
    """Return the name from a top-level ``as`` capture pattern."""
    if isinstance(pattern, ast.MatchAs) and pattern.name is not None and pattern.pattern is None:
        return pattern.name
    return None


def _compound_test_namespace_assignment_values(node):
    """Return walrus namespace bindings from ``if`` / ``while`` tests."""
    if not isinstance(node, (ast.If, ast.While)):
        return []
    return _namedexpr_assignment_values(node.test)


def _match_namespace_capture_assignments(node):
    """Return capture names when matching on the module namespace."""
    if not isinstance(node, ast.Match):
        return []
    if not _is_module_namespace_mapping(node.subject, set()):
        return []
    captures = []
    for case in node.cases:
        name = _match_capture_name(case.pattern)
        if name is not None:
            captures.append((name, node.subject))
    return captures


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
        for name, value in _compound_test_namespace_assignment_values(node):
            assignments.setdefault(name, []).append(value)
        for name, value in _match_namespace_capture_assignments(node):
            assignments.setdefault(name, []).append(value)
        for block in _compound_statement_blocks(node):
            _record_module_namespace_assignments(block, assignments)


def _values_are_module_namespace_aliases(values, aliases):
    """Return True when every assignment resolves to the module namespace."""
    resolved_values = [value for value in values if value is not None]
    return bool(resolved_values) and all(
        _is_module_namespace_mapping(value, aliases) for value in resolved_values
    )


def _resolve_module_namespace_aliases(
    assignments,
    *,
    sys_aliases=None,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Resolve aliases transitively until no additional names can be proven."""
    aliases = _ModuleNamespaceAliases(
        sys_aliases=sys_aliases,
        importlib_aliases=importlib_aliases,
        importlib_module_aliases=importlib_module_aliases,
    )
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


def _collect_module_namespace_aliases(
    tree,
    *,
    sys_aliases=None,
    importlib_aliases=None,
    importlib_module_aliases=None,
):
    """Collect names that are always assigned a module namespace mapping."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    return _resolve_module_namespace_aliases(
        assignments,
        sys_aliases=sys_aliases,
        importlib_aliases=importlib_aliases,
        importlib_module_aliases=importlib_module_aliases,
    )


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


def _call_is_namespace_setdefault_workers(call, namespace_aliases=None):
    """Return True for ``globals().setdefault('workers', ...)`` style binds."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "setdefault":
        return False
    if not call.args or not _constant_is_workers(call.args[0]):
        return False
    return _is_module_namespace_mapping(call.func.value, namespace_aliases)


def _call_is_getattr_setdefault_workers(call, namespace_aliases=None):
    """Return True for ``getattr(globals(), 'setdefault')('workers', ...)``."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    func = call.func
    if not isinstance(func, ast.Call) or len(func.args) < 2:
        return False
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return False
    if not _is_module_namespace_mapping(func.args[0], namespace_aliases):
        return False
    method = func.args[1]
    if not (isinstance(method, ast.Constant) and method.value == "setdefault"):
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


def _getattr_operator_method_name(getattr_call, module_aliases):
    """Return a recognized operator method name from ``getattr(operator, ...)``."""
    if not isinstance(getattr_call, ast.Call):
        return None
    if not isinstance(getattr_call.func, ast.Name) or getattr_call.func.id != "getattr":
        return None
    if len(getattr_call.args) < 2:
        return None
    if not _is_operator_module_reference(getattr_call.args[0], module_aliases):
        return None
    method = getattr_call.args[1]
    if not isinstance(method, ast.Constant) or not isinstance(method.value, str):
        return None
    if method.value in {"setitem", "ior", "__ior__", "update", "methodcaller", "call"}:
        return method.value
    return None


def _getattr_operator_method_is_dynamic(getattr_call, module_aliases):
    """Return True for ``getattr(operator, <dynamic expression>)``."""
    return (
        isinstance(getattr_call, ast.Call)
        and isinstance(getattr_call.func, ast.Name)
        and getattr_call.func.id == "getattr"
        and len(getattr_call.args) >= 2
        and _is_operator_module_reference(getattr_call.args[0], module_aliases)
        and not (
            isinstance(getattr_call.args[1], ast.Constant)
            and isinstance(getattr_call.args[1].value, str)
        )
    )


def _call_is_getattr_operator_namespace_mutation(call, operator_bindings):
    """Return True for ``getattr(operator, ...)`` mutations on the namespace."""
    if not isinstance(call, ast.Call):
        return False
    module_aliases = operator_bindings[0] if operator_bindings else set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    method = _getattr_operator_method_name(call.func, module_aliases)
    if method is None:
        return (
            _getattr_operator_method_is_dynamic(call.func, module_aliases)
            and bool(call.args)
            and _is_module_namespace_mapping(call.args[0], namespace_aliases)
        )
    if method == "setitem":
        return (
            len(call.args) >= 2
            and _is_module_namespace_mapping(call.args[0], namespace_aliases)
            and _key_may_be_workers(call.args[1])
        )
    if method in {"ior", "__ior__"}:
        return (
            len(call.args) >= 2
            and _is_module_namespace_mapping(call.args[0], namespace_aliases)
            and _dict_merge_payload_may_set_workers(call.args[1])
        )
    if method == "update":
        return (
            bool(call.args)
            and _is_module_namespace_mapping(call.args[0], namespace_aliases)
            and _update_payload_may_set_workers(call)
        )
    return False


def _operator_attrgetter_method_name(factory_call):
    """Return the method name passed to ``operator.attrgetter``, if static."""
    if not isinstance(factory_call, ast.Call) or not factory_call.args:
        return None
    method = factory_call.args[0]
    if isinstance(method, ast.Constant) and isinstance(method.value, str):
        return method.value
    return None


def _is_operator_attrgetter_factory(call, operator_bindings):
    """Return True for imported or module-qualified ``operator.attrgetter``."""
    module_aliases = operator_bindings[0] if operator_bindings else set()
    attrgetter_aliases = operator_bindings[11] if len(operator_bindings) > 11 else set()
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in attrgetter_aliases
    if isinstance(func, ast.Attribute) and func.attr == "attrgetter":
        return isinstance(func.value, ast.Name) and func.value.id in module_aliases
    if not isinstance(func, ast.Call):
        return False
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return False
    if len(func.args) < 2:
        return False
    if not isinstance(func.args[0], ast.Name) or func.args[0].id not in module_aliases:
        return False
    attr = func.args[1]
    return isinstance(attr, ast.Constant) and attr.value == "attrgetter"


def _call_is_operator_attrgetter_namespace_mutation(call, operator_bindings):
    """Return True for ``operator.attrgetter(...)(namespace)(...)`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    bound = call.func
    if isinstance(bound, ast.NamedExpr) and isinstance(bound.value, ast.Call):
        bound = bound.value
    if not isinstance(bound, ast.Call) or not bound.args:
        return False
    factory = bound.func
    if not isinstance(factory, ast.Call):
        return False
    if not _is_operator_attrgetter_factory(factory, operator_bindings):
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if not _is_module_namespace_mapping(bound.args[0], namespace_aliases):
        return False
    method = _operator_attrgetter_method_name(factory)
    if method == "update":
        return _update_payload_may_set_workers(call)
    if method in {"__ior__", "ior"}:
        return bool(call.args) and _dict_merge_payload_may_set_workers(call.args[0])
    if method == "__setitem__":
        return len(call.args) >= 2 and _key_may_be_workers(call.args[0])
    return method is None


def _call_is_operator_attrgetter_on_proven_frame_globals(call, operator_bindings):
    """Return True for attrgetter-based live-frame f_globals mutations."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in _NAMESPACE_GETATTR_METHODS
        and isinstance(call.func.value, ast.Call)
        and call.func.value.args
    ):
        return False
    bound = call.func.value
    factory = bound.func
    if not (
        isinstance(factory, ast.Call)
        and _is_operator_attrgetter_factory(factory, operator_bindings)
        and _operator_attrgetter_method_name(factory) == "f_globals"
    ):
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(call, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(
        inspect_analysis,
        reference_line,
    )
    if not _node_is_proven_live_frame(
        bound.args[0],
        inspect_analysis,
        active_frame_names,
    ):
        return False
    return _namespace_mutator_call_may_set_workers(call.func.attr, call)


_NAMESPACE_GETATTR_METHODS = frozenset({"update", "__ior__", "__setitem__"})
_DYNAMIC_EXEC_EVAL_NAMES = frozenset({"exec", "eval"})
_BUILTINS_SHADOW_MARKER = "__builtins_shadowed__"


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


def _builtins_exec_eval_import_aliases(node):
    """Return direct exec/eval names imported from builtins by one statement."""
    if not isinstance(node, ast.ImportFrom) or node.module != "builtins":
        return set()
    return {
        imported.asname or imported.name
        for imported in node.names
        if imported.name in _DYNAMIC_EXEC_EVAL_NAMES
    }


def _value_yields_exec_eval_resolver(value, builtins_aliases):
    """Return True when a value resolves to builtin exec/eval at call time."""
    if _getattr_is_dynamic_exec_eval(value, builtins_aliases):
        return True
    return (
        isinstance(value, ast.Attribute)
        and value.attr in _DYNAMIC_EXEC_EVAL_NAMES
        and _is_known_builtins_module(value.value, builtins_aliases)
    )


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



def _collect_builtins_exec_eval_aliases(statements, builtins_aliases):
    """Collect direct aliases that may resolve to builtin exec/eval."""
    aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        aliases.update(_builtins_exec_eval_import_aliases(node))
        _update_builtins_exec_eval_assignment_aliases(node, aliases, builtins_aliases)
        for block in _compound_statement_blocks(node):
            aliases.update(
                _collect_builtins_exec_eval_aliases(block, builtins_aliases)
            )
    return aliases


def _collect_definite_builtins_shadow_line(tree):
    """Return the first unconditional module-level assignment to ``__builtins__``."""
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if any(
            name == "__builtins__"
            for name, _value in _namespace_assignment_values(node)
        ):
            return getattr(node, "lineno", None)
    return None


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
    shadow_line = _collect_definite_builtins_shadow_line(tree)
    if shadow_line is not None:
        aliases.add((_BUILTINS_SHADOW_MARKER, shadow_line))
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


def _collect_definite_name_shadow_line(tree, name):
    """Return top-level shadow state for ``name`` across source lines."""
    events = []
    builtins_alias_events = _collect_imported_module_alias_events(tree, 'builtins')
    for node in tree.body:
        line = getattr(node, "lineno", None)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                events.append((line, True))
            continue
        for bound_name, value in _namespace_assignment_values(node):
            if bound_name != name:
                continue
            restores_builtin = (
                isinstance(value, ast.Attribute)
                and value.attr == name
                and _module_alias_active_at_line(
                    value.value,
                    set(),
                    builtins_alias_events,
                    line or 0,
                )
            )
            events.append((line, not restores_builtin))
    if not events:
        return None
    if all(is_shadowed for _line, is_shadowed in events):
        return events[0][0]
    return events



def _is_builtins_reference(node, builtins_aliases=None):
    """Return True for the interpreter-provided ``__builtins__`` mapping."""
    if not isinstance(node, ast.Name) or node.id != "__builtins__":
        return False
    if not builtins_aliases:
        return True
    shadow_lines = [
        alias[1]
        for alias in builtins_aliases
        if isinstance(alias, tuple)
        and len(alias) == 2
        and alias[0] == _BUILTINS_SHADOW_MARKER
    ]
    if not shadow_lines:
        return True
    node_line = getattr(node, "lineno", 0)
    return not node_line or node_line <= min(shadow_lines)


def _is_known_builtins_module(node, builtins_aliases):
    """Return True when an expression is known to resolve to ``builtins``."""
    return (
        _is_builtins_import(node)
        or _is_builtins_reference(node, builtins_aliases)
        or (isinstance(node, ast.Name) and node.id in builtins_aliases)
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


def _subscript_is_dynamic_exec_eval(
    func,
    builtins_aliases,
    builtin_shadow_lines=None,
):
    """Return True for ``builtins.__dict__['exec'/'eval']`` callables."""
    if not isinstance(func, ast.Subscript):
        return False
    base = _subscript_base_node(func)
    if (
        _is_known_builtins_module(base, builtins_aliases)
        and _constant_is_exec_eval(func.slice)
    ):
        return True
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "__dict__"
        and _is_known_builtins_module(base.value, builtins_aliases)
        and _constant_is_exec_eval(func.slice)
    ) or _subscript_is_vars_builtins_exec(
        func,
        builtins_aliases,
        builtin_shadow_lines,
    )


def _subscript_is_vars_builtins_exec(
    func,
    builtins_aliases,
    builtin_shadow_lines=None,
):
    """Return True for ``vars(builtins)['exec'/'eval']`` callables."""
    if not isinstance(func, ast.Subscript) or not _constant_is_exec_eval(func.slice):
        return False
    value = func.value
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "vars"
        and len(value.args) == 1
        and not value.keywords
    ):
        return False
    if not _name_is_unshadowed_builtin(
        "vars",
        getattr(value, "lineno", 0),
        builtin_shadow_lines,
    ):
        return False
    return _is_known_builtins_module(value.args[0], builtins_aliases)


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



def _importlib_module_alias_names(node):
    """Return aliases introduced by one ``import importlib`` statement."""
    if not isinstance(node, ast.Import):
        return set()
    return {
        imported.asname or imported.name
        for imported in node.names
        if imported.name == "importlib"
    }


def _collect_importlib_module_aliases(statements):
    """Collect aliases introduced by ``import importlib`` statements."""
    aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        aliases.update(_importlib_module_alias_names(node))
        for block in _compound_statement_blocks(node):
            aliases.update(_collect_importlib_module_aliases(block))
    return aliases


def _collect_importlib_module_alias_events(tree):
    """Track importlib module aliases and later top-level rebindings."""
    active_aliases = set()
    events = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        line = getattr(node, "lineno", 0)
        for name in _importlib_module_alias_names(node):
            active_aliases.add(name)
            events.setdefault(name, []).append((line, True))
        for name, _value in _namespace_assignment_values(node):
            if name in active_aliases or name in events:
                active_aliases.discard(name)
                events.setdefault(name, []).append((line, False))
    return events


def _importlib_import_module_aliases(node):
    """Return import_module names imported from importlib by one statement."""
    if not isinstance(node, ast.ImportFrom) or node.module != "importlib":
        return set()
    return {
        imported.asname or imported.name
        for imported in node.names
        if imported.name == "import_module"
    }


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



def _attribute_is_sys_modules_builtins_exec(func, sys_aliases=None):
    """Return True for ``sys.modules['builtins'].exec/eval`` callables."""
    if not isinstance(func, ast.Attribute) or func.attr not in _DYNAMIC_EXEC_EVAL_NAMES:
        return False
    base = func.value
    if not isinstance(base, ast.Subscript):
        return False
    modules_attr = base.value
    if not (
        isinstance(modules_attr, ast.Attribute)
        and modules_attr.attr == "modules"
        and isinstance(modules_attr.value, ast.Name)
        and modules_attr.value.id in (sys_aliases or {"sys"})
    ):
        return False
    return (
        isinstance(base.slice, ast.Constant)
        and base.slice.value == "builtins"
    )


def _subscript_is_sys_modules_builtins(node, sys_aliases=None):
    """Return True for ``sys.modules['builtins']`` subscripts."""
    if not isinstance(node, ast.Subscript):
        return False
    modules_attr = node.value
    if not (
        isinstance(modules_attr, ast.Attribute)
        and modules_attr.attr == "modules"
        and isinstance(modules_attr.value, ast.Name)
        and modules_attr.value.id in (sys_aliases or {"sys"})
    ):
        return False
    return (
        isinstance(node.slice, ast.Constant)
        and node.slice.value == "builtins"
    )


def _attribute_is_sys_modules_builtins_eager_consumer(func, sys_aliases=None):
    """Return True for ``sys.modules['builtins'].sum/any/...`` callables."""
    if (
        not isinstance(func, ast.Attribute)
        or func.attr not in _EAGER_GENERATOR_CONSUMER_BUILTINS
    ):
        return False
    return _subscript_is_sys_modules_builtins(func.value, sys_aliases)


def _attribute_is_imported_builtins_exec_eval(node):
    """Return True for ``__import__('builtins').exec/eval`` attribute references."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _DYNAMIC_EXEC_EVAL_NAMES
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "__import__"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Constant)
        and node.value.args[0].value == "builtins"
        and not node.value.keywords
    )


def _static_sequence_subscript_element(node):
    """Return a statically selected list/tuple element, or None."""
    if not isinstance(node, ast.Subscript):
        return None
    if not isinstance(node.value, (ast.List, ast.Tuple)):
        return None
    index_node = node.slice
    if isinstance(index_node, ast.Constant) and isinstance(index_node.value, int):
        index = index_node.value
    elif (
        isinstance(index_node, ast.UnaryOp)
        and isinstance(index_node.op, ast.USub)
        and isinstance(index_node.operand, ast.Constant)
        and isinstance(index_node.operand.value, int)
    ):
        index = -index_node.operand.value
    else:
        return None
    elements = node.value.elts
    if index < 0:
        index += len(elements)
    if index < 0 or index >= len(elements):
        return None
    return elements[index]


def _subscript_is_hidden_exec_eval(func, operator_bindings):
    """Return True when a static list/tuple subscript resolves to exec/eval."""
    inner = _static_sequence_subscript_element(func)
    if inner is None:
        return False
    if isinstance(inner, ast.Call):
        return _call_is_dynamic_exec_eval(
            inner,
            operator_bindings=operator_bindings,
        )
    if _attribute_is_imported_builtins_exec_eval(inner):
        return True
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    return _attribute_is_dynamic_exec_eval(inner, builtins_aliases)


def _importlib_import_module_call(node, importlib_aliases, importlib_module_aliases):
    """Return True for ``import_module('builtins')`` via importlib aliases."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in importlib_aliases and bool(node.args)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_module_aliases
    ):
        return bool(node.args)
    return False


def _importlib_alias_state_for_call(
    base,
    importlib_aliases,
    importlib_alias_events,
    reference_line,
):
    """Resolve a direct ``import_module`` alias at one source line."""
    if not isinstance(base.func, ast.Name):
        return None
    is_alias = base.func.id in importlib_aliases
    if not importlib_alias_events or base.func.id not in importlib_alias_events:
        return is_alias
    state = _binding_state_at_line(
        importlib_alias_events,
        base.func.id,
        reference_line,
    )
    return is_alias if state is None else state


def _call_uses_importlib_import_module(
    base,
    importlib_aliases,
    importlib_alias_events,
    importlib_module_aliases,
    importlib_module_alias_events,
    reference_line,
):
    """Return True when ``base`` calls a proven ``import_module``."""
    alias_state = _importlib_alias_state_for_call(
        base,
        importlib_aliases,
        importlib_alias_events,
        reference_line,
    )
    if alias_state is not None:
        return alias_state
    func = base.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
    ):
        return False
    module_name = func.value.id
    if importlib_module_alias_events and module_name in importlib_module_alias_events:
        state = _binding_state_at_line(
            importlib_module_alias_events,
            module_name,
            reference_line,
        )
        if state is not None:
            return state
    return module_name in importlib_module_aliases


def _call_is_importlib_builtins_exec_eval(
    call,
    importlib_aliases,
    importlib_alias_events=None,
    importlib_module_aliases=None,
    importlib_module_alias_events=None,
):
    """Return True for ``import_module('builtins').exec/eval(...)`` calls."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in _DYNAMIC_EXEC_EVAL_NAMES:
        return False
    base = func.value
    if not isinstance(base, ast.Call) or not base.args:
        return False
    if not _call_uses_importlib_import_module(
        base,
        importlib_aliases,
        importlib_alias_events,
        importlib_module_aliases or set(),
        importlib_module_alias_events or {},
        getattr(call, "lineno", 0),
    ):
        return False
    module_name = base.args[0]
    return isinstance(module_name, ast.Constant) and module_name.value == "builtins"


def _call_is_dynamic_exec_eval(
    call,
    builtins_aliases=None,
    exec_eval_shadow_lines=None,
    direct_aliases=None,
    importlib_aliases=None,
    direct_alias_events=None,
    importlib_alias_events=None,
    importlib_module_aliases=None,
    sys_aliases=None,
    operator_bindings=None,
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
    importlib_module_alias_events = (
        operator_bindings[29]
        if operator_bindings is not None and len(operator_bindings) > 29
        else {}
    )
    func = call.func
    builtin_shadow_lines = (
        operator_bindings[32]
        if operator_bindings is not None and len(operator_bindings) > 32
        else {}
    )
    hidden_exec = False
    if operator_bindings is not None:
        hidden_exec = _subscript_is_hidden_exec_eval(func, operator_bindings)
    return (
        hidden_exec
        or _direct_name_is_builtin_exec_eval(
            func,
            call,
            exec_eval_shadow_lines,
            direct_aliases,
            direct_alias_events,
        )
        or _getattr_is_dynamic_exec_eval(func, builtins_aliases)
        or _subscript_is_dynamic_exec_eval(
            func,
            builtins_aliases,
            builtin_shadow_lines,
        )
        or _attribute_is_dynamic_exec_eval(func, builtins_aliases)
        or _attribute_is_sys_modules_builtins_exec(func, sys_aliases)
        or _call_is_importlib_builtins_exec_eval(
            call,
            importlib_aliases,
            importlib_alias_events,
            importlib_module_aliases,
            importlib_module_alias_events,
        )
    )


def _attribute_is_namespace_setitem(node, namespace_aliases=None):
    """Return True for a module namespace ``__setitem__`` attribute."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__setitem__"
        and _is_module_namespace_mapping(node.value, namespace_aliases)
    )


def _attribute_is_namespace_update(node, namespace_aliases=None):
    """Return True for a module namespace ``update`` method."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "update"
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


def _partial_factory_call(node, partial_aliases):
    """Return a ``partial(...)`` call, including ``(alias := partial(...))``."""
    if isinstance(node, ast.Call):
        candidate = node
    elif isinstance(node, ast.NamedExpr) and isinstance(node.value, ast.Call):
        candidate = node.value
    else:
        return None
    partial_func = candidate.func
    if isinstance(partial_func, ast.Name):
        if partial_func.id not in partial_aliases:
            return None
    elif not (
        isinstance(partial_func, ast.Attribute)
        and partial_func.attr == "partial"
        and isinstance(partial_func.value, ast.Name)
        and partial_func.value.id in partial_aliases
    ):
        return None
    return candidate


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


def _collect_partial_dict_namespace_mutator_alias_events(
    tree,
    namespace_aliases,
    partial_aliases,
    dict_update_aliases,
    dict_ior_aliases,
    dict_shadow_line,
):
    """Track saved partial dict mutators at each top-level binding event."""
    events = {}
    current_aliases = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        line = getattr(node, "lineno", 0)
        for name, value in _namespace_assignment_values(node):
            method = None
            if value is not None:
                method = _partial_value_dict_namespace_method(
                    value,
                    namespace_aliases,
                    partial_aliases,
                    current_aliases,
                    dict_update_aliases,
                    dict_ior_aliases,
                    dict_shadow_line,
                )
            current_aliases[name] = method
            events.setdefault(name, []).append((line, method))
    return events

def _call_is_getattr_partial_invocation(call, partial_aliases, builtin_shadow_lines=None):
    """Return True for builtin ``getattr(partial, '__call__')(...)`` invocations."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    reference_line = getattr(call, 'lineno', 0)
    return (
        _name_is_unshadowed_builtin('getattr', reference_line, builtin_shadow_lines)
        and isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == 'getattr'
        and len(func.args) >= 2
        and isinstance(func.args[0], ast.Name)
        and func.args[0].id in partial_aliases
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == '__call__'
    )



def _resolve_partial_invocation(call, partial_aliases, builtin_shadow_lines=None):
    """Return an invoked partial factory and where invocation payloads begin."""
    partial_call = _partial_factory_call(call.func, partial_aliases)
    if partial_call is not None:
        return partial_call, 0
    func = call.func
    reference_line = getattr(call, 'lineno', 0)
    if (
        _name_is_unshadowed_builtin('getattr', reference_line, builtin_shadow_lines)
        and isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == 'getattr'
        and len(func.args) >= 2
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == '__call__'
    ):
        partial_call = _partial_factory_call(func.args[0], partial_aliases)
        if partial_call is not None:
            return partial_call, 0
    if not _call_is_getattr_partial_invocation(
        call,
        partial_aliases,
        builtin_shadow_lines,
    ) or not call.args:
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

def _named_partial_workers_mutation(
    call,
    saved_aliases,
    partial_mutator_alias_events,
):
    """Return a saved partial mutator result, or None when the name is unrelated."""
    if not isinstance(call.func, ast.Name):
        return None
    if call.func.id in saved_aliases:
        return True
    saved_method = _binding_state_at_line(
        partial_mutator_alias_events,
        call.func.id,
        getattr(call, 'lineno', 0),
    )
    if saved_method is None:
        return None
    return _call_payload_may_set_workers(saved_method, call)


def _call_is_partial_bound_workers_setitem(call, operator_bindings):
    """Return True for direct or saved partial workers setters."""
    if not isinstance(call, ast.Call):
        return False
    _, _, namespace_aliases, _, partial_aliases = _unpack_operator_bindings(operator_bindings)
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    saved_aliases = operator_bindings[12] if len(operator_bindings) > 12 else set()
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_ior_aliases = operator_bindings[23] if len(operator_bindings) > 23 else set()
    partial_mutator_alias_events = operator_bindings[27] if len(operator_bindings) > 27 else {}
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    saved_mutation = _named_partial_workers_mutation(
        call,
        saved_aliases,
        partial_mutator_alias_events,
    )
    if saved_mutation is not None:
        return saved_mutation
    partial_call, invocation_start = _resolve_partial_invocation(
        call,
        partial_aliases,
        builtin_shadow_lines,
    )
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
    if _partial_call_binds_proven_frame_globals_workers_setter(
        partial_call,
        operator_bindings,
    ):
        return True
    return _partial_call_binds_namespace_workers_setter(partial_call, namespace_aliases)



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


def _attribute_call_mutates_lambda_param(call, param_name):
    """Return True when an attribute call mutates the lambda parameter."""
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == param_name
    ):
        return False
    if func.attr == "update":
        return _update_payload_may_set_workers(call)
    if func.attr in {"__ior__", "ior"}:
        return bool(call.args) and _dict_merge_payload_may_set_workers(
            call.args[0]
        )
    if func.attr == "__setitem__" and call.args:
        return _key_may_be_workers(call.args[0])
    return False


def _invoked_lambda_param_namespace_mutation(call, param_name):
    """Inspect an immediately invoked lambda without crossing shadowed scope."""
    func = call.func
    if not isinstance(func, ast.Lambda):
        return False
    if any(
        _lambda_param_namespace_mutation(arg, param_name)
        for arg in call.args
    ):
        return True
    if any(
        _lambda_param_namespace_mutation(keyword.value, param_name)
        for keyword in call.keywords
    ):
        return True
    if param_name in _lambda_bound_names(func):
        return False
    return _lambda_param_namespace_mutation(func.body, param_name)


def _call_mutates_lambda_param_namespace(call, param_name, dict_shadow_line=None):
    """Return True when one call can mutate the tracked lambda parameter."""
    return (
        _attribute_call_mutates_lambda_param(call, param_name)
        or _call_is_dict_setitem_on_name(call, param_name, dict_shadow_line)
        or _invoked_lambda_param_namespace_mutation(call, param_name)
    )


def _lambda_param_namespace_mutation(body, param_name, dict_shadow_line=None):
    """Return True when a lambda body mutates ``param_name`` with a workers payload."""
    if isinstance(body, ast.Lambda):
        return False
    if isinstance(body, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        return _comprehension_param_namespace_mutation(body, param_name)
    if isinstance(body, ast.Call) and _call_mutates_lambda_param_namespace(
        body,
        param_name,
        dict_shadow_line,
    ):
        return True
    return any(
        _lambda_param_namespace_mutation(child, param_name, dict_shadow_line)
        for child in ast.iter_child_nodes(body)
        if isinstance(child, ast.AST) and not isinstance(child, ast.Lambda)
    )

def _call_is_dict_setitem_on_name(call, name, dict_shadow_line=None):
    """Return True for ``dict.__setitem__(name, 'workers', ...)`` calls."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    if not isinstance(call.args[0], ast.Name) or call.args[0].id != name:
        return False
    if not _is_dict_type_setitem_callable(
        call.func,
        reference_line=getattr(call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return False
    return _key_may_be_workers(call.args[1])


def _is_operator_setitem_callable(func, setitem_aliases, module_aliases=None):
    """Return True for ``operator.setitem`` or a proven alias."""
    if module_aliases is None:
        module_aliases = set()
    if isinstance(func, ast.Name):
        return func.id in setitem_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "setitem"
        and _is_operator_module_reference(func.value, module_aliases)
    )


def _is_operator_call_factory(func, operator_bindings, bound_names=None):
    """Return True for a source-valid ``operator.call`` factory."""
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    module_events = operator_bindings[31] if len(operator_bindings) > 31 else {}
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    reference_line = getattr(func, 'lineno', 0)
    call_alias_events = builtin_shadow_lines.get(_OPERATOR_CALL_ALIAS_EVENTS_KEY, {})
    if isinstance(func, ast.Name):
        if bound_names and func.id in bound_names:
            return False
        return bool(
            _binding_state_at_line(
                call_alias_events,
                func.id,
                reference_line,
            )
        )
    if isinstance(func, ast.Attribute) and func.attr == 'call':
        return _module_alias_active_at_line(
            func.value,
            module_aliases,
            module_events,
            reference_line,
        ) or _is_operator_import(func.value)
    if not (
        isinstance(func, ast.Call)
        and _name_is_unshadowed_builtin('getattr', reference_line, builtin_shadow_lines)
        and isinstance(func.func, ast.Name)
        and func.func.id == 'getattr'
        and len(func.args) >= 2
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == 'call'
    ):
        return False
    return _module_alias_active_at_line(
        func.args[0],
        module_aliases,
        module_events,
        reference_line,
    ) or _is_operator_import(func.args[0])



def _call_is_operator_call_mutating_callback(call, operator_bindings, bound_names=None):
    """Return True when ``operator.call`` eagerly executes a workers-mutating callback."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    if not _is_operator_call_factory(call.func, operator_bindings, bound_names):
        return False
    callee = call.args[0]
    if isinstance(callee, ast.Lambda):
        return _lambda_mutates_workers(callee, operator_bindings)
    if isinstance(callee, ast.Name):
        return _mutating_callback_alias_is_active(
            callee,
            operator_bindings,
        )
    return False


def _call_is_partial_mutating_callback_invocation(call, operator_bindings):
    """Return True when a partial(...)() call executes a workers-mutating callback."""
    if not isinstance(call, ast.Call):
        return False
    partial_aliases = operator_bindings[4] if len(operator_bindings) > 4 else set()
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    partial_call, _ = _resolve_partial_invocation(
        call,
        partial_aliases,
        builtin_shadow_lines,
    )
    if partial_call is None or not partial_call.args:
        return False
    callback = partial_call.args[0]
    if isinstance(callback, ast.Lambda):
        return _lambda_mutates_workers(callback, operator_bindings)
    if isinstance(callback, ast.Name):
        return _mutating_callback_alias_is_active(
            callback,
            operator_bindings,
        )
    return False


def _call_is_operator_call_namespace_update(call, operator_bindings, bound_names=None):
    """Return True for ``operator.call(globals().update, ...)`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    setitem_aliases = operator_bindings[1] if len(operator_bindings) > 1 else set()
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    if not _is_operator_call_factory(call.func, operator_bindings, bound_names):
        return False
    callee = call.args[0]
    if (
        isinstance(callee, ast.Attribute)
        and callee.attr == "update"
        and _is_module_namespace_mapping(callee.value, namespace_aliases)
    ):
        return _update_payload_may_set_workers(call, start_index=1)
    if (
        isinstance(callee, ast.Attribute)
        and callee.attr == "__setitem__"
        and _is_module_namespace_mapping(callee.value, namespace_aliases)
        and len(call.args) >= 2
        and _key_may_be_workers(call.args[1])
    ):
        return True
    if (
        len(call.args) >= 3
        and _is_operator_setitem_callable(callee, setitem_aliases, module_aliases)
        and _is_module_namespace_mapping(call.args[1], namespace_aliases)
        and _key_may_be_workers(call.args[2])
    ):
        return True
    return False


def _class_overrides_update(class_node):
    """Return True when a class body binds its own ``update`` member."""
    for stmt in class_node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == 'update':
            return True
        if any(name == 'update' for name, _value in _namespace_assignment_values(stmt)):
            return True
    return False



def _dict_subclass_uses_builtin_update(class_node, dict_shadow_line=None):
    """Return whether a class inherits the unmodified builtin dict.update."""
    line = getattr(class_node, 'lineno', 0)
    inherits_builtin_dict = (
        _dict_name_is_builtin_at_line(line, dict_shadow_line)
        and any(
            isinstance(base, ast.Name) and base.id == 'dict'
            for base in class_node.bases
        )
    )
    return inherits_builtin_dict and not _class_overrides_update(class_node)


def _deactivate_tracked_binding(events, name, line):
    """Record that a previously tracked binding is no longer active."""
    if name in events:
        events[name].append((line, False))


def _invalidate_tracked_bindings_from_statement(node, events, line):
    """Deactivate tracked names rebound by a non-class statement."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _deactivate_tracked_binding(events, node.name, line)
    for name, _value in _namespace_assignment_values(node):
        _deactivate_tracked_binding(events, name, line)


def _record_dict_subclass_definition(
    class_node,
    events,
    dict_shadow_line,
    *,
    conditional,
):
    """Record one dict-subclass definition while preserving branch uncertainty."""
    line = getattr(class_node, 'lineno', 0)
    if _dict_subclass_uses_builtin_update(class_node, dict_shadow_line):
        events.setdefault(class_node.name, []).append((line, True))
        return
    if not conditional:
        _deactivate_tracked_binding(events, class_node.name, line)


def _scan_dict_subclass_bindings(
    statements,
    events,
    dict_shadow_line,
    *,
    conditional=False,
):
    """Populate source-ordered dict-subclass binding events."""
    for node in statements:
        line = getattr(node, 'lineno', 0)
        if isinstance(node, ast.ClassDef):
            _record_dict_subclass_definition(
                node,
                events,
                dict_shadow_line,
                conditional=conditional,
            )
            continue
        if not conditional:
            _invalidate_tracked_bindings_from_statement(node, events, line)
        for nested in _compound_statement_blocks(node):
            _scan_dict_subclass_bindings(
                nested,
                events,
                dict_shadow_line,
                conditional=True,
            )


def _collect_dict_subclass_names(statements, dict_shadow_line=None):
    """Track class names that inherit the unmodified builtin ``dict.update``."""
    events = {}
    _scan_dict_subclass_bindings(statements, events, dict_shadow_line)
    return events




def _call_is_dict_subclass_update_on_module_namespace(
    call,
    namespace_aliases=None,
    dict_subclass_names=None,
):
    """Return True for active ``DictSubclass.update(globals(), ...)`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == 'update'
        and isinstance(func.value, ast.Name)
    ):
        return False
    name = func.value.id
    if isinstance(dict_subclass_names, dict):
        active = _binding_state_at_line(
            dict_subclass_names,
            name,
            getattr(call, 'lineno', 0),
        )
        if not active:
            return False
    elif name not in (dict_subclass_names or set()):
        return False
    if not _is_module_namespace_mapping(call.args[0], namespace_aliases):
        return False
    return _update_payload_may_set_workers(call)





_OPERATOR_CALL_ALIAS_EVENTS_KEY = object()
_MUTATING_CALLBACK_ALIAS_EVENTS_KEY = object()
_EXIT_STACK_ALIAS_EVENTS_KEY = object()
_CONTEXTLIB_MODULE_ALIAS_EVENTS_KEY = object()
_EXIT_STACK_CLASS_ALIAS_EVENTS_KEY = object()
_MUTATING_CALLBACK_CONTAINER_EVENTS_KEY = object()


def _mutating_callback_binding_is_active(node, operator_bindings, key):
    """Return True when a name resolves to one tracked callback binding kind."""
    if not isinstance(node, ast.Name):
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    events = shadow_lines.get(key, {})
    return bool(
        _binding_state_at_line(
            events,
            node.id,
            getattr(node, "lineno", 0),
        )
    )


def _mutating_callback_alias_is_active(node, operator_bindings):
    """Return True when a name resolves to a tracked workers-mutating callback."""
    return _mutating_callback_binding_is_active(
        node,
        operator_bindings,
        _MUTATING_CALLBACK_ALIAS_EVENTS_KEY,
    )


def _mutating_callback_container_is_active(node, operator_bindings):
    """Return True when a name resolves to a tracked callback container."""
    return _mutating_callback_binding_is_active(
        node,
        operator_bindings,
        _MUTATING_CALLBACK_CONTAINER_EVENTS_KEY,
    )


def _iterable_literal_contains_mutating_lambda(node, operator_bindings):
    """Return True when a literal iterable holds a workers-mutating callback."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return False
    return any(
        (
            isinstance(element, ast.Lambda)
            and _lambda_mutates_workers(element, operator_bindings)
        )
        or _mutating_callback_alias_is_active(element, operator_bindings)
        or _iterable_literal_contains_mutating_lambda(element, operator_bindings)
        for element in node.elts
    )


def _iterable_holds_mutating_callbacks(node, operator_bindings):
    """Return True when an iterable expression may hold mutating callbacks."""
    if _iterable_literal_contains_mutating_lambda(node, operator_bindings):
        return True
    return _mutating_callback_container_is_active(node, operator_bindings)


def _iterable_literal_contains_active_mutating_callback(
    node,
    active_callbacks,
    operator_bindings,
):
    """Return True when a literal contains a currently tracked risky callback."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return False
    return any(
        (
            isinstance(element, ast.Lambda)
            and _lambda_mutates_workers(element, operator_bindings)
        )
        or (
            isinstance(element, ast.Name)
            and element.id in active_callbacks
        )
        for element in node.elts
    )


def _value_is_active_mutating_callback(
    value,
    active_callbacks,
    operator_bindings,
):
    """Return True when a value resolves to a currently mutating callback."""
    if isinstance(value, ast.Lambda):
        return _lambda_mutates_workers(value, operator_bindings)
    return isinstance(value, ast.Name) and value.id in active_callbacks


def _partial_wraps_active_mutating_callback(
    value,
    active_callbacks,
    operator_bindings,
):
    """Return True when a partial stores one active mutating callback."""
    partial_aliases = operator_bindings[4] if len(operator_bindings) > 4 else set()
    partial_call = _partial_factory_call(value, partial_aliases)
    if partial_call is None or not partial_call.args:
        return False
    return _value_is_active_mutating_callback(
        partial_call.args[0],
        active_callbacks,
        operator_bindings,
    )


def _subscript_selects_mutating_callback(
    value,
    active_callbacks,
    active_containers,
    operator_bindings,
):
    """Return True when a subscript reads from a mutating callback container."""
    if not isinstance(value, ast.Subscript):
        return False
    source = value.value
    return (
        isinstance(source, ast.Name)
        and source.id in active_containers
    ) or _iterable_literal_contains_active_mutating_callback(
        source,
        active_callbacks,
        operator_bindings,
    )


def _callback_assignment_kind(
    value,
    active_callbacks,
    active_containers,
    operator_bindings,
):
    """Classify an assignment as a risky callback or callback container."""
    if _value_is_active_mutating_callback(
        value,
        active_callbacks,
        operator_bindings,
    ):
        return "callback"
    if isinstance(value, ast.Name) and value.id in active_containers:
        return "container"
    if _partial_wraps_active_mutating_callback(
        value,
        active_callbacks,
        operator_bindings,
    ):
        return "callback"
    if _iterable_literal_contains_active_mutating_callback(
        value,
        active_callbacks,
        operator_bindings,
    ):
        return "container"
    if _iterable_literal_contains_mutating_lambda(value, operator_bindings):
        return "container"
    if _subscript_selects_mutating_callback(
        value,
        active_callbacks,
        active_containers,
        operator_bindings,
    ):
        return "callback"
    return None


def _record_callback_binding_state(name, line, active, events, enabled):
    """Record one source-ordered callback binding state."""
    if enabled:
        active.add(name)
    else:
        active.discard(name)
    events.setdefault(name, []).append((line, enabled))


def _record_mutating_callback_assignment(
    name,
    value,
    line,
    active_callbacks,
    active_containers,
    callback_events,
    container_events,
    operator_bindings,
    *,
    conditional,
):
    """Record callback/container provenance for one assignment."""
    kind = _callback_assignment_kind(
        value,
        active_callbacks,
        active_containers,
        operator_bindings,
    )
    if kind == "callback":
        _record_callback_binding_state(
            name,
            line,
            active_callbacks,
            callback_events,
            True,
        )
        if not conditional:
            _record_callback_binding_state(
                name,
                line,
                active_containers,
                container_events,
                False,
            )
        return
    if kind == "container":
        _record_callback_binding_state(
            name,
            line,
            active_containers,
            container_events,
            True,
        )
        if not conditional:
            _record_callback_binding_state(
                name,
                line,
                active_callbacks,
                callback_events,
                False,
            )
        return
    if not conditional:
        _record_callback_binding_state(
            name,
            line,
            active_callbacks,
            callback_events,
            False,
        )
        _record_callback_binding_state(
            name,
            line,
            active_containers,
            container_events,
            False,
        )


def _scan_mutating_callback_alias_events(
    statements,
    operator_bindings,
    active_callbacks,
    active_containers,
    callback_events,
    container_events,
    *,
    conditional=False,
):
    """Track risky callback and callback-container aliases."""
    definition_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in statements:
        line = getattr(node, "lineno", 0)
        if isinstance(node, definition_types):
            if not conditional:
                mutator_names = (
                    operator_bindings[46]
                    if len(operator_bindings) > 46
                    else set()
                )
                is_mutating_function = (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name in mutator_names
                )
                _record_callback_binding_state(
                    node.name,
                    line,
                    active_callbacks,
                    callback_events,
                    is_mutating_function,
                )
                _record_callback_binding_state(
                    node.name,
                    line,
                    active_containers,
                    container_events,
                    False,
                )
            continue

        for name, value in _namespace_assignment_values(node):
            _record_mutating_callback_assignment(
                name,
                value,
                line,
                active_callbacks,
                active_containers,
                callback_events,
                container_events,
                operator_bindings,
                conditional=conditional,
            )

        for block in _compound_statement_blocks(node):
            _scan_mutating_callback_alias_events(
                block,
                operator_bindings,
                active_callbacks,
                active_containers,
                callback_events,
                container_events,
                conditional=True,
            )


def _collect_mutating_callback_alias_events(tree, operator_bindings):
    """Track risky callbacks separately from containers that hold them."""
    callback_events = {}
    container_events = {}
    _scan_mutating_callback_alias_events(
        tree.body,
        operator_bindings,
        set(),
        set(),
        callback_events,
        container_events,
    )
    return callback_events, container_events


def _contextlib_exit_stack_constructor(value, operator_bindings):
    """Return True when ``value`` constructs a contextlib.ExitStack."""
    if not isinstance(value, ast.Call):
        return False
    func = value.func
    reference_line = getattr(value, "lineno", 0)
    binding_store = (
        operator_bindings[32] if len(operator_bindings) > 32 else {}
    )
    exit_stack_class_events = binding_store.get(
        _EXIT_STACK_CLASS_ALIAS_EVENTS_KEY,
        {},
    )
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            exit_stack_class_events,
            func.id,
            reference_line,
        )
    if not (isinstance(func, ast.Attribute) and func.attr == "ExitStack"):
        return False
    module_events = binding_store.get(_CONTEXTLIB_MODULE_ALIAS_EVENTS_KEY, {})
    return _module_alias_active_at_line(
        func.value,
        set(),
        module_events,
        reference_line,
    )


def _record_exit_stack_with_alias(item, events, line, operator_bindings, *, conditional):
    """Record one context-managed ExitStack instance alias."""
    if item.optional_vars is None:
        return
    if not _contextlib_exit_stack_constructor(
        item.context_expr,
        operator_bindings,
    ):
        return
    for name in _loop_target_names(item.optional_vars):
        events.setdefault(name, []).append((line, True))
        if conditional:
            return


def _scan_exit_stack_alias_events(statements, events, operator_bindings, *, conditional=False):
    """Track aliases bound from ``with contextlib.ExitStack()`` blocks."""
    for node in statements:
        if isinstance(node, (ast.With, ast.AsyncWith)):
            line = getattr(node, "lineno", 0)
            for item in node.items:
                _record_exit_stack_with_alias(
                    item,
                    events,
                    line,
                    operator_bindings,
                    conditional=conditional,
                )
        for block in _compound_statement_blocks(node):
            _scan_exit_stack_alias_events(
                block,
                events,
                operator_bindings,
                conditional=True,
            )


def _collect_exit_stack_alias_events(tree, operator_bindings):
    """Collect source-ordered ExitStack instance aliases."""
    events = {}
    _scan_exit_stack_alias_events(tree.body, events, operator_bindings)
    return events


def _weakref_module_alias_events(operator_bindings):
    """Return source-ordered weakref module alias events when present."""
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        return operator_bindings[32].get("weakref_module_alias_events", {})
    return {}


def _weakref_finalize_alias_events(operator_bindings):
    """Return source-ordered direct weakref.finalize alias events."""
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        return operator_bindings[32].get("weakref_finalize_alias_events", {})
    return {}


def _warnings_module_alias_events(operator_bindings):
    """Return source-ordered warnings module alias events when present."""
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        return operator_bindings[32].get("warnings_module_alias_events", {})
    return {}


def _warnings_warn_alias_events(operator_bindings):
    """Return source-ordered direct warnings.warn alias events."""
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        return operator_bindings[32].get("warnings_warn_alias_events", {})
    return {}


def _call_resolves_to_imported_name_or_module_attr(
    call,
    imported_name,
    direct_alias_events,
    module_alias_events,
):
    """Return True when a call resolves to one imported stdlib callable."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    if isinstance(call.func, ast.Name):
        return _imported_alias_is_active(
            direct_alias_events,
            call.func.id,
            reference_line,
        )
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == imported_name
        and isinstance(call.func.value, ast.Name)
    ):
        return False
    return _imported_alias_is_active(
        module_alias_events,
        call.func.value.id,
        reference_line,
    )


def _call_is_weakref_finalize_mutation(call, operator_bindings, bound_names=None):
    """Return True for import-time weakref.finalize with a mutating callback."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    if not _call_resolves_to_imported_name_or_module_attr(
        call,
        "finalize",
        _weakref_finalize_alias_events(operator_bindings),
        _weakref_module_alias_events(operator_bindings),
    ):
        return False
    callback = call.args[1]
    if isinstance(callback, ast.Lambda):
        return _lambda_mutates_workers(callback, operator_bindings)
    return _expression_mutates_workers(
        callback,
        operator_bindings,
        bound_names=bound_names,
    )


def _warnings_showwarning_target_is_active(target, operator_bindings, reference_line):
    """Return True when target is an active warnings.showwarning assignment."""
    if not isinstance(target, ast.Attribute) or target.attr != "showwarning":
        return False
    receiver = target.value
    if not isinstance(receiver, ast.Name):
        return False
    return _imported_alias_is_active(
        _warnings_module_alias_events(operator_bindings),
        receiver.id,
        reference_line,
    )


def _warnings_showwarning_value_mutates(
    value,
    operator_bindings,
    mutator_names,
):
    """Return True when a showwarning replacement can mutate workers."""
    if isinstance(value, ast.Name):
        return value.id in mutator_names
    if isinstance(value, ast.Lambda):
        return _lambda_mutates_workers(value, operator_bindings)
    return _expression_mutates_workers(value, operator_bindings)


def _collect_warnings_showwarning_mutation_events(
    tree,
    operator_bindings,
    mutator_names=None,
):
    """Track source-ordered mutating/safe warnings.showwarning replacements."""
    if mutator_names is None:
        mutator_names = set()
    events = []
    _scan_warnings_showwarning_mutation_events(
        tree.body,
        operator_bindings,
        mutator_names,
        events,
        definite=True,
    )
    return events


def _class_body_bound_names(statements):
    """Return names a class body binds in its own namespace."""
    names = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        names.update(_statement_scope_bound_names(node))
        names.update(_import_bound_names(node))
        for block in _compound_statement_blocks(node):
            names.update(_class_body_bound_names(block))
    return names


def _scan_warnings_showwarning_mutation_events(
    statements,
    operator_bindings,
    mutator_names,
    events,
    *,
    definite,
    shadowed=frozenset(),
):
    """Record showwarning replacements, flagging straight-line module ones.

    Only a definitely executed (straight-line, unconditional) safe assignment
    clears an earlier mutating replacement; a safe assignment inside a compound
    statement or class body may be skipped at runtime, so it must not hide the
    mutating hook. A mutating replacement anywhere still fails closed. Inside a
    class body that locally rebinds the receiver name, ``receiver.showwarning``
    targets that local name instead of the imported module and is ignored.
    """
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.ClassDef):
            _scan_warnings_showwarning_mutation_events(
                node.body,
                operator_bindings,
                mutator_names,
                events,
                definite=False,
                shadowed=_class_body_bound_names(node.body),
            )
            continue
        if isinstance(node, ast.Assign):
            line = getattr(node, "lineno", 0)
            if any(
                _warnings_showwarning_target_is_active(
                    target,
                    operator_bindings,
                    line,
                )
                and not (
                    isinstance(target.value, ast.Name)
                    and target.value.id in shadowed
                )
                for target in node.targets
            ):
                events.append(
                    (
                        line,
                        _warnings_showwarning_value_mutates(
                            node.value,
                            operator_bindings,
                            mutator_names,
                        ),
                        definite,
                    )
                )
        for block in _compound_statement_blocks(node):
            _scan_warnings_showwarning_mutation_events(
                block,
                operator_bindings,
                mutator_names,
                events,
                definite=False,
                shadowed=shadowed,
            )


def _warnings_showwarning_mutates_at_line(operator_bindings, reference_line):
    """Return the latest showwarning mutation state visible at one line."""
    binding_store = (
        operator_bindings[32]
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    state = False
    for event_line, mutates, definite in binding_store.get(
        "warnings_showwarning_mutation_events",
        (),
    ):
        if reference_line and event_line > reference_line:
            break
        if mutates:
            state = True
        elif definite:
            state = False
    return state


def _call_is_warnings_warn_after_mutating_hook(call, operator_bindings):
    """Return True when an active warnings.warn call executes a mutating hook."""
    reference_line = getattr(call, "lineno", 0)
    if not _warnings_showwarning_mutates_at_line(
        operator_bindings,
        reference_line,
    ):
        return False
    return _call_resolves_to_imported_name_or_module_attr(
        call,
        "warn",
        _warnings_warn_alias_events(operator_bindings),
        _warnings_module_alias_events(operator_bindings),
    )


def _node_source_position(node):
    """Return a stable source-order key for an AST node."""
    return (
        getattr(node, "lineno", 0),
        getattr(node, "col_offset", 0),
    )


def _iter_import_time_statements(statements):
    """Yield statements that execute while the config module is imported."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield node
        if isinstance(node, ast.ClassDef):
            yield from _iter_import_time_statements(node.body)
            continue
        for block in _compound_statement_blocks(node):
            yield from _iter_import_time_statements(block)


def _builtins_module_alias_events(operator_bindings):
    """Return source-ordered builtins module alias events when present."""
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        return operator_bindings[32].get("builtins_module_alias_events", {})
    return {}


def _builtins_dunder_import_target_is_active(target, operator_bindings, reference_line):
    """Return True when target references the active builtins.__import__."""
    if not isinstance(target, ast.Attribute) or target.attr != "__import__":
        return False
    receiver = target.value
    if not isinstance(receiver, ast.Name):
        return False
    return _imported_alias_is_active(
        _builtins_module_alias_events(operator_bindings),
        receiver.id,
        reference_line,
    )


def _builtins_dunder_import_assignment_is_noop(node, operator_bindings):
    """Return True for a provable builtins.__import__ self-assignment."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return False
    value = node.value
    if value is None:
        return False
    line = getattr(node, "lineno", 0)
    return _builtins_dunder_import_target_is_active(
        value,
        operator_bindings,
        line,
    )


def _assignment_targets(node):
    """Return assignment targets relevant to import-hook mutation tracking."""
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


def _collect_builtins_dunder_import_replacement_lines(tree, operator_bindings):
    """Return source positions where builtins.__import__ is replaced."""
    positions = []
    for node in _iter_import_time_statements(tree.body):
        targets = _assignment_targets(node)
        if not targets:
            continue
        line = getattr(node, "lineno", 0)
        if not any(
            _builtins_dunder_import_target_is_active(
                target,
                operator_bindings,
                line,
            )
            for target in targets
        ):
            continue
        if _builtins_dunder_import_assignment_is_noop(node, operator_bindings):
            continue
        positions.append(_node_source_position(node))
    return sorted(set(positions))


def _builtins_dunder_import_replaced_before_node(operator_bindings, node):
    """Return True when builtins.__import__ was replaced before one AST node."""
    binding_store = (
        operator_bindings[32]
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    reference_position = _node_source_position(node)
    return any(
        event_position < reference_position
        for event_position in binding_store.get(
            "builtins_dunder_import_replacement_lines",
            (),
        )
    )


def _import_statement_after_builtins_import_hook(node, operator_bindings):
    """Return True when an import runs after a replaced builtins.__import__ hook."""
    return isinstance(node, (ast.Import, ast.ImportFrom)) and (
        _builtins_dunder_import_replaced_before_node(
            operator_bindings,
            node,
        )
    )


def _call_is_active_dunder_import(call, operator_bindings):
    """Return True when a call resolves to the active __import__ builtin."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    func = call.func
    if isinstance(func, ast.Name) and func.id == "__import__":
        binding_store = (
            operator_bindings[32]
            if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
            else {}
        )
        return _name_is_unshadowed_builtin(
            "__import__",
            reference_line,
            binding_store,
        )
    return _builtins_dunder_import_target_is_active(
        func,
        operator_bindings,
        reference_line,
    )


def _statement_calls_dunder_import_after_hook(node, operator_bindings):
    """Return True when an import-time expression directly invokes the hook."""
    expr = _statement_value_expression(node)
    if expr is None:
        return False
    stack = [expr]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Lambda):
            continue
        if (
            isinstance(current, ast.Call)
            and _call_is_active_dunder_import(current, operator_bindings)
            and _builtins_dunder_import_replaced_before_node(
                operator_bindings,
                current,
            )
        ):
            return True
        stack.extend(ast.iter_child_nodes(current))
    return False


def _sys_meta_path_reference_is_active(node, operator_bindings, reference_line):
    """Return True for an active sys.meta_path attribute reference."""
    if not isinstance(node, ast.Attribute) or node.attr != "meta_path":
        return False
    receiver = node.value
    if not isinstance(receiver, ast.Name):
        return False
    sys_events = (
        operator_bindings[32].get("sys_module_alias_events", {})
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    return _imported_alias_is_active(sys_events, receiver.id, reference_line)


def _sys_meta_path_target_is_active(target, operator_bindings, reference_line):
    """Return True when an assignment mutates the active sys.meta_path."""
    if _sys_meta_path_reference_is_active(
        target,
        operator_bindings,
        reference_line,
    ):
        return True
    return (
        isinstance(target, ast.Subscript)
        and _sys_meta_path_reference_is_active(
            target.value,
            operator_bindings,
            reference_line,
        )
    )


def _call_mutates_sys_meta_path(call, operator_bindings):
    """Return True for sys.meta_path.insert/append/extend at config import time."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in {"insert", "append", "extend"}:
        return False
    return _sys_meta_path_reference_is_active(
        call.func.value,
        operator_bindings,
        getattr(call, "lineno", 0),
    )


def _collect_sys_meta_path_mutation_lines(tree, operator_bindings):
    """Return source positions that install or mutate sys.meta_path hooks."""
    positions = []
    for node in _iter_import_time_statements(tree.body):
        expr = _statement_value_expression(node)
        if isinstance(expr, ast.Call) and _call_mutates_sys_meta_path(
            expr,
            operator_bindings,
        ):
            positions.append(_node_source_position(node))
            continue
        line = getattr(node, "lineno", 0)
        if any(
            _sys_meta_path_target_is_active(
                target,
                operator_bindings,
                line,
            )
            for target in _assignment_targets(node)
        ):
            positions.append(_node_source_position(node))
    return sorted(set(positions))


def _sys_meta_path_mutated_before_node(operator_bindings, node):
    """Return True when sys.meta_path was mutated before one AST node."""
    binding_store = (
        operator_bindings[32]
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    reference_position = _node_source_position(node)
    return any(
        event_position < reference_position
        for event_position in binding_store.get("sys_meta_path_mutation_lines", ())
    )


def _import_statement_after_sys_meta_path_mutation(node, operator_bindings):
    """Return True when an import may invoke a custom sys.meta_path hook."""
    return isinstance(node, (ast.Import, ast.ImportFrom)) and (
        _sys_meta_path_mutated_before_node(operator_bindings, node)
    )


def _call_is_dataclasses_field(call, operator_bindings, reference_line):
    """Return True for a proven ``dataclasses.field(...)`` / ``field(...)`` call."""
    func = call.func
    extra = operator_bindings[32] if len(operator_bindings) > 32 and isinstance(
        operator_bindings[32],
        dict,
    ) else {}
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            extra.get("dataclasses_field_alias_events", {}),
            func.id,
            reference_line,
        )
    if isinstance(func, ast.Attribute) and func.attr == "field":
        module = func.value
        if not isinstance(module, ast.Name):
            return False
        return _imported_alias_is_active(
            extra.get("dataclasses_module_alias_events", {}),
            module.id,
            reference_line,
        )
    return False


def _dataclass_decorator_reference(decorator):
    """Return the callable expression behind a dataclass decorator."""
    return decorator.func if isinstance(decorator, ast.Call) else decorator


def _class_uses_dataclass_decorator(class_node, operator_bindings):
    """Return True when a class uses an active dataclasses.dataclass decorator."""
    binding_store = (
        operator_bindings[32]
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    for decorator in class_node.decorator_list:
        reference = _dataclass_decorator_reference(decorator)
        reference_line = getattr(decorator, "lineno", 0)
        if isinstance(reference, ast.Name) and _imported_alias_is_active(
            binding_store.get("dataclasses_dataclass_alias_events", {}),
            reference.id,
            reference_line,
        ):
            return True
        if (
            isinstance(reference, ast.Attribute)
            and reference.attr == "dataclass"
            and isinstance(reference.value, ast.Name)
            and _imported_alias_is_active(
                binding_store.get("dataclasses_module_alias_events", {}),
                reference.value.id,
                reference_line,
            )
        ):
            return True
    return False


def _dataclass_default_factory_mutates(field_call, operator_bindings):
    """Return True when a dataclass field default_factory mutates ``workers``."""
    for keyword in field_call.keywords:
        if keyword.arg != "default_factory":
            continue
        factory = keyword.value
        if isinstance(factory, ast.Lambda):
            return _lambda_mutates_workers(factory, operator_bindings)
        return _expression_mutates_workers(factory, operator_bindings)
    return False


def _class_dataclass_field_default_factory_mutates(class_node, operator_bindings):
    """Return True when a dataclass field default_factory mutates ``workers``."""
    if not _class_uses_dataclass_decorator(class_node, operator_bindings):
        return False
    for stmt in class_node.body:
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(value, ast.Call):
            continue
        line = getattr(stmt, "lineno", 0)
        if _call_is_dataclasses_field(
            value,
            operator_bindings,
            line,
        ) and _dataclass_default_factory_mutates(value, operator_bindings):
            return True
    return False


def _call_is_exit_stack_callback_mutation(call, operator_bindings):
    """Return True for ``stack.callback(mutating)`` on a tracked ExitStack."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "callback" or len(call.args) != 1:
        return False
    if not _thread_pool_callback_mutates_workers(call.args[0], operator_bindings):
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Name):
        return False
    exit_stack_events = {}
    if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict):
        exit_stack_events = operator_bindings[32].get(
            _EXIT_STACK_ALIAS_EVENTS_KEY,
            {},
        )
    return _imported_alias_is_active(
        exit_stack_events,
        receiver.id,
        getattr(call, "lineno", 0),
    )


def _lambda_invokes_first_positional_param(lambda_node):
    """Return True when a lambda body calls its first positional parameter."""
    if not isinstance(lambda_node, ast.Lambda):
        return False
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    if not positional_params:
        return False
    param_name = positional_params[0].arg
    body = lambda_node.body
    return (
        isinstance(body, ast.Call)
        and isinstance(body.func, ast.Name)
        and body.func.id == param_name
        and not body.args
        and not body.keywords
    )


def _resolved_map_filter_name_reference(func, reference_line, operator_bindings):
    """Return map/filter for an unshadowed direct builtin name."""
    if not isinstance(func, ast.Name) or func.id not in {"map", "filter"}:
        return None
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    if not _name_is_unshadowed_builtin(func.id, reference_line, shadow_lines):
        return None
    return func.id


def _resolved_map_filter_attribute(func, reference_line, operator_bindings):
    """Return map/filter for a proven builtins-module attribute."""
    if not (
        isinstance(func, ast.Attribute)
        and func.attr in {"map", "filter"}
    ):
        return None
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    builtins_alias_events = (
        operator_bindings[30] if len(operator_bindings) > 30 else {}
    )
    if not _builtins_module_is_active_at_line(
        func.value,
        builtins_aliases,
        builtins_alias_events,
        reference_line,
    ):
        return None
    return func.attr


def _resolved_map_filter_name(call, operator_bindings):
    """Return ``map`` or ``filter`` when ``call`` resolves to the builtin."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    reference_line = getattr(call, "lineno", 0)
    name = _resolved_map_filter_name_reference(
        call.func,
        reference_line,
        operator_bindings,
    )
    if name is not None:
        return name
    return _resolved_map_filter_attribute(
        call.func,
        reference_line,
        operator_bindings,
    )


def _map_or_filter_lambda_mutates_when_consumed(call, operator_bindings):
    """Return True when consuming a map/filter must execute a risky lambda."""
    name = _resolved_map_filter_name(call, operator_bindings)
    if name is None:
        return False
    lambda_node = call.args[0]
    if not isinstance(lambda_node, ast.Lambda):
        return False
    if _lambda_mutates_workers(lambda_node, operator_bindings):
        return True
    if name == "filter" and len(call.args) > 1:
        return _expression_is_mutating_lazy_iterator(
            call.args[1],
            operator_bindings,
        )
    if name != 'map':
        return False
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if any(
        _map_argument_contains_module_namespace(iterable, namespace_aliases)
        and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        for param, iterable in zip(positional_params, call.args[1:])
    ):
        return True
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    if positional_params:
        param_name = positional_params[0].arg
        if _expression_invokes_loop_callback(lambda_node.body, param_name):
            return any(
                _iterable_holds_mutating_callbacks(arg, operator_bindings)
                for arg in call.args[1:]
            )
    if _lambda_invokes_first_positional_param(lambda_node):
        return any(
            _iterable_holds_mutating_callbacks(arg, operator_bindings)
            for arg in call.args[1:]
        )
    return False




def _lazy_iterator_alias_is_active(expr, operator_bindings):
    """Return True for a saved risky map or filter iterator at this source line."""
    if not isinstance(expr, ast.Name) or len(operator_bindings) <= 40:
        return False
    events = operator_bindings[40]
    return bool(
        _binding_state_at_line(
            events,
            expr.id,
            getattr(expr, "lineno", 0),
        )
    )


_LAZY_ITERATOR_BUILTIN_WRAPPER_NAMES = frozenset(
    {"enumerate", "zip", "iter", "reversed"}
)
_COLLECTIONS_LAZY_CONSUMER_NAMES = frozenset({"deque", "Counter"})


def _imported_alias_is_active(events, name, reference_line):
    """Return whether an imported callable alias is active at one source line."""
    return bool(_binding_state_at_line(events, name, reference_line))


def _attribute_call_wraps_mutating_lazy_iterator(
    call,
    operator_bindings,
    active_names=None,
):
    """Return True for proven itertools.islice wrappers."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "islice" or not call.args:
        return False
    module_events = operator_bindings[35] if len(operator_bindings) > 35 else {}
    if not _module_alias_active_at_line(
        call.func.value,
        set(),
        module_events,
        getattr(call, "lineno", 0),
    ):
        return False
    return _expression_is_mutating_lazy_iterator(
        call.args[0],
        operator_bindings,
        active_names,
    )


def _named_lazy_wrapper_is_active(call, operator_bindings):
    """Return whether a named lazy-iterator wrapper resolves to a known callable."""
    name = call.func.id
    reference_line = getattr(call, "lineno", 0)
    if name in _LAZY_ITERATOR_BUILTIN_WRAPPER_NAMES:
        shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
        return _name_is_unshadowed_builtin(
            name,
            reference_line,
            shadow_lines,
        )
    alias_events = operator_bindings[36] if len(operator_bindings) > 36 else {}
    return _imported_alias_is_active(
        alias_events,
        name,
        reference_line,
    )


def _call_wraps_mutating_lazy_iterator(call, operator_bindings, active_names=None):
    """Return True when a call produces another iterator over a risky source."""
    if not isinstance(call, ast.Call):
        return False
    if _attribute_call_wraps_mutating_lazy_iterator(
        call,
        operator_bindings,
        active_names,
    ):
        return True
    if not isinstance(call.func, ast.Name):
        return False
    if not _named_lazy_wrapper_is_active(call, operator_bindings):
        return False
    return any(
        _expression_is_mutating_lazy_iterator(
            arg,
            operator_bindings,
            active_names,
        )
        for arg in call.args
    )


def _function_runtime_nodes(func_def):
    """Yield evaluated nodes in a function without crossing nested scopes."""
    stack = list(reversed(func_def.body))
    while stack:
        node = stack.pop()
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _function_has_mutating_yield_from(func_def, operator_bindings):
    """Return True when a generator function yields from a risky iterator."""
    return any(
        isinstance(node, ast.YieldFrom)
        and _expression_is_mutating_lazy_iterator(
            node.value,
            operator_bindings,
        )
        for node in _function_runtime_nodes(func_def)
    )


def _function_yields_sys_getframe(func_def, operator_bindings):
    """Return True when a generator yields an active sys._getframe alias."""
    binding_store = (
        operator_bindings[32]
        if len(operator_bindings) > 32 and isinstance(operator_bindings[32], dict)
        else {}
    )
    module_events = binding_store.get("sys_module_alias_events", {})
    direct_events = binding_store.get("sys_getframe_alias_events", {})
    for node in _function_runtime_nodes(func_def):
        if not isinstance(node, ast.Yield) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        line = getattr(call, "lineno", 0)
        if isinstance(call.func, ast.Name) and _imported_alias_is_active(
            direct_events,
            call.func.id,
            line,
        ):
            return True
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "_getframe"
            and isinstance(call.func.value, ast.Name)
            and _imported_alias_is_active(
                module_events,
                call.func.value.id,
                line,
            )
        ):
            return True
    return False


def _function_yields_proven_live_frame(func_def, inspect_analysis):
    """Return True when a generator yields a proven live frame object."""
    active_frame_names = set()
    for node in _function_runtime_nodes(func_def):
        if not isinstance(node, ast.Yield) or node.value is None:
            continue
        if _sys_getframe_call_is_active(node.value, inspect_analysis):
            return True
        if _node_is_proven_live_frame(
            node.value,
            inspect_analysis,
            active_frame_names,
        ):
            return True
    return False


def _scan_mutating_yield_from_functions(statements, operator_bindings, names):
    """Collect risky generator definitions from import-time compound blocks."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if (
                _function_has_mutating_yield_from(node, operator_bindings)
                or _function_yields_sys_getframe(node, operator_bindings)
            ):
                names.add(node.name)
            continue
        if isinstance(node, ast.ClassDef):
            continue
        for block in _compound_statement_blocks(node):
            _scan_mutating_yield_from_functions(
                block,
                operator_bindings,
                names,
            )


def _collect_mutating_yield_from_functions(tree, operator_bindings):
    """Return function names that yield from a risky lazy iterator."""
    names = set()
    _scan_mutating_yield_from_functions(
        tree.body,
        operator_bindings,
        names,
    )
    return names


def _record_mutating_generator_definition(
    node,
    operator_bindings,
    active_names,
    events,
    *,
    conditional,
):
    """Record generator/class definitions and return whether the node was handled."""
    if not isinstance(
        node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
    ):
        return False
    line = getattr(node, "lineno", 0)
    inspect_analysis = (
        operator_bindings[-1]
        if operator_bindings
        and isinstance(operator_bindings[-1], dict)
        and "frame_alias_events" in operator_bindings[-1]
        else {}
    )
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
        _function_has_mutating_yield_from(node, operator_bindings)
        or _function_yields_sys_getframe(node, operator_bindings)
        or _function_yields_proven_live_frame(node, inspect_analysis)
    ):
        active_names.add(node.name)
        events.setdefault(node.name, []).append((line, True))
    elif not conditional:
        _deactivate_imported_module_alias(
            node.name,
            active_names,
            events,
            line,
        )
    return True


def _record_mutating_generator_assignment_aliases(
    node,
    active_names,
    events,
    *,
    conditional,
):
    """Record assignment aliases of risky generator functions."""
    line = getattr(node, "lineno", 0)
    for name, value in _namespace_assignment_values(node):
        if isinstance(value, ast.Name) and value.id in active_names:
            active_names.add(name)
            events.setdefault(name, []).append((line, True))
        elif not conditional:
            _deactivate_imported_module_alias(
                name,
                active_names,
                events,
                line,
            )


def _scan_mutating_generator_alias_events(
    statements,
    operator_bindings,
    active_names,
    events,
    *,
    conditional=False,
):
    """Track risky generator definitions, aliases, and definite rebindings."""
    for node in statements:
        if _record_mutating_generator_definition(
            node,
            operator_bindings,
            active_names,
            events,
            conditional=conditional,
        ):
            continue
        _record_mutating_generator_assignment_aliases(
            node,
            active_names,
            events,
            conditional=conditional,
        )
        for block in _compound_statement_blocks(node):
            _scan_mutating_generator_alias_events(
                block,
                operator_bindings,
                active_names,
                events,
                conditional=True,
            )


def _collect_mutating_generator_alias_events(tree, operator_bindings):
    """Collect source-ordered aliases of risky yield-from generators."""
    events = {}
    _scan_mutating_generator_alias_events(
        tree.body,
        operator_bindings,
        set(),
        events,
    )
    return events


def _call_is_mutating_generator(expr, operator_bindings):
    """Return whether a call invokes an active risky generator."""
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Name):
        return False
    name = expr.func.id
    generator_alias_events = (
        operator_bindings[42] if len(operator_bindings) > 42 else {}
    )
    if name in generator_alias_events:
        state = _binding_state_at_line(
            generator_alias_events,
            name,
            getattr(expr, "lineno", 0),
        )
        if state is not None:
            return bool(state)
    mutating_generators = (
        operator_bindings[41] if len(operator_bindings) > 41 else set()
    )
    return name in mutating_generators


def _name_is_mutating_lazy_iterator(expr, operator_bindings, active_names):
    """Resolve a saved risky lazy iterator name."""
    if not isinstance(expr, ast.Name):
        return False
    if active_names is not None:
        return expr.id in active_names
    return _lazy_iterator_alias_is_active(expr, operator_bindings)


def _generator_expression_uses_mutating_iterator(
    expr,
    operator_bindings,
    active_names,
):
    """Return whether a generator expression iterates over a risky source."""
    if not isinstance(expr, ast.GeneratorExp):
        return False
    return any(
        _expression_is_mutating_lazy_iterator(
            generator.iter,
            operator_bindings,
            active_names,
        )
        for generator in expr.generators
    )


def _expression_is_mutating_lazy_iterator(
    expr,
    operator_bindings,
    active_names=None,
):
    """Return True for a risky lazy iterator without consuming it."""
    if _map_or_filter_lambda_mutates_when_consumed(expr, operator_bindings):
        return True
    if isinstance(expr, ast.Call):
        if _call_wraps_mutating_lazy_iterator(
            expr,
            operator_bindings,
            active_names,
        ):
            return True
        if _call_is_thread_pool_imap_iterator(expr, operator_bindings):
            return True
        if _call_is_mutating_generator(expr, operator_bindings):
            return True
    if _name_is_mutating_lazy_iterator(
        expr,
        operator_bindings,
        active_names,
    ):
        return True
    return _generator_expression_uses_mutating_iterator(
        expr,
        operator_bindings,
        active_names,
    )


def _key_lambda_mutates_workers(call, operator_bindings):
    """Return True when a key callback executed by this call mutates workers."""
    return any(
        keyword.arg == 'key'
        and isinstance(keyword.value, ast.Lambda)
        and _lambda_mutates_workers(keyword.value, operator_bindings)
        for keyword in call.keywords
    )


def _key_lambda_invokes_mutating_callback_container(call, operator_bindings):
    """Return True when a key= lambda invokes callbacks from the sorted iterable."""
    key_lambda = None
    for keyword in call.keywords:
        if keyword.arg == "key" and isinstance(keyword.value, ast.Lambda):
            key_lambda = keyword.value
            break
    if key_lambda is None or not call.args:
        return False
    positional_params = (
        *key_lambda.args.posonlyargs,
        *key_lambda.args.args,
    )
    if not positional_params:
        return False
    param_name = positional_params[0].arg
    if not _expression_invokes_loop_callback(key_lambda.body, param_name):
        return False
    return _iterable_holds_mutating_callbacks(call.args[0], operator_bindings)


def _builtin_consumer_is_active(name, call, operator_bindings, bound_names=None):
    """Return whether a known eager iterable consumer still resolves to a builtin."""
    if bound_names and name in bound_names:
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    return _name_is_unshadowed_builtin(
        name,
        getattr(call, 'lineno', 0),
        shadow_lines,
    )


def _join_receiver_is_string(value, operator_bindings, reference_line):
    """Return True for literal or source-tracked str or bytes join receivers."""
    if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
        return True
    if not isinstance(value, ast.Name):
        return False
    events = operator_bindings[37] if len(operator_bindings) > 37 else {}
    return _imported_alias_is_active(events, value.id, reference_line)


def _attribute_call_consumes_mutating_lazy_iterator(call, operator_bindings):
    """Detect eager str or bytes join consumers of risky iterators."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "join" or not call.args:
        return False
    if not _join_receiver_is_string(
        call.func.value,
        operator_bindings,
        getattr(call, "lineno", 0),
    ):
        return False
    return _expression_is_mutating_lazy_iterator(
        call.args[0],
        operator_bindings,
    )


def _thread_class_reference_is_active(
    reference,
    operator_bindings,
    reference_line,
):
    """Return whether an expression resolves to threading.Thread or Timer."""
    if isinstance(reference, ast.Attribute) and reference.attr in {
        "Thread",
        "Timer",
    }:
        module_events = operator_bindings[38] if len(operator_bindings) > 38 else {}
        return _module_alias_active_at_line(
            reference.value,
            set(),
            module_events,
            reference_line,
        )
    if isinstance(reference, ast.Name):
        alias_events = operator_bindings[39] if len(operator_bindings) > 39 else {}
        return _imported_alias_is_active(
            alias_events,
            reference.id,
            reference_line,
        )
    return False


def _thread_constructor_is_active(call, operator_bindings):
    """Return whether a Thread constructor resolves to the threading module."""
    return _thread_class_reference_is_active(
        call.func,
        operator_bindings,
        getattr(call, "lineno", 0),
    )


def _thread_target_mutates_workers(target, operator_bindings, mutator_names):
    """Return whether one Thread target can mutate workers."""
    if isinstance(target, ast.Lambda):
        return _lambda_mutates_workers(target, operator_bindings)
    return isinstance(target, ast.Name) and target.id in mutator_names


def _thread_targets(call):
    """Return positional and keyword Thread/Timer callback expressions."""
    targets = list(call.args[1:2])
    targets.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"target", "function"}
    )
    return targets


def _thread_constructor_has_mutating_target(
    call,
    operator_bindings,
    mutator_names=None,
):
    """Return True for a proven Thread constructor with a risky target."""
    if not isinstance(call, ast.Call):
        return False
    if not _thread_constructor_is_active(call, operator_bindings):
        return False
    mutator_names = set() if mutator_names is None else mutator_names
    return any(
        _thread_target_mutates_workers(
            target,
            operator_bindings,
            mutator_names,
        )
        for target in _thread_targets(call)
    )


_CONCURRENT_FUTURES_MODULE = "concurrent.futures"


_THREAD_POOL_DIRECT_IMPORT_KINDS = {
    ("multiprocessing.pool", "ThreadPool"): "pool",
    (_CONCURRENT_FUTURES_MODULE, "ThreadPoolExecutor"): "executor",
}
_THREAD_POOL_MODULE_IMPORT_KINDS = {
    "multiprocessing.pool": "pool",
    _CONCURRENT_FUTURES_MODULE: "executor",
}


def _record_thread_pool_alias_event(events, name, state, line):
    """Record a source-ordered thread-pool alias binding or rebinding."""
    if state is not None:
        events.setdefault(name, []).append((line, state))
    elif name in events:
        events[name].append((line, False))


def _record_thread_pool_direct_import_aliases(
    node,
    class_events,
    module_events,
    line,
):
    """Record direct ThreadPool and ThreadPoolExecutor imports."""
    for imported in node.names:
        name = imported.asname or imported.name
        kind = _THREAD_POOL_DIRECT_IMPORT_KINDS.get(
            (node.module, imported.name)
        )
        _record_thread_pool_alias_event(class_events, name, kind, line)
        _record_thread_pool_alias_event(module_events, name, None, line)


def _record_thread_pool_module_import_aliases(
    node,
    class_events,
    module_events,
    line,
):
    """Record supported thread-pool module imports and alias collisions."""
    for imported in node.names:
        bound_name = imported.asname or imported.name.split(".", 1)[0]
        kind = _THREAD_POOL_MODULE_IMPORT_KINDS.get(imported.name)
        module_name = imported.asname or imported.name
        tracked_name = module_name if kind is not None else bound_name
        _record_thread_pool_alias_event(
            module_events,
            tracked_name,
            kind,
            line,
        )
        if module_name != bound_name:
            _record_thread_pool_alias_event(
                module_events,
                bound_name,
                None,
                line,
            )
        _record_thread_pool_alias_event(
            class_events,
            bound_name,
            None,
            line,
        )


def _thread_pool_rebound_names(node):
    """Return names definitely rebound by one non-import statement."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (node.name,)
    return tuple(name for name, _value in _namespace_assignment_values(node))


def _record_thread_pool_rebindings(node, class_events, module_events, line):
    """Deactivate tracked thread-pool aliases rebound by one statement."""
    for name in _thread_pool_rebound_names(node):
        _record_thread_pool_alias_event(class_events, name, None, line)
        _record_thread_pool_alias_event(module_events, name, None, line)


def _collect_thread_pool_alias_events(tree):
    """Track supported thread-pool imports without losing colliding aliases."""
    class_events = {}
    module_events = {}
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.ImportFrom):
            _record_thread_pool_direct_import_aliases(
                node,
                class_events,
                module_events,
                line,
            )
        elif isinstance(node, ast.Import):
            _record_thread_pool_module_import_aliases(
                node,
                class_events,
                module_events,
                line,
            )
        else:
            _record_thread_pool_rebindings(
                node,
                class_events,
                module_events,
                line,
            )
    return class_events, module_events


def _thread_pool_reference_name(node):
    """Return a dotted name for a simple module reference expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _thread_pool_reference_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _thread_pool_constructor_kind(call, operator_bindings):
    """Return pool kind for a proven ThreadPool/ThreadPoolExecutor constructor."""
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    reference_line = getattr(call, "lineno", 0)
    class_events = operator_bindings[43] if len(operator_bindings) > 43 else {}
    module_events = operator_bindings[44] if len(operator_bindings) > 44 else {}
    if isinstance(func, ast.Name):
        state = _binding_state_at_line(
            class_events,
            func.id,
            reference_line,
        )
        return state if state in {"pool", "executor"} else None
    if not isinstance(func, ast.Attribute):
        return None
    module_name = _thread_pool_reference_name(func.value)
    if module_name is None:
        return None
    state = _binding_state_at_line(
        module_events,
        module_name,
        reference_line,
    )
    expected_name = {
        "pool": "ThreadPool",
        "executor": "ThreadPoolExecutor",
    }.get(state)
    return state if expected_name == func.attr else None


def _call_is_thread_pool_class_constructor(call, operator_bindings):
    """Return True when a call constructs ThreadPool or ThreadPoolExecutor."""
    return _thread_pool_constructor_kind(call, operator_bindings) is not None


def _thread_pool_instance_constructor_from_value(
    value,
    operator_bindings,
    events,
):
    """Resolve an expression to the constructor that produced a tracked pool."""
    if isinstance(value, ast.Call) and _call_is_thread_pool_class_constructor(
        value,
        operator_bindings,
    ):
        return value
    if isinstance(value, ast.Name):
        state = _binding_state_at_line(
            events,
            value.id,
            getattr(value, "lineno", 0),
        )
        if isinstance(state, ast.Call):
            return state
    return None


def _record_thread_pool_target_binding(target, constructor, events, line):
    """Bind a with-target or assignment target to one proven pool instance."""
    if isinstance(target, ast.Name):
        events.setdefault(target.id, []).append((line, constructor))
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _record_thread_pool_target_binding(
                element,
                constructor,
                events,
                line,
            )


def _record_thread_pool_definition_rebinding(
    node,
    events,
    line,
    *,
    conditional,
):
    """Handle a definition that may rebind a tracked pool instance."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if not conditional:
        _record_thread_pool_alias_event(events, node.name, None, line)
    return True


def _record_thread_pool_with_alias(
    item,
    operator_bindings,
    events,
    line,
    *,
    conditional,
):
    """Record one context-managed pool instance alias."""
    if item.optional_vars is None:
        return
    constructor = _thread_pool_instance_constructor_from_value(
        item.context_expr,
        operator_bindings,
        events,
    )
    if constructor is not None:
        _record_thread_pool_target_binding(
            item.optional_vars,
            constructor,
            events,
            line,
        )
        return
    if not conditional and isinstance(item.optional_vars, ast.Name):
        _record_thread_pool_alias_event(
            events,
            item.optional_vars.id,
            None,
            line,
        )


def _record_thread_pool_with_aliases(
    node,
    operator_bindings,
    events,
    line,
    *,
    conditional,
):
    """Record context-managed thread-pool aliases from one statement."""
    if not isinstance(node, ast.With):
        return
    for item in node.items:
        _record_thread_pool_with_alias(
            item,
            operator_bindings,
            events,
            line,
            conditional=conditional,
        )


def _record_thread_pool_assignment_alias(
    name,
    value,
    operator_bindings,
    events,
    line,
    *,
    conditional,
):
    """Record one assignment to a possible thread-pool instance."""
    constructor = _thread_pool_instance_constructor_from_value(
        value,
        operator_bindings,
        events,
    )
    if constructor is not None:
        events.setdefault(name, []).append((line, constructor))
    elif not conditional:
        _record_thread_pool_alias_event(events, name, None, line)


def _record_thread_pool_assignment_aliases(
    node,
    operator_bindings,
    events,
    line,
    *,
    conditional,
):
    """Record thread-pool aliases introduced by simple assignments."""
    for name, value in _namespace_assignment_values(node):
        _record_thread_pool_assignment_alias(
            name,
            value,
            operator_bindings,
            events,
            line,
            conditional=conditional,
        )


def _scan_thread_pool_instance_alias_events(
    statements,
    operator_bindings,
    events,
    *,
    conditional=False,
):
    """Track saved and context-managed pool instances in source order."""
    for node in statements:
        line = getattr(node, "lineno", 0)
        if _record_thread_pool_definition_rebinding(
            node,
            events,
            line,
            conditional=conditional,
        ):
            continue
        _record_thread_pool_with_aliases(
            node,
            operator_bindings,
            events,
            line,
            conditional=conditional,
        )
        _record_thread_pool_assignment_aliases(
            node,
            operator_bindings,
            events,
            line,
            conditional=conditional,
        )
        for nested in _compound_statement_blocks(node):
            _scan_thread_pool_instance_alias_events(
                nested,
                operator_bindings,
                events,
                conditional=True,
            )


def _collect_thread_pool_instance_alias_events(tree, operator_bindings):
    """Collect names that hold proven thread-pool instances."""
    events = {}
    _scan_thread_pool_instance_alias_events(
        tree.body,
        operator_bindings,
        events,
    )
    return events


def _thread_pool_receiver_constructor(receiver, operator_bindings):
    """Resolve a map/submit receiver to its proven pool constructor."""
    if isinstance(receiver, ast.Call) and _call_is_thread_pool_class_constructor(
        receiver,
        operator_bindings,
    ):
        return receiver
    if not isinstance(receiver, ast.Name):
        return None
    events = operator_bindings[45] if len(operator_bindings) > 45 else {}
    state = _binding_state_at_line(
        events,
        receiver.id,
        getattr(receiver, "lineno", 0),
    )
    return state if isinstance(state, ast.Call) else None


_FUTURE_ANALYSIS_INDEX = 62


def _ordered_binding_state_at_position(events, name, reference):
    """Resolve a source-ordered binding without seeing later same-line events."""
    if isinstance(reference, ast.AST):
        reference_position = (
            getattr(reference, "lineno", 0),
            getattr(reference, "col_offset", 0),
        )
    else:
        reference_position = (int(reference or 0), 10**9)
    state = None
    for event in events.get(name, ()):
        if len(event) == 3:
            event_position = (event[0], event[1])
            value = event[2]
        else:
            event_position = (event[0], -1)
            value = event[1]
        if event_position > reference_position:
            break
        state = value
    return state


def _future_analysis_state(operator_bindings):
    """Return collected concurrent.futures analysis state."""
    if len(operator_bindings) <= _FUTURE_ANALYSIS_INDEX:
        return {}
    state = operator_bindings[_FUTURE_ANALYSIS_INDEX]
    return state if isinstance(state, dict) else {}


def _thread_pool_callback_mutates_workers(callback, operator_bindings):
    """Return whether one pool callback can mutate module workers."""
    if isinstance(callback, ast.Lambda):
        return _lambda_mutates_workers(callback, operator_bindings)
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if _expression_is_namespace_update_reference(callback, namespace_aliases):
        return True
    if not isinstance(callback, ast.Name):
        return False
    mutator_names = operator_bindings[46] if len(operator_bindings) > 46 else set()
    if callback.id in mutator_names:
        return True
    callback_events = _future_analysis_state(operator_bindings).get(
        "callback_alias_events",
        {},
    )
    return bool(
        _ordered_binding_state_at_position(
            callback_events,
            callback.id,
            callback,
        )
    )


def _thread_pool_constructor_initializer(constructor, operator_bindings):
    """Return a constructor initializer expression, if one is present."""
    if not isinstance(constructor, ast.Call):
        return None
    for keyword in constructor.keywords:
        if keyword.arg == "initializer":
            return keyword.value
    kind = _thread_pool_constructor_kind(constructor, operator_bindings)
    index = {"pool": 1, "executor": 2}.get(kind)
    if index is not None and len(constructor.args) > index:
        return constructor.args[index]
    return None


def _thread_pool_constructor_has_mutating_initializer(
    constructor,
    operator_bindings,
):
    """Return True when a proven pool initializer mutates workers."""
    initializer = _thread_pool_constructor_initializer(
        constructor,
        operator_bindings,
    )
    return (
        initializer is not None
        and _thread_pool_callback_mutates_workers(
            initializer,
            operator_bindings,
        )
    )


def _thread_pool_map_arguments(call):
    """Return callback and iterable expressions supplied to pool.map."""
    callback = call.args[0] if call.args else None
    if callback is None:
        callback = next(
            (
                keyword.value
                for keyword in call.keywords
                if keyword.arg in {"func", "fn"}
            ),
            None,
        )
    iterables = list(call.args[1:])
    iterables.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg == "iterable"
    )
    return callback, iterables


_THREAD_POOL_CALLBACK_METHODS = frozenset(
    {"map", "imap", "imap_unordered", "starmap"}
)


def _call_is_thread_pool_map_mutation(call, operator_bindings):
    """Return True when a proven pool map-like method performs a workers mutation."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr in _THREAD_POOL_CALLBACK_METHODS
    ):
        return False
    constructor = _thread_pool_receiver_constructor(
        func.value,
        operator_bindings,
    )
    if constructor is None:
        return False
    callback, iterables = _thread_pool_map_arguments(call)
    if callback is None or not iterables:
        return False
    if _thread_pool_constructor_has_mutating_initializer(
        constructor,
        operator_bindings,
    ):
        return True
    if _thread_pool_callback_mutates_workers(callback, operator_bindings):
        return True
    return any(
        _expression_is_mutating_lazy_iterator(
            iterable,
            operator_bindings,
        )
        for iterable in iterables
    )


def _future_module_binding_name(reference):
    """Return the tracked binding name for concurrent.futures module references."""
    if isinstance(reference, ast.Name):
        return reference.id
    if (
        isinstance(reference, ast.Attribute)
        and reference.attr == "futures"
        and isinstance(reference.value, ast.Name)
    ):
        return reference.value.id
    return None


def _future_module_reference_is_active(reference, module_events):
    """Return whether an expression resolves to the imported futures module."""
    name = _future_module_binding_name(reference)
    return (
        name is not None
        and bool(
            _ordered_binding_state_at_position(
                module_events,
                name,
                reference,
            )
        )
    )


def _future_reference_is_active(reference, operator_bindings, analysis=None):
    """Return whether an expression resolves to concurrent.futures.Future."""
    analysis = analysis or _future_analysis_state(operator_bindings)
    if isinstance(reference, ast.Name):
        return bool(
            _ordered_binding_state_at_position(
                analysis.get("class_events", {}),
                reference.id,
                reference,
            )
        )
    return (
        isinstance(reference, ast.Attribute)
        and reference.attr == "Future"
        and _future_module_reference_is_active(
            reference.value,
            analysis.get("module_events", {}),
        )
    )


def _record_future_direct_import(node, class_events):
    """Record a direct Future import and return its handled binding names."""
    if not (
        isinstance(node, ast.ImportFrom)
        and node.module == _CONCURRENT_FUTURES_MODULE
    ):
        return set()
    handled = set()
    for imported in node.names:
        if imported.name == "Future":
            name = imported.asname or imported.name
            class_events.setdefault(name, []).append(
                _future_binding_event(node, True)
            )
            handled.add(name)
    return handled


def _record_future_from_concurrent_import(node, module_events):
    """Record from concurrent import futures bindings."""
    if not (
        isinstance(node, ast.ImportFrom)
        and node.module == "concurrent"
    ):
        return set()
    handled = set()
    for imported in node.names:
        if imported.name == "futures":
            name = imported.asname or imported.name
            module_events.setdefault(name, []).append(
                _future_binding_event(node, True)
            )
            handled.add(name)
    return handled


def _record_future_module_import(node, module_events):
    """Record import concurrent.futures bindings."""
    if not isinstance(node, ast.Import):
        return set()
    handled = set()
    for imported in node.names:
        if imported.name == _CONCURRENT_FUTURES_MODULE:
            name = imported.asname or "concurrent"
            module_events.setdefault(name, []).append(
                _future_binding_event(node, True)
            )
            handled.add(name)
    return handled


def _record_future_constructor_imports(
    node,
    class_events,
    module_events,
):
    """Record Future constructor and module imports at source position."""
    handled = _record_future_direct_import(node, class_events)
    handled.update(
        _record_future_from_concurrent_import(node, module_events)
    )
    handled.update(
        _record_future_module_import(node, module_events)
    )
    return handled


def _record_future_constructor_assignment(
    node,
    name,
    value,
    class_events,
    module_events,
):
    """Record Future constructor/module aliases introduced by one assignment."""
    class_active = _future_reference_is_active(
        value,
        (),
        {
            "class_events": class_events,
            "module_events": module_events,
        },
    )
    module_active = _future_module_reference_is_active(
        value,
        module_events,
    )
    class_events.setdefault(name, []).append(
        _future_binding_event(node, class_active)
    )
    module_events.setdefault(name, []).append(
        _future_binding_event(node, module_active)
    )


def _collect_future_constructor_alias_events(tree):
    """Track Future constructors and futures-module aliases in source order."""
    class_events = {}
    module_events = {}
    for node in tree.body:
        handled_imports = _record_future_constructor_imports(
            node,
            class_events,
            module_events,
        )
        for name, value in _namespace_assignment_values(node):
            _record_future_constructor_assignment(
                node,
                name,
                value,
                class_events,
                module_events,
            )
        rebound_names = set(_import_bound_names(node)) - handled_imports
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound_names.add(node.name)
        for name in rebound_names:
            class_events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )
            module_events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )
    return class_events, module_events


def _future_submit_call_is_active(call, operator_bindings):
    """Return whether a call is a proven ThreadPoolExecutor.submit."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "submit"
    ):
        return False
    constructor = _thread_pool_receiver_constructor(
        call.func.value,
        operator_bindings,
    )
    return (
        constructor is not None
        and _thread_pool_constructor_kind(constructor, operator_bindings)
        == "executor"
    )


def _future_instance_from_value(
    value,
    operator_bindings,
    analysis,
    events=None,
):
    """Resolve an expression to a proven Future-producing call."""
    if isinstance(value, ast.Call):
        if _future_reference_is_active(
            value.func,
            operator_bindings,
            analysis,
        ):
            return value
        if _future_submit_call_is_active(value, operator_bindings):
            return value
    if not isinstance(value, ast.Name):
        return None
    events = analysis.get("instance_events", {}) if events is None else events
    state = _ordered_binding_state_at_position(
        events,
        value.id,
        value,
    )
    return state if isinstance(state, ast.Call) else None


def _future_binding_event(node, value):
    """Create a source-positioned Future binding event."""
    return (
        getattr(node, "lineno", 0),
        getattr(node, "col_offset", 0),
        value,
    )


def _record_future_instance_aliases(
    node,
    operator_bindings,
    analysis,
    events,
    *,
    conditional,
):
    """Track assignments that bind names to proven Future instances."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional:
            events.setdefault(node.name, []).append(
                _future_binding_event(node, False)
            )
        return
    for name, value in _namespace_assignment_values(node):
        instance = _future_instance_from_value(
            value,
            operator_bindings,
            analysis,
            events,
        )
        if instance is not None:
            events.setdefault(name, []).append(
                _future_binding_event(node, instance)
            )
        elif not conditional:
            events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )
    if not conditional:
        for name in _import_bound_names(node):
            events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )


def _scan_future_instance_alias_events(
    statements,
    operator_bindings,
    analysis,
    events,
    *,
    conditional=False,
):
    """Collect Future instance aliases from import-time statements."""
    for node in statements:
        _record_future_instance_aliases(
            node,
            operator_bindings,
            analysis,
            events,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_future_instance_alias_events(
                block,
                operator_bindings,
                analysis,
                events,
                conditional=True,
            )


def _collect_future_instance_alias_events(tree, operator_bindings, analysis):
    """Collect names that resolve to proven Future instances."""
    events = {}
    _scan_future_instance_alias_events(
        tree.body,
        operator_bindings,
        analysis,
        events,
    )
    return events


def _statement_import_time_expression_nodes(node):
    """Yield evaluated expression nodes without descending into nested scopes."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    stack = [
        child
        for child in ast.iter_child_nodes(node)
        if not isinstance(child, ast.stmt)
    ]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Lambda):
            continue
        yield current
        stack.extend(
            child
            for child in ast.iter_child_nodes(current)
            if not isinstance(child, ast.stmt)
        )


def _future_completion_instance(call, operator_bindings, analysis):
    """Return the Future instance completed by one explicit call."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in {"set_result", "set_exception", "cancel"}
    ):
        return None
    return _future_instance_from_value(
        call.func.value,
        operator_bindings,
        analysis,
    )


def _future_completion_instances_in_statement(
    node,
    operator_bindings,
    analysis,
):
    """Return Future instances completed by one import-time statement."""
    completed = set()
    expressions = _statement_import_time_expression_nodes(node) or ()
    for expression in expressions:
        instance = _future_completion_instance(
            expression,
            operator_bindings,
            analysis,
        )
        if instance is not None:
            completed.add(instance)
    return completed


def _future_import_time_nested_blocks(node):
    """Yield nested statement blocks that execute during module import."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    if isinstance(node, ast.ClassDef):
        yield node.body
        return
    yield from _compound_statement_blocks(node)


def _collect_future_completed_instances(tree, operator_bindings, analysis):
    """Collect proven Future instances that can become done at import time."""
    completed = set()
    pending_blocks = [tree.body]
    while pending_blocks:
        statements = pending_blocks.pop()
        for node in statements:
            completed.update(
                _future_completion_instances_in_statement(
                    node,
                    operator_bindings,
                    analysis,
                )
            )
            pending_blocks.extend(
                _future_import_time_nested_blocks(node)
            )
    return completed


def _callback_alias_value_mutates_workers(
    value,
    operator_bindings,
    events,
):
    """Resolve a callback value, including aliases to saved lambdas."""
    if value is None:
        return False
    if _thread_pool_callback_mutates_workers(value, operator_bindings):
        return True
    return (
        isinstance(value, ast.Name)
        and bool(
            _ordered_binding_state_at_position(
                events,
                value.id,
                value,
            )
        )
    )


def _record_callback_alias_events(
    node,
    operator_bindings,
    events,
    *,
    conditional,
):
    """Track names assigned to callbacks that mutate module workers."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional:
            events.setdefault(node.name, []).append(
                _future_binding_event(node, False)
            )
        return
    for name, value in _namespace_assignment_values(node):
        mutates = _callback_alias_value_mutates_workers(
            value,
            operator_bindings,
            events,
        )
        if mutates or not conditional:
            events.setdefault(name, []).append(
                _future_binding_event(node, mutates)
            )
    if not conditional:
        for name in _import_bound_names(node):
            events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )


def _scan_callback_alias_events(
    statements,
    operator_bindings,
    events,
    *,
    conditional=False,
):
    """Collect source-ordered aliases to workers-mutating callbacks."""
    for node in statements:
        _record_callback_alias_events(
            node,
            operator_bindings,
            events,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_callback_alias_events(
                block,
                operator_bindings,
                events,
                conditional=True,
            )


def _collect_callback_alias_events(tree, operator_bindings):
    """Collect callback aliases needed by Future.add_done_callback analysis."""
    events = {}
    _scan_callback_alias_events(
        tree.body,
        operator_bindings,
        events,
    )
    return events


def _future_starred_callback_values(value):
    """Extract the sole positional callback from a literal expanded argument."""
    if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == 1:
        return [value.elts[0]]
    return []


def _future_expanded_keyword_callbacks(value):
    """Extract fn from a literal expanded keyword mapping."""
    if not isinstance(value, ast.Dict):
        return []
    callbacks = []
    for key, callback in zip(value.keys, value.values):
        if isinstance(key, ast.Constant) and key.value == "fn":
            callbacks.append(callback)
    return callbacks


def _future_add_done_callback_arguments(call):
    """Return statically provable callbacks supplied to add_done_callback."""
    callbacks = []
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Starred):
            callbacks.extend(_future_starred_callback_values(first.value))
        else:
            callbacks.append(first)
    for keyword in call.keywords:
        if keyword.arg == "fn":
            callbacks.append(keyword.value)
        elif keyword.arg is None:
            callbacks.extend(
                _future_expanded_keyword_callbacks(keyword.value)
            )
    return callbacks


def _future_instance_can_complete(instance, operator_bindings, analysis):
    """Return whether a proven Future can run callbacks during config import."""
    if _future_submit_call_is_active(instance, operator_bindings):
        return True
    return instance in analysis.get("completed_instances", set())


def _future_callback_method_instance(value, operator_bindings, analysis, events):
    """Resolve a saved or direct add_done_callback method to its Future."""
    if (
        isinstance(value, ast.Attribute)
        and value.attr == "add_done_callback"
    ):
        return _future_instance_from_value(
            value.value,
            operator_bindings,
            analysis,
        )
    if not isinstance(value, ast.Name):
        return None
    state = _ordered_binding_state_at_position(
        events,
        value.id,
        value,
    )
    return state if isinstance(state, ast.Call) else None


def _record_future_callback_method_aliases(
    node,
    operator_bindings,
    analysis,
    events,
    *,
    conditional,
):
    """Track names assigned to bound Future.add_done_callback methods."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional:
            events.setdefault(node.name, []).append(
                _future_binding_event(node, False)
            )
        return
    for name, value in _namespace_assignment_values(node):
        instance = _future_callback_method_instance(
            value,
            operator_bindings,
            analysis,
            events,
        )
        if instance is not None:
            events.setdefault(name, []).append(
                _future_binding_event(node, instance)
            )
        elif not conditional:
            events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )
    if not conditional:
        for name in _import_bound_names(node):
            events.setdefault(name, []).append(
                _future_binding_event(node, False)
            )


def _scan_future_callback_method_alias_events(
    statements,
    operator_bindings,
    analysis,
    events,
    *,
    conditional=False,
):
    """Collect aliases of bound Future.add_done_callback methods."""
    for node in statements:
        _record_future_callback_method_aliases(
            node,
            operator_bindings,
            analysis,
            events,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_future_callback_method_alias_events(
                block,
                operator_bindings,
                analysis,
                events,
                conditional=True,
            )


def _collect_future_callback_method_alias_events(
    tree,
    operator_bindings,
    analysis,
):
    """Collect source-ordered bound add_done_callback method aliases."""
    events = {}
    _scan_future_callback_method_alias_events(
        tree.body,
        operator_bindings,
        analysis,
        events,
    )
    return events


def _future_add_done_callback_instance(call, operator_bindings, analysis):
    """Resolve direct and saved add_done_callback call targets."""
    if not isinstance(call, ast.Call):
        return None
    method_events = analysis.get("callback_method_events", {})
    return _future_callback_method_instance(
        call.func,
        operator_bindings,
        analysis,
        method_events,
    )


def _call_is_future_add_done_callback_mutation(call, operator_bindings):
    """Return True for a completed proven Future with a mutating callback."""
    analysis = _future_analysis_state(operator_bindings)
    instance = _future_add_done_callback_instance(
        call,
        operator_bindings,
        analysis,
    )
    if instance is None or not _future_instance_can_complete(
        instance,
        operator_bindings,
        analysis,
    ):
        return False
    return any(
        _thread_pool_callback_mutates_workers(callback, operator_bindings)
        for callback in _future_add_done_callback_arguments(call)
    )


def _thread_pool_apply_task_argument(call):
    """Return the primary task callable from a pool apply/apply_async call."""
    if call.args:
        return call.args[0]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "func"),
        None,
    )


def _call_is_thread_pool_apply_method_mutation(
    call,
    operator_bindings,
    method_name,
    *,
    extra_callback_keyword_names=(),
):
    """Return True when apply/apply_async runs workers-mutating pool callbacks."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == method_name
    ):
        return False
    constructor = _thread_pool_receiver_constructor(
        call.func.value,
        operator_bindings,
    )
    if constructor is None:
        return False
    task = _thread_pool_apply_task_argument(call)
    if task is None:
        return False
    if _thread_pool_constructor_has_mutating_initializer(
        constructor,
        operator_bindings,
    ):
        return True
    callbacks = [task]
    if extra_callback_keyword_names:
        extra_names = frozenset(extra_callback_keyword_names)
        callbacks.extend(
            keyword.value
            for keyword in call.keywords
            if keyword.arg in extra_names
        )
    return any(
        _thread_pool_callback_mutates_workers(callback, operator_bindings)
        for callback in callbacks
    )


def _call_is_thread_pool_apply_mutation(call, operator_bindings):
    """Return True when apply synchronously runs a workers-mutating callback."""
    return _call_is_thread_pool_apply_method_mutation(
        call,
        operator_bindings,
        "apply",
    )


def _call_is_thread_pool_apply_async_mutation(call, operator_bindings):
    """Return True when apply_async schedules a workers-mutating callback."""
    return _call_is_thread_pool_apply_method_mutation(
        call,
        operator_bindings,
        "apply_async",
        extra_callback_keyword_names=("callback", "error_callback"),
    )


def _call_is_thread_pool_imap_iterator(expr, operator_bindings):
    """Return True when a proven pool imap variant yields mutating callbacks."""
    if not isinstance(expr, ast.Call):
        return False
    func = expr.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr in {"imap", "imap_unordered"}
    ):
        return False
    constructor = _thread_pool_receiver_constructor(
        func.value,
        operator_bindings,
    )
    if constructor is None:
        return False
    callback, iterables = _thread_pool_map_arguments(expr)
    if callback is None or not iterables:
        return False
    if _thread_pool_constructor_has_mutating_initializer(
        constructor,
        operator_bindings,
    ):
        return True
    if _thread_pool_callback_mutates_workers(callback, operator_bindings):
        return True
    return any(
        _expression_is_mutating_lazy_iterator(
            iterable,
            operator_bindings,
        )
        for iterable in iterables
    )


# Asyncio binding indexes appended by _scan_gunicorn_config_worker_details.
_ASYNCIO_MODULE_EVENTS_INDEX = 47
_ASYNCIO_RUN_EVENTS_INDEX = 48
_ASYNCIO_TO_THREAD_EVENTS_INDEX = 49
_ASYNCIO_NEW_EVENT_LOOP_EVENTS_INDEX = 50
_ASYNCIO_GET_EVENT_LOOP_EVENTS_INDEX = 51
_ASYNCIO_RUNNER_EVENTS_INDEX = 52
_ASYNCIO_GATHER_EVENTS_INDEX = 53
_ASYNCIO_SHIELD_EVENTS_INDEX = 54
_ASYNCIO_WAIT_FOR_EVENTS_INDEX = 55
_ASYNCIO_CREATE_TASK_EVENTS_INDEX = 56
_ASYNCIO_ENSURE_FUTURE_EVENTS_INDEX = 57
_ASYNCIO_LOOP_FACTORY_ALIAS_EVENTS_INDEX = 58
_ASYNCIO_EVENT_LOOP_ALIAS_EVENTS_INDEX = 59
_ASYNCIO_RUNNER_ALIAS_EVENTS_INDEX = 60
_ASYNCIO_WRAPPER_BINDING_EVENTS_INDEX = 61


def _asyncio_reference_line(reference):
    """Return a source line for an AST node or numeric line reference."""
    if isinstance(reference, ast.AST):
        return getattr(reference, "lineno", 0)
    return int(reference or 0)


def _asyncio_module_active_at_line(node, operator_bindings, reference_line):
    """Return True when ``node`` resolves to the asyncio module at ``reference_line``."""
    if not isinstance(node, ast.Name):
        return False
    if len(operator_bindings) <= _ASYNCIO_MODULE_EVENTS_INDEX:
        return False
    asyncio_events = operator_bindings[_ASYNCIO_MODULE_EVENTS_INDEX]
    return _imported_alias_is_active(
        asyncio_events,
        node.id,
        _asyncio_reference_line(reference_line),
    )


def _asyncio_helper_active_at_line(
    node,
    helper_name,
    operator_bindings,
    reference_line,
):
    """Resolve module-qualified or directly imported asyncio helpers."""
    if isinstance(node, ast.Attribute) and node.attr == helper_name:
        return _asyncio_module_active_at_line(
            node.value,
            operator_bindings,
            reference_line,
        )
    if not isinstance(node, ast.Name):
        return False
    event_index = {
        "run": _ASYNCIO_RUN_EVENTS_INDEX,
        "to_thread": _ASYNCIO_TO_THREAD_EVENTS_INDEX,
        "new_event_loop": _ASYNCIO_NEW_EVENT_LOOP_EVENTS_INDEX,
        "get_event_loop": _ASYNCIO_GET_EVENT_LOOP_EVENTS_INDEX,
        "Runner": _ASYNCIO_RUNNER_EVENTS_INDEX,
        "gather": _ASYNCIO_GATHER_EVENTS_INDEX,
        "shield": _ASYNCIO_SHIELD_EVENTS_INDEX,
        "wait_for": _ASYNCIO_WAIT_FOR_EVENTS_INDEX,
        "create_task": _ASYNCIO_CREATE_TASK_EVENTS_INDEX,
        "ensure_future": _ASYNCIO_ENSURE_FUTURE_EVENTS_INDEX,
    }.get(helper_name)
    if event_index is None or len(operator_bindings) <= event_index:
        return False
    return _imported_alias_is_active(
        operator_bindings[event_index],
        node.id,
        _asyncio_reference_line(reference_line),
    )


def _asyncio_to_thread_reference_is_active(
    node,
    operator_bindings,
    reference_line,
    local_state=None,
):
    """Resolve to_thread while honoring wrapper-local name shadowing."""
    if (
        local_state is not None
        and isinstance(node, ast.Name)
        and node.id in local_state["bound_names"]
    ):
        return node.id in local_state["to_thread_names"]
    if (
        local_state is not None
        and isinstance(node, ast.Attribute)
        and node.attr == "to_thread"
        and isinstance(node.value, ast.Name)
        and node.value.id in local_state["bound_names"]
    ):
        return node.value.id in local_state["asyncio_modules"]
    return _asyncio_helper_active_at_line(
        node,
        "to_thread",
        operator_bindings,
        reference_line,
    )


def _asyncio_to_thread_call_mutates_workers(
    to_thread_call,
    operator_bindings,
    reference_line,
    local_state=None,
):
    """Return True when a resolved asyncio.to_thread call mutates workers."""
    if not isinstance(to_thread_call, ast.Call):
        return False
    if not _asyncio_to_thread_reference_is_active(
        to_thread_call.func,
        operator_bindings,
        reference_line,
        local_state,
    ):
        return False
    target = to_thread_call.args[0] if to_thread_call.args else next(
        (
            keyword.value
            for keyword in to_thread_call.keywords
            if keyword.arg == "func"
        ),
        None,
    )
    if (
        target is not None
        and local_state is not None
        and isinstance(target, ast.Name)
        and target.id in local_state["callback_mutators"]
    ):
        return True
    return target is not None and _thread_pool_callback_mutates_workers(
        target,
        operator_bindings,
    )


def _asyncio_binding_state_at_position(events, name, reference):
    """Resolve an asyncio binding without seeing later same-line events."""
    if isinstance(reference, ast.AST):
        reference_position = (
            getattr(reference, "lineno", 0),
            getattr(reference, "col_offset", 0),
        )
    else:
        reference_position = (int(reference or 0), 10**9)
    state = None
    for event in events.get(name, ()):
        if len(event) == 3:
            event_position = (event[0], event[1])
            value = event[2]
        else:
            event_position = (event[0], -1)
            value = event[1]
        if event_position > reference_position:
            break
        state = value
    return state


def _asyncio_positioned_event(node, value):
    """Return a source-positioned asyncio binding event."""
    return (
        getattr(node, "lineno", 0),
        getattr(node, "col_offset", 0),
        value,
    )


def _asyncio_loop_factory_reference_is_active(
    node,
    operator_bindings,
    reference_line,
):
    """Resolve asyncio loop factories and source-ordered aliases."""
    if any(
        _asyncio_helper_active_at_line(
            node,
            helper_name,
            operator_bindings,
            reference_line,
        )
        for helper_name in ("new_event_loop", "get_event_loop")
    ):
        return True
    if (
        not isinstance(node, ast.Name)
        or len(operator_bindings) <= _ASYNCIO_LOOP_FACTORY_ALIAS_EVENTS_INDEX
    ):
        return False
    events = operator_bindings[_ASYNCIO_LOOP_FACTORY_ALIAS_EVENTS_INDEX]
    return bool(_asyncio_binding_state_at_position(events, node.id, node))


def _asyncio_loop_factory_call_is_active(call, operator_bindings, reference_line):
    """Return True for a proven asyncio event-loop factory call."""
    return isinstance(call, ast.Call) and _asyncio_loop_factory_reference_is_active(
        call.func,
        operator_bindings,
        reference_line,
    )


def _collect_asyncio_loop_factory_alias_events(tree, operator_bindings):
    """Track aliases of asyncio event-loop factory callables."""
    events = {}
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            events.setdefault(node.name, []).append(
                _asyncio_positioned_event(node, False)
            )
            continue
        for name, value in _namespace_assignment_values(node):
            active = _asyncio_loop_factory_reference_is_active(
                value,
                operator_bindings,
                line,
            )
            events.setdefault(name, []).append(
                _asyncio_positioned_event(node, active)
            )
        for name in _import_bound_names(node):
            events.setdefault(name, []).append(
                _asyncio_positioned_event(node, False)
            )
    return events


def _asyncio_event_loop_alias_is_active(
    node,
    operator_bindings,
    reference_line,
    events=None,
):
    """Resolve a proven event-loop expression at one source line."""
    if isinstance(node, ast.Call):
        return _asyncio_loop_factory_call_is_active(
            node,
            operator_bindings,
            reference_line,
        )
    if not isinstance(node, ast.Name):
        return False
    if events is None:
        if len(operator_bindings) <= _ASYNCIO_EVENT_LOOP_ALIAS_EVENTS_INDEX:
            return False
        events = operator_bindings[_ASYNCIO_EVENT_LOOP_ALIAS_EVENTS_INDEX]
    return bool(_asyncio_binding_state_at_position(events, node.id, node))


def _record_asyncio_event_loop_aliases(
    node,
    operator_bindings,
    events,
    *,
    conditional,
):
    """Record event-loop instance aliases introduced by one statement."""
    line = getattr(node, "lineno", 0)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional:
            events.setdefault(node.name, []).append(
                _asyncio_positioned_event(node, False)
            )
        return
    for name, value in _namespace_assignment_values(node):
        active = _asyncio_event_loop_alias_is_active(
            value,
            operator_bindings,
            value if isinstance(value, ast.AST) else line,
            events,
        )
        if active or not conditional:
            events.setdefault(name, []).append(
                _asyncio_positioned_event(node, active)
            )


def _scan_asyncio_event_loop_alias_events(
    statements,
    operator_bindings,
    events,
    *,
    conditional=False,
):
    """Track proven event-loop objects through import-time statements."""
    for node in statements:
        _record_asyncio_event_loop_aliases(
            node,
            operator_bindings,
            events,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_asyncio_event_loop_alias_events(
                block,
                operator_bindings,
                events,
                conditional=True,
            )


def _collect_asyncio_event_loop_alias_events(tree, operator_bindings):
    """Collect source-ordered aliases of known asyncio event-loop instances."""
    events = {}
    _scan_asyncio_event_loop_alias_events(
        tree.body,
        operator_bindings,
        events,
    )
    return events


def _import_bound_names(node):
    """Return names definitely rebound by one import statement."""
    if isinstance(node, ast.Import):
        return {
            imported.asname or imported.name.split(".", 1)[0]
            for imported in node.names
        }
    if isinstance(node, ast.ImportFrom):
        return {
            imported.asname or imported.name
            for imported in node.names
            if imported.name != "*"
        }
    return set()


def _async_wrapper_state(events, name, reference_line):
    """Return async-function candidates bound to ``name`` at one line."""
    state = _binding_state_at_line(events, name, reference_line)
    return state if isinstance(state, frozenset) else frozenset()


def _record_async_wrapper_binding(
    events,
    name,
    candidates,
    line,
    *,
    conditional,
):
    """Record one async-wrapper binding while preserving conditional risks."""
    candidates = frozenset(candidates)
    if conditional:
        previous = _async_wrapper_state(events, name, line)
        candidates = previous | candidates
        if not candidates:
            return
    events.setdefault(name, []).append((line, candidates))


def _record_class_async_wrapper_bindings(
    node,
    events,
    operator_bindings,
    *,
    conditional,
):
    """Record callable static/class async methods on one module-level class."""
    line = getattr(node, "lineno", 0)
    prefix = f"{node.name}."
    if not conditional:
        for key in tuple(events):
            if key.startswith(prefix):
                _record_async_wrapper_binding(
                    events,
                    key,
                    set(),
                    line,
                    conditional=False,
                )
    for stmt in node.body:
        if (
            isinstance(stmt, ast.AsyncFunctionDef)
            and _function_is_static_or_class_method(stmt, operator_bindings)
        ):
            _record_async_wrapper_binding(
                events,
                f"{node.name}.{stmt.name}",
                {stmt},
                line,
                conditional=conditional,
            )


def _record_async_wrapper_assignments(
    node,
    events,
    operator_bindings,
    *,
    conditional,
):
    """Track async wrappers, aliases, class methods, and definite rebindings."""
    line = getattr(node, "lineno", 0)
    if isinstance(node, ast.AsyncFunctionDef):
        _record_async_wrapper_binding(
            events,
            node.name,
            {node},
            line,
            conditional=conditional,
        )
        return True
    if isinstance(node, ast.ClassDef):
        _record_class_async_wrapper_bindings(
            node,
            events,
            operator_bindings,
            conditional=conditional,
        )
        if not conditional:
            _record_async_wrapper_binding(
                events,
                node.name,
                set(),
                line,
                conditional=False,
            )
        return True
    if isinstance(node, ast.FunctionDef):
        if not conditional:
            _record_async_wrapper_binding(
                events,
                node.name,
                set(),
                line,
                conditional=False,
            )
        return True

    for name in _import_bound_names(node):
        if not conditional:
            _record_async_wrapper_binding(
                events,
                name,
                set(),
                line,
                conditional=False,
            )
    for name, value in _namespace_assignment_values(node):
        candidates = (
            _async_wrapper_state(events, value.id, line)
            if isinstance(value, ast.Name)
            else frozenset()
        )
        _record_async_wrapper_binding(
            events,
            name,
            candidates,
            line,
            conditional=conditional,
        )
    return False


def _scan_async_wrapper_binding_events(
    statements,
    events,
    operator_bindings,
    *,
    conditional=False,
):
    """Collect async definitions and aliases without entering function bodies."""
    for node in statements:
        if _record_async_wrapper_assignments(
            node,
            events,
            operator_bindings,
            conditional=conditional,
        ):
            continue
        for block in _compound_statement_blocks(node):
            _scan_async_wrapper_binding_events(
                block,
                events,
                operator_bindings,
                conditional=True,
            )


def _collect_async_wrapper_binding_events(tree, operator_bindings):
    """Collect source-ordered bindings for import-time async wrapper calls."""
    events = {}
    _scan_async_wrapper_binding_events(
        tree.body,
        events,
        operator_bindings,
    )
    return events


def _async_wrapper_candidates_at_line(
    func,
    operator_bindings,
    reference_line,
):
    """Resolve a called name or class-qualified method to async candidates."""
    if len(operator_bindings) <= _ASYNCIO_WRAPPER_BINDING_EVENTS_INDEX:
        return frozenset()
    if isinstance(func, ast.Name):
        key = func.id
    elif (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
    ):
        key = f"{func.value.id}.{func.attr}"
    else:
        return frozenset()
    events = operator_bindings[_ASYNCIO_WRAPPER_BINDING_EVENTS_INDEX]
    return _async_wrapper_state(events, key, reference_line)


def _local_async_wrapper_candidates(func, local_state):
    """Resolve a local async helper or alias within an async wrapper."""
    if not isinstance(func, ast.Name):
        return frozenset()
    return local_state["wrappers"].get(func.id, frozenset())


def _argument_value_for_parameter(call, parameter_name, position):
    """Resolve a simple positional/keyword argument bound to one parameter."""
    if position < len(call.args) and not isinstance(call.args[position], ast.Starred):
        return call.args[position]
    return next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg == parameter_name
        ),
        None,
    )


def _wrapper_bound_to_thread_names(
    func_node,
    invocation,
    operator_bindings,
    reference_line,
):
    """Return wrapper parameters bound to asyncio.to_thread at invocation."""
    if invocation is None:
        return set()
    params = (*func_node.args.posonlyargs, *func_node.args.args)
    names = set()
    for position, parameter in enumerate(params):
        value = _argument_value_for_parameter(
            invocation,
            parameter.arg,
            position,
        )
        if value is not None and _asyncio_to_thread_reference_is_active(
            value,
            operator_bindings,
            reference_line,
        ):
            names.add(parameter.arg)
    return names


def _new_local_async_state(
    func_node,
    invocation,
    operator_bindings,
    reference_line,
):
    """Create mutable source-ordered state for one async wrapper analysis."""
    args = func_node.args
    bound_names = {
        arg.arg
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    }
    if args.vararg is not None:
        bound_names.add(args.vararg.arg)
    if args.kwarg is not None:
        bound_names.add(args.kwarg.arg)
    return {
        "wrappers": {},
        "awaitables": set(),
        "asyncio_modules": set(),
        "to_thread_names": _wrapper_bound_to_thread_names(
            func_node,
            invocation,
            operator_bindings,
            reference_line,
        ),
        "consumer_names": set(),
        "callback_mutators": set(),
        "bound_names": bound_names,
    }


_ASYNCIO_AWAITABLE_CONSUMERS = frozenset({"gather", "shield", "wait_for"})


def _asyncio_consumer_reference_is_active(
    node,
    operator_bindings,
    reference_line,
    local_state,
):
    """Resolve known asyncio awaitable consumers in global or local scope."""
    if isinstance(node, ast.Name):
        if node.id in local_state["bound_names"]:
            return node.id in local_state["consumer_names"]
        return any(
            _asyncio_helper_active_at_line(
                node,
                helper_name,
                operator_bindings,
                reference_line,
            )
            for helper_name in _ASYNCIO_AWAITABLE_CONSUMERS
        )
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.attr in _ASYNCIO_AWAITABLE_CONSUMERS
    ):
        if node.value.id in local_state["bound_names"]:
            return node.value.id in local_state["asyncio_modules"]
        return _asyncio_module_active_at_line(
            node.value,
            operator_bindings,
            reference_line,
        )
    return False


def _asyncio_awaitable_expression_mutates_workers(
    expr,
    operator_bindings,
    reference_line,
    local_state,
    seen,
):
    """Resolve a stored or nested awaitable expression."""
    if isinstance(expr, ast.Name) and expr.id in local_state["awaitables"]:
        return True
    return _asyncio_awaitable_mutates_workers(
        expr,
        operator_bindings,
        reference_line,
        local_state=local_state,
        seen=seen,
    )


def _asyncio_consumer_call_mutates_workers(
    call,
    operator_bindings,
    reference_line,
    local_state,
    seen,
):
    """Propagate mutations through known asyncio awaitable consumers."""
    if not _asyncio_consumer_reference_is_active(
        call.func,
        operator_bindings,
        reference_line,
        local_state,
    ):
        return False
    return any(
        _asyncio_awaitable_expression_mutates_workers(
            arg.value if isinstance(arg, ast.Starred) else arg,
            operator_bindings,
            reference_line,
            local_state,
            seen,
        )
        for arg in call.args
    )


def _asyncio_awaitable_mutates_workers(
    expr,
    operator_bindings,
    reference_line,
    *,
    local_state=None,
    seen=None,
):
    """Return True when awaiting an expression can mutate module workers."""
    if not isinstance(expr, ast.Call):
        return False
    if local_state is None:
        local_state = {
            "wrappers": {},
            "awaitables": set(),
            "asyncio_modules": set(),
            "to_thread_names": set(),
            "consumer_names": set(),
            "callback_mutators": set(),
            "bound_names": set(),
        }
    if _asyncio_to_thread_call_mutates_workers(
        expr,
        operator_bindings,
        reference_line,
        local_state,
    ):
        return True
    if _asyncio_consumer_call_mutates_workers(
        expr,
        operator_bindings,
        reference_line,
        local_state,
        seen,
    ):
        return True
    candidates = _local_async_wrapper_candidates(expr.func, local_state)
    if not candidates:
        candidates = _async_wrapper_candidates_at_line(
            expr.func,
            operator_bindings,
            reference_line,
        )
    return any(
        _async_function_mutates_workers_via_asyncio(
            candidate,
            operator_bindings,
            reference_line,
            invocation=expr,
            seen=seen,
        )
        for candidate in candidates
    )


def _expression_awaits_mutating_asyncio(
    expr,
    operator_bindings,
    reference_line,
    local_state,
    seen,
):
    """Inspect an evaluated expression for a risky await operation."""
    if isinstance(expr, ast.Lambda):
        return False
    if isinstance(expr, ast.Await):
        awaited = expr.value
        if (
            isinstance(awaited, ast.Name)
            and awaited.id in local_state["awaitables"]
        ):
            return True
        if _asyncio_awaitable_mutates_workers(
            awaited,
            operator_bindings,
            reference_line,
            local_state=local_state,
            seen=seen,
        ):
            return True
    return any(
        _expression_awaits_mutating_asyncio(
            child,
            operator_bindings,
            reference_line,
            local_state,
            seen,
        )
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.AST)
    )


def _statement_awaits_mutating_asyncio(
    node,
    operator_bindings,
    reference_line,
    local_state,
    seen,
):
    """Inspect only expressions evaluated by the current statement."""
    if isinstance(node, (ast.With, ast.AsyncWith)):
        expressions = [item.context_expr for item in node.items]
    else:
        expressions = [
            child
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
        ]
    return any(
        _expression_awaits_mutating_asyncio(
            expr,
            operator_bindings,
            reference_line,
            local_state,
            seen,
        )
        for expr in expressions
    )


def _clear_local_async_binding(name, local_state):
    """Clear tracked async meanings for one newly bound local name."""
    local_state["bound_names"].add(name)
    local_state["to_thread_names"].discard(name)
    local_state["consumer_names"].discard(name)
    local_state["asyncio_modules"].discard(name)
    local_state["wrappers"].pop(name, None)
    local_state["awaitables"].discard(name)
    local_state["callback_mutators"].discard(name)


def _record_local_asyncio_module_imports(node, local_state):
    """Record local asyncio module import aliases."""
    if not isinstance(node, ast.Import):
        return
    for imported in node.names:
        if imported.name == "asyncio":
            local_state["asyncio_modules"].add(
                imported.asname or imported.name
            )


def _record_local_asyncio_helper_imports(node, local_state):
    """Record directly imported asyncio helpers used by async analysis."""
    if not isinstance(node, ast.ImportFrom) or node.module != "asyncio":
        return
    for imported in node.names:
        name = imported.asname or imported.name
        if imported.name == "to_thread":
            local_state["to_thread_names"].add(name)
        if imported.name in _ASYNCIO_AWAITABLE_CONSUMERS:
            local_state["consumer_names"].add(name)


def _record_local_asyncio_import(node, local_state):
    """Record imports and local shadowing executed inside an async wrapper."""
    bound_names = _import_bound_names(node)
    if not bound_names:
        return False
    for name in bound_names:
        _clear_local_async_binding(name, local_state)

    _record_local_asyncio_module_imports(node, local_state)
    _record_local_asyncio_helper_imports(node, local_state)
    return True


def _record_local_async_definition(
    node,
    operator_bindings,
    local_state,
    *,
    conditional,
):
    """Handle local definitions and callable callback mutations."""
    name = getattr(node, "name", None)
    if name is not None:
        local_state["bound_names"].add(name)
        local_state["to_thread_names"].discard(name)
        local_state["consumer_names"].discard(name)
        local_state["asyncio_modules"].discard(name)
    if isinstance(node, ast.AsyncFunctionDef):
        candidates = frozenset({node})
        if conditional:
            candidates |= local_state["wrappers"].get(
                node.name,
                frozenset(),
            )
        local_state["wrappers"][node.name] = candidates
        return True
    if not isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return False
    if isinstance(node, ast.FunctionDef) and _function_mutates_workers(
        node,
        operator_bindings,
    ):
        local_state["callback_mutators"].add(node.name)
    elif not conditional and name is not None:
        local_state["callback_mutators"].discard(name)
    if not conditional and name is not None:
        local_state["wrappers"].pop(name, None)
        local_state["awaitables"].discard(name)
        local_state["to_thread_names"].discard(name)
        local_state["asyncio_modules"].discard(name)
    return True


def _local_async_wrapper_candidates_for_value(
    value,
    operator_bindings,
    reference_line,
    local_state,
):
    """Resolve local or module-level async wrapper aliases for one value."""
    if not isinstance(value, ast.Name):
        return frozenset()
    candidates = local_state["wrappers"].get(value.id, frozenset())
    if candidates:
        return candidates
    return _async_wrapper_candidates_at_line(
        value,
        operator_bindings,
        reference_line,
    )


def _record_local_async_wrapper_assignment(
    name,
    value,
    operator_bindings,
    reference_line,
    local_state,
    *,
    conditional,
):
    """Update one local async-wrapper or helper alias assignment."""
    candidates = _local_async_wrapper_candidates_for_value(
        value,
        operator_bindings,
        reference_line,
        local_state,
    )
    if candidates:
        local_state["wrappers"][name] = candidates
    elif not conditional:
        local_state["wrappers"].pop(name, None)

    if _asyncio_to_thread_reference_is_active(
        value,
        operator_bindings,
        reference_line,
        local_state,
    ):
        local_state["to_thread_names"].add(name)
    elif not conditional:
        local_state["to_thread_names"].discard(name)


def _record_local_awaitable_assignment(
    name,
    value,
    operator_bindings,
    reference_line,
    local_state,
    seen,
    *,
    conditional,
):
    """Update one stored awaitable binding, including name aliases."""
    risky_awaitable = (
        isinstance(value, ast.Name)
        and value.id in local_state["awaitables"]
    ) or _asyncio_awaitable_mutates_workers(
        value,
        operator_bindings,
        reference_line,
        local_state=local_state,
        seen=seen,
    )
    if risky_awaitable:
        local_state["awaitables"].add(name)
    elif not conditional:
        local_state["awaitables"].discard(name)


def _record_local_async_bindings(
    node,
    operator_bindings,
    reference_line,
    local_state,
    seen,
    *,
    conditional,
):
    """Update local imports, wrappers, callbacks, and stored awaitables."""
    if _record_local_asyncio_import(node, local_state):
        return isinstance(node, (ast.Import, ast.ImportFrom))
    if _record_local_async_definition(
        node,
        operator_bindings,
        local_state,
        conditional=conditional,
    ):
        return True

    for name, value in _namespace_assignment_values(node):
        local_state["bound_names"].add(name)
        local_state["asyncio_modules"].discard(name)
        local_state["consumer_names"].discard(name)
        _record_local_async_wrapper_assignment(
            name,
            value,
            operator_bindings,
            reference_line,
            local_state,
            conditional=conditional,
        )
        _record_local_awaitable_assignment(
            name,
            value,
            operator_bindings,
            reference_line,
            local_state,
            seen,
            conditional=conditional,
        )
        if not conditional:
            local_state["callback_mutators"].discard(name)
    return False


def _asyncio_task_factory_call_mutates_workers(
    call,
    operator_bindings,
    reference_line,
    *,
    local_state=None,
    seen=None,
):
    """Return True when create_task/ensure_future schedules a mutating awaitable."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    helper_names = ("create_task", "ensure_future")
    if not any(
        _asyncio_helper_active_at_line(
            call.func,
            helper_name,
            operator_bindings,
            reference_line,
        )
        for helper_name in helper_names
    ):
        return False
    return _asyncio_awaitable_expression_mutates_workers(
        call.args[0],
        operator_bindings,
        reference_line,
        local_state=local_state,
        seen=seen,
    )


def _statement_schedules_mutating_asyncio_task(
    node,
    operator_bindings,
    reference_line,
    local_state,
    seen,
):
    """Return True when a statement schedules a risky asyncio task/future."""
    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call):
        return False
    return _asyncio_task_factory_call_mutates_workers(
        expr,
        operator_bindings,
        reference_line,
        local_state=local_state,
        seen=seen,
    )


def _async_statements_mutate_workers_via_asyncio(
    statements,
    operator_bindings,
    reference_line,
    local_state,
    seen,
    *,
    conditional=False,
):
    """Scan async statements while excluding uninvoked nested function bodies."""
    for node in statements:
        if _record_local_async_bindings(
            node,
            operator_bindings,
            reference_line,
            local_state,
            seen,
            conditional=conditional,
        ):
            continue
        if _statement_awaits_mutating_asyncio(
            node,
            operator_bindings,
            reference_line,
            local_state,
            seen,
        ):
            return True
        if _statement_schedules_mutating_asyncio_task(
            node,
            operator_bindings,
            reference_line,
            local_state,
            seen,
        ):
            return True
        for block in _compound_statement_blocks(node):
            if _async_statements_mutate_workers_via_asyncio(
                block,
                operator_bindings,
                reference_line,
                local_state,
                seen,
                conditional=True,
            ):
                return True
    return False


def _async_function_mutates_workers_via_asyncio(
    func_node,
    operator_bindings,
    reference_line,
    *,
    invocation=None,
    seen=None,
):
    """Evaluate one async wrapper using globals active when it is invoked."""
    if not isinstance(func_node, ast.AsyncFunctionDef):
        return False
    seen = set() if seen is None else set(seen)
    marker = id(func_node)
    if marker in seen:
        return False
    seen.add(marker)
    local_state = _new_local_async_state(
        func_node,
        invocation,
        operator_bindings,
        reference_line,
    )
    return _async_statements_mutate_workers_via_asyncio(
        func_node.body,
        operator_bindings,
        reference_line,
        local_state,
        seen,
    )


def _single_starred_call_argument(call):
    """Return the sole value unpacked from a one-item literal sequence."""
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Starred):
        return None
    value = call.args[0].value
    if not isinstance(value, (ast.Tuple, ast.List)) or len(value.elts) != 1:
        return None
    return value.elts[0]


def _dict_unpack_call_argument(call, keyword_names):
    """Resolve a selected key from a literal unpacked mapping argument."""
    for keyword in call.keywords:
        if keyword.arg is not None or not isinstance(keyword.value, ast.Dict):
            continue
        for key, value in zip(keyword.value.keys, keyword.value.values):
            if isinstance(key, ast.Constant) and key.value in keyword_names:
                return value
    return None


def _unpacked_call_argument(call, keyword_names):
    """Resolve a single awaitable passed through argument unpacking."""
    positional = _single_starred_call_argument(call)
    if positional is not None:
        return positional
    return _dict_unpack_call_argument(call, keyword_names)


def _call_argument(call, keyword_names):
    """Return the first direct or unpacked selected argument value."""
    if call.args and not isinstance(call.args[0], ast.Starred):
        return call.args[0]
    direct = next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg in keyword_names
        ),
        None,
    )
    return direct if direct is not None else _unpacked_call_argument(
        call,
        keyword_names,
    )


def _asyncio_runner_constructor_is_active(
    expr,
    operator_bindings,
    reference_line,
):
    """Return True for a proven asyncio.Runner constructor call."""
    return (
        isinstance(expr, ast.Call)
        and _asyncio_helper_active_at_line(
            expr.func,
            "Runner",
            operator_bindings,
            reference_line,
        )
    )


def _asyncio_runner_alias_is_active(
    expr,
    operator_bindings,
    reference_line,
    events=None,
):
    """Resolve a proven asyncio.Runner instance."""
    if _asyncio_runner_constructor_is_active(
        expr,
        operator_bindings,
        reference_line,
    ):
        return True
    if not isinstance(expr, ast.Name):
        return False
    if events is None:
        if len(operator_bindings) <= _ASYNCIO_RUNNER_ALIAS_EVENTS_INDEX:
            return False
        events = operator_bindings[_ASYNCIO_RUNNER_ALIAS_EVENTS_INDEX]
    return bool(_asyncio_binding_state_at_position(events, expr.id, expr))


def _record_asyncio_runner_aliases(
    node,
    operator_bindings,
    events,
    *,
    conditional,
):
    """Record assigned and context-managed asyncio.Runner instances."""
    line = getattr(node, "lineno", 0)
    for name, value in _namespace_assignment_values(node):
        active = _asyncio_runner_alias_is_active(
            value,
            operator_bindings,
            line,
            events,
        )
        if active or not conditional:
            events.setdefault(name, []).append(
                _asyncio_positioned_event(node, active)
            )

    if isinstance(node, ast.With):
        for item in node.items:
            if (
                isinstance(item.optional_vars, ast.Name)
                and _asyncio_runner_constructor_is_active(
                    item.context_expr,
                    operator_bindings,
                    line,
                )
            ):
                events.setdefault(item.optional_vars.id, []).append(
                    _asyncio_positioned_event(item.context_expr, True)
                )

    for name in _import_bound_names(node):
        if not conditional:
            events.setdefault(name, []).append(
                _asyncio_positioned_event(node, False)
            )


def _scan_asyncio_runner_alias_events(
    statements,
    operator_bindings,
    events,
    *,
    conditional=False,
):
    """Track Runner aliases through import-time compound statements."""
    for node in statements:
        _record_asyncio_runner_aliases(
            node,
            operator_bindings,
            events,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_asyncio_runner_alias_events(
                block,
                operator_bindings,
                events,
                conditional=True,
            )


def _collect_asyncio_runner_alias_events(tree, operator_bindings):
    """Collect asyncio.Runner aliases from import-time statements."""
    events = {}
    _scan_asyncio_runner_alias_events(
        tree.body,
        operator_bindings,
        events,
    )
    return events


def _call_is_asyncio_runner_run_mutation(call, operator_bindings):
    """Return True when asyncio.Runner.run executes a risky awaitable."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "run"
    ):
        return False
    reference_line = getattr(call, "lineno", 0)
    if not _asyncio_runner_alias_is_active(
        call.func.value,
        operator_bindings,
        reference_line,
    ):
        return False
    awaitable = _call_argument(call, {"coro"})
    return awaitable is not None and _asyncio_awaitable_mutates_workers(
        awaitable,
        operator_bindings,
        reference_line,
    )


def _call_is_event_loop_run_until_complete_to_thread_mutation(
    call,
    operator_bindings,
):
    """Detect worker mutations executed by a proven event loop."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "run_until_complete"
    ):
        return False
    reference_line = getattr(call, "lineno", 0)
    if not _asyncio_event_loop_alias_is_active(
        func.value,
        operator_bindings,
        reference_line,
    ):
        return False
    awaitable = _call_argument(call, {"future"})
    return awaitable is not None and _asyncio_awaitable_mutates_workers(
        awaitable,
        operator_bindings,
        reference_line,
    )


def _call_is_asyncio_run_to_thread_mutation(call, operator_bindings):
    """Return True when asyncio.run executes a workers-mutating awaitable."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    if not _asyncio_helper_active_at_line(
        call.func,
        "run",
        operator_bindings,
        reference_line,
    ):
        return False
    awaitable = _call_argument(call, {"main", "coro"})
    return awaitable is not None and _asyncio_awaitable_mutates_workers(
        awaitable,
        operator_bindings,
        reference_line,
    )


def _call_is_thread_pool_submit_mutation(call, operator_bindings):
    """Return True when ThreadPoolExecutor.submit schedules a risky callback."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "submit"):
        return False
    constructor = _thread_pool_receiver_constructor(
        func.value,
        operator_bindings,
    )
    if (
        constructor is None
        or _thread_pool_constructor_kind(constructor, operator_bindings)
        != "executor"
    ):
        return False
    target = call.args[0] if call.args else next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg == "fn"
        ),
        None,
    )
    if target is None:
        return False
    return (
        _thread_pool_constructor_has_mutating_initializer(
            constructor,
            operator_bindings,
        )
        or _thread_pool_callback_mutates_workers(
            target,
            operator_bindings,
        )
    )


def _call_is_thread_pool_constructor_initializer_mutation(
    call,
    operator_bindings,
):
    """Detect eager multiprocessing ThreadPool initializer side effects."""
    return (
        _thread_pool_constructor_kind(call, operator_bindings) == "pool"
        and _thread_pool_constructor_has_mutating_initializer(
            call,
            operator_bindings,
        )
    )

def _thread_expression_is_active(
    thread,
    active_thread_names,
    operator_bindings,
    mutator_names,
):
    """Return whether an expression resolves to a workers-mutating Thread."""
    if isinstance(thread, ast.Name):
        return thread.id in active_thread_names
    return isinstance(thread, ast.Call) and _thread_constructor_has_mutating_target(
        thread,
        operator_bindings,
        mutator_names,
    )


def _thread_call_starts_mutating_target(
    call,
    active_thread_names,
    operator_bindings,
    mutator_names,
):
    """Return whether one Thread start/run call executes a risky target."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in {"start", "run"}
    ):
        return False

    owner = call.func.value
    if _thread_expression_is_active(
        owner,
        active_thread_names,
        operator_bindings,
        mutator_names,
    ):
        return True

    return (
        call.func.attr == "run"
        and bool(call.args)
        and _thread_class_reference_is_active(
            owner,
            operator_bindings,
            getattr(call, "lineno", 0),
        )
        and _thread_expression_is_active(
            call.args[0],
            active_thread_names,
            operator_bindings,
            mutator_names,
        )
    )


def _expression_starts_mutating_thread(
    expr,
    active_thread_names,
    operator_bindings,
    mutator_names,
):
    """Return True when an evaluated expression starts a risky Thread."""
    if isinstance(expr, ast.Lambda):
        return False
    if _thread_call_starts_mutating_target(
        expr,
        active_thread_names,
        operator_bindings,
        mutator_names,
    ):
        return True
    return any(
        _expression_starts_mutating_thread(
            child,
            active_thread_names,
            operator_bindings,
            mutator_names,
        )
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.AST)
    )


def _record_mutating_thread_assignments(
    node,
    active_thread_names,
    operator_bindings,
    mutator_names,
    *,
    conditional,
):
    """Track names holding risky Thread instances after this statement."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional:
            active_thread_names.discard(node.name)
        return
    for name, value in _namespace_assignment_values(node):
        risky = (
            isinstance(value, ast.Call)
            and _thread_constructor_has_mutating_target(
                value,
                operator_bindings,
                mutator_names,
            )
        ) or (
            isinstance(value, ast.Name)
            and value.id in active_thread_names
        )
        if risky:
            active_thread_names.add(name)
        elif not conditional:
            active_thread_names.discard(name)


def _scan_started_mutating_threads(
    statements,
    operator_bindings,
    mutator_names,
    active_thread_names,
    *,
    conditional=False,
):
    """Scan one import-time statement list for risky Thread.start calls."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _record_mutating_thread_assignments(
                node,
                active_thread_names,
                operator_bindings,
                mutator_names,
                conditional=conditional,
            )
            continue
        if any(
            isinstance(child, ast.expr)
            and _expression_starts_mutating_thread(
                child,
                active_thread_names,
                operator_bindings,
                mutator_names,
            )
            for child in ast.iter_child_nodes(node)
        ):
            return True
        _record_mutating_thread_assignments(
            node,
            active_thread_names,
            operator_bindings,
            mutator_names,
            conditional=conditional,
        )
        for block in _compound_statement_blocks(node):
            if _scan_started_mutating_threads(
                block,
                operator_bindings,
                mutator_names,
                active_thread_names,
                conditional=True,
            ):
                return True
    return False


def _statements_start_mutating_thread(
    statements,
    operator_bindings,
    mutator_names=None,
):
    """Return True only when a risky Thread target is actually started."""
    return _scan_started_mutating_threads(
        statements,
        operator_bindings,
        set() if mutator_names is None else mutator_names,
        set(),
    )


def _call_is_collections_lazy_consumer(call, operator_bindings):
    """Return True for proven collections deque or Counter eager consumers."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    func = call.func
    if isinstance(func, ast.Name):
        alias_events = operator_bindings[34] if len(operator_bindings) > 34 else {}
        return _imported_alias_is_active(
            alias_events,
            func.id,
            reference_line,
        )
    if not (
        isinstance(func, ast.Attribute)
        and func.attr in _COLLECTIONS_LAZY_CONSUMER_NAMES
    ):
        return False
    module_events = operator_bindings[33] if len(operator_bindings) > 33 else {}
    return _module_alias_active_at_line(
        func.value,
        set(),
        module_events,
        reference_line,
    )


_EAGER_LAZY_ITERATOR_CONSUMERS = frozenset(
    {
        "list",
        "tuple",
        "set",
        "frozenset",
        "any",
        "all",
        "max",
        "min",
        "next",
        "sorted",
        "sum",
    }
)

_EAGER_GENERATOR_CONSUMER_BUILTINS = _EAGER_LAZY_ITERATOR_CONSUMERS | {"sum"}

_HEAPQ_ORDERED_CALLBACK_METHODS = frozenset({"nsmallest", "nlargest"})


def _call_is_heapq_ordered_callback_mutation(call, operator_bindings):
    """Return True when heapq.nsmallest/nlargest executes mutating callbacks."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in _HEAPQ_ORDERED_CALLBACK_METHODS:
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Name):
        return False
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    if receiver.id not in module_aliases and receiver.id != "heapq":
        return False
    if len(call.args) < 2:
        return False
    if _key_lambda_mutates_workers(call, operator_bindings):
        return True
    if _key_lambda_invokes_mutating_callback_container(call, operator_bindings):
        return True
    iterable = call.args[1]
    return (
        _iterable_holds_mutating_callbacks(iterable, operator_bindings)
        or _expression_is_mutating_lazy_iterator(iterable, operator_bindings)
    )


def _call_is_itertools_starmap_mutation(call, operator_bindings):
    """Return True when itertools.starmap executes workers-mutating callbacks."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "starmap" or len(call.args) < 2:
        return False
    module_events = operator_bindings[35] if len(operator_bindings) > 35 else {}
    if not _module_alias_active_at_line(
        call.func.value,
        set(),
        module_events,
        getattr(call, "lineno", 0),
    ):
        return False
    callback = call.args[0]
    if _thread_pool_callback_mutates_workers(callback, operator_bindings):
        return True
    if isinstance(callback, ast.Lambda):
        positional_params = (
            *callback.args.posonlyargs,
            *callback.args.args,
        )
        if positional_params:
            param_name = positional_params[0].arg
            if _expression_invokes_loop_callback(callback.body, param_name):
                return any(
                    _iterable_holds_mutating_callbacks(iterable, operator_bindings)
                    for iterable in call.args[1:]
                )
    return any(
        _expression_is_mutating_lazy_iterator(iterable, operator_bindings)
        or _iterable_holds_mutating_callbacks(iterable, operator_bindings)
        for iterable in call.args[1:]
    )


def _call_is_special_lazy_iterator_consumer(call, operator_bindings):
    """Return True for non-builtin eager consumers handled specially."""
    return (
        _call_is_thread_pool_constructor_initializer_mutation(
            call,
            operator_bindings,
        )
        or _call_is_thread_pool_map_mutation(call, operator_bindings)
        or _call_is_itertools_starmap_mutation(call, operator_bindings)
        or _call_is_heapq_ordered_callback_mutation(call, operator_bindings)
        or _call_is_thread_pool_submit_mutation(call, operator_bindings)
        or _call_is_thread_pool_apply_async_mutation(call, operator_bindings)
        or _call_is_thread_pool_apply_mutation(call, operator_bindings)
        or _call_is_future_add_done_callback_mutation(call, operator_bindings)
        or _call_is_asyncio_run_to_thread_mutation(call, operator_bindings)
        or _call_is_asyncio_runner_run_mutation(call, operator_bindings)
        or _call_is_event_loop_run_until_complete_to_thread_mutation(
            call,
            operator_bindings,
        )
        or _attribute_call_consumes_mutating_lazy_iterator(
            call,
            operator_bindings,
        )
    )


def _collections_call_consumes_mutating_lazy_iterator(
    call,
    operator_bindings,
):
    """Return whether a proven collections consumer eagerly drains a risky source."""
    if not _call_is_collections_lazy_consumer(call, operator_bindings):
        return False
    return bool(call.args) and _expression_is_mutating_lazy_iterator(
        call.args[0],
        operator_bindings,
    )


def _constant_is_eager_generator_consumer(node):
    return isinstance(node, ast.Constant) and node.value in _EAGER_GENERATOR_CONSUMER_BUILTINS


def _builtins_module_is_active_at_line(
    node,
    builtins_aliases,
    builtins_alias_events=None,
    reference_line=0,
):
    """Return whether an expression resolves to builtins at this source line."""
    if _is_builtins_import(node) or _is_builtins_reference(node, builtins_aliases):
        return True
    return _module_alias_active_at_line(
        node,
        builtins_aliases,
        builtins_alias_events,
        reference_line or getattr(node, "lineno", 0),
    )


def _getattr_is_builtin_eager_consumer(
    func,
    builtins_aliases,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Return True for builtin getattr resolving an eager consumer."""
    if not isinstance(func, ast.Call) or len(func.args) < 2:
        return False
    reference_line = getattr(func, "lineno", 0)
    resolver = func.func
    direct_getattr = (
        isinstance(resolver, ast.Name)
        and resolver.id == "getattr"
        and _name_is_unshadowed_builtin(
            "getattr",
            reference_line,
            builtin_shadow_lines,
        )
    )
    module_getattr = (
        isinstance(resolver, ast.Attribute)
        and resolver.attr == "getattr"
        and _builtins_module_is_active_at_line(
            resolver.value,
            builtins_aliases,
            builtins_alias_events,
            reference_line,
        )
    )
    return (
        (direct_getattr or module_getattr)
        and _builtins_module_is_active_at_line(
            func.args[0],
            builtins_aliases,
            builtins_alias_events,
            reference_line,
        )
        and _constant_is_eager_generator_consumer(func.args[1])
    )


def _subscript_is_vars_builtins_eager_consumer(
    func,
    builtins_aliases,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Return True for ``vars(builtins)['sum'/'any'/...]`` callables."""
    if not isinstance(func, ast.Subscript) or not _constant_is_eager_generator_consumer(
        func.slice
    ):
        return False
    value = func.value
    if not (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "vars"
        and len(value.args) == 1
        and not value.keywords
    ):
        return False
    reference_line = getattr(value, "lineno", 0)
    if not _name_is_unshadowed_builtin(
        "vars",
        reference_line,
        builtin_shadow_lines,
    ):
        return False
    return _builtins_module_is_active_at_line(
        value.args[0],
        builtins_aliases,
        builtins_alias_events,
        reference_line,
    )


def _subscript_is_builtin_eager_consumer(
    func,
    builtins_aliases,
    builtins_alias_events=None,
    builtin_shadow_lines=None,
):
    """Return True for ``builtins.__dict__['sum'/'any'/...]`` callables."""
    if not isinstance(func, ast.Subscript) or not _constant_is_eager_generator_consumer(
        func.slice
    ):
        return False
    reference_line = getattr(func, "lineno", 0)
    base = _subscript_base_node(func)
    if _builtins_module_is_active_at_line(
        base,
        builtins_aliases,
        builtins_alias_events,
        reference_line,
    ):
        return True
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "__dict__"
        and _builtins_module_is_active_at_line(
            base.value,
            builtins_aliases,
            builtins_alias_events,
            reference_line,
        )
    ) or _subscript_is_vars_builtins_eager_consumer(
        func,
        builtins_aliases,
        builtins_alias_events,
        builtin_shadow_lines,
    )


def _attribute_is_builtin_eager_consumer(
    func,
    builtins_aliases,
    builtins_alias_events=None,
):
    """Return True for ``builtins.sum`` / ``builtins.any`` / ... callables."""
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _EAGER_GENERATOR_CONSUMER_BUILTINS
        and _builtins_module_is_active_at_line(
            func.value,
            builtins_aliases,
            builtins_alias_events,
            getattr(func, "lineno", 0),
        )
    )


def _call_is_importlib_builtins_eager_consumer(call, operator_bindings):
    """Return True for ``import_module('builtins').sum(...)`` style calls."""
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in _EAGER_GENERATOR_CONSUMER_BUILTINS:
        return False
    base = func.value
    if not isinstance(base, ast.Call) or not base.args:
        return False
    importlib_aliases = (
        operator_bindings[16] if len(operator_bindings) > 16 else set()
    )
    importlib_alias_events = (
        operator_bindings[19] if len(operator_bindings) > 19 else {}
    )
    importlib_module_aliases = (
        operator_bindings[24] if len(operator_bindings) > 24 else set()
    )
    importlib_module_alias_events = (
        operator_bindings[29] if len(operator_bindings) > 29 else {}
    )
    if not _call_uses_importlib_import_module(
        base,
        importlib_aliases,
        importlib_alias_events,
        importlib_module_aliases,
        importlib_module_alias_events,
        getattr(call, "lineno", 0),
    ):
        return False
    module_name = base.args[0]
    return isinstance(module_name, ast.Constant) and module_name.value == "builtins"


def _resolved_builtin_eager_consumer_name(call, operator_bindings):
    """Return an eager consumer name when ``call`` resolves via the builtins module."""
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    builtins_alias_events = (
        operator_bindings[30] if len(operator_bindings) > 30 else {}
    )
    builtin_shadow_lines = (
        operator_bindings[32] if len(operator_bindings) > 32 else {}
    )
    if _attribute_is_builtin_eager_consumer(
        func,
        builtins_aliases,
        builtins_alias_events,
    ):
        return func.attr
    if _getattr_is_builtin_eager_consumer(
        func,
        builtins_aliases,
        builtins_alias_events,
        builtin_shadow_lines,
    ):
        return func.args[1].value
    if isinstance(func, ast.Subscript) and _subscript_is_builtin_eager_consumer(
        func,
        builtins_aliases,
        builtins_alias_events,
        builtin_shadow_lines,
    ):
        return func.slice.value
    if _call_is_importlib_builtins_eager_consumer(call, operator_bindings):
        return call.func.attr
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else {"sys"}
    if _attribute_is_sys_modules_builtins_eager_consumer(func, sys_aliases):
        return func.attr
    return None


def _eager_consumer_drains_mutating_lazy_iterator(name, call, operator_bindings):
    """Shared argument checks for direct and builtins-module eager consumers."""
    if name in {"sorted", "max", "min"} and (
        _key_lambda_mutates_workers(call, operator_bindings)
        or _key_lambda_invokes_mutating_callback_container(call, operator_bindings)
    ):
        return True
    if not call.args:
        return False
    if name in {"max", "min"} and len(call.args) != 1:
        return False
    return _expression_is_mutating_lazy_iterator(
        call.args[0],
        operator_bindings,
    )


def _named_builtin_consumes_mutating_lazy_iterator(
    call,
    operator_bindings,
    bound_names=None,
):
    """Detect eager builtin consumers of a risky lazy iterator."""
    if not isinstance(call.func, ast.Name):
        return False
    name = call.func.id
    if (
        name not in _EAGER_LAZY_ITERATOR_CONSUMERS
        or not _builtin_consumer_is_active(
            name,
            call,
            operator_bindings,
            bound_names,
        )
    ):
        return False
    return _eager_consumer_drains_mutating_lazy_iterator(
        name,
        call,
        operator_bindings,
    )


def _builtin_module_consumes_mutating_lazy_iterator(call, operator_bindings):
    """Detect builtins-module indirection for eager generator consumers."""
    name = _resolved_builtin_eager_consumer_name(call, operator_bindings)
    if not name:
        return False
    return _eager_consumer_drains_mutating_lazy_iterator(
        name,
        call,
        operator_bindings,
    )


def _call_consumes_mutating_lazy_iterator(call, operator_bindings, bound_names=None):
    """Detect eager consumers of direct or saved risky map/filter iterators."""
    if not isinstance(call, ast.Call):
        return False
    return (
        _call_is_special_lazy_iterator_consumer(call, operator_bindings)
        or _collections_call_consumes_mutating_lazy_iterator(
            call,
            operator_bindings,
        )
        or _named_builtin_consumes_mutating_lazy_iterator(
            call,
            operator_bindings,
            bound_names,
        )
        or _builtin_module_consumes_mutating_lazy_iterator(
            call,
            operator_bindings,
        )
    )


def _lazy_iterator_assignment_is_mutating(value, active_names, operator_bindings):
    """Return whether an assignment stores a risky lazy iterator."""
    return _expression_is_mutating_lazy_iterator(
        value,
        operator_bindings,
        active_names,
    )


def _record_lazy_iterator_assignment_events(
    node,
    active_names,
    events,
    operator_bindings,
    *,
    conditional,
):
    """Record source-ordered assignment/rebinding events for lazy iterators."""
    line = getattr(node, 'lineno', 0)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        if not conditional and node.name in active_names:
            active_names.discard(node.name)
            events.setdefault(node.name, []).append((line, False))
        return
    for name, value in _namespace_assignment_values(node):
        if _lazy_iterator_assignment_is_mutating(
            value,
            active_names,
            operator_bindings,
        ):
            active_names.add(name)
            events.setdefault(name, []).append((line, True))
        elif not conditional and name in active_names:
            active_names.discard(name)
            events.setdefault(name, []).append((line, False))


def _scan_lazy_iterator_alias_events(
    statements,
    active_names,
    events,
    operator_bindings,
    *,
    conditional=False,
):
    """Collect risky lazy-iterator aliases through import-time compound blocks."""
    for node in statements:
        _record_lazy_iterator_assignment_events(
            node,
            active_names,
            events,
            operator_bindings,
            conditional=conditional,
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for block in _compound_statement_blocks(node):
            _scan_lazy_iterator_alias_events(
                block,
                active_names,
                events,
                operator_bindings,
                conditional=True,
            )


def _collect_mutating_lazy_iterator_alias_events(tree, operator_bindings):
    """Collect source-ordered names that hold risky lazy map/filter iterators."""
    events = {}
    _scan_lazy_iterator_alias_events(
        tree.body,
        set(),
        events,
        operator_bindings,
    )
    return events


def _call_has_mutating_lambda_argument(call, operator_bindings, bound_names=None):
    """Detect callbacks only when the current call actually executes them."""
    return _call_consumes_mutating_lazy_iterator(
        call,
        operator_bindings,
        bound_names,
    )



def _decorator_resolves_to_builtin(decorator, name, operator_bindings=None):
    """Return True only when a decorator resolves to the requested builtin."""
    reference_line = getattr(decorator, 'lineno', 0)
    shadow_lines = operator_bindings[32] if operator_bindings and len(operator_bindings) > 32 else {}
    if isinstance(decorator, ast.Name):
        return decorator.id == name and _name_is_unshadowed_builtin(
            name,
            reference_line,
            shadow_lines,
        )
    if not (
        isinstance(decorator, ast.Attribute)
        and decorator.attr == name
    ):
        return False
    builtins_aliases = operator_bindings[8] if operator_bindings and len(operator_bindings) > 8 else set()
    builtins_events = operator_bindings[30] if operator_bindings and len(operator_bindings) > 30 else {}
    return _module_alias_active_at_line(
        decorator.value,
        builtins_aliases,
        builtins_events,
        reference_line,
    )


def _function_is_static_or_class_method(func_node, operator_bindings=None):
    """Return True for proven builtin staticmethod/classmethod decorators."""
    return any(
        _decorator_resolves_to_builtin(decorator, 'staticmethod', operator_bindings)
        or _decorator_resolves_to_builtin(decorator, 'classmethod', operator_bindings)
        for decorator in func_node.decorator_list
    )



def _function_is_property_method(func_node, operator_bindings=None):
    """Return True for a proven builtin ``property`` decorator."""
    return any(
        _decorator_resolves_to_builtin(decorator, 'property', operator_bindings)
        for decorator in func_node.decorator_list
    )



def _function_invokes_mutating_super_method(
    func_node,
    class_name,
    class_bases,
    methods,
    class_methods=None,
):
    """Return True when super().method() reaches a mutating MRO implementation."""
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        super_call = node.func.value
        if not (
            isinstance(super_call, ast.Call)
            and isinstance(super_call.func, ast.Name)
            and super_call.func.id == "super"
        ):
            continue
        if _class_super_method_mutates(
            methods,
            class_bases,
            class_name,
            node.func.attr,
            class_methods,
        ):
            return True
    return False


def _collect_metaclass_class_names(tree):
    """Return locally defined classes that are type subclasses."""
    class_nodes = [
        node for node in tree.body if isinstance(node, ast.ClassDef)
    ]
    metaclass_names = set()
    while True:
        discovered = {
            node.name
            for node in class_nodes
            if any(
                isinstance(base, ast.Name)
                and (base.id == "type" or base.id in metaclass_names)
                for base in node.bases
            )
        }
        if discovered <= metaclass_names:
            return metaclass_names
        metaclass_names.update(discovered)


def _collect_mutating_metaclass_hook_definitions(
    tree,
    operator_bindings,
    metaclass_names,
):
    """Return mutating hook definitions owned by local metaclass classes."""
    return {
        (node.name, stmt.name)
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name in metaclass_names
        for stmt in node.body
        if isinstance(stmt, ast.FunctionDef)
        and stmt.name in {"__new__", "__init__", "__call__"}
        and _function_mutates_workers(stmt, operator_bindings)
    }


def _mutating_metaclass_names_for_hooks(tree, operator_bindings, hook_names):
    """Return metaclasses whose effective MRO hook mutates workers."""
    metaclass_names = _collect_metaclass_class_names(tree)
    if not metaclass_names:
        return set()
    class_bases, class_methods, _class_attributes = (
        _collect_class_definition_metadata(tree)
    )
    mutating_hooks = _collect_mutating_metaclass_hook_definitions(
        tree,
        operator_bindings,
        metaclass_names,
    )
    return {
        name
        for name in metaclass_names
        if any(
            _class_hierarchy_defines_method(
                mutating_hooks,
                class_bases,
                name,
                hook_name,
                class_methods,
            )
            for hook_name in hook_names
        )
    }


def _explicit_metaclass_name(class_node):
    """Return a simple explicit metaclass name, if present."""
    for keyword in class_node.keywords:
        if keyword.arg == "metaclass" and isinstance(keyword.value, ast.Name):
            return keyword.value.id
    return None


def _classes_with_mutating_effective_metaclass(
    tree,
    operator_bindings,
    hook_names,
):
    """Return classes whose effective metaclass runs a mutating hook."""
    mutating_metaclasses = _mutating_metaclass_names_for_hooks(
        tree,
        operator_bindings,
        hook_names,
    )
    affected = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        explicit = _explicit_metaclass_name(node)
        inherited = any(
            isinstance(base, ast.Name) and base.id in affected
            for base in node.bases
        )
        if explicit in mutating_metaclasses or inherited:
            affected.add(node.name)
    return affected


def _collect_metaclass_definition_mutators(tree, operator_bindings):
    """Return classes whose definition runs mutating metaclass new/init hooks."""
    return _classes_with_mutating_effective_metaclass(
        tree,
        operator_bindings,
        {"__new__", "__init__"},
    )


def _record_class_side_effect_target(
    class_name,
    stmt,
    operator_bindings,
    constructors,
    methods,
    properties,
):
    """Record one class method that mutates ``workers`` when invoked."""
    if not isinstance(stmt, ast.FunctionDef):
        return False
    if not _function_mutates_workers(stmt, operator_bindings):
        return False
    if stmt.name == "__class_getitem__":
        methods.add((class_name, stmt.name))
        return True
    if stmt.name in ("__init__", "__post_init__"):
        constructors.add(class_name)
        methods.add((class_name, stmt.name))
        return True
    target = (class_name, stmt.name)
    if stmt.name == "__init_subclass__" or _function_is_static_or_class_method(
        stmt, operator_bindings
    ):
        methods.add(target)
        return True
    if _function_is_property_method(stmt, operator_bindings):
        properties.add(target)
        return True
    if stmt.name == "__get__":
        methods.add(target)
        return True
    # A plain instance method runs the mutation through an instance
    # (``Helper().bump()``, ``h.bump()``) or through the class
    # (``Helper.bump(Helper())``). A decorator can replace the function with a
    # wrapper that never runs its body, so only undecorated methods are proven.
    if stmt.decorator_list:
        return False
    methods.add(target)
    return True




def _class_has_worker_side_effect_target(
    class_node,
    operator_bindings,
    constructors,
    methods,
    properties,
):
    """Record all risky hooks in one class and report whether any were found."""
    risky = False
    for stmt in class_node.body:
        if _record_class_side_effect_target(
            class_node.name,
            stmt,
            operator_bindings,
            constructors,
            methods,
            properties,
        ):
            risky = True
    if _class_dataclass_field_default_factory_mutates(
        class_node,
        operator_bindings,
    ):
        constructors.add(class_node.name)
        risky = True
    return risky


def _descriptor_hooks_for_class(descriptor_class, methods, descriptor_fields):
    """Return hooks whose mutating method is defined on ``descriptor_class``."""
    return [
        hook
        for hook in descriptor_fields
        if (descriptor_class, hook) in methods
    ]


def _record_descriptor_targets(class_name, targets, hooks, descriptor_fields):
    """Record ``(class, field)`` for each simple target and each hook."""
    if not hooks:
        return False
    found = False
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        for hook in hooks:
            descriptor_fields[hook].add((class_name, target.id))
        found = True
    return found


def _record_descriptor_field_assignments(class_node, methods, descriptor_fields):
    """Record descriptor fields keyed by the hook an access kind invokes."""
    found = False
    for stmt in class_node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not isinstance(stmt.value, ast.Call) or not isinstance(stmt.value.func, ast.Name):
            continue
        found = (
            _record_descriptor_targets(
                class_node.name,
                stmt.targets,
                _descriptor_hooks_for_class(
                    stmt.value.func.id, methods, descriptor_fields
                ),
                descriptor_fields,
            )
            or found
        )
    return found


def _record_class_side_effect_binding(
    class_node,
    binding_events,
    risky,
    *,
    conditional,
):
    """Record activation or definite replacement of one risky class binding."""
    line = getattr(class_node, 'lineno', 0)
    if risky:
        binding_events.setdefault(class_node.name, []).append((line, True))
        return
    if not conditional:
        _deactivate_tracked_binding(binding_events, class_node.name, line)


def _scan_class_side_effect_bindings(
    statements,
    operator_bindings,
    constructors,
    methods,
    properties,
    binding_events,
    *,
    descriptor_fields=None,
    conditional=False,
):
    """Populate source-ordered risky class bindings through compound blocks."""
    for node in statements:
        line = getattr(node, 'lineno', 0)
        if isinstance(node, ast.ClassDef):
            risky = _class_has_worker_side_effect_target(
                node,
                operator_bindings,
                constructors,
                methods,
                properties,
            )
            if descriptor_fields is not None:
                risky = (
                    _record_descriptor_field_assignments(
                        node,
                        methods,
                        descriptor_fields,
                    )
                    or risky
                )
            _record_class_side_effect_binding(
                node,
                binding_events,
                risky,
                conditional=conditional,
            )
            continue
        if not conditional:
            _invalidate_tracked_bindings_from_statement(
                node,
                binding_events,
                line,
            )
        for block in _compound_statement_blocks(node):
            _scan_class_side_effect_bindings(
                block,
                operator_bindings,
                constructors,
                methods,
                properties,
                binding_events,
                descriptor_fields=descriptor_fields,
                conditional=True,
            )


def _class_instance_assignment_bindings(node, enum_members=None):
    """Return ``(name, class name)`` pairs for ``name = Class()`` bindings."""
    if isinstance(node, ast.Assign):
        targets = node.targets
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
        value = node.value
    else:
        return ()
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        class_name = value.func.id
    elif (
        enum_members
        and isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and (value.value.id, value.attr) in enum_members
    ):
        class_name = value.value.id
    else:
        return ()
    return tuple(
        (target.id, class_name)
        for target in targets
        if isinstance(target, ast.Name)
    )


def _record_class_instance_statement(node, line, events, conditional, enum_members=None):
    """Record or invalidate one statement's class-instance bindings."""
    bindings = _class_instance_assignment_bindings(node, enum_members)
    if bindings:
        for name, class_name in bindings:
            events.setdefault(name, []).append(
                (line, class_name, True) if conditional else (line, class_name)
            )
        return
    if not conditional:
        _invalidate_tracked_bindings_from_statement(node, events, line)


def _scan_class_instance_bindings(
    statements,
    events,
    *,
    conditional=False,
    enum_members=None,
):
    """Populate source-ordered class-instance bindings through compound blocks."""
    for node in statements:
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not conditional:
                _deactivate_tracked_binding(events, node.name, line)
            continue
        _record_class_instance_statement(node, line, events, conditional, enum_members)
        for block in _compound_statement_blocks(node):
            _scan_class_instance_bindings(
                block,
                events,
                conditional=True,
                enum_members=enum_members,
            )


_ENUM_BASE_NAMES = frozenset({"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"})


def _enum_import_aliases(tree):
    """Return module, direct-base and nonmember aliases that identify enums."""
    module_aliases = {
        imported.asname or imported.name
        for node in tree.body
        if isinstance(node, ast.Import)
        for imported in node.names
        if imported.name == "enum"
    }
    base_aliases = {
        imported.asname or imported.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "enum"
        for imported in node.names
        if imported.name in _ENUM_BASE_NAMES
    }
    nonmember_aliases = {
        imported.asname or imported.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "enum"
        for imported in node.names
        if imported.name == "nonmember"
    }
    return module_aliases, base_aliases, nonmember_aliases


def _base_is_direct_enum(base, module_aliases, base_aliases):
    """Return True when one base expression names a supported enum base."""
    if isinstance(base, ast.Name):
        return base.id in base_aliases
    return (
        isinstance(base, ast.Attribute)
        and base.attr in _ENUM_BASE_NAMES
        and isinstance(base.value, ast.Name)
        and base.value.id in module_aliases
    )


def _class_is_direct_enum(class_node, module_aliases, base_aliases):
    """Return True when a class directly derives from a supported enum base."""
    return any(
        _base_is_direct_enum(base, module_aliases, base_aliases)
        for base in class_node.bases
    )


def _statement_simple_targets(stmt):
    """Return simple assignment targets without nested conditional expressions."""
    if isinstance(stmt, ast.Assign):
        return stmt.targets
    if isinstance(stmt, ast.AnnAssign):
        return [stmt.target]
    return []


def _enum_value_is_nonmember(value, module_aliases, nonmember_aliases):
    """Return True when an enum-body value is ``nonmember(...)``."""
    if not isinstance(value, ast.Call):
        return False
    func = value.func
    if isinstance(func, ast.Name):
        return func.id in nonmember_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "nonmember"
        and isinstance(func.value, ast.Name)
        and func.value.id in module_aliases
    )


def _enum_member_names(class_node, module_aliases, nonmember_aliases):
    """Yield public simple names that create true members in an enum body."""
    for stmt in class_node.body:
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if isinstance(value, ast.Lambda) or _enum_value_is_nonmember(
            value,
            module_aliases,
            nonmember_aliases,
        ):
            continue
        for target in _statement_simple_targets(stmt):
            if isinstance(target, ast.Name) and not target.id.startswith("_"):
                yield target.id


def _collect_enum_member_targets(tree):
    """Return enum class/member pairs for direct enum definitions."""
    module_aliases, base_aliases, nonmember_aliases = _enum_import_aliases(tree)
    members = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if not _class_is_direct_enum(node, module_aliases, base_aliases):
            continue
        members.update(
            (node.name, member_name)
            for member_name in _enum_member_names(
                node,
                module_aliases,
                nonmember_aliases,
            )
        )
    return members


def _class_body_plain_attribute_names(class_node):
    """Return names bound to provably plain values in one class body.

    Only values that cannot implement the descriptor protocol (constants and
    literal containers) qualify, so the barrier can never hide a descriptor
    assigned through a name or a factory call.
    """
    names = set()
    for stmt in class_node.body:
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(
            value,
            (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.JoinedStr),
        ):
            continue
        for target in _statement_simple_targets(stmt):
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _collect_class_definition_metadata(tree):
    """Collect class bases, defined methods, and plain class attributes."""
    class_bases = {}
    class_methods = set()
    class_attributes = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        class_bases[node.name] = tuple(
            base.id for base in node.bases if isinstance(base, ast.Name)
        )
        class_methods.update(
            (node.name, stmt.name)
            for stmt in node.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        class_attributes.update(
            (node.name, attribute_name)
            for attribute_name in _class_body_plain_attribute_names(node)
        )
    return class_bases, class_methods, class_attributes


def _collect_metaclass_call_constructor_names(tree, operator_bindings):
    """Return classes whose construction runs a mutating metaclass __call__."""
    return _classes_with_mutating_effective_metaclass(
        tree,
        operator_bindings,
        {"__call__"},
    )


def _record_mutating_super_methods(
    node,
    class_bases,
    methods,
    class_methods,
    constructors,
):
    """Record methods that delegate to a mutating superclass method."""
    if not isinstance(node, ast.ClassDef):
        return
    for stmt in node.body:
        if not isinstance(stmt, ast.FunctionDef):
            continue
        if not _function_invokes_mutating_super_method(
            stmt,
            node.name,
            class_bases,
            methods,
            class_methods,
        ):
            continue
        if stmt.name in ("__init__", "__post_init__"):
            constructors.add(node.name)
        else:
            methods.add((node.name, stmt.name))


def _class_constructor_assignment_is_non_mutating(value, operator_bindings):
    """Return True when an assigned constructor provably cannot mutate workers."""
    if isinstance(value, ast.Lambda):
        return not _lambda_mutates_workers(value, operator_bindings)
    if (
        isinstance(value, ast.Attribute)
        and value.attr in ("__init__", "__post_init__")
        and isinstance(value.value, ast.Name)
        and value.value.id == "object"
    ):
        shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
        return _name_is_unshadowed_builtin(
            "object",
            getattr(value, "lineno", 0),
            shadow_lines,
        )
    return False


def _record_class_constructor_assignment_barriers(
    tree,
    operator_bindings,
    class_methods,
):
    """Record non-mutating ``__init__`` assignments as hierarchy barriers.

    A class-body assignment replaces the inherited initializer with a value the
    scanner can prove safe, so the MRO lookup must stop at that class. Unknown
    or mutating assigned constructors stay unrecorded, leaving the existing
    inherited-constructor lookup unchanged.
    """
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            if isinstance(stmt, ast.AnnAssign) and stmt.value is None:
                continue
            if not _class_constructor_assignment_is_non_mutating(
                stmt.value,
                operator_bindings,
            ):
                continue
            for target in _statement_simple_targets(stmt):
                if isinstance(target, ast.Name) and target.id in (
                    "__init__",
                    "__post_init__",
                ):
                    class_methods.add((node.name, target.id))


def _collect_class_side_effect_targets(tree, operator_bindings):
    """Collect risky class hooks plus source-ordered class bindings."""
    constructors = set()
    methods = set()
    properties = set()
    descriptor_fields = {"__get__": set(), "__set__": set(), "__delete__": set()}
    metaclass_definitions = _collect_metaclass_definition_mutators(
        tree,
        operator_bindings,
    )

    _scan_class_side_effect_bindings(
        tree.body,
        operator_bindings,
        constructors,
        methods,
        properties,
        {},
    )

    binding_events = {}
    _scan_class_side_effect_bindings(
        tree.body,
        operator_bindings,
        constructors,
        methods,
        properties,
        binding_events,
        descriptor_fields=descriptor_fields,
    )

    enum_members = _collect_enum_member_targets(tree)
    instance_events = {}
    _scan_class_instance_bindings(
        tree.body,
        instance_events,
        enum_members=enum_members,
    )
    class_bases, class_methods, class_attributes = (
        _collect_class_definition_metadata(tree)
    )
    class_definition_lines = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_definition_lines.setdefault(node.name, []).append(
                getattr(node, "lineno", 0)
            )
    _record_class_constructor_assignment_barriers(
        tree,
        operator_bindings,
        class_methods,
    )
    constructors.update(
        _collect_metaclass_call_constructor_names(
            tree,
            operator_bindings,
        )
    )
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        _record_mutating_super_methods(
            node,
            class_bases,
            methods,
            class_methods,
            constructors,
        )
    return (
        constructors,
        methods,
        properties,
        metaclass_definitions,
        binding_events,
        descriptor_fields,
        instance_events,
        class_bases,
        class_methods,
        enum_members,
        class_attributes,
        class_definition_lines,
    )


def _class_binding_is_active(class_targets, class_name, reference_line):
    """Return whether the risky class definition still owns this name."""
    if len(class_targets) < 5:
        return True
    events = class_targets[4]
    if class_name not in events:
        return True
    return bool(_binding_state_at_line(events, class_name, reference_line))


def _class_definition_line_at(definition_lines, class_name, reference_line):
    """Return the last class definition line visible at ``reference_line``."""
    line = 0
    for definition_line in definition_lines.get(class_name, ()):
        if reference_line and definition_line > reference_line:
            break
        line = definition_line
    return line


def _class_hook_is_active(class_targets, class_name, method_name, hooks, reference_line):
    """Return True when ``class_name.method_name`` is a live mutating hook."""
    return (class_name, method_name) in hooks and _class_binding_is_active(
        class_targets,
        class_name,
        reference_line,
    )


def _merge_class_mro_sequences(sequences):
    """Merge parent MRO sequences using Python's C3 candidate rule."""
    pending = [list(sequence) for sequence in sequences if sequence]
    result = []
    while pending:
        candidate = next(
            (
                sequence[0]
                for sequence in pending
                if all(
                    sequence[0] not in other[1:]
                    for other in pending
                )
            ),
            None,
        )
        if candidate is None:
            return None
        result.append(candidate)
        for sequence in pending:
            if sequence and sequence[0] == candidate:
                sequence.pop(0)
        pending = [sequence for sequence in pending if sequence]
    return tuple(result)


def _class_mro_names(class_name, class_bases, cache=None, active=None):
    """Return the best-known C3 MRO for locally defined classes."""
    cache = {} if cache is None else cache
    active = frozenset() if active is None else active
    if class_name in cache:
        return cache[class_name]
    if class_name in active:
        return (class_name,)
    bases = class_bases.get(class_name, ())
    if not bases:
        cache[class_name] = (class_name,)
        return cache[class_name]
    next_active = active | {class_name}
    parent_mros = [
        _class_mro_names(base, class_bases, cache, next_active)
        for base in bases
    ]
    merged = _merge_class_mro_sequences([*parent_mros, bases])
    if merged is None:
        merged = tuple(dict.fromkeys(
            name
            for parent_mro in parent_mros
            for name in parent_mro
        ))
    cache[class_name] = (class_name, *merged)
    return cache[class_name]


def _mro_method_mutation_owner(
    methods,
    class_methods,
    class_attributes,
    mro_names,
    method_name,
):
    """Return the first MRO owner with a mutating definition, if any."""
    for owner in mro_names:
        if (owner, method_name) in methods:
            return owner
        if class_methods is not None and (owner, method_name) in class_methods:
            return None
        if class_attributes is not None and (owner, method_name) in class_attributes:
            return None
    return None


def _mro_method_mutation_state(
    methods,
    class_methods,
    class_attributes,
    mro_names,
    method_name,
):
    """Return whether the first known MRO definition is mutating."""
    return _mro_method_mutation_owner(
        methods,
        class_methods,
        class_attributes,
        mro_names,
        method_name,
    ) is not None


def _class_hierarchy_defines_method(
    methods,
    class_bases,
    class_name,
    method_name,
    class_methods=None,
    seen=None,
    class_attributes=None,
):
    """Return True when the first MRO definition is a mutating method."""
    del seen  # Compatibility with older callers; C3 resolution handles cycles.
    return _mro_method_mutation_state(
        methods,
        class_methods,
        class_attributes,
        _class_mro_names(class_name, class_bases),
        method_name,
    )


def _class_super_method_mutates(
    methods,
    class_bases,
    class_name,
    method_name,
    class_methods=None,
):
    """Return True when super() selects a mutating base implementation."""
    mro_names = _class_mro_names(class_name, class_bases)
    return _mro_method_mutation_state(
        methods,
        class_methods,
        None,
        mro_names[1:],
        method_name,
    )


def _instance_hook_is_active(
    class_targets,
    instance_events,
    methods,
    instance_name,
    method_name,
    reference_line,
    class_attributes=None,
):
    """Return True when a module-bound instance reaches a mutating method.

    The instance captured its class at assignment time, so the class name only
    has to be live *then*: rebinding it before the call (``h = Helper();
    Helper = None; h.bump()``) does not make the recorded method safe. A
    conditional rebinding leaves both classes as candidates, so any risky one
    makes the config dynamic.
    """
    class_bases = class_targets[7] if len(class_targets) > 7 else {}
    class_methods = class_targets[8] if len(class_targets) > 8 else None
    for instance_line, instance_class in _instance_binding_candidates_at_line(
        instance_events,
        instance_name,
        reference_line,
    ):
        if not _class_hierarchy_defines_method(
            methods,
            class_bases,
            instance_class,
            method_name,
            class_methods,
            class_attributes=class_attributes,
        ):
            continue
        if _class_binding_is_active(
            class_targets,
            instance_class,
            instance_line,
        ):
            return True
    return False


def _class_call_triggers_workers(expr, constructors, class_targets, reference_line):
    """Return True when a ``ClassName(...)`` call constructs a risky class."""
    if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name)):
        return False
    if not _class_binding_is_active(class_targets, expr.func.id, reference_line):
        return False
    if expr.func.id in constructors:
        return True
    class_bases = class_targets[7] if len(class_targets) > 7 else {}
    class_methods = class_targets[8] if len(class_targets) > 8 else None
    owner = _mro_method_mutation_owner(
        class_targets[1],
        class_methods,
        None,
        _class_mro_names(expr.func.id, class_bases),
        "__init__",
    )
    if owner is None or owner == expr.func.id:
        return owner is not None
    class_definition_lines = (
        class_targets[11] if len(class_targets) > 11 else {}
    )
    class_def_line = _class_definition_line_at(
        class_definition_lines,
        expr.func.id,
        reference_line,
    )
    if class_def_line and not _class_binding_is_active(
        class_targets,
        owner,
        class_def_line,
    ):
        # The subclass captured an earlier (non-mutating) binding of the base
        # name, so a later mutating redefinition cannot provide its __init__.
        return False
    return True


def _name_receiver_call_triggers_workers(
    receiver,
    method_name,
    methods,
    class_targets,
    instance_events,
    reference_line,
):
    """Return True when a named class or tracked instance reaches a risky hook."""
    if _class_hook_is_active(
        class_targets,
        receiver.id,
        method_name,
        methods,
        reference_line,
    ):
        return True
    class_bases = class_targets[7] if len(class_targets) > 7 else {}
    class_methods = class_targets[8] if len(class_targets) > 8 else None
    if (
        _class_hierarchy_defines_method(
            methods,
            class_bases,
            receiver.id,
            method_name,
            class_methods,
        )
        and _class_binding_is_active(class_targets, receiver.id, reference_line)
    ):
        return True
    return _instance_hook_is_active(
        class_targets,
        instance_events,
        methods,
        receiver.id,
        method_name,
        reference_line,
    )


def _constructed_receiver_call_triggers_workers(
    receiver,
    method_name,
    methods,
    class_targets,
    reference_line,
):
    """Return True when ClassName().method() resolves to a risky hook."""
    class_name = receiver.func.id
    class_bases = class_targets[7] if len(class_targets) > 7 else {}
    class_methods = class_targets[8] if len(class_targets) > 8 else None
    return (
        _class_hierarchy_defines_method(
            methods,
            class_bases,
            class_name,
            method_name,
            class_methods,
        )
        and _class_binding_is_active(
            class_targets,
            class_name,
            reference_line,
        )
    )


def _enum_member_call_triggers_workers(
    receiver,
    method_name,
    methods,
    class_targets,
    reference_line,
):
    """Return True when EnumClass.MEMBER.method() reaches a risky hook."""
    class_name = receiver.value.id
    enum_members = class_targets[9] if len(class_targets) > 9 else set()
    return (
        (class_name, receiver.attr) in enum_members
        and _class_hook_is_active(
            class_targets,
            class_name,
            method_name,
            methods,
            reference_line,
        )
    )


def _attribute_call_triggers_workers(
    expr,
    methods,
    class_targets,
    instance_events,
    reference_line,
):
    """Return True for calls that reach proven mutating class hooks."""
    if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)):
        return False
    method_name = expr.func.attr
    receiver = expr.func.value
    if isinstance(receiver, ast.Name):
        return _name_receiver_call_triggers_workers(
            receiver,
            method_name,
            methods,
            class_targets,
            instance_events,
            reference_line,
        )
    if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Name):
        return _constructed_receiver_call_triggers_workers(
            receiver,
            method_name,
            methods,
            class_targets,
            reference_line,
        )
    if isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name):
        return _enum_member_call_triggers_workers(
            receiver,
            method_name,
            methods,
            class_targets,
            reference_line,
        )
    return False


def _attribute_access_triggers_workers(
    expr,
    properties,
    descriptor_fields,
    class_targets,
    instance_events,
    reference_line,
):
    """Return True for property/descriptor reads that execute a risky hook."""
    if not isinstance(expr, ast.Attribute):
        return False
    class_name = None
    instance_read = False
    if (
        isinstance(expr.value, ast.Call)
        and isinstance(expr.value.func, ast.Name)
    ):
        class_name = expr.value.func.id
        instance_read = True
    elif isinstance(expr.value, ast.Name):
        class_name = expr.value.id
    if class_name is None:
        return False
    get_fields = descriptor_fields.get("__get__", set())
    if instance_read and _class_hook_is_active(
        class_targets,
        class_name,
        expr.attr,
        properties,
        reference_line,
    ):
        return True
    if _class_hook_is_active(
        class_targets,
        class_name,
        expr.attr,
        get_fields,
        reference_line,
    ):
        return True
    if instance_read:
        return False
    class_attributes = class_targets[10] if len(class_targets) > 10 else None
    return _instance_hook_is_active(
        class_targets,
        instance_events,
        properties | get_fields,
        class_name,
        expr.attr,
        reference_line,
        class_attributes=class_attributes,
    )


def _class_subscript_triggers_workers(expr, class_targets):
    """Return True when Class[item] reaches a mutating __class_getitem__."""
    if not isinstance(expr, ast.Subscript) or not isinstance(expr.value, ast.Name):
        return False
    class_name = expr.value.id
    reference_line = getattr(expr, "lineno", 0)
    if not _class_binding_is_active(class_targets, class_name, reference_line):
        return False
    methods = class_targets[1]
    class_bases = class_targets[7] if len(class_targets) > 7 else {}
    class_methods = class_targets[8] if len(class_targets) > 8 else None
    return _class_hierarchy_defines_method(
        methods,
        class_bases,
        class_name,
        "__class_getitem__",
        class_methods,
    )


def _expression_triggers_class_workers_side_effect(expr, class_targets):
    """Return True when attribute access or construction runs a mutating class hook."""
    constructors, methods, properties = class_targets[:3]
    descriptor_fields = class_targets[5] if len(class_targets) > 5 else {}
    instance_events = class_targets[6] if len(class_targets) > 6 else {}
    reference_line = getattr(expr, 'lineno', 0)
    return (
        _class_subscript_triggers_workers(expr, class_targets)
        or _class_call_triggers_workers(expr, constructors, class_targets, reference_line)
        or _attribute_call_triggers_workers(
            expr,
            methods,
            class_targets,
            instance_events,
            reference_line,
        )
        or _attribute_access_triggers_workers(
            expr,
            properties,
            descriptor_fields,
            class_targets,
            instance_events,
            reference_line,
        )
    )



def _classdef_has_import_time_workers_side_effect(class_node, class_targets):
    """Return True when defining the class itself mutates ``workers``."""
    methods = class_targets[1]
    metaclass_definitions = class_targets[3]
    if class_node.name in metaclass_definitions:
        return True
    return any(
        isinstance(base, ast.Name) and (base.id, "__init_subclass__") in methods
        for base in class_node.bases
    )



def _map_argument_contains_module_namespace(arg, namespace_aliases):
    """Return True when one map iterable can yield the module namespace."""
    if _is_module_namespace_mapping(arg, namespace_aliases):
        return True
    return isinstance(arg, (ast.List, ast.Tuple)) and any(
        _is_module_namespace_mapping(element, namespace_aliases)
        for element in arg.elts
    )


def _call_is_map_lambda_namespace_update(call, operator_bindings):
    """Return True when map binds the module namespace to a mutating lambda arg."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    if not isinstance(call.func, ast.Name) or call.func.id != "map":
        return False
    lambda_node = call.args[0]
    if not isinstance(lambda_node, ast.Lambda):
        return False
    positional_params = (*lambda_node.args.posonlyargs, *lambda_node.args.args)
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    return any(
        _map_argument_contains_module_namespace(iterable, namespace_aliases)
        and _lambda_param_namespace_mutation(lambda_node.body, param.arg)
        for param, iterable in zip(positional_params, call.args[1:])
    )


def _dict_init_lambda_workers_effect(namespace_dict, operator_bindings):
    """Return the first ``__init__`` lambda effect, or None when absent."""
    if not isinstance(namespace_dict, ast.Dict):
        return None
    for key, value in zip(namespace_dict.keys, namespace_dict.values):
        if isinstance(key, ast.Constant) and key.value == "__init__":
            if isinstance(value, ast.Lambda):
                return _expression_mutates_workers(value.body, operator_bindings)
    return None


def _keyword_init_lambda_workers_effect(keywords, operator_bindings):
    """Return the first keyword ``__init__`` lambda effect, or None."""
    for keyword in keywords:
        if keyword.arg == "__init__" and isinstance(keyword.value, ast.Lambda):
            return _expression_mutates_workers(
                keyword.value.body,
                operator_bindings,
            )
    return None


def _call_is_type_constructor_side_effect(call, operator_bindings):
    """Return True for an immediately instantiated dynamic type with risky init."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Call):
        return False
    constructor = call.func
    func = constructor.func
    if not (isinstance(func, ast.Name) and func.id == "type"):
        return False
    namespace_dict = constructor.args[2] if len(constructor.args) >= 3 else None
    dict_effect = _dict_init_lambda_workers_effect(
        namespace_dict,
        operator_bindings,
    )
    if dict_effect is not None:
        return dict_effect
    keyword_effect = _keyword_init_lambda_workers_effect(
        constructor.keywords,
        operator_bindings,
    )
    return bool(keyword_effect)


def _partial_reduce_initializer(partial_call, invocation, invocation_start):
    """Resolve a reduce initializer bound by partial or supplied at invocation."""
    if len(partial_call.args) >= 4:
        return partial_call.args[3]
    for keyword in partial_call.keywords:
        if keyword.arg == "initial":
            return keyword.value
    bound_reduce_args = max(len(partial_call.args) - 1, 0)
    invocation_args = invocation.args[invocation_start:]
    initial_offset = 2 - bound_reduce_args
    if 0 <= initial_offset < len(invocation_args):
        return invocation_args[initial_offset]
    return next(
        (
            keyword.value
            for keyword in invocation.keywords
            if keyword.arg == "initial"
        ),
        None,
    )


def _call_is_partial_reduce_namespace_mutation(call, operator_bindings):
    """Return True for partial(reduce, ...) namespace mutations."""
    partial_aliases = operator_bindings[4] if len(operator_bindings) > 4 else set()
    reduce_aliases = operator_bindings[15] if len(operator_bindings) > 15 else set()
    functools_aliases = operator_bindings[14] if len(operator_bindings) > 14 else set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    partial_call, invocation_start = _resolve_partial_invocation(call, partial_aliases, builtin_shadow_lines)
    if partial_call is None or len(partial_call.args) < 2:
        return False
    first = partial_call.args[0]
    is_reduce = (isinstance(first, ast.Name) and first.id in reduce_aliases) or (
        isinstance(first, ast.Attribute)
        and first.attr == 'reduce'
        and isinstance(first.value, ast.Name)
        and first.value.id in functools_aliases
    )
    lambda_node = partial_call.args[1]
    if not is_reduce or not isinstance(lambda_node, ast.Lambda):
        return False
    initializer = _partial_reduce_initializer(partial_call, call, invocation_start)
    if initializer is None or not _is_module_namespace_mapping(initializer, namespace_aliases):
        return False
    lambda_args = lambda_node.args.args
    if not lambda_args:
        return False
    return _lambda_param_namespace_mutation(lambda_node.body, lambda_args[0].arg)



def _call_is_partial_operator_methodcaller_namespace_update(call, operator_bindings):
    """Return True for ``partial(methodcaller(...), globals())()`` mutations."""
    partial_aliases = operator_bindings[4] if len(operator_bindings) > 4 else set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    partial_call, _ = _resolve_partial_invocation(call, partial_aliases, builtin_shadow_lines)
    if partial_call is None or len(partial_call.args) < 2:
        return False
    if not _is_module_namespace_mapping(partial_call.args[1], namespace_aliases):
        return False
    factory = partial_call.args[0]
    if not isinstance(factory, ast.Call):
        return False
    return _call_is_operator_methodcaller_on_module_namespace(
        ast.Call(func=factory, args=[partial_call.args[1]], keywords=[]),
        operator_bindings,
        namespace_aliases,
    )



def _reduce_lambda_argument(call):
    """Return the first reduce lambda argument when present."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    lambda_node = call.args[0]
    return lambda_node if isinstance(lambda_node, ast.Lambda) else None


def _is_known_reduce_callable(func, functools_aliases, reduce_aliases):
    """Return True for a proven direct or module-qualified reduce callable."""
    if isinstance(func, ast.Name):
        return func.id in reduce_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "reduce"
        and isinstance(func.value, ast.Name)
        and func.value.id in functools_aliases
    )


def _reduce_initializer(call):
    """Return the positional or keyword reduce initializer."""
    if len(call.args) >= 3:
        return call.args[2]
    return next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg == "initial"
        ),
        None,
    )


def _call_is_known_reduce_lambda_mutation(call, operator_bindings):
    """Return True when a known ``functools.reduce`` invocation runs a risky lambda."""
    lambda_node = _reduce_lambda_argument(call)
    if lambda_node is None:
        return False
    functools_aliases = operator_bindings[14] if len(operator_bindings) > 14 else set()
    reduce_aliases = operator_bindings[15] if len(operator_bindings) > 15 else set()
    if not _is_known_reduce_callable(
        call.func,
        functools_aliases,
        reduce_aliases,
    ):
        return False
    if _lambda_mutates_workers(lambda_node, operator_bindings):
        return True
    if _reduce_lambda_invokes_mutating_iterable_callback(
        call,
        operator_bindings,
    ):
        return True
    initializer = _reduce_initializer(call)
    if initializer is None:
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if not _is_module_namespace_mapping(initializer, namespace_aliases):
        return False
    lambda_args = lambda_node.args.args
    if not lambda_args:
        return False
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    return _lambda_param_namespace_mutation(
        lambda_node.body,
        lambda_args[0].arg,
        dict_shadow_line,
    )


def _call_has_primary_worker_mutation(expr, operator_bindings):
    """Check the core exec/operator/namespace worker mutation forms."""
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    exec_eval_shadow_lines = operator_bindings[9] if len(operator_bindings) > 9 else {}
    direct_exec_eval_aliases = operator_bindings[10] if len(operator_bindings) > 10 else set()
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else set()
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    direct_exec_eval_alias_events = operator_bindings[18] if len(operator_bindings) > 18 else {}
    importlib_alias_events = operator_bindings[19] if len(operator_bindings) > 19 else {}
    importlib_module_aliases = operator_bindings[24] if len(operator_bindings) > 24 else set()
    return (
        _call_is_dynamic_exec_eval(
            expr,
            builtins_aliases,
            exec_eval_shadow_lines,
            direct_exec_eval_aliases,
            importlib_aliases,
            direct_exec_eval_alias_events,
            importlib_alias_events,
            importlib_module_aliases,
            sys_aliases,
            operator_bindings,
        )
        or _call_is_operator_methodcaller_exec_on_builtins(expr, operator_bindings)
        or _call_is_module_namespace_workers_update(expr, namespace_aliases)
        or _call_is_module_namespace_workers_ior(expr, namespace_aliases)
        or _call_is_getattr_namespace_workers_mutation(
            expr,
            namespace_aliases,
            mutator_aliases,
        )
        or _call_is_getattr_proven_frame_globals_mutation(expr, operator_bindings)
        or _call_is_operator_namespace_ior(expr, operator_bindings)
        or _call_is_getattr_operator_namespace_mutation(expr, operator_bindings)
        or _call_is_operator_attrgetter_namespace_mutation(expr, operator_bindings)
        or _call_is_operator_attrgetter_on_proven_frame_globals(
            expr,
            operator_bindings,
        )
        or _call_is_partial_bound_workers_setitem(expr, operator_bindings)
        or _call_is_known_reduce_lambda_mutation(expr, operator_bindings)
    )


def _call_is_functiontype_namespace_alias(expr, aliases):
    """Return True when a saved FunctionType namespace callable is invoked."""
    return isinstance(expr.func, ast.Name) and expr.func.id in aliases


def _call_has_secondary_worker_mutation(
    expr,
    operator_bindings,
    dict_subclass_names=None,
    bound_names=None,
):
    """Check extended FunctionType/ChainMap/partial mutation forms."""
    if dict_subclass_names is None:
        dict_subclass_names = set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    delegated_update_aliases = operator_bindings[17] if len(operator_bindings) > 17 else set()
    delegated_update_alias_events = operator_bindings[20] if len(operator_bindings) > 20 else {}
    functiontype_namespace_aliases = operator_bindings[22] if len(operator_bindings) > 22 else set()
    types_module_aliases = operator_bindings[25] if len(operator_bindings) > 25 else set()
    functiontype_aliases = operator_bindings[26] if len(operator_bindings) > 26 else set()
    chainmap_aliases = operator_bindings[28] if len(operator_bindings) > 28 else set()
    return (
        _call_is_inspect_currentframe_globals_update(expr, operator_bindings)
        or _call_is_inspect_currentframe_globals_ior(expr, operator_bindings)
        or _call_is_invoked_functiontype_namespace_code(expr, namespace_aliases, types_module_aliases, functiontype_aliases)
        or _call_is_functiontype_namespace_alias(expr, functiontype_namespace_aliases)
        or _call_mutates_workers_via_indirection(expr, operator_bindings)
        or _call_is_chainmap_maps_update(expr, namespace_aliases, chainmap_aliases)
        or _call_is_delegated_simplenamespace_update(expr, delegated_update_aliases, delegated_update_alias_events)
        or _call_is_operator_call_namespace_update(expr, operator_bindings, bound_names)
        or _call_has_mutating_lambda_argument(expr, operator_bindings, bound_names)
        or _call_is_type_constructor_side_effect(expr, operator_bindings)
        or _call_is_partial_reduce_namespace_mutation(expr, operator_bindings)
        or _call_is_partial_operator_methodcaller_namespace_update(expr, operator_bindings)
        or _call_is_dict_subclass_update_on_module_namespace(expr, namespace_aliases, dict_subclass_names)
        or _call_is_literal_callback_invocation(expr, operator_bindings)
        or _call_is_operator_call_mutating_callback(expr, operator_bindings, bound_names)
        or _call_is_partial_mutating_callback_invocation(expr, operator_bindings)
        or _call_is_exit_stack_callback_mutation(expr, operator_bindings)
        or _call_is_weakref_finalize_mutation(
            expr,
            operator_bindings,
            bound_names,
        )
        or _call_is_warnings_warn_after_mutating_hook(expr, operator_bindings)
    )



def _call_expression_mutates_workers(
    expr,
    operator_bindings,
    dict_subclass_names=None,
    bound_names=None,
):
    """Return True when one call expression can mutate module workers."""
    return (
        _call_consumes_mutating_generator(
            expr,
            operator_bindings,
            bound_names,
        )
        or _call_has_primary_worker_mutation(
            expr,
            operator_bindings,
        )
        or _call_has_secondary_worker_mutation(
            expr,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
    )



def _expression_consumes_mutating_lazy_iterator(expr, operator_bindings):
    """Return True for eager expression forms that consume a risky lazy iterator."""
    if isinstance(expr, ast.Starred) and isinstance(expr.ctx, ast.Load):
        return _expression_is_mutating_lazy_iterator(
            expr.value,
            operator_bindings,
        )
    if isinstance(expr, (ast.ListComp, ast.SetComp, ast.DictComp)):
        return any(
            _expression_is_mutating_lazy_iterator(
                generator.iter,
                operator_bindings,
            )
            for generator in expr.generators
        )
    return False


def _expression_mutates_workers(
    expr,
    operator_bindings,
    dict_subclass_names=None,
    bound_names=None,
):
    """Return True when an evaluated expression mutates ``workers`` indirectly."""
    if isinstance(expr, ast.Lambda):
        # A lambda body only runs when the lambda is called, but its default
        # arguments are evaluated while the lambda object is created.
        return any(
            _expression_mutates_workers(
                expression,
                operator_bindings,
                dict_subclass_names,
                bound_names,
            )
            for expression in _definition_time_expressions(expr)
        )
    if _expression_consumes_mutating_lazy_iterator(expr, operator_bindings):
        return True
    if _comprehension_invokes_mutating_callback(expr, operator_bindings):
        return True
    if isinstance(expr, ast.Call) and _call_expression_mutates_workers(
        expr,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    ):
        return True
    return any(
        _expression_mutates_workers(
            child,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
        for child in ast.iter_child_nodes(expr)
    )





def _lambda_bound_names(lambda_node):
    """Return parameter names that shadow globals inside a lambda body."""
    args = lambda_node.args
    names = {
        arg.arg
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    }
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _lambda_mutates_workers(lambda_node, operator_bindings):
    """Return True when an invoked lambda body mutates ``workers`` indirectly."""
    if not isinstance(lambda_node, ast.Lambda):
        return False
    if _expression_has_risky_instance_update(
        lambda_node.body,
        _lambda_bound_names(lambda_node),
    ):
        return True
    return _expression_mutates_workers(
        lambda_node.body,
        operator_bindings,
        bound_names=_lambda_bound_names(lambda_node),
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

def _call_has_direct_worker_indirection(call, operator_bindings):
    """Return True for non-lambda indirect namespace mutation calls."""
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    mutator_aliases = operator_bindings[5] if len(operator_bindings) > 5 else {}
    dict_update_aliases = operator_bindings[7] if len(operator_bindings) > 7 else set()
    sys_aliases = operator_bindings[13] if len(operator_bindings) > 13 else {'sys'}
    importlib_aliases = operator_bindings[16] if len(operator_bindings) > 16 else set()
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_ior_aliases = operator_bindings[23] if len(operator_bindings) > 23 else set()
    importlib_module_aliases = operator_bindings[24] if len(operator_bindings) > 24 else set()
    return (
        _call_sets_workers_via_setitem(call)
        or _call_is_namespace_setdefault_workers(call, namespace_aliases)
        or _call_is_getattr_setdefault_workers(call, namespace_aliases)
        or _call_is_operator_setitem_workers(call, operator_bindings)
        or _call_is_getattr_setitem_workers(call)
        or _call_is_dict_type_setitem_on_module_namespace(call, namespace_aliases, dict_shadow_line)
        or _call_is_dict_type_setitem_on_proven_frame_globals(call, operator_bindings)
        or _call_sets_workers_attribute(call, sys_aliases, importlib_aliases, importlib_module_aliases)
        or _call_is_dict_type_update_on_module_namespace(
            call,
            namespace_aliases,
            dict_update_aliases,
            dict_shadow_line,
            operator_bindings,
        )
        or _call_is_dict_type_ior_on_module_namespace(call, namespace_aliases, dict_shadow_line, dict_ior_aliases)
        or _call_is_importlib_sys_namespace_mutation(call, operator_bindings)
        or _call_is_subscript_namespace_workers_update(call, namespace_aliases, mutator_aliases)
        or _call_is_operator_methodcaller_on_module_namespace(call, operator_bindings, namespace_aliases)
        or _call_is_operator_methodcaller_on_proven_frame_globals(
            call,
            operator_bindings,
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

def _call_mutates_workers_via_indirection(call, operator_bindings):
    """Return True for indirect import-time ``workers`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    if _call_has_direct_worker_indirection(call, operator_bindings):
        return True
    return _lambda_invocation_mutates_workers(call, operator_bindings)





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



def _import_from_binds_workers(node):
    """Return True when an import statement may define ``workers`` indirectly."""
    if not isinstance(node, ast.ImportFrom):
        return False
    return any(
        alias.name == "*" or (alias.asname or alias.name) == "workers"
        for alias in node.names
    )


def _namespace_workers_removal(node, operator_bindings=None):
    """Return True for a call that empties the module ``workers`` name.

    ``pop('workers')`` names the key directly, while ``popitem()``, ``clear()``
    and ``__delitem__('workers')`` drop the binding it refers to, so all of
    them leave Gunicorn without a ``workers`` setting to install.
    """
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    namespace_aliases = (
        operator_bindings[2]
        if operator_bindings is not None and len(operator_bindings) > 2
        else set()
    )
    receiver = node.func.value
    if not (
        _globals_name_is_unshadowed_at(receiver, operator_bindings)
        and _is_module_namespace_mapping(receiver, namespace_aliases)
    ):
        return False
    method = node.func.attr
    if method in ("popitem", "clear"):
        return True
    return (
        method in ("pop", "__delitem__")
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "workers"
    )


def _statement_removes_namespace_workers(node, operator_bindings=None):
    """Return True when a statement removes ``workers`` via the namespace mapping.

    Unlike a bare ``del workers``, a removal through ``globals()`` names the
    module namespace directly, so it applies from any function scope.
    """
    if isinstance(node, ast.Delete):
        return any(
            _globals_workers_subscript(target, operator_bindings)
            for target in node.targets
        )
    if isinstance(node, ast.Expr):
        return _namespace_workers_removal(node.value, operator_bindings)
    return False


def _workers_binding_removal(node, operator_bindings=None):
    """Return True when a statement removes the module ``workers`` name.

    Gunicorn installs only the names present in the module namespace
    (``if k not in self.cfg.settings: continue`` in
    ``Application.load_config_from_module_name_or_filename``), so once
    ``workers`` is gone the setting keeps its ``WEB_CONCURRENCY`` default
    instead of the value a previous assignment left behind.
    """
    if isinstance(node, ast.Delete):
        return any(
            _target_assigns_workers(target)
            or _globals_workers_subscript(target, operator_bindings)
            for target in node.targets
        )
    if isinstance(node, ast.Expr):
        return _namespace_workers_removal(node.value, operator_bindings)
    return False


def _worker_assignment_value(node, operator_bindings=None):
    """Return whether node assigns workers and its static value when available."""
    if _workers_binding_removal(node, operator_bindings):
        return True, None
    if isinstance(node, ast.Assign):
        targets_workers = any(
            _target_assigns_workers(target)
            or _globals_workers_subscript(target, operator_bindings)
            for target in node.targets
        )
        if not targets_workers:
            return False, None
        return True, _static_int_from_ast(node.value)

    if isinstance(node, ast.AnnAssign) and node.target and (
        _target_assigns_workers(node.target)
        or _globals_workers_subscript(node.target, operator_bindings)
    ):
        return True, _static_int_from_ast(node.value)

    if isinstance(node, ast.AugAssign) and (
        _target_assigns_workers(node.target)
        or _globals_workers_subscript(node.target, operator_bindings)
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



def _statement_consumes_mutating_lazy_iterator(node, operator_bindings):
    """Return True when a loop eagerly advances a risky lazy iterator."""
    return isinstance(node, (ast.For, ast.AsyncFor)) and (
        _expression_is_mutating_lazy_iterator(
            node.iter,
            operator_bindings,
        )
    )


def _match_guard_mutates_workers(
    node,
    operator_bindings,
    dict_subclass_names,
    bound_names=None,
):
    """Return True when a ``match`` guard mutates ``workers``."""
    if not isinstance(node, ast.Match):
        return False
    return any(
        case.guard is not None
        and _expression_mutates_workers(
            case.guard,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
        for case in node.cases
    )


def _static_sequence_length(node):
    """Return the length of a statically known sequence subject."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return len(node.elts)
    return None


def _expression_is_statically_false(expr):
    """Return True only when an expression is provably false without execution."""
    try:
        return not bool(ast.literal_eval(expr))
    except (ValueError, TypeError):
        return False


def _match_case_invokes_mutating_callback(
    case,
    subject,
    subject_holds_mutating_callbacks,
):
    """Return True when a reachable match case calls a bound mutating callback."""
    if not subject_holds_mutating_callbacks:
        return False
    if case.guard is not None and _expression_is_statically_false(case.guard):
        return False
    if not (
        isinstance(case.pattern, ast.MatchSequence)
        and len(case.pattern.patterns) == 1
        and isinstance(case.pattern.patterns[0], ast.MatchAs)
    ):
        return False
    subject_length = _static_sequence_length(subject)
    if subject_length is not None and subject_length != 1:
        return False
    capture = case.pattern.patterns[0].name
    if capture is None:
        return False
    return any(
        _statement_zero_arg_calls_name(stmt, capture) for stmt in case.body
    )


def _compound_statement_body_mutates_workers(
    node,
    operator_bindings,
    dict_subclass_names,
    bound_names=None,
):
    """Return True when a compound statement body performs import-time mutations."""
    if isinstance(node, ast.Match):
        subject_holds_mutating_callbacks = (
            _iter_expression_holds_mutating_callbacks(
                node.subject,
                operator_bindings,
            )
        )
        if any(
            _match_case_invokes_mutating_callback(
                case,
                node.subject,
                subject_holds_mutating_callbacks,
            )
            for case in node.cases
        ):
            return True
        bodies = [case.body for case in node.cases]
    elif isinstance(node, ast.While):
        bodies = [node.body]
    elif isinstance(node, ast.Try):
        bodies = [node.body, node.orelse, node.finalbody]
        bodies.extend(handler.body for handler in node.handlers)
    else:
        return False
    return any(
        _is_dynamic_workers_mutation(
            stmt,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
        for body in bodies
        for stmt in body
    )


def _node_or_child_expression_mutates_workers(
    node,
    operator_bindings,
    dict_subclass_names,
    bound_names,
):
    """Return True when an expression node or one of its expression children mutates workers."""
    return any(
        isinstance(child, ast.expr)
        and _expression_mutates_workers(
            child,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
        for child in ast.iter_child_nodes(node)
    ) or (
        isinstance(node, ast.expr)
        and _expression_mutates_workers(
            node,
            operator_bindings,
            dict_subclass_names,
            bound_names,
        )
    )


def _is_dynamic_workers_mutation(
    node,
    operator_bindings,
    dict_subclass_names=None,
    bound_names=None,
):
    """Return True for import-time mutations the AST scan cannot treat as static."""
    if dict_subclass_names is None:
        dict_subclass_names = set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if _namespace_mapping_may_gain_workers_via_merge(node, namespace_aliases):
        return True
    if _for_loop_invokes_mutating_callback(node, operator_bindings):
        return True
    if _for_loop_inspect_stack_body_mutates_workers(node, operator_bindings):
        return True
    if _statement_consumes_mutating_lazy_iterator(node, operator_bindings):
        return True
    if _compound_statement_body_mutates_workers(
        node,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    ):
        return True
    if _node_or_child_expression_mutates_workers(
        node,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    ):
        # A definition-time expression such as exec("workers = 2") can
        # arrive here as the bare call, while statement nodes expose the call
        # through their expression children.
        return True
    if isinstance(node, ast.Assign):
        if _assign_mutates_proven_frame_globals_workers(node, operator_bindings):
            return True
        return any(
            _indirect_workers_assignment_target(target)
            for target in node.targets
        )
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        if _indirect_workers_assignment_target(node.target):
            return True
        return _augassign_mutates_proven_frame_globals(node, operator_bindings)
    return _match_guard_mutates_workers(
        node,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    )


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
    if not func_names:
        return False
    if isinstance(expr, ast.Lambda):
        # A lambda body only runs when the lambda is called, but its default
        # arguments are evaluated while the lambda object is created.
        return any(
            _expression_invokes_function(default, func_names)
            for default in _definition_time_expressions(expr)
        )
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
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return any(
            _expression_invokes_function(item.context_expr, func_names)
            for item in node.items
        )
    return any(
        isinstance(child, ast.expr)
        and _expression_invokes_function(child, func_names)
        for child in ast.iter_child_nodes(node)
    )


def _expression_has_class_workers_side_effect(expr, class_targets):
    """Recursively inspect evaluated expressions without entering lambda scopes."""
    if isinstance(expr, ast.Lambda):
        return False
    if _comprehension_hook_write_triggers_workers(expr, class_targets):
        return True
    if _expression_triggers_class_workers_side_effect(expr, class_targets):
        return True
    return any(
        _expression_has_class_workers_side_effect(child, class_targets)
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.AST)
    )


def _attribute_hook_write_triggers_workers(
    expr,
    hook_fields,
    class_targets,
    instance_events,
    reference_line,
):
    """Return True when an assignment/deletion target reaches a mutating hook."""
    if not isinstance(expr, ast.Attribute):
        return False
    class_name = None
    instance_write = False
    if (
        isinstance(expr.value, ast.Call)
        and isinstance(expr.value.func, ast.Name)
    ):
        class_name = expr.value.func.id
        instance_write = True
    elif isinstance(expr.value, ast.Name):
        class_name = expr.value.id
    if class_name is None:
        return False
    if _class_hook_is_active(
        class_targets,
        class_name,
        expr.attr,
        hook_fields,
        reference_line,
    ):
        return True
    if instance_write:
        return False
    return _instance_hook_is_active(
        class_targets,
        instance_events,
        hook_fields,
        class_name,
        expr.attr,
        reference_line,
    )


def _target_hook_write_triggers_workers(
    target,
    hook_fields,
    class_targets,
    instance_events,
):
    """Return True when one assignment/deletion target tree reaches a hook."""
    if isinstance(target, ast.Attribute):
        return _attribute_hook_write_triggers_workers(
            target,
            hook_fields,
            class_targets,
            instance_events,
            getattr(target, "lineno", 0),
        )
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(
            _target_hook_write_triggers_workers(
                element,
                hook_fields,
                class_targets,
                instance_events,
            )
            for element in target.elts
        )
    if isinstance(target, ast.Starred):
        return _target_hook_write_triggers_workers(
            target.value,
            hook_fields,
            class_targets,
            instance_events,
        )
    return False


def _comprehension_hook_write_triggers_workers(expr, class_targets):
    """Return True when a comprehension target invokes a mutating hook."""
    if not isinstance(expr, ast.comprehension):
        return False
    descriptor_fields = class_targets[5] if len(class_targets) > 5 else {}
    hook_fields = descriptor_fields.get("__set__", set())
    if not hook_fields:
        return False
    instance_events = class_targets[6] if len(class_targets) > 6 else {}
    return _target_hook_write_triggers_workers(
        expr.target,
        hook_fields,
        class_targets,
        instance_events,
    )


def _statement_hook_write_triggers_workers(node, class_targets):
    """Return True when a statement's assignment/deletion targets run a hook."""
    if isinstance(node, ast.Delete):
        targets = node.targets
        hook = "__delete__"
    elif isinstance(node, ast.Assign):
        targets = node.targets
        hook = "__set__"
    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
        if isinstance(node, ast.AnnAssign) and node.value is None:
            return False
        targets = [node.target]
        hook = "__set__"
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        targets = [node.target]
        hook = "__set__"
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        targets = [
            item.optional_vars
            for item in node.items
            if item.optional_vars is not None
        ]
        hook = "__set__"
    else:
        return False
    descriptor_fields = class_targets[5] if len(class_targets) > 5 else {}
    hook_fields = descriptor_fields.get(hook, set())
    if not hook_fields:
        return False
    instance_events = class_targets[6] if len(class_targets) > 6 else {}
    return any(
        _target_hook_write_triggers_workers(
            target,
            hook_fields,
            class_targets,
            instance_events,
        )
        for target in targets
    )


def _statement_has_class_workers_side_effect(node, class_targets):
    """Return True when an evaluated statement expression invokes a risky class hook."""
    if not class_targets or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if _statement_hook_write_triggers_workers(node, class_targets):
        return True
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return any(
            _expression_has_class_workers_side_effect(item.context_expr, class_targets)
            for item in node.items
        )
    return any(
        isinstance(child, ast.expr)
        and _expression_has_class_workers_side_effect(child, class_targets)
        for child in ast.iter_child_nodes(node)
    )



def _statement_mutates_workers(
    node,
    operator_bindings,
    *,
    global_workers,
    mutator_names,
    class_targets=None,
    dict_subclass_names=None,
    bound_names=None,
):
    """Return True when one statement may mutate the module ``workers`` binding."""
    if _statement_invokes_function(node, mutator_names):
        return True
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if _statement_has_class_workers_side_effect(node, class_targets):
        return True
    if _is_dynamic_workers_mutation(
        node,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    ):
        return True
    assigns_workers, _ = _worker_assignment_value(node, operator_bindings)
    if global_workers and assigns_workers:
        return True
    if _statement_removes_namespace_workers(node, operator_bindings):
        # ``globals()`` names the module namespace from any function scope, so a
        # removal through it needs no ``global workers`` declaration to apply.
        return True
    return any(
        _statements_mutate_workers(
            block,
            operator_bindings,
            global_workers=global_workers,
            mutator_names=mutator_names,
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
            bound_names=bound_names,
        )
        for block in _compound_statement_blocks(node)
    )



def _statements_mutate_workers(
    statements,
    operator_bindings,
    *,
    global_workers=False,
    mutator_names=None,
    class_targets=None,
    dict_subclass_names=None,
    bound_names=None,
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
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
            bound_names=bound_names,
        )
        for node in statements
    )



def _function_argument_bound_names(func_node):
    """Return names bound by a function's arguments."""
    args = func_node.args
    names = {
        arg.arg
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
    }
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _statement_scope_bound_names(node):
    """Return names bound directly by one statement in the current scope."""
    names = {
        name
        for name, _value in _namespace_assignment_values(node)
    }
    if isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_loop_target_names(node.target))
    if isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_loop_target_names(item.optional_vars))
    if isinstance(node, ast.ExceptHandler) and node.name:
        names.add(node.name)
    return names


def _function_scope_node_bindings(node):
    """Return local/global bindings and whether to inspect child nodes."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}, set(), False
    if isinstance(node, ast.Lambda):
        return set(), set(), False
    if isinstance(node, ast.Global):
        return set(), set(node.names), False
    if isinstance(node, ast.Nonlocal):
        return set(node.names), set(), False
    return _statement_scope_bound_names(node), set(), True


def _function_local_bound_names(func_node):
    """Return names bound by one function's own scope, excluding nested scopes."""
    names = _function_argument_bound_names(func_node)
    module_names = set()
    stack = list(func_node.body)
    while stack:
        node = stack.pop()
        local_names, global_names, inspect_children = _function_scope_node_bindings(node)
        names.update(local_names)
        module_names.update(global_names)
        if inspect_children:
            stack.extend(ast.iter_child_nodes(node))
    return names - module_names


def _function_mutates_workers(
    func_node,
    operator_bindings,
    mutator_names=None,
    class_targets=None,
    dict_subclass_names=None,
):
    """Return True when a function may mutate the module ``workers`` binding."""
    if _statements_start_mutating_thread(
        func_node.body,
        operator_bindings,
        mutator_names,
    ):
        return True
    has_global_workers = _statements_declare_global_workers(func_node.body)
    return _statements_mutate_workers(
        func_node.body,
        operator_bindings,
        global_workers=has_global_workers,
        mutator_names=mutator_names,
        class_targets=class_targets,
        dict_subclass_names=dict_subclass_names,
        bound_names=_function_local_bound_names(func_node),
    )



def _call_invokes_function(call_node, func_names):
    """Return True when ``call_node`` invokes one of ``func_names``."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id in func_names
    return False


def _collect_import_time_workers_mutators(
    tree,
    operator_bindings,
    class_targets=None,
    dict_subclass_names=None,
):
    """Return function names that may mutate ``workers`` when called at import time.

    Definitions nested inside another function are collected too, because a
    top-level helper that calls a nested one is only known to mutate once the
    nested name is in the fixpoint. A name counts as a mutator when *any* of
    its definitions mutates, since a nested definition can shadow a
    module-level one of the same name.
    """
    functions = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
    mutators = set()
    changed = True
    while changed:
        changed = False
        for name, nodes in functions.items():
            if name in mutators:
                continue
            if any(
                _function_mutates_workers(
                    node,
                    operator_bindings,
                    mutators,
                    class_targets,
                    dict_subclass_names,
                )
                for node in nodes
            ):
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

    def clear_workers_assignment(self) -> None:
        """Forget a static count that a later removal of ``workers`` invalidated."""
        self.found = False
        self.count = 1

    def record_workers_assignment(self, value, *, in_compound: bool) -> None:
        self.found = True
        if in_compound or value is None or value < 1:
            self.dynamic = True
        elif not self.dynamic:
            self.count = value


def _sync_callback_tracking(scan_state):
    """Return source-ordered tracking state for synchronous callback containers."""
    tracking = getattr(scan_state, "_sync_callback_tracking", None)
    if tracking is None:
        tracking = {
            "queue_modules": set(),
            "collections_modules": set(),
            "sched_modules": set(),
            "heapq_modules": set(),
            "queue_constructors": set(),
            "deque_constructors": set(),
            "userlist_constructors": set(),
            "containers": {},
            "mutating": set(),
            "mutating_subscript_indexes": {},
            "sched_event_ids": {},
            "sched_pending_events": {},
            "next_sched_event_id": 1,
        }
        scan_state._sync_callback_tracking = tracking
    return tracking


def _simple_assignment_names(node):
    """Return simple names definitely rebound by one assignment statement."""
    targets = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    elif isinstance(node, ast.NamedExpr):
        targets = [node.target]
    names = set()
    for target in targets:
        if isinstance(target, ast.Name):
            names.add(target.id)
    return names


def _record_sync_callback_module_imports(node, tracking):
    """Track queue and collections module aliases."""
    destinations = {
        "queue": tracking["queue_modules"],
        "collections": tracking["collections_modules"],
        "sched": tracking["sched_modules"],
        "heapq": tracking["heapq_modules"],
    }
    for imported in node.names:
        destination = destinations.get(imported.name)
        if destination is not None:
            destination.add(imported.asname or imported.name)


def _record_sync_callback_direct_imports(node, tracking):
    """Track direct callback-container constructor aliases."""
    if node.module == "collections":
        destinations = {
            "deque": tracking["deque_constructors"],
            "UserList": tracking["userlist_constructors"],
        }
        for imported in node.names:
            destination = destinations.get(imported.name)
            if destination is not None:
                destination.add(imported.asname or imported.name)
        return
    if node.module != "queue":
        return
    queue_names = {"Queue", "LifoQueue", "PriorityQueue", "SimpleQueue"}
    for imported in node.names:
        if imported.name in queue_names:
            tracking["queue_constructors"].add(imported.asname or imported.name)


def _record_sync_callback_imports(node, tracking):
    """Track queue/deque constructor aliases used for callback containers."""
    if isinstance(node, ast.Import):
        _record_sync_callback_module_imports(node, tracking)
    elif isinstance(node, ast.ImportFrom):
        _record_sync_callback_direct_imports(node, tracking)


def _sync_callback_named_constructor_kind(func, tracking):
    """Return the callback-container kind for a directly imported constructor."""
    constructor_groups = (
        ("queue", tracking["queue_constructors"]),
        ("deque", tracking["deque_constructors"]),
        ("userlist", tracking["userlist_constructors"]),
    )
    for kind, constructors in constructor_groups:
        if func.id in constructors:
            return kind
    return None


def _sync_callback_attribute_constructor_kind(func, tracking):
    """Return the callback-container kind for a module-qualified constructor."""
    module_name = func.value.id
    constructor_name = func.attr
    constructor_groups = (
        (
            tracking["queue_modules"],
            {"Queue", "LifoQueue", "PriorityQueue", "SimpleQueue"},
            "queue",
        ),
        (tracking["collections_modules"], {"deque"}, "deque"),
        (tracking["collections_modules"], {"UserList"}, "userlist"),
        (tracking["sched_modules"], {"scheduler"}, "sched"),
    )
    for module_aliases, constructor_names, kind in constructor_groups:
        if module_name in module_aliases and constructor_name in constructor_names:
            return kind
    return None


def _sync_callback_constructor_kind(value, tracking):
    """Return the proven callback-container kind created by an expression."""
    if isinstance(value, ast.List):
        return "list"
    if isinstance(value, (ast.Tuple, ast.Set)):
        return "literal"
    if not isinstance(value, ast.Call):
        return None
    func = value.func
    if isinstance(func, ast.Name):
        return _sync_callback_named_constructor_kind(func, tracking)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return _sync_callback_attribute_constructor_kind(func, tracking)
    return None


def _sync_callback_value_contains_mutating_lambda(value, operator_bindings):
    """Return True when a new container starts with a workers-mutating callback."""
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return _iterable_literal_contains_mutating_lambda(value, operator_bindings)
    if isinstance(value, ast.Call) and value.args:
        return _iterable_literal_contains_mutating_lambda(
            value.args[0],
            operator_bindings,
        )
    return False


def _sync_callback_assignment_source_state(value, tracking):
    """Return tracked state copied from a simple callback-container alias."""
    if not isinstance(value, ast.Name):
        return None, False, set()
    return (
        tracking["containers"].get(value.id),
        value.id in tracking["mutating"],
        set(tracking["mutating_subscript_indexes"].get(value.id, ())),
    )


def _assignment_creates_callback_iterator(value, operator_bindings):
    """Return True when an assignment creates a mutating callback iterator."""
    return (
        isinstance(value, ast.Call)
        and _builtin_call_is_active(value, "iter", operator_bindings)
        and len(value.args) == 1
        and not value.keywords
        and _iter_expression_holds_mutating_callbacks(
            value.args[0],
            operator_bindings,
        )
    )


def _sync_callback_assignment_kind(
    value,
    existing_kind,
    tracking,
    operator_bindings,
):
    """Resolve the callback-container kind assigned by one statement."""
    if _assignment_creates_callback_iterator(value, operator_bindings):
        return "callback_iter"
    return existing_kind or _sync_callback_constructor_kind(value, tracking)


def _sync_callback_assignment_starts_mutating(
    value,
    kind,
    existing_mutating,
    operator_bindings,
):
    """Return True when the assigned callback container is mutating."""
    return existing_mutating or (
        kind is not None
        and (
            kind == "callback_iter"
            or _sync_callback_value_contains_mutating_lambda(
                value,
                operator_bindings,
            )
        )
    )


def _clear_sync_callback_name_tracking(name, tracking):
    """Clear stale callback-container state after a definite rebinding."""
    tracking["containers"].pop(name, None)
    tracking["mutating"].discard(name)
    tracking["queue_modules"].discard(name)
    tracking["collections_modules"].discard(name)
    tracking["sched_modules"].discard(name)
    tracking["heapq_modules"].discard(name)
    tracking["queue_constructors"].discard(name)
    tracking["deque_constructors"].discard(name)
    tracking["userlist_constructors"].discard(name)
    tracking["mutating_subscript_indexes"].pop(name, None)
    tracking["sched_event_ids"].pop(name, None)
    if name in tracking["sched_pending_events"]:
        tracking["sched_pending_events"].pop(name, None)
        tracking["sched_event_ids"] = {
            event_name: event_data
            for event_name, event_data in tracking["sched_event_ids"].items()
            if event_data[0] != name
        }


def _apply_sync_callback_assignment(
    name,
    tracking,
    kind,
    starts_mutating,
    existing_subscript_indexes,
):
    """Apply resolved callback-container state to one assigned name."""
    _clear_sync_callback_name_tracking(name, tracking)
    if kind is None:
        return
    tracking["containers"][name] = kind
    if starts_mutating:
        tracking["mutating"].add(name)
    if existing_subscript_indexes:
        tracking["mutating_subscript_indexes"][name] = set(
            existing_subscript_indexes
        )


def _record_sync_callback_assignment(node, tracking, operator_bindings):
    """Track proven callback-container instances and definite rebindings."""
    names = _simple_assignment_names(node)
    if not names:
        return

    value = (
        node.value
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        else None
    )
    (
        existing_kind,
        existing_mutating,
        existing_subscript_indexes,
    ) = _sync_callback_assignment_source_state(value, tracking)
    kind = _sync_callback_assignment_kind(
        value,
        existing_kind,
        tracking,
        operator_bindings,
    )
    starts_mutating = _sync_callback_assignment_starts_mutating(
        value,
        kind,
        existing_mutating,
        operator_bindings,
    )

    for name in names:
        _apply_sync_callback_assignment(
            name,
            tracking,
            kind,
            starts_mutating,
            existing_subscript_indexes,
        )


def _statement_value_expression(node):
    """Return the import-time expression directly executed by a statement."""
    if isinstance(node, ast.Expr):
        return node.value
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return node.value
    return None


def _mutating_lambda_subscript_indexes(payload, operator_bindings):
    """Return literal indexes whose callback mutates workers."""
    if not isinstance(payload, (ast.Tuple, ast.List)):
        return set()
    indexes = set()
    length = len(payload.elts)
    for index, element in enumerate(payload.elts):
        if isinstance(element, ast.Lambda) and _lambda_mutates_workers(
            element,
            operator_bindings,
        ):
            indexes.add(index)
            indexes.add(index - length)
    return indexes


def _record_heapq_heappush_mutating_callback(node, tracking, operator_bindings):
    """Track list heaps that receive a workers-mutating callback via heapq.heappush."""
    expr = _statement_value_expression(node)
    if not (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "heappush"
        and isinstance(expr.func.value, ast.Name)
        and expr.func.value.id in tracking["heapq_modules"]
        and len(expr.args) >= 2
    ):
        return
    receiver = expr.args[0]
    payload = expr.args[1]
    if not isinstance(receiver, ast.Name) or not isinstance(
        payload,
        (ast.Tuple, ast.List),
    ):
        return
    indexes = _mutating_lambda_subscript_indexes(
        payload,
        operator_bindings,
    )
    if not indexes:
        return
    tracking["containers"][receiver.id] = "heap"
    tracking["mutating"].add(receiver.id)
    tracking["mutating_subscript_indexes"].setdefault(
        receiver.id,
        set(),
    ).update(indexes)


def _sync_callback_direct_insert_argument(expr, kind):
    """Return the callback argument for direct container insertion methods."""
    direct_callback_methods = {
        "queue": {"put", "put_nowait"},
        "deque": {"append", "appendleft"},
        "list": {"append"},
        "userlist": {"append"},
        "sched": {"enter"},
    }
    if expr.func.attr not in direct_callback_methods.get(kind, set()):
        return None
    callback_index = 2 if kind == "sched" else 0
    if len(expr.args) <= callback_index:
        return None
    callback = expr.args[callback_index]
    if isinstance(callback, (ast.Tuple, ast.List)) and callback.elts:
        return callback.elts[-1]
    return callback


def _sync_callback_insert_mutates(expr, kind, operator_bindings):
    """Return True when one supported insertion stores a mutating callback."""
    callback = _sync_callback_direct_insert_argument(expr, kind)
    if callback is not None:
        return (
            isinstance(callback, ast.Lambda)
            and _lambda_mutates_workers(callback, operator_bindings)
        )
    iterable_callback_methods = {
        "deque": {"extend", "extendleft"},
        "list": {"extend"},
    }
    if expr.func.attr in iterable_callback_methods.get(kind, set()):
        return _iterable_literal_contains_mutating_lambda(
            expr.args[0],
            operator_bindings,
        )
    return False


def _record_sched_mutating_event(node, scheduler_name, tracking):
    """Track a mutating scheduler event and any simple assigned handle."""
    event_id = tracking["next_sched_event_id"]
    tracking["next_sched_event_id"] += 1
    tracking["sched_pending_events"].setdefault(
        scheduler_name,
        set(),
    ).add(event_id)
    for event_name in _simple_assignment_names(node):
        tracking["sched_event_ids"][event_name] = (scheduler_name, event_id)


def _record_queue_mutating_subscript_indexes(
    expr,
    receiver_name,
    tracking,
    operator_bindings,
):
    """Track tuple/list callback positions inserted into a queue."""
    if not expr.args:
        return
    indexes = _mutating_lambda_subscript_indexes(
        expr.args[0],
        operator_bindings,
    )
    if indexes:
        tracking["mutating_subscript_indexes"].setdefault(
            receiver_name,
            set(),
        ).update(indexes)


def _record_sync_callback_insert(node, tracking, operator_bindings):
    """Remember containers that receive a workers-mutating callback."""
    _record_heapq_heappush_mutating_callback(node, tracking, operator_bindings)
    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        return
    receiver = expr.func.value
    if not isinstance(receiver, ast.Name):
        return
    kind = tracking["containers"].get(receiver.id)
    if kind is None or not expr.args:
        return
    if kind == "queue":
        _record_queue_mutating_subscript_indexes(
            expr,
            receiver.id,
            tracking,
            operator_bindings,
        )
    if _sync_callback_insert_mutates(expr, kind, operator_bindings):
        tracking["mutating"].add(receiver.id)
        if kind == "sched":
            _record_sched_mutating_event(node, receiver.id, tracking)


def _queue_get_arguments_are_valid(call):
    """Return True for argument shapes accepted by Queue.get."""
    if len(call.args) > 2:
        return False
    keyword_names = []
    for keyword in call.keywords:
        if keyword.arg not in {"block", "timeout"}:
            return False
        keyword_names.append(keyword.arg)
    if len(keyword_names) != len(set(keyword_names)):
        return False
    positional_names = set()
    if len(call.args) == 2:
        positional_names = {"block", "timeout"}
    elif len(call.args) == 1:
        positional_names = {"block"}
    return not positional_names.intersection(keyword_names)


def _sync_callback_accessor_arguments_are_valid(call, kind, method):
    """Return True when a proven callback-container accessor can execute."""
    accessor = (kind, method)
    if accessor == ("queue", "get"):
        return _queue_get_arguments_are_valid(call)
    zero_arg_accessors = {
        ("queue", "get_nowait"),
        ("deque", "pop"),
        ("deque", "popleft"),
    }
    if accessor in zero_arg_accessors:
        return not call.args and not call.keywords
    optional_index_accessors = {
        ("list", "pop"),
        ("userlist", "pop"),
    }
    if accessor in optional_index_accessors:
        return len(call.args) <= 1 and not call.keywords
    return accessor == ("sched", "run")


def _builtin_call_is_active(call, name, operator_bindings):
    """Return True when one call resolves to the requested unshadowed builtin."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == name
    ):
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    return _name_is_unshadowed_builtin(
        name,
        getattr(call, "lineno", 0),
        shadow_lines,
    )


def _expression_is_zero_arg_call_of_name(expr, name):
    """Return True when an evaluated expression invokes ``name()``."""
    if isinstance(expr, ast.Lambda):
        return False
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == name
        and not expr.args
        and not expr.keywords
    ):
        return True
    return any(
        _expression_is_zero_arg_call_of_name(child, name)
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.expr)
    )


def _statement_zero_arg_calls_name(node, name):
    """Return True when an evaluated part of a statement invokes ``name()``."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.expr) and _expression_is_zero_arg_call_of_name(
            child,
            name,
        ):
            return True
        if isinstance(child, ast.stmt) and _statement_zero_arg_calls_name(
            child,
            name,
        ):
            return True
    return False


def _for_loop_iter_holds_mutating_callbacks(node, operator_bindings):
    """Return True when a for-loop iterates a proven mutating callback container."""
    return _iter_expression_holds_mutating_callbacks(
        node.iter,
        operator_bindings,
    )


def _comprehension_call_targets_loop_name(call, loop_name):
    """Return True when a zero-arg call invokes the comprehension loop variable."""
    if not isinstance(call, ast.Call) or call.args or call.keywords:
        return False
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == loop_name
    if isinstance(func, ast.NamedExpr) and isinstance(func.target, ast.Name):
        return func.target.id == loop_name
    return False


def _literal_expression_truthiness(expr):
    """Return statically known truthiness, or None when it is not literal."""
    try:
        return bool(ast.literal_eval(expr))
    except (ValueError, TypeError):
        return None


def _boolop_invokes_loop_callback(expr, loop_name):
    """Respect literal short-circuiting while scanning a boolean expression."""
    for value in expr.values:
        if _expression_invokes_loop_callback(value, loop_name):
            return True
        truthiness = _literal_expression_truthiness(value)
        if isinstance(expr.op, ast.Or) and truthiness is True:
            return False
        if isinstance(expr.op, ast.And) and truthiness is False:
            return False
    return False


def _expression_invokes_loop_callback(expr, loop_name):
    """Return True when evaluating an expression can invoke ``loop_name()``."""
    if _comprehension_call_targets_loop_name(expr, loop_name):
        return True
    if isinstance(expr, ast.BoolOp):
        return _boolop_invokes_loop_callback(expr, loop_name)
    if isinstance(expr, ast.IfExp):
        test_truthiness = _literal_expression_truthiness(expr.test)
        if test_truthiness is True:
            return _expression_invokes_loop_callback(expr.body, loop_name)
        if test_truthiness is False:
            return _expression_invokes_loop_callback(expr.orelse, loop_name)
        return (
            _expression_invokes_loop_callback(expr.body, loop_name)
            or _expression_invokes_loop_callback(expr.orelse, loop_name)
        )
    if isinstance(expr, ast.UnaryOp):
        return _expression_invokes_loop_callback(expr.operand, loop_name)
    return False


def _iter_expression_holds_mutating_callbacks(iterator, operator_bindings):
    """Return True when an iterable expression holds mutating callbacks."""
    if _iterable_literal_contains_mutating_lambda(iterator, operator_bindings):
        return True
    if isinstance(iterator, ast.Name):
        return _mutating_callback_container_is_active(
            iterator,
            operator_bindings,
        )
    if (
        isinstance(iterator, ast.Subscript)
        and isinstance(iterator.slice, ast.Slice)
        and iterator.slice.lower is None
        and iterator.slice.upper is None
        and iterator.slice.step is None
    ):
        return _callback_container_expression_is_mutating(
            iterator.value,
            operator_bindings,
        )
    if (
        _unshadowed_builtin_call(iterator, "iter", operator_bindings)
        and len(iterator.args) == 1
        and not iterator.keywords
    ):
        return _callback_container_expression_is_mutating(
            iterator.args[0],
            operator_bindings,
        )
    if _unshadowed_builtin_call(iterator, "zip", operator_bindings) and iterator.args:
        return any(
            _callback_container_expression_is_mutating(arg, operator_bindings)
            for arg in iterator.args
        )
    if (
        isinstance(iterator, ast.Call)
        and iterator.args
        and any(
            _unshadowed_builtin_call(iterator, name, operator_bindings)
            for name in ("reversed", "enumerate", "sorted")
        )
    ):
        return _callback_container_expression_is_mutating(
            iterator.args[0],
            operator_bindings,
        )
    return False


def _reduce_lambda_invokes_mutating_iterable_callback(call, operator_bindings):
    """Return True for reduce(lambda _, f: f(), [mutator], ...) forms."""
    lambda_node = _reduce_lambda_argument(call)
    if lambda_node is None or len(call.args) < 2:
        return False
    iterable = call.args[1]
    if isinstance(iterable, (ast.List, ast.Tuple)):
        minimum_items = 1 if len(call.args) >= 3 else 2
        if len(iterable.elts) < minimum_items:
            return False
    if not _iter_expression_holds_mutating_callbacks(
        iterable,
        operator_bindings,
    ):
        return False
    lambda_args = lambda_node.args.args
    if len(lambda_args) < 2:
        return False
    return _expression_invokes_loop_callback(
        lambda_node.body,
        lambda_args[1].arg,
    )


def _frame_globals_receiver(call, inspect_analysis=None):
    """Return the live-frame expression behind an f_globals receiver."""
    base = call.func.value
    shadow_lines = (inspect_analysis or {}).get("builtin_shadow_lines", {})
    frame_from_getattribute = _object_getattribute_f_globals_frame(
        base,
        inspect_analysis,
    )
    if frame_from_getattribute is not None:
        return frame_from_getattribute
    if isinstance(base, ast.Attribute) and base.attr == "f_globals":
        return base.value
    if (
        isinstance(base, ast.Call)
        and isinstance(base.func, ast.Name)
        and base.func.id == "getattr"
        and _name_is_unshadowed_builtin(
            "getattr",
            getattr(base, "lineno", 0),
            shadow_lines,
        )
        and len(base.args) in (2, 3)
        and not base.keywords
        and isinstance(base.args[1], ast.Constant)
        and base.args[1].value == "f_globals"
    ):
        return base.args[0]
    return None


def _call_is_frame_globals_update(call):
    """Return True for frame f_globals update mutations."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
    ):
        return False
    if _frame_globals_receiver(call) is None:
        return False
    return _update_payload_may_set_workers(call)


def _inspect_named_call_is_active(call, inspect_analysis, name, alias_events_key):
    """Return True when a call resolves to one tracked inspect callable."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == name:
        return _module_alias_active_at_line(
            func.value,
            set(),
            inspect_analysis.get("module_alias_events", {}),
            reference_line,
        )
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            inspect_analysis.get(alias_events_key, {}),
            func.id,
            reference_line,
        )
    return False


def _traceback_named_call_is_active(call, inspect_analysis, name, alias_events_key):
    """Return True when a call resolves to one tracked traceback callable."""
    if not isinstance(call, ast.Call):
        return False
    reference_line = getattr(call, "lineno", 0)
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == name:
        return _module_alias_active_at_line(
            func.value,
            set(),
            inspect_analysis.get("traceback_module_alias_events", {}),
            reference_line,
        )
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            inspect_analysis.get(alias_events_key, {}),
            func.id,
            reference_line,
        )
    return False


def _traceback_walk_stack_call_is_active(call, inspect_analysis):
    """Return True for proven traceback.walk_stack calls."""
    return _traceback_named_call_is_active(
        call,
        inspect_analysis,
        "walk_stack",
        "walk_stack_alias_events",
    )


def _inspect_frameinfo_source_call_is_active(call, inspect_analysis):
    """Return True for proven inspect FrameInfo-producing calls."""
    return (
        _inspect_named_call_is_active(
            call,
            inspect_analysis,
            "stack",
            "stack_alias_events",
        )
        or _inspect_named_call_is_active(
            call,
            inspect_analysis,
            "getouterframes",
            "getouterframes_alias_events",
        )
        or _inspect_named_call_is_active(
            call,
            inspect_analysis,
            "innerframes",
            "innerframes_alias_events",
        )
    )


def _inspect_frameinfo_iterable_is_active(expr, inspect_analysis):
    """Return True when an expression iterates inspect FrameInfo values."""
    if _inspect_frameinfo_source_call_is_active(expr, inspect_analysis):
        return True
    return (
        isinstance(expr, ast.Subscript)
        and isinstance(expr.slice, ast.Slice)
        and _inspect_frameinfo_source_call_is_active(
            expr.value,
            inspect_analysis,
        )
    )


def _module_scope_ast_nodes(tree):
    """Yield module-scope AST nodes without entering function or class bodies."""
    stack = list(reversed(tree.body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _record_alias_span(spans, target, start_line, end_line):
    """Record one line-bounded alias span for a simple name target."""
    if isinstance(target, ast.Name):
        spans.setdefault(target.id, []).append((start_line, end_line))


def _collect_inspect_frameinfo_alias_spans(tree, inspect_analysis):
    """Track loop/comprehension names bound to inspect FrameInfo values."""
    spans = {}
    comprehension_types = (
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    for node in _module_scope_ast_nodes(tree):
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            if _inspect_frameinfo_iterable_is_active(node.iter, inspect_analysis):
                _record_alias_span(
                    spans,
                    node.target,
                    start_line,
                    end_line,
                )
            continue
        if not isinstance(node, comprehension_types):
            continue
        for generator in node.generators:
            if _inspect_frameinfo_iterable_is_active(
                generator.iter,
                inspect_analysis,
            ):
                _record_alias_span(
                    spans,
                    generator.target,
                    start_line,
                    end_line,
                )
    return spans


def _frameinfo_assignment_value_is_active(
    value,
    inspect_analysis,
    active_aliases,
):
    """Return True for a top-level value proven to hold inspect.FrameInfo."""
    if isinstance(value, ast.NamedExpr):
        value = value.value
    if isinstance(value, ast.Name):
        return value.id in active_aliases
    return (
        isinstance(value, ast.Subscript)
        and not isinstance(value.slice, ast.Slice)
        and _inspect_frameinfo_source_call_is_active(
            value.value,
            inspect_analysis,
        )
    )


def _record_frameinfo_alias_assignment(
    name,
    value,
    line,
    active,
    events,
    inspect_analysis,
):
    """Update one source-ordered top-level FrameInfo alias binding."""
    if _frameinfo_assignment_value_is_active(
        value,
        inspect_analysis,
        active,
    ):
        active.add(name)
        events.setdefault(name, []).append((line, True))
        return
    _deactivate_imported_module_alias(name, active, events, line)


def _collect_inspect_frameinfo_alias_events(tree, inspect_analysis):
    """Track top-level FrameInfo aliases and invalidate them on rebinding."""
    events = {}
    active = set()
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _deactivate_imported_module_alias(node.name, active, events, line)
            continue
        assignments = [
            *_namespace_assignment_values(node),
            *_compound_test_namespace_assignment_values(node),
        ]
        for name, value in assignments:
            _record_frameinfo_alias_assignment(
                name,
                value,
                line,
                active,
                events,
                inspect_analysis,
            )
    return events


def _inspect_frameinfo_alias_is_active(node, inspect_analysis):
    """Return True when a name currently resolves to inspect.FrameInfo."""
    if not isinstance(node, ast.Name):
        return False
    reference_line = getattr(node, "lineno", 0)
    events = inspect_analysis.get("frameinfo_alias_events", {})
    if node.id in events:
        state = _binding_state_at_line(events, node.id, reference_line)
        if state is not None:
            return bool(state)
    return any(
        start_line <= reference_line <= end_line
        for start_line, end_line in inspect_analysis.get(
            "frameinfo_alias_spans",
            {},
        ).get(node.id, ())
    )


def _inspect_frameinfo_value_is_active(node, inspect_analysis):
    """Return True for a proven FrameInfo alias or indexed inspect result."""
    if isinstance(node, ast.NamedExpr):
        return _inspect_frameinfo_value_is_active(
            node.value,
            inspect_analysis,
        )
    if _inspect_frameinfo_alias_is_active(node, inspect_analysis):
        return True
    return (
        isinstance(node, ast.Subscript)
        and not isinstance(node.slice, ast.Slice)
        and _inspect_frameinfo_source_call_is_active(
            node.value,
            inspect_analysis,
        )
    )

def _frame_globals_call_targets_live_frame(call, operator_bindings):
    """Return True when a frame f_globals receiver is a proven live frame."""
    inspect_analysis = (
        operator_bindings[-1]
        if operator_bindings
        and isinstance(operator_bindings[-1], dict)
        and "frame_alias_events" in operator_bindings[-1]
        else {}
    )
    reference_line = getattr(call, "lineno", 0)
    active_frame_names = {
        name
        for name in inspect_analysis.get("frame_alias_events", {})
        if _imported_alias_is_active(
            inspect_analysis.get("frame_alias_events", {}),
            name,
            reference_line,
        )
    }
    frame_node = _frame_globals_receiver(call, inspect_analysis)
    if frame_node is None:
        return False
    frame_node = _unwrap_ast_node(frame_node)
    if _node_is_proven_live_frame(frame_node, inspect_analysis, active_frame_names):
        return True
    if isinstance(frame_node, ast.Name):
        return _imported_alias_is_active(
            inspect_analysis.get("frame_alias_events", {}),
            frame_node.id,
            reference_line,
        )
    return False


def _call_is_inspect_currentframe_globals_update(call, operator_bindings):
    """Return True for f_globals updates on proven interpreter frame objects."""
    if not _call_is_frame_globals_update(call):
        return False
    return _frame_globals_call_targets_live_frame(call, operator_bindings)


def _call_is_inspect_currentframe_globals_ior(call, operator_bindings):
    """Return True for ``frame.f_globals.__ior__({...})`` worker mutations."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "__ior__"
    ):
        return False
    if not call.args or not _dict_merge_payload_may_set_workers(call.args[0]):
        return False
    return _frame_globals_call_targets_live_frame(call, operator_bindings)


def _inspect_analysis_from_bindings(operator_bindings):
    """Return the inspect/frame provenance bundle from operator bindings."""
    if (
        operator_bindings
        and isinstance(operator_bindings[-1], dict)
        and "frame_alias_events" in operator_bindings[-1]
    ):
        return operator_bindings[-1]
    return {}


def _active_frame_names_at_line(inspect_analysis, reference_line):
    """Return frame aliases that are active at ``reference_line``."""
    events = inspect_analysis.get("frame_alias_events", {})
    return {
        name
        for name in events
        if _imported_alias_is_active(events, name, reference_line)
    }


def _active_frame_globals_dict_names_at_line(inspect_analysis, reference_line):
    """Return ``f_globals`` dict aliases active at ``reference_line``."""
    events = inspect_analysis.get("frame_globals_dict_alias_events", {})
    return {
        name
        for name in events
        if _imported_alias_is_active(events, name, reference_line)
    }


def _uses_builtin_object_getattribute(func, reference_line, shadow_lines):
    """Return True for a proven builtin object.__getattribute__ resolver."""
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "__getattribute__"
            and isinstance(func.value, ast.Name)
            and func.value.id == "object"
        )
    if not (isinstance(func, ast.Call) and isinstance(func.func, ast.Name)):
        return False
    if func.func.id != "getattr" or len(func.args) < 2:
        return False
    if not _name_is_unshadowed_builtin(
        "getattr",
        reference_line,
        shadow_lines,
    ):
        return False
    module = func.args[0]
    attr = func.args[1]
    return (
        isinstance(module, ast.Name)
        and module.id == "object"
        and isinstance(attr, ast.Constant)
        and attr.value == "__getattribute__"
    )


def _object_getattribute_f_globals_frame(node, inspect_analysis=None):
    """Return the frame in a proven builtin object.__getattribute__ call."""
    if not isinstance(node, ast.Call) or len(node.args) < 2:
        return None
    reference_line = getattr(node, "lineno", 0)
    shadow_lines = (inspect_analysis or {}).get("builtin_shadow_lines", {})
    if not _name_is_unshadowed_builtin("object", reference_line, shadow_lines):
        return None
    if not _uses_builtin_object_getattribute(
        node.func,
        reference_line,
        shadow_lines,
    ):
        return None
    key = node.args[1]
    if isinstance(key, ast.Constant) and key.value == "f_globals":
        return node.args[0]
    return None


def _is_proven_frame_globals_mapping(
    node,
    inspect_analysis,
    active_frame_names,
    active_fg_dict_names,
):
    """Return True when a node refers to a live frame's ``f_globals`` mapping."""
    node = _unwrap_ast_node(node)
    if isinstance(node, ast.Name) and node.id in active_fg_dict_names:
        return True
    frame_from_getattribute = _object_getattribute_f_globals_frame(
        node,
        inspect_analysis,
    )
    if frame_from_getattribute is not None:
        return _node_is_proven_live_frame(
            frame_from_getattribute,
            inspect_analysis,
            active_frame_names,
        )
    if not (isinstance(node, ast.Attribute) and node.attr == "f_globals"):
        return False
    return _node_is_proven_live_frame(
        node.value,
        inspect_analysis,
        active_frame_names,
    )


def _getattr_proven_frame_globals_mutator_method(
    func,
    inspect_analysis,
    active_frame_names,
    active_fg_dict_names,
):
    """Return a mutator name from a proven ``f_globals`` mapping callable."""
    if isinstance(func, ast.Attribute):
        if func.attr in _NAMESPACE_GETATTR_METHODS and _is_proven_frame_globals_mapping(
            func.value,
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        ):
            return func.attr
        return None
    if not isinstance(func, ast.Call):
        return None
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return None
    if len(func.args) < 2 or not _is_proven_frame_globals_mapping(
        func.args[0],
        inspect_analysis,
        active_frame_names,
        active_fg_dict_names,
    ):
        return None
    key = func.args[1]
    if not isinstance(key, ast.Constant) or key.value not in _NAMESPACE_GETATTR_METHODS:
        return None
    return key.value


def _call_is_getattr_proven_frame_globals_mutation(call, operator_bindings):
    """Return True for ``getattr(frame.f_globals, 'update')(...)`` style mutations."""
    if not isinstance(call, ast.Call):
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(call, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(inspect_analysis, reference_line)
    active_fg_dict_names = _active_frame_globals_dict_names_at_line(
        inspect_analysis,
        reference_line,
    )
    method = None
    if isinstance(call.func, ast.Name):
        mutator_aliases = inspect_analysis.get("frame_globals_mutator_aliases", {})
        method = mutator_aliases.get(call.func.id)
    if method is None:
        method = _getattr_proven_frame_globals_mutator_method(
            call.func,
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        )
    return method is not None and _namespace_mutator_call_may_set_workers(
        method,
        call,
    )


def _call_is_operator_methodcaller_on_proven_frame_globals(
    call,
    operator_bindings,
):
    """Return True for ``methodcaller('update', ...)(frame.f_globals)`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    factory = _resolve_operator_methodcaller_factory(call, operator_bindings)
    if factory is None:
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(call, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(inspect_analysis, reference_line)
    active_fg_dict_names = _active_frame_globals_dict_names_at_line(
        inspect_analysis,
        reference_line,
    )
    if not _is_proven_frame_globals_mapping(
        call.args[0],
        inspect_analysis,
        active_frame_names,
        active_fg_dict_names,
    ):
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


def _call_is_dict_type_setitem_on_proven_frame_globals(
    call,
    operator_bindings,
):
    """Return True for ``dict.__setitem__(frame.f_globals, 'workers', ...)``."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    dict_shadow_line = (
        operator_bindings[21] if len(operator_bindings) > 21 else None
    )
    if not _is_dict_type_setitem_callable(
        call.func,
        reference_line=getattr(call, "lineno", 0),
        dict_shadow_line=dict_shadow_line,
    ):
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(call, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(inspect_analysis, reference_line)
    active_fg_dict_names = _active_frame_globals_dict_names_at_line(
        inspect_analysis,
        reference_line,
    )
    if not _is_proven_frame_globals_mapping(
        call.args[0],
        inspect_analysis,
        active_frame_names,
        active_fg_dict_names,
    ):
        return False
    return _key_may_be_workers(call.args[1])


def _attribute_is_proven_frame_globals_update(
    node,
    inspect_analysis,
    active_frame_names,
    active_fg_dict_names,
):
    """Return True for a proven ``f_globals.update`` attribute reference."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "update"
        and _is_proven_frame_globals_mapping(
            node.value,
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        )
    )


def _partial_call_binds_proven_frame_globals_workers_setter(
    partial_call,
    operator_bindings,
):
    """Return True for partials that bind workers on a proven ``f_globals`` dict."""
    if not partial_call.args:
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(partial_call, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(inspect_analysis, reference_line)
    active_fg_dict_names = _active_frame_globals_dict_names_at_line(
        inspect_analysis,
        reference_line,
    )
    if (
        len(partial_call.args) >= 2
        and _attribute_is_proven_frame_globals_update(
            partial_call.args[0],
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        )
        and _update_payload_may_set_workers(partial_call, start_index=1)
    ):
        return True
    if (
        len(partial_call.args) >= 2
        and isinstance(partial_call.args[0], ast.Attribute)
        and partial_call.args[0].attr == "__setitem__"
        and _is_proven_frame_globals_mapping(
            partial_call.args[0].value,
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        )
        and _constant_is_workers(partial_call.args[1])
    ):
        return True
    return False


def _assign_mutates_proven_frame_globals_workers(node, operator_bindings):
    """Return True for ``frame.f_globals['workers'] = ...`` assignments."""
    if not isinstance(node, ast.Assign):
        return False
    inspect_analysis = _inspect_analysis_from_bindings(operator_bindings)
    reference_line = getattr(node, "lineno", 0)
    active_frame_names = _active_frame_names_at_line(inspect_analysis, reference_line)
    active_fg_dict_names = _active_frame_globals_dict_names_at_line(
        inspect_analysis,
        reference_line,
    )
    for target in node.targets:
        if not isinstance(target, ast.Subscript):
            continue
        if not _subscript_slice_is_workers(target.slice):
            continue
        if _is_proven_frame_globals_mapping(
            target.value,
            inspect_analysis,
            active_frame_names,
            active_fg_dict_names,
        ):
            return True
    return False


def _sys_getframe_call_is_active(frame_call, inspect_analysis):
    """Return True when a call resolves to a proven ``sys._getframe`` binding."""
    if not isinstance(frame_call, ast.Call):
        return False
    reference_line = getattr(frame_call, "lineno", 0)
    func = frame_call.func
    if isinstance(func, ast.Attribute) and func.attr == "_getframe":
        return _module_alias_active_at_line(
            func.value,
            set(),
            inspect_analysis.get("sys_module_alias_events", {}),
            reference_line,
        )
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            inspect_analysis.get("sys_getframe_alias_events", {}),
            func.id,
            reference_line,
        )
    if not (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value == "_getframe"
    ):
        return False
    return _module_alias_active_at_line(
        func.args[0],
        set(),
        inspect_analysis.get("sys_module_alias_events", {}),
        reference_line,
    )


def _inspect_currentframe_call_is_active(frame_call, inspect_analysis):
    """Return True when a call resolves to the real inspect.currentframe."""
    if not (
        isinstance(frame_call, ast.Call)
        and not frame_call.args
        and not frame_call.keywords
    ):
        return False
    reference_line = getattr(frame_call, "lineno", 0)
    func = frame_call.func
    if isinstance(func, ast.Attribute) and func.attr == "currentframe":
        return _module_alias_active_at_line(
            func.value,
            set(),
            inspect_analysis.get("module_alias_events", {}),
            reference_line,
        )
    if isinstance(func, ast.Name):
        return _imported_alias_is_active(
            inspect_analysis.get("currentframe_alias_events", {}),
            func.id,
            reference_line,
        )
    return False


def _inspect_getouterframes_call_is_active(frame_call, inspect_analysis):
    """Return True when a call resolves to ``inspect.getouterframes``."""
    return _inspect_named_call_is_active(
        frame_call,
        inspect_analysis,
        "getouterframes",
        "getouterframes_alias_events",
    )


def _getouterframes_call_has_active_frame_arg(
    frame_call,
    inspect_analysis,
    active_frame_names,
):
    """Return True when getouterframes is called with a live frame argument."""
    if not frame_call.args:
        return False
    first = frame_call.args[0]
    if _inspect_currentframe_call_is_active(first, inspect_analysis):
        return True
    if _sys_getframe_call_is_active(first, inspect_analysis):
        return True
    return isinstance(first, ast.Name) and first.id in active_frame_names


def _walk_stack_loop_frame_target_names(node, inspect_analysis):
    """Return direct frame aliases unpacked from traceback.walk_stack."""
    if not isinstance(node, ast.For):
        return None
    if not _traceback_walk_stack_call_is_active(node.iter, inspect_analysis):
        return None
    if isinstance(node.target, (ast.Tuple, ast.List)) and node.target.elts:
        first = node.target.elts[0]
        if isinstance(first, ast.Name):
            return {first.id}
    return set()


def _collect_walk_stack_pair_alias_spans(tree, inspect_analysis):
    """Track single-name loop targets that hold walk_stack frame/line pairs."""
    spans = {}
    for node in _module_scope_ast_nodes(tree):
        if not isinstance(node, ast.For):
            continue
        if not _traceback_walk_stack_call_is_active(node.iter, inspect_analysis):
            continue
        if not isinstance(node.target, ast.Name):
            continue
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)
        _record_alias_span(
            spans,
            node.target,
            start_line,
            end_line,
        )
    return spans


def _walk_stack_pair_first_item_is_active(node, inspect_analysis):
    """Return True for pair_alias[0] from a proven walk_stack loop."""
    if not (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == 0
    ):
        return False
    reference_line = getattr(node, "lineno", 0)
    return any(
        start_line <= reference_line <= end_line
        for start_line, end_line in inspect_analysis.get(
            "walk_stack_pair_alias_spans",
            {},
        ).get(node.value.id, ())
    )

def _getouterframes_loop_target_names(
    node,
    inspect_analysis,
    active_frame_names,
):
    """Return frame aliases bound by one proven getouterframes loop."""
    if not isinstance(node, ast.For):
        return None
    if not _inspect_getouterframes_call_is_active(node.iter, inspect_analysis):
        return None
    if not _getouterframes_call_has_active_frame_arg(
        node.iter,
        inspect_analysis,
        active_frame_names,
    ):
        return set()
    return _loop_target_names(node.target)


def _value_is_active_frame_alias(
    value,
    inspect_analysis,
    active_frame_names,
):
    """Return True when an assignment value is a proven live frame."""
    if _inspect_currentframe_call_is_active(value, inspect_analysis):
        return True
    if _sys_getframe_call_is_active(value, inspect_analysis):
        return True
    return isinstance(value, ast.Name) and value.id in active_frame_names


def _unwrap_ast_node(node):
    """Return the inner value when ``node`` is a walrus expression."""
    while isinstance(node, ast.NamedExpr):
        node = node.value
    return node


def _node_is_proven_live_frame(node, inspect_analysis, active_frame_names):
    """Return True when a node refers to the config's live frame object."""
    node = _unwrap_ast_node(node)
    if _value_is_active_frame_alias(node, inspect_analysis, active_frame_names):
        return True
    if _walk_stack_pair_first_item_is_active(node, inspect_analysis):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "frame":
        return _inspect_frameinfo_value_is_active(
            node.value,
            inspect_analysis,
        )
    return False

def _augassign_mutates_proven_frame_globals(node, operator_bindings):
    """Return True for ``frame.f_globals |= {...}`` style worker mutations."""
    inspect_analysis = (
        operator_bindings[-1]
        if operator_bindings
        and isinstance(operator_bindings[-1], dict)
        and "frame_alias_events" in operator_bindings[-1]
        else {}
    )
    if not isinstance(node, ast.AugAssign) or not isinstance(node.op, ast.BitOr):
        return False
    target = node.target
    if not isinstance(target, ast.Attribute) or target.attr != "f_globals":
        return False
    if not _dict_merge_payload_may_set_workers(node.value):
        return False
    reference_line = getattr(node, "lineno", 0)
    active_frame_names = {
        name
        for name in inspect_analysis.get("frame_alias_events", {})
        if _imported_alias_is_active(
            inspect_analysis.get("frame_alias_events", {}),
            name,
            reference_line,
        )
    }
    return _node_is_proven_live_frame(
        target.value,
        inspect_analysis,
        active_frame_names,
    )


def _record_frame_alias_assignment(
    name,
    value,
    line,
    active,
    events,
    inspect_analysis,
):
    """Update tracked frame aliases for one namespace assignment."""
    if _value_is_active_frame_alias(
        value,
        inspect_analysis,
        active,
    ):
        active.add(name)
        events.setdefault(name, []).append((line, True))
        return
    _deactivate_imported_module_alias(name, active, events, line)


def _record_frame_globals_dict_alias_assignment(
    name,
    value,
    line,
    active_frames,
    active_fg_dict,
    events,
    inspect_analysis,
):
    """Track names bound to a proven live frame's ``f_globals`` mapping."""
    value = _unwrap_ast_node(value)
    if (
        isinstance(value, ast.Attribute)
        and value.attr == "f_globals"
        and _node_is_proven_live_frame(
            value.value,
            inspect_analysis,
            active_frames,
        )
    ) or (isinstance(value, ast.Name) and value.id in active_fg_dict):
        active_fg_dict.add(name)
        events.setdefault(name, []).append((line, True))
        return
    _deactivate_imported_module_alias(name, active_fg_dict, events, line)


def _sys_current_frames_mapping_call_is_active(iter_expr, inspect_analysis, method):
    """Return True when ``iter_expr`` is ``sys._current_frames().<method>()``."""
    if not isinstance(iter_expr, ast.Call):
        return False
    if not isinstance(iter_expr.func, ast.Attribute) or iter_expr.func.attr != method:
        return False
    inner = iter_expr.func.value
    if not isinstance(inner, ast.Call):
        return False
    func = inner.func
    if isinstance(func, ast.Attribute) and func.attr == "_current_frames":
        return _module_alias_active_at_line(
            func.value,
            set(),
            inspect_analysis.get("sys_module_alias_events", {}),
            getattr(iter_expr, "lineno", 0),
        )
    return False


def _sys_current_frames_items_call_is_active(iter_expr, inspect_analysis):
    """Return True when ``iter_expr`` is ``sys._current_frames().items()``."""
    return _sys_current_frames_mapping_call_is_active(
        iter_expr,
        inspect_analysis,
        "items",
    )


def _current_frames_loop_frame_target_names(node, inspect_analysis):
    """Return frame aliases unpacked from ``sys._current_frames()`` mapping loops."""
    if not isinstance(node, ast.For):
        return None
    if _sys_current_frames_items_call_is_active(node.iter, inspect_analysis):
        if isinstance(node.target, ast.Tuple) and len(node.target.elts) >= 2:
            frame_target = node.target.elts[1]
            if isinstance(frame_target, ast.Name):
                return {frame_target.id}
        return set()
    if (
        _sys_current_frames_mapping_call_is_active(
            node.iter,
            inspect_analysis,
            "values",
        )
        and isinstance(node.target, ast.Name)
    ):
        return {node.target.id}
    return set()


def _collect_frame_globals_mutator_aliases(tree, inspect_analysis):
    """Collect names bound to one proven ``f_globals`` mutator callable."""
    assignments = {}
    _record_module_namespace_assignments(tree.body, assignments)
    aliases = {}
    for name, values in assignments.items():
        methods = []
        for value in values:
            if value is None:
                methods.append(None)
                continue
            reference_line = getattr(value, "lineno", 0)
            active_frame_names = _active_frame_names_at_line(
                inspect_analysis,
                reference_line,
            )
            active_fg_dict_names = _active_frame_globals_dict_names_at_line(
                inspect_analysis,
                reference_line,
            )
            methods.append(
                _getattr_proven_frame_globals_mutator_method(
                    value,
                    inspect_analysis,
                    active_frame_names,
                    active_fg_dict_names,
                )
            )
        if methods and methods[0] is not None and all(
            method == methods[0] for method in methods
        ):
            aliases[name] = methods[0]
    return aliases


def _deactivate_frame_alias_bindings(
    name,
    active,
    events,
    active_fg_dict,
    fg_dict_events,
    line,
):
    """Deactivate frame and f_globals aliases shadowed by a definition."""
    _deactivate_imported_module_alias(name, active, events, line)
    _deactivate_imported_module_alias(
        name,
        active_fg_dict,
        fg_dict_events,
        line,
    )


def _scan_frameinfo_loop_body_f_globals_aliases(
    for_node,
    inspect_analysis,
    active_fg_dict,
    fg_dict_events,
    active,
):
    """Track ``f_globals`` walrus/assign aliases inside ``for fi in inspect.stack()``."""
    if not isinstance(for_node, ast.For):
        return
    if not _inspect_frameinfo_iterable_is_active(for_node.iter, inspect_analysis):
        return
    for child in for_node.body:
        line = getattr(child, "lineno", 0)
        for name in _import_bound_names(child):
            _deactivate_imported_module_alias(
                name,
                active_fg_dict,
                fg_dict_events,
                line,
            )
        for name, value in (
            *_namespace_assignment_values(child),
            *_compound_test_namespace_assignment_values(child),
        ):
            _record_frame_globals_dict_alias_assignment(
                name,
                value,
                line,
                active,
                active_fg_dict,
                fg_dict_events,
                inspect_analysis,
            )


def _module_scope_frame_loop_target_names(node, inspect_analysis, active):
    """Return frame aliases introduced by a supported module-scope frame loop."""
    loop_target_names = _getouterframes_loop_target_names(
        node,
        inspect_analysis,
        active,
    )
    if loop_target_names is not None:
        return loop_target_names
    walk_stack_targets = _walk_stack_loop_frame_target_names(
        node,
        inspect_analysis,
    )
    if walk_stack_targets is not None:
        return walk_stack_targets
    return _current_frames_loop_frame_target_names(
        node,
        inspect_analysis,
    )


def _activate_frame_alias_targets(names, active, events, line):
    """Record frame aliases proven active from a module-scope loop."""
    for name in names:
        active.add(name)
        events.setdefault(name, []).append((line, True))


def _collect_inspect_frame_alias_events(tree, inspect_analysis):
    """Track names proven to hold frames from inspect.currentframe or sys._getframe."""
    events = {}
    fg_dict_events = {}
    active = set()
    active_fg_dict = set()
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _deactivate_frame_alias_bindings(
                node.name,
                active,
                events,
                active_fg_dict,
                fg_dict_events,
                line,
            )
            continue
        for name in _import_bound_names(node):
            _deactivate_frame_alias_bindings(
                name,
                active,
                events,
                active_fg_dict,
                fg_dict_events,
                line,
            )
        loop_target_names = _module_scope_frame_loop_target_names(
            node,
            inspect_analysis,
            active,
        )
        if loop_target_names:
            _activate_frame_alias_targets(
                loop_target_names,
                active,
                events,
                line,
            )
            continue
        if isinstance(node, ast.For):
            _scan_frameinfo_loop_body_f_globals_aliases(
                node,
                inspect_analysis,
                active_fg_dict,
                fg_dict_events,
                active,
            )
        for name, value in _namespace_assignment_values(node):
            _record_frame_alias_assignment(
                name,
                value,
                line,
                active,
                events,
                inspect_analysis,
            )
            _record_frame_globals_dict_alias_assignment(
                name,
                value,
                line,
                active,
                active_fg_dict,
                fg_dict_events,
                inspect_analysis,
            )
    inspect_analysis["frame_globals_dict_alias_events"] = fg_dict_events
    inspect_analysis["frame_alias_events"] = events
    inspect_analysis["frame_globals_mutator_aliases"] = (
        _collect_frame_globals_mutator_aliases(tree, inspect_analysis)
    )
    return events


def _loop_target_names(target):
    """Return names bound by a for-loop or comprehension target."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names = set()
        for element in target.elts:
            names.update(_loop_target_names(element))
        return names
    return set()


def _zip_mutating_callback_target_names(node, operator_bindings):
    """Return tuple-target names fed by mutating callback zip iterables."""
    iterator = node.iter
    target = node.target
    if not (
        _unshadowed_builtin_call(iterator, "zip", operator_bindings)
        and isinstance(target, (ast.Tuple, ast.List))
        and len(target.elts) == len(iterator.args)
    ):
        return None
    names = set()
    for target_element, iterable in zip(target.elts, iterator.args):
        if _callback_container_expression_is_mutating(
            iterable,
            operator_bindings,
        ):
            names.update(_loop_target_names(target_element))
    return names


def _mutating_callback_loop_target_names(node, operator_bindings):
    """Return loop-target names that can hold workers-mutating callbacks."""
    zip_names = _zip_mutating_callback_target_names(
        node,
        operator_bindings,
    )
    if zip_names is not None:
        return zip_names
    if _for_loop_iter_holds_mutating_callbacks(node, operator_bindings):
        return _loop_target_names(node.target)
    return set()


def _expression_is_direct_zero_arg_call_of_names(expr, names):
    """Return True when ``expr`` directly invokes one of ``names`` with no arguments."""
    return (
        isinstance(expr, ast.Call)
        and not expr.args
        and not expr.keywords
        and isinstance(expr.func, ast.Name)
        and expr.func.id in names
    )


def _comprehension_invokes_mutating_callback(
    node,
    operator_bindings,
    eager_consumer=False,
):
    """Return True when a comprehension eagerly calls a mutating loop callback."""
    if (
        isinstance(node, (ast.ListComp, ast.SetComp))
        and isinstance(node.elt, ast.Call)
        and not node.elt.args
        and not node.elt.keywords
        and isinstance(node.elt.func, ast.NamedExpr)
        and isinstance(node.elt.func.value, ast.Lambda)
        and _lambda_mutates_workers(node.elt.func.value, operator_bindings)
    ):
        return True
    if isinstance(node, ast.DictComp):
        elements = (node.key, node.value)
    elif isinstance(node, (ast.ListComp, ast.SetComp)) or (
        eager_consumer and isinstance(node, ast.GeneratorExp)
    ):
        elements = (node.elt,)
    else:
        return False
    if len(node.generators) != 1:
        return False
    generator = node.generators[0]
    if generator.ifs or generator.is_async:
        return False
    loop_names = _mutating_callback_loop_target_names(
        generator,
        operator_bindings,
    )
    if not loop_names:
        return False
    if eager_consumer and isinstance(node, ast.GeneratorExp):
        return any(
            _expression_invokes_loop_callback(element, loop_name)
            for element in elements
            for loop_name in loop_names
        )
    return any(
        _expression_is_direct_zero_arg_call_of_names(element, loop_names)
        for element in elements
    )


def _generator_consumer_name(call, operator_bindings, bound_names=None):
    """Return the active eager builtin consuming the first positional argument."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    name = None
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name not in _EAGER_GENERATOR_CONSUMER_BUILTINS:
            return None
        if bound_names and name in bound_names:
            return None
        if not _unshadowed_builtin_call(call, name, operator_bindings):
            return None
    else:
        name = _resolved_builtin_eager_consumer_name(call, operator_bindings)
        if not name:
            return None
    if name in {"max", "min"} and len(call.args) != 1:
        return None
    return name


def _callback_expression_mutates_workers(callback, operator_bindings):
    """Return True when invoking one callback expression mutates workers."""
    if isinstance(callback, ast.Lambda):
        return _lambda_mutates_workers(callback, operator_bindings)
    return _mutating_callback_alias_is_active(
        callback,
        operator_bindings,
    )


def _callback_literal_truthiness(callback):
    """Return statically known callback truthiness, or None when unknown."""
    if not isinstance(callback, ast.Lambda):
        return None
    try:
        value = ast.literal_eval(callback.body)
    except (ValueError, TypeError):
        return None
    return bool(value)


def _short_circuit_generator_mutates_workers(
    generator_expr,
    operator_bindings,
    consumer_name,
):
    """Resolve ordered literal callbacks for any/all/next consumers."""
    if not isinstance(generator_expr, ast.GeneratorExp):
        return None
    if len(generator_expr.generators) != 1:
        return None
    generator = generator_expr.generators[0]
    if generator.ifs or generator.is_async or not isinstance(generator.target, ast.Name):
        return None
    if not _expression_is_direct_zero_arg_call_of_names(
        generator_expr.elt,
        {generator.target.id},
    ):
        # Complex generator elements such as cb() or True still execute the
        # callback. Let the eager-consumer fallback inspect them conservatively.
        return None
    if not isinstance(generator.iter, (ast.List, ast.Tuple)):
        return None

    callbacks = generator.iter.elts
    if consumer_name == "next":
        callbacks = callbacks[:1]
    for callback in callbacks:
        if _callback_expression_mutates_workers(
            callback,
            operator_bindings,
        ):
            return True
        truthiness = _callback_literal_truthiness(callback)
        if (
            consumer_name == "any"
            and truthiness is True
        ) or (
            consumer_name == "all"
            and truthiness is False
        ):
            return False
    return False


def _call_consumes_mutating_generator(
    call,
    operator_bindings,
    bound_names=None,
):
    """Return True when an eager builtin consumes a mutating generator expression."""
    consumer_name = _generator_consumer_name(
        call,
        operator_bindings,
        bound_names,
    )
    if consumer_name is None:
        return False
    generator_expr = call.args[0]
    if consumer_name in {"any", "all", "next"}:
        short_circuit_result = _short_circuit_generator_mutates_workers(
            generator_expr,
            operator_bindings,
            consumer_name,
        )
        if short_circuit_result is not None:
            return short_circuit_result
    return _comprehension_invokes_mutating_callback(
        generator_expr,
        operator_bindings,
        eager_consumer=True,
    )


def _inspect_analysis_from_operator_bindings(operator_bindings):
    """Return the inspect frame analysis dict when present on ``operator_bindings``."""
    if not operator_bindings:
        return {}
    for item in reversed(operator_bindings):
        if isinstance(item, dict) and "frameinfo_alias_spans" in item:
            return item
    return {}


def _call_updates_frame_globals_workers(call):
    """Return True when an f_globals.update call may assign workers."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
    ):
        return False
    receiver = call.func.value
    while isinstance(receiver, ast.Attribute):
        if receiver.attr == "f_globals":
            return _update_payload_may_set_workers(call)
        receiver = receiver.value
    return False


def _for_loop_inspect_stack_body_mutates_workers(node, operator_bindings):
    """Return True when a ``for ... in inspect.stack()`` body mutates ``workers``."""
    if not isinstance(node, ast.For):
        return False
    inspect_analysis = _inspect_analysis_from_operator_bindings(operator_bindings)
    if not _inspect_frameinfo_iterable_is_active(node.iter, inspect_analysis):
        return False
    if _statements_mutate_workers(
        node.body,
        operator_bindings,
        global_workers=True,
    ):
        return True
    return any(
        _call_updates_frame_globals_workers(child)
        for child in ast.walk(node)
    )


def _for_loop_invokes_mutating_callback(node, operator_bindings):
    """Return True when a for-loop eagerly invokes a mutating literal callback."""
    if not isinstance(node, (ast.For, ast.AsyncFor)):
        return False
    loop_names = _mutating_callback_loop_target_names(
        node,
        operator_bindings,
    )
    if not loop_names:
        return False
    return any(
        _statement_zero_arg_calls_name(stmt, name)
        for stmt in node.body
        for name in loop_names
    )


def _callback_container_expression_is_mutating(value, operator_bindings):
    """Return True when an expression holds workers-mutating callbacks."""
    if _iterable_literal_contains_mutating_lambda(value, operator_bindings):
        return True
    return _mutating_callback_container_is_active(value, operator_bindings)


def _call_is_literal_callback_invocation(call, operator_bindings):
    """Return True for proven direct callback/container callback execution."""
    if not isinstance(call, ast.Call) or call.args or call.keywords:
        return False
    if _mutating_callback_alias_is_active(call.func, operator_bindings):
        return True
    if isinstance(call.func, ast.Subscript):
        return _callback_container_expression_is_mutating(
            call.func.value,
            operator_bindings,
        )

    inner = call.func
    if not isinstance(inner, ast.Call) or inner.args or inner.keywords:
        return False
    if isinstance(inner.func, ast.Subscript):
        return _callback_container_expression_is_mutating(
            inner.func.value,
            operator_bindings,
        )
    if isinstance(inner.func, ast.Attribute) and inner.func.attr == "pop":
        return _callback_container_expression_is_mutating(
            inner.func.value,
            operator_bindings,
        )
    return False

def _unshadowed_builtin_call(call, name, operator_bindings):
    """Return True when ``call`` is a direct builtin invocation."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == name
    ):
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    return _name_is_unshadowed_builtin(
        name,
        getattr(call, "lineno", 0),
        shadow_lines,
    )


def _getattr_call_targets_queue_get(call, operator_bindings):
    """Return True when ``getattr(receiver, 'get')`` targets Queue.get."""
    if not _unshadowed_builtin_call(call, "getattr", operator_bindings):
        return False
    if len(call.args) != 2:
        return False
    key = call.args[1]
    return isinstance(key, ast.Constant) and key.value == "get"


def _getattr_queue_receiver_mutates(getattr_call, tracking, operator_bindings):
    """Return True when getattr targets Queue.get on a mutating queue container."""
    if not _getattr_call_targets_queue_get(getattr_call, operator_bindings):
        return False
    receiver = getattr_call.args[0]
    if not isinstance(receiver, ast.Name) or receiver.id not in tracking["mutating"]:
        return False
    return tracking["containers"].get(receiver.id) == "queue"


def _sync_callback_getattr_dispatch_mutates(inner, tracking, operator_bindings):
    """Return True for getattr-based Queue.get callback execution forms."""
    if _getattr_queue_receiver_mutates(inner, tracking, operator_bindings):
        return True
    if (
        isinstance(inner, ast.Call)
        and _queue_get_arguments_are_valid(inner)
        and isinstance(inner.func, ast.Call)
    ):
        return _getattr_queue_receiver_mutates(
            inner.func,
            tracking,
            operator_bindings,
        )
    return False

def _asyncio_loop_schedule_tracking(scan_state):
    """Return source-ordered asyncio loop scheduling state."""
    tracking = getattr(scan_state, "_asyncio_loop_schedule_tracking", None)
    if tracking is None:
        tracking = {
            "loop_ids": {},
            "pending_loop_ids": set(),
            "pending_work": {},
            "task_tokens": {},
            "next_loop_id": 1,
            "next_pending_id": 1,
        }
        scan_state._asyncio_loop_schedule_tracking = tracking
    return tracking


def _new_asyncio_loop_id(tracking):
    """Allocate one scanner-local identity for a proven event-loop object."""
    loop_id = tracking["next_loop_id"]
    tracking["next_loop_id"] += 1
    return loop_id


def _asyncio_loop_ids_for_value(value, tracking, operator_bindings):
    """Resolve tracked event-loop identities for one assignment value."""
    if isinstance(value, ast.Name):
        return set(tracking["loop_ids"].get(value.id, ()))
    reference_line = value if isinstance(value, ast.AST) else 0
    if _asyncio_loop_factory_call_is_active(
        value,
        operator_bindings,
        reference_line,
    ):
        return {_new_asyncio_loop_id(tracking)}
    return set()


def _record_asyncio_loop_alias_assignment(
    node,
    tracking,
    operator_bindings,
    *,
    conditional,
):
    """Track event-loop identity through simple source-ordered aliases."""
    for name, value in _namespace_assignment_values(node):
        loop_ids = _asyncio_loop_ids_for_value(
            value,
            tracking,
            operator_bindings,
        )
        if conditional:
            if loop_ids:
                tracking["loop_ids"].setdefault(name, set()).update(loop_ids)
        elif loop_ids:
            tracking["loop_ids"][name] = loop_ids
        else:
            tracking["loop_ids"].pop(name, None)


def _asyncio_receiver_loop_ids(receiver, tracking, operator_bindings):
    """Return tracked identities for a proven event-loop receiver."""
    if not isinstance(receiver, ast.Name):
        return set()
    loop_ids = set(tracking["loop_ids"].get(receiver.id, ()))
    if loop_ids:
        return loop_ids
    if _asyncio_event_loop_alias_is_active(
        receiver,
        operator_bindings,
        receiver,
    ):
        loop_ids = {_new_asyncio_loop_id(tracking)}
        tracking["loop_ids"][receiver.id] = set(loop_ids)
    return loop_ids


def _call_schedules_mutating_callback_on_loop(call, operator_bindings):
    """Return True when an asyncio loop schedules a workers-mutating callback."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    method = call.func.attr
    if method in {"call_soon", "call_soon_threadsafe"}:
        callback_index = 0
    elif method in {"call_later", "call_at"}:
        callback_index = 1
    elif method == "create_task":
        if not call.args:
            return False
        reference_line = getattr(call, "lineno", 0)
        if not _asyncio_event_loop_alias_is_active(
            call.func.value,
            operator_bindings,
            reference_line,
        ):
            return False
        return _asyncio_awaitable_mutates_workers(
            call.args[0],
            operator_bindings,
            reference_line,
        )
    else:
        return False
    reference_line = getattr(call, "lineno", 0)
    if not _asyncio_event_loop_alias_is_active(
        call.func.value,
        operator_bindings,
        reference_line,
    ):
        return False
    if len(call.args) <= callback_index:
        return False
    return _thread_pool_callback_mutates_workers(
        call.args[callback_index],
        operator_bindings,
    )


def _refresh_asyncio_pending_loop_ids(tracking):
    """Rebuild loop IDs that still have pending mutating work."""
    pending_loop_ids = set()
    for loop_ids in tracking["pending_work"].values():
        pending_loop_ids.update(loop_ids)
    tracking["pending_loop_ids"] = pending_loop_ids


def _drop_rebound_asyncio_task_aliases(node, tracking):
    """Forget task handles that are definitely rebound without canceling work."""
    for name in _simple_assignment_names(node):
        tracking["task_tokens"].pop(name, None)


def _record_asyncio_pending_work(node, expr, tracking, loop_ids):
    """Track one scheduled mutating callback or task."""
    pending_id = tracking["next_pending_id"]
    tracking["next_pending_id"] += 1
    tracking["pending_work"][pending_id] = set(loop_ids)
    if expr.func.attr == "create_task":
        for task_name in _simple_assignment_names(node):
            tracking["task_tokens"][task_name] = pending_id
    _refresh_asyncio_pending_loop_ids(tracking)


def _record_asyncio_task_cancel(node, tracking, *, conditional):
    """Remove a proven task canceled before an unconditional loop run."""
    if conditional:
        return
    expr = _statement_value_expression(node)
    if not (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "cancel"
        and not expr.args
        and not expr.keywords
        and isinstance(expr.func.value, ast.Name)
    ):
        return
    pending_id = tracking["task_tokens"].get(expr.func.value.id)
    if pending_id is None:
        return
    tracking["pending_work"].pop(pending_id, None)
    tracking["task_tokens"] = {
        task_name: task_pending_id
        for task_name, task_pending_id in tracking["task_tokens"].items()
        if task_pending_id != pending_id
    }
    _refresh_asyncio_pending_loop_ids(tracking)


def _track_asyncio_loop_schedule(
    node,
    scan_state,
    operator_bindings,
    *,
    conditional=False,
):
    """Track scheduled mutators and executions across event-loop aliases."""
    tracking = _asyncio_loop_schedule_tracking(scan_state)
    _record_asyncio_loop_alias_assignment(
        node,
        tracking,
        operator_bindings,
        conditional=conditional,
    )
    _drop_rebound_asyncio_task_aliases(node, tracking)
    _record_asyncio_task_cancel(
        node,
        tracking,
        conditional=conditional,
    )

    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call):
        return False

    if _call_schedules_mutating_callback_on_loop(expr, operator_bindings):
        loop_ids = _asyncio_receiver_loop_ids(
            expr.func.value,
            tracking,
            operator_bindings,
        )
        _record_asyncio_pending_work(
            node,
            expr,
            tracking,
            loop_ids,
        )
        if expr.func.attr == "create_task":
            return False

    if not isinstance(expr.func, ast.Attribute):
        return False
    if expr.func.attr not in {"run_until_complete", "run_forever"}:
        return False
    receiver_ids = _asyncio_receiver_loop_ids(
        expr.func.value,
        tracking,
        operator_bindings,
    )
    return bool(receiver_ids.intersection(tracking["pending_loop_ids"]))

def _next_iter_callback_source_mutates(inner, tracking, operator_bindings):
    """Return True for next(iter(callback_source)) when its result is invoked."""
    if not _builtin_call_is_active(inner, "next", operator_bindings):
        return False
    if len(inner.args) != 1 or inner.keywords:
        return False
    iterator = inner.args[0]
    if not _builtin_call_is_active(iterator, "iter", operator_bindings):
        return False
    if len(iterator.args) != 1 or iterator.keywords:
        return False

    source = iterator.args[0]
    if isinstance(source, ast.Name):
        return source.id in tracking["mutating"]
    return _iterable_literal_contains_mutating_lambda(
        source,
        operator_bindings,
    )


def _sync_callback_sched_run_mutates(expr, tracking):
    """Return True for ``scheduler.run(...)`` on a mutating sched container."""
    if not (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "run"
    ):
        return False
    receiver = expr.func.value
    if not isinstance(receiver, ast.Name):
        return False
    return (
        receiver.id in tracking["mutating"]
        and tracking["containers"].get(receiver.id) == "sched"
    )


def _sync_callback_iterator_next_invocation_mutates(inner, tracking):
    """Return True for ``iterator.__next__()()`` callback execution."""
    if not (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Attribute)
        and inner.func.attr == "__next__"
        and not inner.args
        and not inner.keywords
    ):
        return False
    receiver = inner.func.value
    if not isinstance(receiver, ast.Name) or receiver.id not in tracking["mutating"]:
        return False
    return tracking["containers"].get(receiver.id) == "callback_iter"


def _sync_callback_pop_result_invocation_mutates(inner, tracking):
    """Return True for ``container.pop(...)()`` callback execution."""
    if not (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Attribute)
        and inner.func.attr == "pop"
    ):
        return False
    receiver = inner.func.value
    if not isinstance(receiver, ast.Name) or receiver.id not in tracking["mutating"]:
        return False
    kind = tracking["containers"].get(receiver.id)
    if kind not in {"list", "deque", "userlist"}:
        return False
    return len(inner.args) <= 1 and not inner.keywords


def _sync_callback_zero_arg_subscript_invocation(expr):
    """Return inner accessor call and literal index for ``accessor()[index]()``."""
    if not (
        isinstance(expr, ast.Call)
        and not expr.args
        and not expr.keywords
        and isinstance(expr.func, ast.Subscript)
        and isinstance(expr.func.value, ast.Call)
    ):
        return None, None
    index_node = expr.func.slice
    index = (
        index_node.value
        if isinstance(index_node, ast.Constant)
        and isinstance(index_node.value, int)
        and not isinstance(index_node.value, bool)
        else None
    )
    return expr.func.value, index


def _sync_callback_heap_heappop_subscript_mutates(expr, tracking):
    """Return True for ``heapq.heappop(heap)[1]()`` callback execution."""
    heappop_call, selected_index = _sync_callback_zero_arg_subscript_invocation(expr)
    if heappop_call is None or selected_index is None:
        return False
    if not (
        isinstance(heappop_call.func, ast.Attribute)
        and heappop_call.func.attr == "heappop"
        and isinstance(heappop_call.func.value, ast.Name)
        and heappop_call.func.value.id in tracking["heapq_modules"]
        and len(heappop_call.args) == 1
        and isinstance(heappop_call.args[0], ast.Name)
    ):
        return False
    heap_name = heappop_call.args[0].id
    return (
        heap_name in tracking["mutating"]
        and tracking["containers"].get(heap_name) == "heap"
        and selected_index
        in tracking["mutating_subscript_indexes"].get(heap_name, set())
    )


def _sync_callback_deque_subscript_invocation_mutates(expr, tracking):
    """Return True for ``deque[index]()`` callback execution on a mutating deque."""
    if not (
        isinstance(expr, ast.Call)
        and not expr.args
        and not expr.keywords
        and isinstance(expr.func, ast.Subscript)
        and isinstance(expr.func.value, ast.Name)
    ):
        return False
    receiver = expr.func.value.id
    if receiver not in tracking["mutating"]:
        return False
    return tracking["containers"].get(receiver) == "deque"


def _sync_callback_queue_get_subscript_mutates(expr, tracking):
    """Return True for ``queue.get()[1]()`` PriorityQueue callback execution."""
    get_call, selected_index = _sync_callback_zero_arg_subscript_invocation(expr)
    if (
        get_call is None
        or selected_index is None
        or not isinstance(get_call.func, ast.Attribute)
    ):
        return False
    receiver = get_call.func.value
    if not isinstance(receiver, ast.Name) or receiver.id not in tracking["mutating"]:
        return False
    if tracking["containers"].get(receiver.id) != "queue":
        return False
    method = get_call.func.attr
    if method not in {"get", "get_nowait"}:
        return False
    return (
        selected_index
        in tracking["mutating_subscript_indexes"].get(receiver.id, set())
        and _sync_callback_accessor_arguments_are_valid(
            get_call,
            "queue",
            method,
        )
    )


def _record_sync_callback_cancel(node, tracking):
    """Remove a proven mutating scheduler event canceled before run()."""
    expr = _statement_value_expression(node)
    if not (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "cancel"
        and len(expr.args) == 1
        and not expr.keywords
        and isinstance(expr.func.value, ast.Name)
        and isinstance(expr.args[0], ast.Name)
    ):
        return
    scheduler_name = expr.func.value.id
    if tracking["containers"].get(scheduler_name) != "sched":
        return
    event_data = tracking["sched_event_ids"].get(expr.args[0].id)
    if event_data is None or event_data[0] != scheduler_name:
        return
    event_id = event_data[1]
    pending = tracking["sched_pending_events"].get(scheduler_name, set())
    pending.discard(event_id)
    tracking["sched_event_ids"] = {
        event_name: known_event
        for event_name, known_event in tracking["sched_event_ids"].items()
        if known_event != event_data
    }
    if not pending:
        tracking["sched_pending_events"].pop(scheduler_name, None)
        tracking["mutating"].discard(scheduler_name)


def _sync_callback_direct_dispatch_mutates(expr, tracking):
    """Return True for zero-argument direct container callback dispatch."""
    checks = (
        _sync_callback_heap_heappop_subscript_mutates(expr, tracking),
        _sync_callback_deque_subscript_invocation_mutates(expr, tracking),
        _sync_callback_queue_get_subscript_mutates(expr, tracking),
    )
    return any(checks)


def _sync_callback_dispatch_mutates(node, tracking, operator_bindings):
    """Return True only for proven synchronous execution of a mutating callback."""
    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call):
        return False
    if _sync_callback_sched_run_mutates(expr, tracking):
        return True
    if expr.args or expr.keywords:
        return False
    if _sync_callback_direct_dispatch_mutates(expr, tracking):
        return True
    inner = expr.func
    if not isinstance(inner, ast.Call):
        return False
    if _sync_callback_pop_result_invocation_mutates(inner, tracking):
        return True
    if _sync_callback_iterator_next_invocation_mutates(inner, tracking):
        return True

    if _next_iter_callback_source_mutates(
        inner,
        tracking,
        operator_bindings,
    ):
        return True

    if _sync_callback_getattr_dispatch_mutates(inner, tracking, operator_bindings):
        return True

    if not isinstance(inner.func, ast.Attribute):
        return False
    receiver = inner.func.value
    if not isinstance(receiver, ast.Name) or receiver.id not in tracking["mutating"]:
        return False

    kind = tracking["containers"].get(receiver.id)
    method = inner.func.attr
    dispatch_methods = {
        "queue": {"get", "get_nowait"},
        "deque": {"pop", "popleft"},
        "list": {"pop"},
        "userlist": {"pop"},
        "sched": {"run"},
    }
    return (
        method in dispatch_methods.get(kind, set())
        and _sync_callback_accessor_arguments_are_valid(inner, kind, method)
    )


def _track_sync_callback_dispatch(node, scan_state, operator_bindings):
    """Update container tracking and report proven synchronous callback execution."""
    tracking = _sync_callback_tracking(scan_state)
    _record_sync_callback_imports(node, tracking)
    _record_sync_callback_cancel(node, tracking)
    dispatch_mutates = _sync_callback_dispatch_mutates(
        node,
        tracking,
        operator_bindings,
    )
    _record_sync_callback_assignment(node, tracking, operator_bindings)
    _record_sync_callback_insert(node, tracking, operator_bindings)
    return dispatch_mutates


def _compound_statement_blocks(node):
    """Yield statement lists from compound statement bodies."""
    if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
        yield node.body
        yield node.orelse
    elif isinstance(node, (ast.With, ast.AsyncWith)):
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
    attrgetter_aliases,
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
            "attrgetter": attrgetter_aliases,
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
    attrgetter_aliases,
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
            attrgetter_aliases,
        )
        for block in _compound_statement_blocks(node):
            _collect_operator_bindings_from_statements(
                block,
                module_aliases,
                setitem_aliases,
                ior_aliases,
                partial_aliases,
                methodcaller_aliases,
                attrgetter_aliases,
            )


def _collect_sys_import_aliases(statements):
    """Collect names introduced by ``import sys`` statements."""
    aliases = {"sys"}
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "sys":
                    aliases.add(imported.asname or imported.name)
        for block in _compound_statement_blocks(node):
            aliases.update(_collect_sys_import_aliases(block))
    return aliases


def _record_functools_reduce_import(node, module_aliases, reduce_aliases):
    """Record functools module and direct reduce aliases from one statement."""
    if isinstance(node, ast.Import):
        _record_relevant_import_aliases(
            node.names,
            {"functools": module_aliases},
        )
        return
    if isinstance(node, ast.ImportFrom) and node.module == "functools":
        _record_relevant_import_aliases(
            node.names,
            {"reduce": reduce_aliases},
        )


def _collect_functools_reduce_aliases(statements):
    """Collect module and direct aliases that prove a ``functools.reduce`` call."""
    module_aliases = set()
    reduce_aliases = set()
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        _record_functools_reduce_import(node, module_aliases, reduce_aliases)
        for block in _compound_statement_blocks(node):
            nested_modules, nested_reduce = _collect_functools_reduce_aliases(block)
            module_aliases.update(nested_modules)
            reduce_aliases.update(nested_reduce)
    return module_aliases, reduce_aliases



def _record_imported_module_aliases(node, module_name, active, events, line):
    """Record aliases introduced by a matching import statement."""
    if not isinstance(node, ast.Import):
        return
    for imported in node.names:
        if imported.name == module_name:
            name = imported.asname or imported.name
            active.add(name)
            events.setdefault(name, []).append((line, True))


def _deactivate_imported_module_alias(name, active, events, line):
    """Deactivate a proven module alias after a definite rebinding."""
    if name in active or name in events:
        active.discard(name)
        events.setdefault(name, []).append((line, False))


def _invalidate_imported_module_aliases(node, active, events, line):
    """Record definite definition/assignment rebindings of module aliases."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        _deactivate_imported_module_alias(node.name, active, events, line)
        return
    for name, _value in _namespace_assignment_values(node):
        _deactivate_imported_module_alias(name, active, events, line)


def _collect_imported_module_alias_events(tree, module_name):
    """Track unconditional module import aliases and later rebindings."""
    events = {}
    active = set()
    for node in tree.body:
        line = getattr(node, 'lineno', 0)
        _record_imported_module_aliases(
            node,
            module_name,
            active,
            events,
            line,
        )
        _invalidate_imported_module_aliases(node, active, events, line)
    return events




def _record_imported_name_aliases(
    node,
    module_name,
    imported_names,
    active,
    events,
    line,
):
    """Record direct-import aliases for selected names from one module."""
    if not isinstance(node, ast.ImportFrom) or node.module != module_name:
        return
    for imported in node.names:
        if imported.name not in imported_names:
            continue
        name = imported.asname or imported.name
        active.add(name)
        events.setdefault(name, []).append((line, True))


def _record_imported_name_alias_propagation(
    node,
    module_aliases,
    imported_names,
    active,
    events,
    line,
):
    """Propagate active imported-name aliases through simple assignments."""
    for name, value in _namespace_assignment_values(node):
        alias_active = (
            isinstance(value, ast.Name)
            and value.id in active
        ) or (
            isinstance(value, ast.Attribute)
            and value.attr in imported_names
            and isinstance(value.value, ast.Name)
            and value.value.id in module_aliases
        )
        if alias_active:
            active.add(name)
            events.setdefault(name, []).append((line, True))


def _collect_imported_name_alias_events(tree, module_name, imported_names):
    """Track selected direct-import aliases and later top-level rebindings."""
    events = {}
    active = set()
    module_aliases = set()
    module_events = {}
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        _record_imported_module_aliases(
            node,
            module_name,
            module_aliases,
            module_events,
            line,
        )
        _record_imported_name_aliases(
            node,
            module_name,
            imported_names,
            active,
            events,
            line,
        )
        _invalidate_imported_module_aliases(node, active, events, line)
        _record_imported_name_alias_propagation(
            node,
            module_aliases,
            imported_names,
            active,
            events,
            line,
        )
        _invalidate_imported_module_aliases(
            node,
            module_aliases,
            module_events,
            line,
        )
    return events


def _collect_literal_string_alias_events(tree):
    """Track top-level names that resolve to literal str or bytes values."""
    events = {}
    active = set()
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _deactivate_imported_module_alias(node.name, active, events, line)
            continue
        for name, value in _namespace_assignment_values(node):
            is_string = (
                isinstance(value, ast.Constant)
                and isinstance(value.value, (str, bytes))
            ) or (
                isinstance(value, ast.Name)
                and value.id in active
            )
            if is_string:
                active.add(name)
                events.setdefault(name, []).append((line, True))
            else:
                _deactivate_imported_module_alias(name, active, events, line)
    return events


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
    builtin_shadow_lines = {
        name: _collect_definite_name_shadow_line(tree, name)
        for name in {
            'globals', 'getattr', 'object', 'staticmethod', 'classmethod', 'property',
            'type', 'sorted', 'list', 'tuple', 'set', 'frozenset', 'any',
            'all', 'max', 'min', 'next', 'map', 'filter', 'enumerate', 'zip',
            'iter', 'reversed', 'vars', 'sum',
        }
    }
    builtin_shadow_lines = {
        name: line for name, line in builtin_shadow_lines.items() if line is not None
    }
    builtins_aliases = _collect_builtins_aliases(tree)
    builtins_alias_events = _collect_imported_module_alias_events(tree, 'builtins')
    operator_module_alias_events = _collect_imported_module_alias_events(tree, 'operator')
    collections_module_alias_events = _collect_imported_module_alias_events(
        tree,
        'collections',
    )
    collections_consumer_alias_events = _collect_imported_name_alias_events(
        tree,
        'collections',
        {'deque', 'Counter'},
    )
    itertools_module_alias_events = _collect_imported_module_alias_events(
        tree,
        'itertools',
    )
    islice_alias_events = _collect_imported_name_alias_events(
        tree,
        'itertools',
        {'islice'},
    )
    string_literal_alias_events = _collect_literal_string_alias_events(tree)
    threading_module_alias_events = _collect_imported_module_alias_events(
        tree,
        'threading',
    )
    thread_alias_events = _collect_imported_name_alias_events(
        tree,
        'threading',
        {'Thread', 'Timer'},
    )
    dict_shadow_line = _collect_definite_name_shadow_line(tree, 'dict')
    dict_update_aliases = _collect_dict_update_aliases(
        tree,
        dict_shadow_line,
        builtins_aliases,
        builtins_alias_events,
        builtin_shadow_lines,
    )
    dict_ior_aliases = _collect_dict_ior_aliases(tree, dict_shadow_line)
    exec_eval_shadow_lines = _collect_definite_exec_eval_shadow_lines(tree)
    direct_exec_eval_aliases = _collect_builtins_exec_eval_aliases(tree.body, builtins_aliases)
    direct_exec_eval_alias_events = _collect_builtins_exec_eval_alias_events(tree, builtins_aliases)
    importlib_aliases = _collect_importlib_import_module_aliases(tree.body)
    importlib_alias_events = _collect_importlib_import_module_alias_events(tree)
    importlib_module_aliases = _collect_importlib_module_aliases(tree.body)
    importlib_module_alias_events = _collect_importlib_module_alias_events(tree)
    sys_aliases = _collect_sys_import_aliases(tree.body)
    namespace_aliases = _collect_module_namespace_aliases(
        tree,
        sys_aliases=sys_aliases,
        importlib_aliases=importlib_aliases,
        importlib_module_aliases=importlib_module_aliases,
    )
    mutator_aliases = _collect_namespace_mutator_aliases(tree, namespace_aliases)
    partial_workers_setter_aliases = _collect_partial_workers_setter_aliases(
        tree, namespace_aliases, partial_aliases, dict_update_aliases, dict_shadow_line, dict_ior_aliases
    )
    partial_dict_mutator_alias_events = _collect_partial_dict_namespace_mutator_alias_events(
        tree, namespace_aliases, partial_aliases, dict_update_aliases, dict_ior_aliases, dict_shadow_line
    )
    functools_aliases, reduce_aliases = _collect_functools_reduce_aliases(tree.body)
    delegated_update_aliases = _collect_delegated_update_namespace_aliases(tree, namespace_aliases)
    delegated_update_alias_events = _collect_delegated_update_alias_events(tree, namespace_aliases)
    types_module_aliases, functiontype_aliases = _collect_types_functiontype_aliases(tree.body)
    functiontype_namespace_aliases = _collect_functiontype_namespace_aliases(
        tree, namespace_aliases, types_module_aliases, functiontype_aliases
    )
    chainmap_namespace_aliases = _collect_chainmap_namespace_aliases(tree, namespace_aliases)
    return (
        module_aliases, setitem_aliases, namespace_aliases, ior_aliases,
        partial_aliases, mutator_aliases, methodcaller_aliases, dict_update_aliases,
        builtins_aliases, exec_eval_shadow_lines, direct_exec_eval_aliases,
        attrgetter_aliases, partial_workers_setter_aliases, sys_aliases,
        functools_aliases, reduce_aliases, importlib_aliases,
        delegated_update_aliases, direct_exec_eval_alias_events,
        importlib_alias_events, delegated_update_alias_events, dict_shadow_line,
        functiontype_namespace_aliases, dict_ior_aliases, importlib_module_aliases,
        types_module_aliases, functiontype_aliases, partial_dict_mutator_alias_events,
        chainmap_namespace_aliases, importlib_module_alias_events,
        builtins_alias_events, operator_module_alias_events, builtin_shadow_lines,
        collections_module_alias_events, collections_consumer_alias_events,
        itertools_module_alias_events, islice_alias_events,
        string_literal_alias_events, threading_module_alias_events,
        thread_alias_events,
    )





def _node_has_dynamic_workers_effect(
    node,
    global_workers_mutators,
    operator_bindings,
    *,
    class_targets=None,
    dict_subclass_names=None,
):
    """Return True when one statement makes the worker value non-static."""
    if _statement_invokes_function(node, global_workers_mutators):
        return True
    if _statement_has_class_workers_side_effect(node, class_targets):
        return True
    if isinstance(node, ast.For) and _target_assigns_workers(node.target):
        return True
    if _is_dynamic_workers_mutation(
        node,
        operator_bindings,
        dict_subclass_names,
    ):
        return True
    if _import_statement_after_builtins_import_hook(node, operator_bindings):
        return True
    if _statement_calls_dunder_import_after_hook(node, operator_bindings):
        return True
    if _import_statement_after_sys_meta_path_mutation(node, operator_bindings):
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


def _record_direct_workers_assignment(node, state, *, in_compound, operator_bindings=None):
    """Record direct assignments to workers."""
    if _workers_binding_removal(node, operator_bindings) and not in_compound:
        # An unconditional top-level removal is the only shape that provably
        # empties the module namespace, so the stale static count is dropped and
        # the WEB_CONCURRENCY default Gunicorn would actually apply is used.
        state.clear_workers_assignment()
        return
    assigns_workers, value = _worker_assignment_value(node, operator_bindings)
    if assigns_workers:
        state.record_workers_assignment(value, in_compound=in_compound)


def _node_has_worker_mutating_decorator(node, global_workers_mutators):
    """Return True when a function or class decorator mutates workers.

    A decorator is an expression the interpreter evaluates while the ``def``
    or ``class`` statement runs, so ``@f()`` mutates ``workers`` at config
    import exactly like the bare ``@f`` form and must be treated the same.
    """
    return any(
        (
            isinstance(decorator, ast.Name)
            and decorator.id in global_workers_mutators
        )
        or (
            isinstance(decorator, ast.Call)
            and _call_invokes_function(decorator, global_workers_mutators)
        )
        for decorator in node.decorator_list
    )


def _config_defers_annotations(tree):
    """Return True when a return annotation is not evaluated by ``def``.

    PEP 649 defers annotation evaluation on Python 3.14, and
    ``from __future__ import annotations`` does the same on every earlier
    release, so in both cases the annotation never runs while the function
    object is created.
    """
    if sys.version_info >= (3, 14):
        return True
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _definition_time_expressions(node, defer_annotations=False):
    """Return expressions evaluated while a function-like object is created.

    ``def`` evaluates decorators, default arguments and the return annotation
    before the body exists, so a helper called from one of them runs at config
    import. A lambda body is excluded because it only runs when it is called,
    and a deferred return annotation is excluded for the same reason.
    """
    expressions = [*node.args.defaults]
    expressions.extend(
        default for default in node.args.kw_defaults if default is not None
    )
    if defer_annotations:
        return expressions
    returns = getattr(node, "returns", None)  # ast.Lambda has no annotation
    if returns is not None:
        expressions.append(returns)
    return expressions


def _definition_time_workers_effect(
    node,
    global_workers_mutators,
    operator_bindings,
    class_targets,
    dict_subclass_names,
    defer_annotations=False,
):
    """Return True when a definition-time expression mutates the worker count."""
    return any(
        _expression_invokes_function(expression, global_workers_mutators)
        or _node_has_dynamic_workers_effect(
            expression,
            global_workers_mutators,
            operator_bindings,
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
        )
        for expression in _definition_time_expressions(node, defer_annotations)
    )


def _worker_scan_defaults(
    global_workers_mutators,
    operator_bindings,
    class_targets,
    dict_subclass_names,
):
    """Return normalized optional inputs for the recursive worker scan."""
    return (
        set() if global_workers_mutators is None else global_workers_mutators,
        (set(), set()) if operator_bindings is None else operator_bindings,
        (set(), set(), set(), set(), {}, set(), {}) if class_targets is None else class_targets,
        {} if dict_subclass_names is None else dict_subclass_names,
    )



def _node_has_workers_walrus(node):
    """Return True when an evaluated walrus expression in ``node`` binds ``workers``.

    Only expressions that actually run while the enclosing definition is created
    count. A ``def`` evaluates its decorators and default arguments at definition
    time but defers its body, and a lambda defers its body while still evaluating
    its defaults, so ``cb = lambda x=(workers := 2): None`` binds module-level
    ``workers`` even though ``lambda: (workers := 2)`` never does.

    A generator expression defers everything except its outermost iterable:
    ``(x for x in range((workers := 4)))`` binds ``workers`` when the generator
    object is created, while ``((workers := 4) for _ in ())`` does not bind it
    unless the generator is actually iterated.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        expressions = [
            *getattr(node, "decorator_list", ()),
            *_definition_time_expressions(node),
        ]
        return any(_node_has_workers_walrus(expression) for expression in expressions)
    if isinstance(node, ast.GeneratorExp):
        return _node_has_workers_walrus(node.generators[0].iter)
    if isinstance(node, ast.NamedExpr) and _target_assigns_workers(node.target):
        return True
    return any(_node_has_workers_walrus(child) for child in ast.iter_child_nodes(node))


def _class_body_statement_assigns_workers(node):
    """Return True when the statement binds the bare name ``workers``."""
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    elif isinstance(node, ast.For):
        targets = [node.target]
    else:
        targets = []
    if any(_target_assigns_workers(target) for target in targets):
        return True
    return _node_has_workers_walrus(node)


def _class_body_statement_has_dynamic_workers_effect(
    node,
    global_workers_mutators,
    operator_bindings,
    class_targets,
    dict_subclass_names,
    defer_annotations,
    global_workers_declared=False,
    bound_names=None,
):
    """Return True when one class-body statement mutates the module ``workers``.

    A class body has its own namespace: plain assignments, ``for`` targets and
    imports bind class-local names and only reach the module value after an
    applicable ``global workers`` declaration. Calls and proven
    module-namespace mutations (``globals()``, namespace mappings, risky class
    hooks) always count.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _node_has_worker_mutating_decorator(
            node,
            global_workers_mutators,
        ) or _definition_time_workers_effect(
            node,
            global_workers_mutators,
            operator_bindings,
            class_targets,
            dict_subclass_names,
            defer_annotations,
        )
    if isinstance(node, ast.ClassDef):
        return (
            _node_has_worker_mutating_decorator(
                node,
                global_workers_mutators,
            )
            or _classdef_has_import_time_workers_side_effect(
                node,
                class_targets,
            )
            or _class_body_has_dynamic_workers_effect(
                node.body,
                global_workers_mutators,
                operator_bindings,
                class_targets,
                dict_subclass_names,
                defer_annotations,
            )
        )
    if global_workers_declared and _class_body_statement_assigns_workers(node):
        return True
    if _statement_invokes_function(node, global_workers_mutators):
        return True
    if _statement_has_class_workers_side_effect(node, class_targets):
        return True
    if _is_dynamic_workers_mutation(
        node,
        operator_bindings,
        dict_subclass_names,
        bound_names,
    ):
        return True
    if _import_statement_after_builtins_import_hook(node, operator_bindings):
        return True
    if _statement_calls_dunder_import_after_hook(node, operator_bindings):
        return True
    if _import_statement_after_sys_meta_path_mutation(node, operator_bindings):
        return True
    return any(
        _class_body_has_dynamic_workers_effect(
            block,
            global_workers_mutators,
            operator_bindings,
            class_targets,
            dict_subclass_names,
            defer_annotations,
            global_workers_declared,
            bound_names,
        )
        for block in _compound_statement_blocks(node)
    )


def _statement_bound_names(node):
    """Return names bound by one statement in its enclosing scope."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    names = _statement_scope_bound_names(node)
    names.update(_import_bound_names(node))
    return names


def _class_body_has_dynamic_workers_effect(
    statements,
    global_workers_mutators,
    operator_bindings,
    class_targets,
    dict_subclass_names,
    defer_annotations=False,
    global_workers_declared=False,
    bound_names=None,
):
    """Return True when class-body statements mutate the module ``workers`` name.

    A class body runs while the ``class`` statement executes at config import,
    so ``globals()['workers'] = 4`` inside one must make the config dynamic,
    while a plain ``workers = 4`` class attribute only binds a class name.
    Earlier class-body bindings shadow module globals for later statements,
    which keeps a class-local ``sum = ...`` from reading as the builtin.
    """
    declared = global_workers_declared
    local_names = set() if bound_names is None else set(bound_names)
    for node in statements:
        if isinstance(node, ast.Global) and "workers" in node.names:
            declared = True
            continue
        if _class_body_statement_has_dynamic_workers_effect(
            node,
            global_workers_mutators,
            operator_bindings,
            class_targets,
            dict_subclass_names,
            defer_annotations,
            declared,
            local_names,
        ):
            return True
        local_names.update(_statement_bound_names(node))
    return False


def _handle_worker_scan_definition(
    node,
    state,
    global_workers_mutators,
    class_targets,
    operator_bindings,
    dict_subclass_names,
    defer_annotations=False,
):
    """Handle definitions without descending into function or class bodies."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if (
            _node_has_worker_mutating_decorator(
                node,
                global_workers_mutators,
            )
            or _definition_time_workers_effect(
                node,
                global_workers_mutators,
                operator_bindings,
                class_targets,
                dict_subclass_names,
                defer_annotations,
            )
            or _node_has_workers_walrus(node)
        ):
            state.dynamic = True
        return True
    if not isinstance(node, ast.ClassDef):
        return False
    if (
        _node_has_worker_mutating_decorator(node, global_workers_mutators)
        or _classdef_has_import_time_workers_side_effect(node, class_targets)
        or _class_body_has_dynamic_workers_effect(
            node.body,
            global_workers_mutators,
            operator_bindings,
            class_targets,
            dict_subclass_names,
            defer_annotations,
        )
    ):
        state.dynamic = True
    return True


def _walk_gunicorn_workers_statements(
    statements,
    state,
    *,
    in_compound: bool,
    global_workers_mutators=None,
    operator_bindings=None,
    class_targets=None,
    dict_subclass_names=None,
    defer_annotations: bool = False,
) -> None:
    (
        global_workers_mutators,
        operator_bindings,
        class_targets,
        dict_subclass_names,
    ) = _worker_scan_defaults(
        global_workers_mutators,
        operator_bindings,
        class_targets,
        dict_subclass_names,
    )

    for node in statements:
        if _handle_worker_scan_definition(
            node,
            state,
            global_workers_mutators,
            class_targets,
            operator_bindings,
            dict_subclass_names,
            defer_annotations,
        ):
            continue
        if _track_sync_callback_dispatch(node, state, operator_bindings):
            state.dynamic = True
        if _track_asyncio_loop_schedule(
            node,
            state,
            operator_bindings,
            conditional=in_compound,
        ):
            state.dynamic = True
        if _node_has_dynamic_workers_effect(
            node,
            global_workers_mutators,
            operator_bindings,
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
        ):
            state.dynamic = True
        if _node_has_workers_walrus(node):
            state.dynamic = True
        _record_walrus_workers_assignment(
            node,
            state,
            in_compound=in_compound,
        )
        _record_direct_workers_assignment(
            node,
            state,
            in_compound=in_compound,
            operator_bindings=operator_bindings,
        )
        for block in _compound_statement_blocks(node):
            _walk_gunicorn_workers_statements(
                block,
                state,
                in_compound=True,
                global_workers_mutators=global_workers_mutators,
                operator_bindings=operator_bindings,
                class_targets=class_targets,
                dict_subclass_names=dict_subclass_names,
                defer_annotations=defer_annotations,
            )


# Gunicorn runs the config file and installs every name in the module namespace
# that matches a setting, so any of these hooks can raise the worker count after
# the gate read a static ``workers = 1``. Derived from the "Server Hooks" section
# of the pinned Gunicorn release (gunicorn==26.2.0, gunicorn/config.py) rather
# than hand-curated, so a hook cannot be missed by omission. ``configure`` is not
# a Gunicorn setting in any supported release; it is kept because the gate has
# always failed closed on it and dropping it would only widen acceptance.
_GUNICORN_RUNTIME_HOOK_NAMES = frozenset(
    {
        "configure",
        "child_exit",
        "nworkers_changed",
        "on_exit",
        "on_reload",
        "on_starting",
        "post_fork",
        "post_request",
        "post_worker_init",
        "pre_exec",
        "pre_fork",
        "pre_request",
        "ssl_context",
        "when_ready",
        "worker_abort",
        "worker_exit",
        "worker_int",
    }
)


# Calls that can obtain a callable the config file never names, matched both as
# a bare name (``getattr(ns, "helper")``) and as an attribute
# (``operator.attrgetter("helper")``, ``pickle.loads(stream)``). They are what
# stops the walk from treating an unreferenced function as one that can never
# run, so every one of them keeps the hook detection fail-closed.
_DYNAMIC_NAME_LOOKUP_CALLS = frozenset(
    {
        "__import__",
        "attrgetter",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "import_module",
        "importlib",
        "itemgetter",
        "load",
        "loads",
        "locals",
        "methodcaller",
        "setattr",
        "vars",
    }
)

# Modules whose calls launder a name the config file never writes down: the
# accessor and deserialisation factories, and the namespace registries.
_DYNAMIC_NAME_LOOKUP_MODULES = frozenset(
    {
        "builtins",
        "ctypes",
        "dill",
        "importlib",
        "marshal",
        "operator",
        "pickle",
        "shelve",
        "sys",
    }
)

# Attributes that hand back a namespace the file can then reach into by key.
_NAMESPACE_ESCAPE_ATTRS = frozenset(
    {
        "__bases__",
        "__builtins__",
        "__class__",
        "__dict__",
        "__func__",
        "__getattribute__",
        "__globals__",
        "__import__",
        "__loader__",
        "__mro__",
        "__name__",
        "__reduce__",
        "__reduce_ex__",
        "__self__",
        "__spec__",
        "__subclasses__",
        "modules",
    }
)


def _class_body_global_names(node):
    """Return the names a class body binds to the module scope via ``global``.

    ``global`` is legal in a class body, and a name it declares keeps binding
    into the module namespace rather than becoming a class attribute. The same
    is true inside the methods of that class, so the walk over the whole class
    body collects them too; the wider set can only make the gate fail closed.
    """
    return frozenset(
        name
        for child in ast.walk(node)
        if isinstance(child, ast.Global)
        for name in child.names
    )


def _is_current_module_namespace_object(node, namespace_aliases=None):
    """Return True for a mapping/object that is this config module's namespace."""
    return _is_module_namespace_mapping(
        node, namespace_aliases
    ) or _namespace_aliases_reference_current_module(node, namespace_aliases)


def _hook_mapping_payload_may_bind(node):
    """Return True when a mapping payload may bind a runtime hook name."""
    if isinstance(node, ast.Dict):
        for key in node.keys:
            if key is None:
                return True
            if not isinstance(key, ast.Constant):
                return True
            if key.value in _GUNICORN_RUNTIME_HOOK_NAMES:
                return True
        return False
    return True


def _hook_store_target_name(target, namespace_aliases=None):
    """Return the hook name an attribute/subscript store binds, if any."""
    if isinstance(target, ast.Attribute):
        if not _is_current_module_namespace_object(target.value, namespace_aliases):
            return None
        return target.attr
    if isinstance(target, ast.Subscript):
        if not _is_current_module_namespace_object(target.value, namespace_aliases):
            return None
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        # A computed key cannot be proven different from a hook name.
        return "*"
    return None


def _hook_store_key_name(key):
    """Return a constant key, or ``"*"`` for a computed key that may be one."""
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return "*"


def _setattr_binds_hook_name(call, namespace_aliases):
    """Return a hook name a bare ``setattr`` call may bind, if any."""
    if len(call.args) < 2:
        return None
    if not _is_current_module_namespace_object(call.args[0], namespace_aliases):
        return None
    return _hook_store_key_name(call.args[1])


def _method_binds_hook_name(call, receiver, namespace_aliases):
    """Return a hook name a namespace method call may bind, if any."""
    if not _is_current_module_namespace_object(receiver, namespace_aliases):
        return None
    method = call.func.attr
    if method in ("__setattr__", "__setitem__", "setdefault"):
        if not call.args:
            return None
        return _hook_store_key_name(call.args[0])
    if method != "update":
        return None
    if any(_hook_mapping_payload_may_bind(arg) for arg in call.args):
        return "*"
    for keyword in call.keywords:
        if keyword.arg is None:
            return "*"
        if keyword.arg in _GUNICORN_RUNTIME_HOOK_NAMES:
            return keyword.arg
    return None


def _call_binds_hook_name(call, namespace_aliases=None):
    """Return a hook name a call binds into the config namespace, if any."""
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    if isinstance(func, ast.Name) and func.id == "setattr":
        return _setattr_binds_hook_name(call, namespace_aliases)
    if not isinstance(func, ast.Attribute):
        return None
    return _method_binds_hook_name(call, func.value, namespace_aliases)


def _import_from_bound_names(child):
    """Return the names a ``from x import ...`` statement binds."""
    names = []
    for alias in child.names:
        if alias.name == "*":
            names.append("*")
        else:
            names.append(alias.asname or alias.name)
    return tuple(names)


def _single_hook_binding(name, explicit):
    """Return a one-name binding result, or an empty one when there is none."""
    if name is None:
        return (), False
    return (name,), explicit


def _gunicorn_hook_binding_names(child, namespace_aliases=None):
    """Return ``(hook names, explicit)`` a node may bind into the module namespace.

    ``explicit`` marks bindings that target the module namespace directly
    (attribute/subscript stores and ``setattr``/``update`` calls); those count
    even in a class body, where an ordinary name binding would only reach the
    class namespace.
    """
    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return (child.name,), False
    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
        return (child.id,), False
    if isinstance(child, ast.ImportFrom):
        return _import_from_bound_names(child), False
    if isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
        child.ctx, ast.Store
    ):
        return _single_hook_binding(
            _hook_store_target_name(child, namespace_aliases), True
        )
    if isinstance(child, ast.Call):
        return _single_hook_binding(
            _call_binds_hook_name(child, namespace_aliases), True
        )
    return (), False


def _hook_binding_name_is_live(child, name, explicit, scope):
    """Return True when one bound hook name reaches the module namespace."""
    in_class, declared_globals, may_run, in_function = scope
    if explicit:
        # An explicit module-namespace mutation reaches the module regardless
        # of the class scope; only whether the enclosing body can run matters.
        return may_run
    if isinstance(child, ast.ImportFrom):
        # An import inside a class body or function binds a class attribute or
        # local, not a module name, unless the name was declared `global`;
        # only a module-level import reaches Gunicorn.
        if in_class or in_function:
            return name in declared_globals
        return may_run
    if in_class:
        return name in declared_globals
    return may_run


def _is_live_gunicorn_hook_binding(child, scope, namespace_aliases=None):
    """Return True when a node binds a hook name into the module namespace.

    A hook is live whenever the name reaches the module namespace, so a ``def``
    nested in any block and a binding of any kind count just like a top-level
    ``def``; anything else would let the hook bypass the fail-closed signal.
    Bindings include imports (``from hooks import when_ready``), ``setattr``
    calls, and attribute/subscript stores on the config module namespace; a
    ``from x import *`` may bind any hook and counts fail-closed. What does not
    reach the module namespace is the exception: a binding in a class body
    binds a class attribute, and a store or import in a function body binds a
    local. ``scope`` is ``(in_class, declared_globals, may_run, in_function)``;
    inside a class body an ordinary binding counts only when a ``global`` in
    that class promoted it, an import inside a function counts only when the
    name was declared ``global``, and an explicit module-namespace mutation
    counts whenever the enclosing body can run.
    """
    names, explicit = _gunicorn_hook_binding_names(child, namespace_aliases)
    for name in names:
        if name != "*" and name not in _GUNICORN_RUNTIME_HOOK_NAMES:
            continue
        if _hook_binding_name_is_live(child, name, explicit, scope):
            return True
    return False


def _gunicorn_hook_binding_scope(child, scope, uncalled_names):
    """Return the binding scope that applies to the nodes inside ``child``.

    A class body runs when the file is loaded, so it opens a scope of its own
    that its methods inherit untouched: a method body is judged by the class
    rule, never by the function rule. Every other node keeps the scope it is
    already in, which is what makes a ``def`` in a plain block bind at module
    scope. Entering a function outside a class is what consults
    ``uncalled_names``: a body no reference can reach cannot run, and a hook
    bound in it never reaches the module namespace.
    """
    in_class, declared_globals, may_run, _ = scope
    if isinstance(child, ast.ClassDef):
        return (True, _class_body_global_names(child), True, False)
    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if in_class:
            return scope
        return (
            False,
            declared_globals,
            may_run and child.name not in uncalled_names,
            True,
        )
    return scope


def _is_dynamic_lookup_call(node):
    """Return True when a call can build a callable out of a string."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _DYNAMIC_NAME_LOOKUP_CALLS
    if not isinstance(func, ast.Attribute):
        return False
    return func.attr in _DYNAMIC_NAME_LOOKUP_CALLS or (
        isinstance(func.value, ast.Name)
        and func.value.id in _DYNAMIC_NAME_LOOKUP_MODULES
    )


def _is_namespace_escape_attr(node):
    """Return True when an attribute read exposes a namespace mapping."""
    return isinstance(node, ast.Attribute) and node.attr in _NAMESPACE_ESCAPE_ATTRS


def _is_string_keyed_subscript(node):
    """Return True when a subscript reads a key the file spells as a string.

    A string key is the only way to pull one member out of a mapping without a
    name load naming it, so ``d["helper"]`` -- whether it calls the value or
    stores it for later dispatch -- counts for the guard as much as
    ``sys.modules[__name__].__dict__["helper"]`` does. The container need not
    look like a namespace at all: ``ctypes.cast(id(mod), ctypes.py_object)
    .value["helper"]`` spells no dunder anywhere.
    """
    if not isinstance(node, ast.Subscript):
        return False
    index = node.slice.elts if isinstance(node.slice, ast.Tuple) else (node.slice,)
    return any(
        isinstance(key, ast.Constant) and isinstance(key.value, str) for key in index
    )


def _uses_dynamic_name_lookup(tree):
    """Return True when the file can reach a callable without naming it.

    ``eval``, ``exec``, ``getattr`` and the namespace accessors can call a
    function this walk can prove nothing else calls, and so can the two forms
    that never spell a name at all: reading a namespace attribute, and reading
    a mapping key out of a string literal. Any of the three voids the
    inert-function proof below, because a hook bound in a function the file
    only ever names as ``d["helper"]`` still runs.
    """
    return any(
        _is_dynamic_lookup_call(node)
        or _is_namespace_escape_attr(node)
        or _is_string_keyed_subscript(node)
        for node in ast.walk(tree)
    )


def _provably_uncalled_function_names(tree):
    """Return the names of functions the config file never references.

    Any load of the name counts as a reference, including the forms this walk
    cannot follow -- ``callbacks.append(helper)``, ``class X(helper)``,
    ``register(helper)`` -- so a function that no load mentions is the only
    shape whose body provably cannot run, and a hook bound there is not a module
    binding. A file that looks names up dynamically references everything, so it
    proves nothing and the walk stays fail-closed.
    """
    if _uses_dynamic_name_lookup(tree):
        return frozenset()
    referenced = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    } | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name not in referenced
    )


def _gunicorn_config_has_runtime_hooks(tree, namespace_aliases=None):
    """Return True when the config defines hooks that can mutate workers at runtime.

    Walks every node; ``_is_live_gunicorn_hook_binding`` decides which bindings
    count, and ``_gunicorn_hook_binding_scope`` carries the enclosing binding
    scope into the nodes below it. ``namespace_aliases`` resolves aliases such
    as ``namespace = globals()`` so hook stores through them are recognized.
    """
    uncalled_names = _provably_uncalled_function_names(tree)
    stack = [(tree, (False, frozenset(), True, False))]
    while stack:
        node, scope = stack.pop()
        for child in ast.iter_child_nodes(node):
            if _is_live_gunicorn_hook_binding(child, scope, namespace_aliases):
                return True
            stack.append(
                (child, _gunicorn_hook_binding_scope(child, scope, uncalled_names))
            )
    return False


def _scan_gunicorn_config_worker_details(tree):
    """Return configured count, assignment dynamism, and runtime-hook dynamism."""
    state = _GunicornWorkersScanState()
    operator_bindings = _collect_operator_setitem_bindings(tree)
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    runtime_dynamic = _gunicorn_config_has_runtime_hooks(tree, namespace_aliases)
    operator_call_alias_events = _collect_imported_name_alias_events(
        tree,
        "operator",
        {"call"},
    )
    operator_bindings[32][_OPERATOR_CALL_ALIAS_EVENTS_KEY] = (
        operator_call_alias_events
    )
    (
        callback_alias_events,
        callback_container_events,
    ) = _collect_mutating_callback_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings[32][_MUTATING_CALLBACK_ALIAS_EVENTS_KEY] = (
        callback_alias_events
    )
    operator_bindings[32][_MUTATING_CALLBACK_CONTAINER_EVENTS_KEY] = (
        callback_container_events
    )
    operator_bindings[32][_CONTEXTLIB_MODULE_ALIAS_EVENTS_KEY] = (
        _collect_imported_module_alias_events(tree, "contextlib")
    )
    operator_bindings[32][_EXIT_STACK_CLASS_ALIAS_EVENTS_KEY] = (
        _collect_imported_name_alias_events(tree, "contextlib", {"ExitStack"})
    )
    operator_bindings[32][_EXIT_STACK_ALIAS_EVENTS_KEY] = (
        _collect_exit_stack_alias_events(tree, operator_bindings)
    )
    operator_bindings[32]["weakref_module_alias_events"] = (
        _collect_imported_module_alias_events(tree, "weakref")
    )
    operator_bindings[32]["weakref_finalize_alias_events"] = (
        _collect_imported_name_alias_events(tree, "weakref", {"finalize"})
    )
    operator_bindings[32]["warnings_module_alias_events"] = (
        _collect_imported_module_alias_events(tree, "warnings")
    )
    operator_bindings[32]["warnings_warn_alias_events"] = (
        _collect_imported_name_alias_events(tree, "warnings", {"warn"})
    )
    operator_bindings[32]["builtins_module_alias_events"] = (
        _collect_imported_module_alias_events(tree, "builtins")
    )
    operator_bindings[32]["builtins_dunder_import_replacement_lines"] = (
        _collect_builtins_dunder_import_replacement_lines(tree, operator_bindings)
    )
    operator_bindings[32]["dataclasses_module_alias_events"] = (
        _collect_imported_module_alias_events(tree, "dataclasses")
    )
    operator_bindings[32]["dataclasses_field_alias_events"] = (
        _collect_imported_name_alias_events(tree, "dataclasses", {"field"})
    )
    operator_bindings[32]["dataclasses_dataclass_alias_events"] = (
        _collect_imported_name_alias_events(tree, "dataclasses", {"dataclass"})
    )
    operator_bindings[32]["sys_module_alias_events"] = (
        _collect_imported_module_alias_events(tree, "sys")
    )
    operator_bindings[32]["sys_meta_path_mutation_lines"] = (
        _collect_sys_meta_path_mutation_lines(tree, operator_bindings)
    )
    operator_bindings[32]["sys_getframe_alias_events"] = (
        _collect_imported_name_alias_events(tree, "sys", {"_getframe"})
    )
    lazy_iterator_alias_events = _collect_mutating_lazy_iterator_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        lazy_iterator_alias_events,
    )
    mutating_yield_from_functions = _collect_mutating_yield_from_functions(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        mutating_yield_from_functions,
    )
    mutating_generator_alias_events = _collect_mutating_generator_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        mutating_generator_alias_events,
    )
    (
        thread_pool_class_alias_events,
        thread_pool_module_alias_events,
    ) = _collect_thread_pool_alias_events(tree)
    operator_bindings = (
        *operator_bindings,
        thread_pool_class_alias_events,
        thread_pool_module_alias_events,
    )
    thread_pool_instance_alias_events = (
        _collect_thread_pool_instance_alias_events(
            tree,
            operator_bindings,
        )
    )
    operator_bindings = (
        *operator_bindings,
        thread_pool_instance_alias_events,
    )
    dict_shadow_line = operator_bindings[21] if len(operator_bindings) > 21 else None
    dict_subclass_names = _collect_dict_subclass_names(tree.body, dict_shadow_line)
    class_targets = _collect_class_side_effect_targets(tree, operator_bindings)
    import_time_workers_mutators = _collect_import_time_workers_mutators(
        tree,
        operator_bindings,
        class_targets,
        dict_subclass_names,
    )
    operator_bindings = (
        *operator_bindings,
        import_time_workers_mutators,
    )
    operator_bindings[32]["warnings_showwarning_mutation_events"] = (
        _collect_warnings_showwarning_mutation_events(
            tree,
            operator_bindings,
            import_time_workers_mutators,
        )
    )
    (
        callback_alias_events,
        callback_container_events,
    ) = _collect_mutating_callback_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings[32][_MUTATING_CALLBACK_ALIAS_EVENTS_KEY] = (
        callback_alias_events
    )
    operator_bindings[32][_MUTATING_CALLBACK_CONTAINER_EVENTS_KEY] = (
        callback_container_events
    )
    operator_bindings[32][_CONTEXTLIB_MODULE_ALIAS_EVENTS_KEY] = (
        _collect_imported_module_alias_events(tree, "contextlib")
    )
    operator_bindings[32][_EXIT_STACK_CLASS_ALIAS_EVENTS_KEY] = (
        _collect_imported_name_alias_events(tree, "contextlib", {"ExitStack"})
    )
    operator_bindings[32][_EXIT_STACK_ALIAS_EVENTS_KEY] = (
        _collect_exit_stack_alias_events(tree, operator_bindings)
    )
    asyncio_module_alias_events = _collect_imported_module_alias_events(
        tree,
        "asyncio",
    )
    asyncio_run_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"run"},
    )
    asyncio_to_thread_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"to_thread"},
    )
    asyncio_new_event_loop_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"new_event_loop"},
    )
    asyncio_get_event_loop_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"get_event_loop"},
    )
    asyncio_runner_import_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"Runner"},
    )
    asyncio_gather_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"gather"},
    )
    asyncio_shield_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"shield"},
    )
    asyncio_wait_for_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"wait_for"},
    )
    asyncio_create_task_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"create_task"},
    )
    asyncio_ensure_future_alias_events = _collect_imported_name_alias_events(
        tree,
        "asyncio",
        {"ensure_future"},
    )
    operator_bindings = (
        *operator_bindings,
        asyncio_module_alias_events,
        asyncio_run_alias_events,
        asyncio_to_thread_alias_events,
        asyncio_new_event_loop_alias_events,
        asyncio_get_event_loop_alias_events,
        asyncio_runner_import_alias_events,
        asyncio_gather_alias_events,
        asyncio_shield_alias_events,
        asyncio_wait_for_alias_events,
        asyncio_create_task_alias_events,
        asyncio_ensure_future_alias_events,
    )
    asyncio_loop_factory_alias_events = _collect_asyncio_loop_factory_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        asyncio_loop_factory_alias_events,
    )
    asyncio_event_loop_alias_events = _collect_asyncio_event_loop_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        asyncio_event_loop_alias_events,
    )
    asyncio_runner_alias_events = _collect_asyncio_runner_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        asyncio_runner_alias_events,
    )
    asyncio_wrapper_binding_events = _collect_async_wrapper_binding_events(
        tree,
        operator_bindings,
    )
    operator_bindings = (
        *operator_bindings,
        asyncio_wrapper_binding_events,
    )
    (
        future_class_events,
        future_module_events,
    ) = _collect_future_constructor_alias_events(tree)
    future_analysis = {
        "class_events": future_class_events,
        "module_events": future_module_events,
    }
    future_analysis["instance_events"] = _collect_future_instance_alias_events(
        tree,
        operator_bindings,
        future_analysis,
    )
    future_analysis["completed_instances"] = _collect_future_completed_instances(
        tree,
        operator_bindings,
        future_analysis,
    )
    future_analysis["callback_alias_events"] = _collect_callback_alias_events(
        tree,
        operator_bindings,
    )
    future_analysis["callback_method_events"] = (
        _collect_future_callback_method_alias_events(
            tree,
            operator_bindings,
            future_analysis,
        )
    )
    operator_bindings = (
        *operator_bindings,
        future_analysis,
    )
    inspect_module_alias_events = _collect_imported_module_alias_events(
        tree,
        "inspect",
    )
    inspect_currentframe_alias_events = _collect_imported_name_alias_events(
        tree,
        "inspect",
        {"currentframe"},
    )
    inspect_analysis = {
        "module_alias_events": inspect_module_alias_events,
        "currentframe_alias_events": inspect_currentframe_alias_events,
        "builtin_shadow_lines": (
            operator_bindings[32] if len(operator_bindings) > 32 else {}
        ),
        "stack_alias_events": _collect_imported_name_alias_events(
            tree,
            "inspect",
            {"stack"},
        ),
        "getouterframes_alias_events": _collect_imported_name_alias_events(
            tree,
            "inspect",
            {"getouterframes"},
        ),
        "innerframes_alias_events": _collect_imported_name_alias_events(
            tree,
            "inspect",
            {"innerframes"},
        ),
        "traceback_module_alias_events": _collect_imported_module_alias_events(
            tree,
            "traceback",
        ),
        "walk_stack_alias_events": _collect_imported_name_alias_events(
            tree,
            "traceback",
            {"walk_stack"},
        ),
        "sys_module_alias_events": _collect_imported_module_alias_events(
            tree,
            "sys",
        ),
        "sys_getframe_alias_events": _collect_imported_name_alias_events(
            tree,
            "sys",
            {"_getframe"},
        ),
    }
    inspect_analysis["frameinfo_alias_spans"] = (
        _collect_inspect_frameinfo_alias_spans(
            tree,
            inspect_analysis,
        )
    )
    inspect_analysis["frameinfo_alias_events"] = (
        _collect_inspect_frameinfo_alias_events(
            tree,
            inspect_analysis,
        )
    )
    inspect_analysis["walk_stack_pair_alias_spans"] = (
        _collect_walk_stack_pair_alias_spans(
            tree,
            inspect_analysis,
        )
    )
    inspect_analysis["frame_alias_events"] = _collect_inspect_frame_alias_events(
        tree,
        inspect_analysis,
    )
    operator_bindings = (
        *operator_bindings,
        inspect_analysis,
    )
    if _statements_start_mutating_thread(
        tree.body,
        operator_bindings,
        import_time_workers_mutators,
    ):
        state.dynamic = True
    _walk_gunicorn_workers_statements(
        tree.body,
        state,
        in_compound=False,
        global_workers_mutators=import_time_workers_mutators,
        operator_bindings=operator_bindings,
        class_targets=class_targets,
        dict_subclass_names=dict_subclass_names,
        defer_annotations=_config_defers_annotations(tree),
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
    """Return worker details while preserving an omitted workers setting.

    Explicit ``--config`` values that cannot be inspected (``python:MODULE``,
    missing ``file:PATH``, unreadable files) are treated as dynamic so
    ``memory://`` cannot silently pair with a multi-worker Gunicorn process.
    """
    spec = (config_path or "").strip()
    if spec.startswith("python:"):
        return None, True, True
    path = _resolve_gunicorn_config_path(config_path)
    if path is None:
        return None, True, True
    tree = _parse_gunicorn_config_tree(path)
    if tree is None:
        return None, True, True
    try:
        return _scan_gunicorn_config_worker_details(tree)
    except RecursionError:
        # The expression walks have no depth guard, so an unusually deep
        # expression chain exhausts the stack after ast.parse() succeeded.
        # Same fail-closed verdict as an uninspectable config.
        return None, True, True


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
        if token.startswith("-c") and len(token) > 2:
            # argparse gives ``-c==prod.py`` the value ``=prod.py``, so only the
            # single option separator may be dropped here.
            value = token[2:]
            config_path = value[1:] if value.startswith("=") else value
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


def _gunicorn_relative_config_paths(
    relative: Path, *, fail_closed_if_ambiguous: bool = False
) -> list[Path]:
    """Locate a relative Gunicorn config using launch-directory chdir rules."""
    directories = _gunicorn_launch_directories()
    if not directories:
        return []
    cwd = directories[0]
    try:
        cwd_config = (cwd / relative).resolve()
    except (OSError, RuntimeError):
        cwd_config = None

    pwd_config = None
    if len(directories) > 1:
        try:
            pwd_config = (directories[1] / relative).resolve()
        except (OSError, RuntimeError):
            pwd_config = None
        if (
            pwd_config is not None
            and pwd_config.is_file()
            and _gunicorn_config_chdir_matches(pwd_config, cwd)
        ):
            return [pwd_config]

    cwd_exists = cwd_config is not None and cwd_config.is_file()
    pwd_exists = (
        pwd_config is not None
        and pwd_config.is_file()
        and pwd_config != cwd_config
    )
    if fail_closed_if_ambiguous and cwd_exists and pwd_exists:
        return []
    if cwd_exists:
        return [cwd_config]
    return []


def _default_gunicorn_config_paths() -> list[Path]:
    """Return the implicit config, accepting PWD only when chdir proves it."""
    return _gunicorn_relative_config_paths(Path("gunicorn.conf.py"))


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
        count = _parse_worker_count(os.environ.get(env_key, "").strip())
        if count is not None:
            counts.append(count)
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
