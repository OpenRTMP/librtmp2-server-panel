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
    shadow_line = (shadow_lines or {}).get(name)
    return shadow_line is None or not reference_line or reference_line < shadow_line


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


def _subscript_is_dynamic_exec_eval(func, builtins_aliases):
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
        or _subscript_is_dynamic_exec_eval(func, builtins_aliases)
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
    if isinstance(call.func, ast.Name):
        if call.func.id in saved_aliases:
            return True
        saved_method = _binding_state_at_line(
            partial_mutator_alias_events,
            call.func.id,
            getattr(call, 'lineno', 0),
        )
        if saved_method is not None:
            return _call_payload_may_set_workers(saved_method, call)
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


def _is_operator_call_factory(func, operator_bindings):
    """Return True for a source-valid ``operator.call`` factory."""
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    module_events = operator_bindings[31] if len(operator_bindings) > 31 else {}
    builtin_shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    reference_line = getattr(func, 'lineno', 0)
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



def _call_is_operator_call_namespace_update(call, operator_bindings):
    """Return True for ``operator.call(globals().update, ...)`` mutations."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    setitem_aliases = operator_bindings[1] if len(operator_bindings) > 1 else set()
    module_aliases = operator_bindings[0] if len(operator_bindings) > 0 else set()
    if not _is_operator_call_factory(call.func, operator_bindings):
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





_MUTATING_CALLBACK_ALIAS_EVENTS_KEY = object()


def _mutating_callback_alias_is_active(node, operator_bindings):
    """Return True when a name resolves to a tracked workers-mutating callback."""
    if not isinstance(node, ast.Name):
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    events = shadow_lines.get(_MUTATING_CALLBACK_ALIAS_EVENTS_KEY, {})
    return bool(
        _binding_state_at_line(
            events,
            node.id,
            getattr(node, "lineno", 0),
        )
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
        for element in node.elts
    )


def _collect_mutating_callback_alias_events(tree, operator_bindings):
    """Track top-level names bound to workers-mutating lambdas and their aliases."""
    events = {}
    active = set()

    def scan(statements, *, conditional=False):
        for node in statements:
            line = getattr(node, "lineno", 0)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not conditional:
                    _deactivate_imported_module_alias(
                        node.name,
                        active,
                        events,
                        line,
                    )
                continue

            for name, value in _namespace_assignment_values(node):
                is_mutating = (
                    isinstance(value, ast.Lambda)
                    and _lambda_mutates_workers(value, operator_bindings)
                ) or (
                    isinstance(value, ast.Name)
                    and value.id in active
                )
                if is_mutating:
                    active.add(name)
                    events.setdefault(name, []).append((line, True))
                elif not conditional:
                    _deactivate_imported_module_alias(
                        name,
                        active,
                        events,
                        line,
                    )

            for block in _compound_statement_blocks(node):
                scan(block, conditional=True)

    scan(tree.body)
    return events


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


def _map_or_filter_lambda_mutates_when_consumed(call, operator_bindings):
    """Return True when consuming a map/filter must execute a risky lambda."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        return False
    name = call.func.id
    if name not in {'map', 'filter'} or not call.args:
        return False
    shadow_lines = operator_bindings[32] if len(operator_bindings) > 32 else {}
    if not _name_is_unshadowed_builtin(
        name,
        getattr(call, 'lineno', 0),
        shadow_lines,
    ):
        return False
    lambda_node = call.args[0]
    if not isinstance(lambda_node, ast.Lambda):
        return False
    if _lambda_mutates_workers(lambda_node, operator_bindings):
        return True
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
    if _lambda_invokes_first_positional_param(lambda_node):
        return any(
            _iterable_literal_contains_mutating_lambda(arg, operator_bindings)
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


def _scan_mutating_yield_from_functions(statements, operator_bindings, names):
    """Collect risky generator definitions from import-time compound blocks."""
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _function_has_mutating_yield_from(node, operator_bindings):
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
    if (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _function_has_mutating_yield_from(node, operator_bindings)
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


def _builtin_consumer_is_active(name, call, operator_bindings):
    """Return whether a known eager iterable consumer still resolves to a builtin."""
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


_FUTURE_ANALYSIS_INDEX = 60


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


def _call_is_thread_pool_apply_async_mutation(call, operator_bindings):
    """Return True when apply_async schedules a workers-mutating callback."""
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "apply_async"
    ):
        return False
    constructor = _thread_pool_receiver_constructor(
        call.func.value,
        operator_bindings,
    )
    if constructor is None:
        return False
    task = call.args[0] if call.args else next(
        (
            keyword.value
            for keyword in call.keywords
            if keyword.arg == "func"
        ),
        None,
    )
    if task is None:
        return False
    if _thread_pool_constructor_has_mutating_initializer(
        constructor,
        operator_bindings,
    ):
        return True
    callbacks = [task]
    callbacks.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"callback", "error_callback"}
    )
    return any(
        _thread_pool_callback_mutates_workers(callback, operator_bindings)
        for callback in callbacks
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
_ASYNCIO_LOOP_FACTORY_ALIAS_EVENTS_INDEX = 56
_ASYNCIO_EVENT_LOOP_ALIAS_EVENTS_INDEX = 57
_ASYNCIO_RUNNER_ALIAS_EVENTS_INDEX = 58
_ASYNCIO_WRAPPER_BINDING_EVENTS_INDEX = 59


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
    }
)


def _call_is_special_lazy_iterator_consumer(call, operator_bindings):
    """Return True for non-builtin eager consumers handled specially."""
    return (
        _call_is_thread_pool_constructor_initializer_mutation(
            call,
            operator_bindings,
        )
        or _call_is_thread_pool_map_mutation(call, operator_bindings)
        or _call_is_thread_pool_submit_mutation(call, operator_bindings)
        or _call_is_thread_pool_apply_async_mutation(call, operator_bindings)
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


def _named_builtin_consumes_mutating_lazy_iterator(call, operator_bindings):
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
        )
    ):
        return False
    if (
        name in {"sorted", "max", "min"}
        and _key_lambda_mutates_workers(call, operator_bindings)
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


def _call_consumes_mutating_lazy_iterator(call, operator_bindings):
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


def _call_has_mutating_lambda_argument(call, operator_bindings):
    """Detect callbacks only when the current call actually executes them."""
    return _call_consumes_mutating_lazy_iterator(call, operator_bindings)



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



def _metaclass_init_mutates_workers(class_node, operator_bindings):
    """Return True when a ``type`` subclass hook mutates ``workers``."""
    if not any(
        isinstance(base, ast.Name) and base.id == "type"
        for base in class_node.bases
    ):
        return False
    for stmt in class_node.body:
        if (
            isinstance(stmt, ast.FunctionDef)
            and stmt.name in ("__init__", "__new__")
            and _function_mutates_workers(stmt, operator_bindings)
        ):
            return True
    return False


def _collect_metaclass_definition_mutators(tree, operator_bindings):
    """Return class names whose definition invokes a mutating metaclass."""
    metaclass_names = {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and _metaclass_init_mutates_workers(node, operator_bindings)
    }
    if not metaclass_names:
        return set()
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(
            keyword.arg == "metaclass"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id in metaclass_names
            for keyword in node.keywords
        )
    }


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
    if stmt.name in ("__init__", "__post_init__"):
        constructors.add(class_name)
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
    return False




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
    return risky


def _descriptor_class_names(methods):
    """Return classes whose ``__get__`` hook may mutate ``workers``."""
    return {class_name for class_name, method_name in methods if method_name == "__get__"}


def _record_descriptor_field_assignments(class_node, descriptor_classes, descriptor_fields):
    """Record class attributes instantiated from descriptor classes."""
    for stmt in class_node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not isinstance(stmt.value, ast.Call) or not isinstance(stmt.value.func, ast.Name):
            continue
        if stmt.value.func.id not in descriptor_classes:
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                descriptor_fields.add((class_node.name, target.id))


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
                conditional=True,
            )


def _collect_class_side_effect_targets(tree, operator_bindings):
    """Collect risky class hooks plus source-ordered class bindings."""
    constructors = set()
    methods = set()
    properties = set()
    descriptor_fields = set()
    metaclass_definitions = _collect_metaclass_definition_mutators(
        tree,
        operator_bindings,
    )
    binding_events = {}
    _scan_class_side_effect_bindings(
        tree.body,
        operator_bindings,
        constructors,
        methods,
        properties,
        binding_events,
    )
    descriptor_classes = _descriptor_class_names(methods)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            _record_descriptor_field_assignments(
                node,
                descriptor_classes,
                descriptor_fields,
            )
    return (
        constructors,
        methods,
        properties,
        metaclass_definitions,
        binding_events,
        descriptor_fields,
    )




def _class_binding_is_active(class_targets, class_name, reference_line):
    """Return whether the risky class definition still owns this name."""
    if len(class_targets) < 5:
        return True
    events = class_targets[4]
    if class_name not in events:
        return True
    return bool(_binding_state_at_line(events, class_name, reference_line))


def _expression_triggers_class_workers_side_effect(expr, class_targets):
    """Return True when attribute access or construction runs a mutating class hook."""
    constructors, methods, properties = class_targets[:3]
    descriptor_fields = class_targets[5] if len(class_targets) > 5 else set()
    reference_line = getattr(expr, 'lineno', 0)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        return expr.func.id in constructors and _class_binding_is_active(
            class_targets,
            expr.func.id,
            reference_line,
        )
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and isinstance(expr.func.value, ast.Name)
    ):
        class_name = expr.func.value.id
        return (
            (class_name, expr.func.attr) in methods
            and _class_binding_is_active(class_targets, class_name, reference_line)
        )
    if (
        isinstance(expr, ast.Attribute)
        and isinstance(expr.value, ast.Call)
        and isinstance(expr.value.func, ast.Name)
    ):
        class_name = expr.value.func.id
        if (
            (class_name, expr.attr) in properties
            and _class_binding_is_active(class_targets, class_name, reference_line)
        ):
            return True
        return (
            (class_name, expr.attr) in descriptor_fields
            and _class_binding_is_active(class_targets, class_name, reference_line)
        )
    return False



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
        or _call_is_operator_namespace_ior(expr, operator_bindings)
        or _call_is_getattr_operator_namespace_mutation(expr, operator_bindings)
        or _call_is_operator_attrgetter_namespace_mutation(expr, operator_bindings)
        or _call_is_partial_bound_workers_setitem(expr, operator_bindings)
        or _call_is_known_reduce_lambda_mutation(expr, operator_bindings)
    )


def _call_is_functiontype_namespace_alias(expr, aliases):
    """Return True when a saved FunctionType namespace callable is invoked."""
    return isinstance(expr.func, ast.Name) and expr.func.id in aliases


def _call_has_secondary_worker_mutation(expr, operator_bindings, dict_subclass_names=None):
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
        _call_is_invoked_functiontype_namespace_code(expr, namespace_aliases, types_module_aliases, functiontype_aliases)
        or _call_is_functiontype_namespace_alias(expr, functiontype_namespace_aliases)
        or _call_mutates_workers_via_indirection(expr, operator_bindings)
        or _call_is_chainmap_maps_update(expr, namespace_aliases, chainmap_aliases)
        or _call_is_delegated_simplenamespace_update(expr, delegated_update_aliases, delegated_update_alias_events)
        or _call_is_operator_call_namespace_update(expr, operator_bindings)
        or _call_has_mutating_lambda_argument(expr, operator_bindings)
        or _call_is_type_constructor_side_effect(expr, operator_bindings)
        or _call_is_partial_reduce_namespace_mutation(expr, operator_bindings)
        or _call_is_partial_operator_methodcaller_namespace_update(expr, operator_bindings)
        or _call_is_dict_subclass_update_on_module_namespace(expr, namespace_aliases, dict_subclass_names)
    )



def _call_expression_mutates_workers(expr, operator_bindings, dict_subclass_names=None):
    """Return True when one call expression can mutate module workers."""
    return _call_has_primary_worker_mutation(
        expr,
        operator_bindings,
    ) or _call_has_secondary_worker_mutation(
        expr,
        operator_bindings,
        dict_subclass_names,
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


def _expression_mutates_workers(expr, operator_bindings, dict_subclass_names=None):
    """Return True when an evaluated expression mutates ``workers`` indirectly."""
    if isinstance(expr, ast.Lambda):
        return False
    if _expression_consumes_mutating_lazy_iterator(expr, operator_bindings):
        return True
    if isinstance(expr, ast.Call) and _call_expression_mutates_workers(
        expr,
        operator_bindings,
        dict_subclass_names,
    ):
        return True
    return any(
        _expression_mutates_workers(child, operator_bindings, dict_subclass_names)
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
    return _expression_mutates_workers(lambda_node.body, operator_bindings)


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
        or _call_is_operator_setitem_workers(call, operator_bindings)
        or _call_is_getattr_setitem_workers(call)
        or _call_is_dict_type_setitem_on_module_namespace(call, namespace_aliases, dict_shadow_line)
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
        )
        for case in node.cases
    )


def _is_dynamic_workers_mutation(node, operator_bindings, dict_subclass_names=None):
    """Return True for import-time mutations the AST scan cannot treat as static."""
    if dict_subclass_names is None:
        dict_subclass_names = set()
    namespace_aliases = operator_bindings[2] if len(operator_bindings) > 2 else set()
    if _namespace_mapping_may_gain_workers_via_merge(node, namespace_aliases):
        return True
    if _statement_consumes_mutating_lazy_iterator(node, operator_bindings):
        return True
    if any(
        isinstance(child, ast.expr)
        and _expression_mutates_workers(
            child,
            operator_bindings,
            dict_subclass_names,
        )
        for child in ast.iter_child_nodes(node)
    ):
        return True
    if isinstance(node, ast.Assign):
        return any(
            _indirect_workers_assignment_target(target)
            for target in node.targets
        )
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return _indirect_workers_assignment_target(node.target)
    return _match_guard_mutates_workers(
        node,
        operator_bindings,
        dict_subclass_names,
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
    if _expression_triggers_class_workers_side_effect(expr, class_targets):
        return True
    return any(
        _expression_has_class_workers_side_effect(child, class_targets)
        for child in ast.iter_child_nodes(expr)
        if isinstance(child, ast.AST)
    )


def _statement_has_class_workers_side_effect(node, class_targets):
    """Return True when an evaluated statement expression invokes a risky class hook."""
    if not class_targets or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
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
):
    """Return True when one statement may mutate the module ``workers`` binding."""
    if _statement_invokes_function(node, mutator_names):
        return True
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if _statement_has_class_workers_side_effect(node, class_targets):
        return True
    if _is_dynamic_workers_mutation(node, operator_bindings, dict_subclass_names):
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
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
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
        )
        for node in statements
    )



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
            if _function_mutates_workers(
                node,
                operator_bindings,
                mutators,
                class_targets,
                dict_subclass_names,
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
            "queue_constructors": set(),
            "deque_constructors": set(),
            "containers": {},
            "mutating": set(),
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
    }
    for imported in node.names:
        destination = destinations.get(imported.name)
        if destination is not None:
            destination.add(imported.asname or imported.name)


def _record_sync_callback_direct_imports(node, tracking):
    """Track direct queue/deque constructor aliases."""
    supported = {
        "queue": (
            {"Queue", "LifoQueue", "PriorityQueue", "SimpleQueue"},
            tracking["queue_constructors"],
        ),
        "collections": ({"deque"}, tracking["deque_constructors"]),
    }
    entry = supported.get(node.module)
    if entry is None:
        return
    names, destination = entry
    for imported in node.names:
        if imported.name in names:
            destination.add(imported.asname or imported.name)


def _record_sync_callback_imports(node, tracking):
    """Track queue/deque constructor aliases used for callback containers."""
    if isinstance(node, ast.Import):
        _record_sync_callback_module_imports(node, tracking)
    elif isinstance(node, ast.ImportFrom):
        _record_sync_callback_direct_imports(node, tracking)


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
        if func.id in tracking["queue_constructors"]:
            return "queue"
        if func.id in tracking["deque_constructors"]:
            return "deque"
        return None
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return None
    if (
        func.value.id in tracking["queue_modules"]
        and func.attr in {"Queue", "LifoQueue", "PriorityQueue", "SimpleQueue"}
    ):
        return "queue"
    if func.value.id in tracking["collections_modules"] and func.attr == "deque":
        return "deque"
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


def _record_sync_callback_assignment(node, tracking, operator_bindings):
    """Track proven callback-container instances and definite rebindings."""
    names = _simple_assignment_names(node)
    if not names:
        return

    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
    existing_kind = None
    existing_mutating = False
    if isinstance(value, ast.Name):
        existing_kind = tracking["containers"].get(value.id)
        existing_mutating = value.id in tracking["mutating"]

    kind = existing_kind or _sync_callback_constructor_kind(value, tracking)
    starts_mutating = existing_mutating or (
        kind is not None
        and _sync_callback_value_contains_mutating_lambda(value, operator_bindings)
    )

    for name in names:
        tracking["containers"].pop(name, None)
        tracking["mutating"].discard(name)
        tracking["queue_modules"].discard(name)
        tracking["collections_modules"].discard(name)
        tracking["queue_constructors"].discard(name)
        tracking["deque_constructors"].discard(name)
        if kind is not None:
            tracking["containers"][name] = kind
            if starts_mutating:
                tracking["mutating"].add(name)


def _statement_value_expression(node):
    """Return the import-time expression directly executed by a statement."""
    if isinstance(node, ast.Expr):
        return node.value
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        return node.value
    return None


def _record_sync_callback_insert(node, tracking, operator_bindings):
    """Remember containers that receive a workers-mutating callback."""
    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Attribute):
        return
    receiver = expr.func.value
    if not isinstance(receiver, ast.Name):
        return
    kind = tracking["containers"].get(receiver.id)
    if kind is None or not expr.args:
        return

    method = expr.func.attr
    direct_callback_methods = {
        "queue": {"put", "put_nowait"},
        "deque": {"append", "appendleft"},
        "list": {"append"},
    }
    iterable_callback_methods = {
        "deque": {"extend", "extendleft"},
        "list": {"extend"},
    }

    mutates = False
    if method in direct_callback_methods.get(kind, set()):
        callback = expr.args[0]
        mutates = (
            isinstance(callback, ast.Lambda)
            and _lambda_mutates_workers(callback, operator_bindings)
        )
    elif method in iterable_callback_methods.get(kind, set()):
        mutates = _iterable_literal_contains_mutating_lambda(
            expr.args[0],
            operator_bindings,
        )
    if mutates:
        tracking["mutating"].add(receiver.id)


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
    positional_names = {"block", "timeout"} if len(call.args) == 2 else (
        {"block"} if len(call.args) == 1 else set()
    )
    return not positional_names.intersection(keyword_names)


def _sync_callback_accessor_arguments_are_valid(call, kind, method):
    """Return True when a proven callback-container accessor can execute."""
    if kind == "queue" and method == "get":
        return _queue_get_arguments_are_valid(call)
    if kind == "queue" and method == "get_nowait":
        return not call.args and not call.keywords
    if kind == "list" and method == "pop":
        return len(call.args) <= 1 and not call.keywords
    if kind == "deque" and method in {"pop", "popleft"}:
        return not call.args and not call.keywords
    return False


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


def _sync_callback_dispatch_mutates(node, tracking, operator_bindings):
    """Return True only for proven synchronous execution of a mutating callback."""
    expr = _statement_value_expression(node)
    if not isinstance(expr, ast.Call) or expr.args or expr.keywords:
        return False
    inner = expr.func
    if not isinstance(inner, ast.Call):
        return False

    if _next_iter_callback_source_mutates(
        inner,
        tracking,
        operator_bindings,
    ):
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
    }
    return (
        method in dispatch_methods.get(kind, set())
        and _sync_callback_accessor_arguments_are_valid(inner, kind, method)
    )


def _track_sync_callback_dispatch(node, scan_state, operator_bindings):
    """Update container tracking and report proven synchronous callback execution."""
    tracking = _sync_callback_tracking(scan_state)
    dispatch_mutates = _sync_callback_dispatch_mutates(
        node,
        tracking,
        operator_bindings,
    )
    _record_sync_callback_imports(node, tracking)
    _record_sync_callback_insert(node, tracking, operator_bindings)
    _record_sync_callback_assignment(node, tracking, operator_bindings)
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


def _collect_imported_name_alias_events(tree, module_name, imported_names):
    """Track selected direct-import aliases and later top-level rebindings."""
    events = {}
    active = set()
    for node in tree.body:
        line = getattr(node, "lineno", 0)
        _record_imported_name_aliases(
            node,
            module_name,
            imported_names,
            active,
            events,
            line,
        )
        _invalidate_imported_module_aliases(node, active, events, line)
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
            'globals', 'getattr', 'staticmethod', 'classmethod', 'property',
            'type', 'sorted', 'list', 'tuple', 'set', 'frozenset', 'any',
            'all', 'max', 'min', 'next', 'map', 'filter', 'enumerate', 'zip',
            'iter', 'reversed',
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


def _node_has_worker_mutating_decorator(node, global_workers_mutators):
    """Return True when a function or class decorator mutates workers."""
    return any(
        isinstance(decorator, ast.Name)
        and decorator.id in global_workers_mutators
        for decorator in node.decorator_list
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
        (set(), set(), set(), set(), {}, set()) if class_targets is None else class_targets,
        {} if dict_subclass_names is None else dict_subclass_names,
    )



def _handle_worker_scan_definition(
    node,
    state,
    global_workers_mutators,
    class_targets,
):
    """Handle definitions without descending into function or class bodies."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if _node_has_worker_mutating_decorator(
            node,
            global_workers_mutators,
        ):
            state.dynamic = True
        return True
    if not isinstance(node, ast.ClassDef):
        return False
    if _node_has_worker_mutating_decorator(
        node,
        global_workers_mutators,
    ) or _classdef_has_import_time_workers_side_effect(node, class_targets):
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
        ):
            continue
        if _track_sync_callback_dispatch(node, state, operator_bindings):
            state.dynamic = True
        if _node_has_dynamic_workers_effect(
            node,
            global_workers_mutators,
            operator_bindings,
            class_targets=class_targets,
            dict_subclass_names=dict_subclass_names,
        ):
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
    callback_alias_events = _collect_mutating_callback_alias_events(
        tree,
        operator_bindings,
    )
    operator_bindings[32][_MUTATING_CALLBACK_ALIAS_EVENTS_KEY] = (
        callback_alias_events
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
