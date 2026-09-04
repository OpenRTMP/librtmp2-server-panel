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


def _workers_from_command_tokens(tokens: list[str]) -> int:
    """Parse Gunicorn `-w` / `--workers` flags from a token list."""
    count = 1
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("--workers", "-w"):
            if i + 1 < len(tokens) and tokens[i + 1].isdigit():
                count = max(count, int(tokens[i + 1]))
                i += 2
                continue
        elif tok.startswith("--workers="):
            value = tok.split("=", 1)[1]
            if value.isdigit():
                count = max(count, int(value))
        elif tok.startswith("-w="):
            value = tok.split("=", 1)[1]
            if value.isdigit():
                count = max(count, int(value))
        elif tok.startswith("-w") and len(tok) > 2 and tok[2:].isdigit():
            count = max(count, int(tok[2:]))
        i += 1
    return count


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


def _globals_workers_subscript(node):
    """Return True for ``globals()['workers']``-style subscript targets."""
    if not _subscript_slice_is_workers(node):
        return False
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    return isinstance(func, ast.Name) and func.id == "globals"


def _dict_literal_sets_workers(node):
    """Return True when a dict literal contains a ``workers`` key."""
    if not isinstance(node, ast.Dict):
        return False
    return any(
        isinstance(key, ast.Constant) and key.value == "workers"
        for key in node.keys
    )


def _call_is_globals_workers_update(call):
    """Return True for ``globals().update({...})`` that sets ``workers``."""
    if not isinstance(call, ast.Call):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "update":
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Call):
        return False
    func = receiver.func
    if not isinstance(func, ast.Name) or func.id != "globals":
        return False
    for arg in call.args:
        if _dict_literal_sets_workers(arg):
            return True
    for keyword in call.keywords:
        if keyword.arg == "workers":
            return True
        if _dict_literal_sets_workers(keyword.value):
            return True
    return False


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


def _call_is_operator_setitem_workers(call):
    """Return True for ``operator.setitem(globals(), 'workers', ...)`` mutations."""
    if not isinstance(call, ast.Call) or len(call.args) < 2:
        return False
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr != "setitem":
        return False
    if not isinstance(func.value, ast.Name) or func.value.id != "operator":
        return False
    return _constant_is_workers(call.args[1])


def _call_is_getattr_setitem_workers(call):
    """Return True for ``getattr(globals(), '__setitem__')('workers', ...)``."""
    if not isinstance(call, ast.Call) or not call.args:
        return False
    func = call.func
    if not isinstance(func, ast.Call) or len(func.args) < 2:
        return False
    if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
        return False
    attr = func.args[1]
    if not isinstance(attr, ast.Constant) or attr.value != "__setitem__":
        return False
    return _constant_is_workers(call.args[0])


def _lambda_mutates_workers(lambda_node):
    """Return True when a lambda body assigns ``workers`` via setitem helpers."""
    if not isinstance(lambda_node, ast.Lambda):
        return False
    body = lambda_node.body
    if not isinstance(body, ast.Call):
        return False
    return (
        _call_sets_workers_via_setitem(body)
        or _call_is_operator_setitem_workers(body)
        or _call_is_getattr_setitem_workers(body)
    )


def _call_mutates_workers_via_indirection(call):
    """Return True for indirect import-time ``workers`` mutations."""
    if not isinstance(call, ast.Call):
        return False
    if (
        _call_sets_workers_via_setitem(call)
        or _call_is_operator_setitem_workers(call)
        or _call_is_getattr_setitem_workers(call)
        or _call_sets_workers_attribute(call)
    ):
        return True
    return isinstance(call.func, ast.Lambda) and _lambda_mutates_workers(call.func)


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


def _expression_mutates_workers(expr):
    """Return True when an expression statement mutates ``workers`` indirectly."""
    if isinstance(expr, ast.Call):
        return (
            _call_is_globals_workers_update(expr)
            or _call_mutates_workers_via_indirection(expr)
        )
    if isinstance(expr, ast.List):
        return any(
            isinstance(elt, ast.Call) and _call_mutates_workers_via_indirection(elt)
            for elt in expr.elts
        )
    return False


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


def _is_dynamic_workers_mutation(node):
    """Return True for import-time mutations the AST scan cannot treat as static."""
    if isinstance(node, ast.Expr):
        if _expression_mutates_workers(node.value):
            return True
        if isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id in {"exec", "eval"}:
                return True
            if _call_mutates_workers_via_indirection(call):
                return True

    if isinstance(node, ast.Assign):
        return any(
            _globals_workers_subscript(target)
            or _subscript_slice_is_workers(target)
            for target in node.targets
        )

    return False


def _function_mutates_global_workers(func_node):
    """Return True when a function assigns to ``global workers``."""
    has_global_workers = any(
        isinstance(child, ast.Global) and "workers" in child.names
        for child in func_node.body
    )
    if not has_global_workers:
        return False
    return any(_worker_assignment_value(stmt)[0] for stmt in func_node.body)


def _call_invokes_function(call_node, func_names):
    """Return True when ``call_node`` invokes one of ``func_names``."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id in func_names
    return False


def _collect_global_workers_mutators(tree):
    """Return function names that mutate ``global workers`` when called."""
    mutators = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _function_mutates_global_workers(node):
                mutators.add(node.name)
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


def _walk_gunicorn_workers_statements(
    statements,
    state,
    *,
    in_compound: bool,
    global_workers_mutators=None,
) -> None:
    if global_workers_mutators is None:
        global_workers_mutators = set()

    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        if isinstance(node, ast.For) and _target_assigns_workers(node.target):
            state.dynamic = True

        if _is_dynamic_workers_mutation(node):
            state.dynamic = True

        if _import_from_binds_workers(node):
            state.dynamic = True

        if isinstance(node, ast.Expr) and isinstance(node.value, ast.NamedExpr):
            walrus = node.value
            if _target_assigns_workers(walrus.target):
                state.dynamic = True
                state.record_workers_assignment(
                    _static_int_from_ast(walrus.value),
                    in_compound=in_compound,
                )

        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and _call_invokes_function(node.value, global_workers_mutators)
        ):
            state.dynamic = True

        assigns_workers, value = _worker_assignment_value(node)
        if assigns_workers:
            state.record_workers_assignment(value, in_compound=in_compound)

        for block in _compound_statement_blocks(node):
            _walk_gunicorn_workers_statements(
                block,
                state,
                in_compound=True,
                global_workers_mutators=global_workers_mutators,
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


def _scan_gunicorn_config_workers(tree):
    """Return worker count and dynamic flag from a gunicorn config module AST.

    Top-level ``workers = N`` literals are treated as static. Assignments inside
    compound statements (``if``/``for``/``while``/``with``/``try``), augmented
    assignments, or non-literal expressions cannot be verified at import time and
    are treated as dynamic so multi-worker deployments fail closed unless a
    shared rate-limit/session backend is configured.
    """
    state = _GunicornWorkersScanState()
    runtime_hooks = _gunicorn_config_has_runtime_hooks(tree)
    global_workers_mutators = _collect_global_workers_mutators(tree)
    _walk_gunicorn_workers_statements(
        tree.body,
        state,
        in_compound=False,
        global_workers_mutators=global_workers_mutators,
    )
    if runtime_hooks:
        state.dynamic = True
    if not state.found:
        return 1, state.dynamic
    return state.count, state.dynamic


def _workers_from_gunicorn_config_path(config_path: str) -> tuple[int, bool]:
    """Parse worker count and whether the effective assignment is dynamic."""
    path = _resolve_gunicorn_config_path(config_path)
    if path is None:
        return 1, False
    tree = _parse_gunicorn_config_tree(path)
    if tree is None:
        return 1, False
    return _scan_gunicorn_config_workers(tree)


def _workers_from_gunicorn_config_flag(tokens: list[str]) -> tuple[int, bool]:
    """Parse ``-c/--config`` paths from a token list and read worker counts."""
    count = 1
    dynamic = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-c", "--config") and i + 1 < len(tokens):
            config_count, config_dynamic = _workers_from_gunicorn_config_path(tokens[i + 1])
            count = max(count, config_count)
            dynamic = dynamic or config_dynamic
            i += 2
            continue
        if tok.startswith("--config="):
            config_count, config_dynamic = _workers_from_gunicorn_config_path(
                tok.split("=", 1)[1]
            )
            count = max(count, config_count)
            dynamic = dynamic or config_dynamic
        i += 1
    return count, dynamic


def _detect_worker_settings() -> tuple[int, bool]:
    """Best-effort worker count and dynamic-config flag for Gunicorn deployments."""
    count = 1
    dynamic = False
    for env_key in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        raw = os.environ.get(env_key, "").strip()
        if raw.isdigit():
            count = max(count, int(raw))
    cmd_args = os.environ.get("GUNICORN_CMD_ARGS", "")
    for match in re.finditer(r"(?:--workers|-w)(?:=(\d+)| ?(\d+))", cmd_args):
        value = match.group(1) or match.group(2)
        count = max(count, int(value))
    if cmd_args.strip():
        cmd_tokens = shlex.split(cmd_args)
        count = max(count, _workers_from_command_tokens(cmd_tokens))
        config_count, config_dynamic = _workers_from_gunicorn_config_flag(cmd_tokens)
        count = max(count, config_count)
        dynamic = dynamic or config_dynamic
    count = max(count, _workers_from_command_tokens(sys.argv))
    config_count, config_dynamic = _workers_from_gunicorn_config_flag(sys.argv)
    count = max(count, config_count)
    dynamic = dynamic or config_dynamic
    return count, dynamic


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
