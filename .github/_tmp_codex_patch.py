from pathlib import Path

config_path = Path("config.py")
text = config_path.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new)


replace_once(
    '''def _collect_builtins_import_aliases(statements):
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


def _collect_builtins_aliases(tree):''',
    '''def _collect_builtins_import_aliases(statements):
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


def _collect_builtins_aliases(tree):''',
)

replace_once(
    '''def _direct_name_is_builtin_exec_eval(func, call, shadow_lines):
    """Return True when a direct exec/eval name still resolves to the builtin."""
    if not isinstance(func, ast.Name) or func.id not in _DYNAMIC_EXEC_EVAL_NAMES:
        return False
    shadow_line = shadow_lines.get(func.id)
    call_line = getattr(call, "lineno", 0)
    return shadow_line is None or not call_line or shadow_line > call_line


def _call_is_dynamic_exec_eval(
    call,
    builtins_aliases=None,
    exec_eval_shadow_lines=None,
):
    """Return True for direct built-ins or known builtins-module calls."""
    if not isinstance(call, ast.Call):
        return False
    if builtins_aliases is None:
        builtins_aliases = set()
    if exec_eval_shadow_lines is None:
        exec_eval_shadow_lines = {}
    func = call.func
    return (
        _direct_name_is_builtin_exec_eval(func, call, exec_eval_shadow_lines)
        or _getattr_is_dynamic_exec_eval(func, builtins_aliases)
        or _subscript_is_dynamic_exec_eval(func, builtins_aliases)
        or _attribute_is_dynamic_exec_eval(func, builtins_aliases)
    )''',
    '''def _direct_name_is_builtin_exec_eval(
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
    )''',
)

replace_once(
    '''    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
    exec_eval_shadow_lines = operator_bindings[9] if len(operator_bindings) > 9 else {}
    if isinstance(expr, ast.Call) and (
        _call_is_dynamic_exec_eval(
            expr,
            builtins_aliases,
            exec_eval_shadow_lines,
        )''',
    '''    builtins_aliases = operator_bindings[8] if len(operator_bindings) > 8 else set()
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
        )''',
)

replace_once(
    '''    builtins_aliases = _collect_builtins_aliases(tree)
    exec_eval_shadow_lines = _collect_definite_exec_eval_shadow_lines(tree)
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
    )''',
    '''    builtins_aliases = _collect_builtins_aliases(tree)
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
    )''',
)

replace_once(
    '''def _default_gunicorn_config_paths() -> list[Path]:
    """Return the implicit config from Gunicorn's launch directory, if present."""
    for directory in _gunicorn_launch_directories():
        try:
            resolved = (directory / "gunicorn.conf.py").resolve()
        except (OSError, RuntimeError):
            continue
        if resolved.is_file():
            return [resolved]
    return []''',
    '''def _static_gunicorn_chdir(tree):
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
    return []''',
)

replace_once(
    '''def _worker_count_from_environment() -> int:
    """Return the environment-provided default worker count."""
    count = 1
    for env_key in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        raw = os.environ.get(env_key, "").strip()
        if raw.isdigit():
            count = int(raw)
    return count''',
    '''def _worker_count_from_environment() -> int:
    """Return the largest safety-relevant environment worker count."""
    counts = [1]
    for env_key in ("WEB_CONCURRENCY", "GUNICORN_WORKERS"):
        raw = os.environ.get(env_key, "").strip()
        if raw.isdigit():
            counts.append(int(raw))
    return max(counts)''',
)

config_path.write_text(text, encoding="utf-8")

tests_path = Path("tests/test_gunicorn_worker_regressions.py")
tests = tests_path.read_text(encoding="utf-8")
extra = '''


def test_environment_does_not_let_gunicorn_workers_mask_web_concurrency(
    monkeypatch, tmp_path, config_module
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    monkeypatch.setenv("GUNICORN_WORKERS", "1")
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config_module._detect_worker_settings() == (4, False)


def test_direct_builtins_exec_alias_fails_closed(config_module):
    tree = ast.parse(
        "workers = 1\\n"
        "from builtins import exec as run\\n"
        "run('workers = 4')\\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, True)


def test_direct_builtins_alias_reassignment_is_not_false_positive(config_module):
    tree = ast.parse(
        "workers = 1\\n"
        "from builtins import exec as run\\n"
        "run = lambda value: value\\n"
        "result = run('workers = 4')\\n"
    )

    assert config_module._scan_gunicorn_config_workers(tree) == (1, False)


def test_post_chdir_prefers_verified_launch_pwd_config(
    monkeypatch, tmp_path, config_module
):
    launch_dir = tmp_path / "launch"
    app_dir = tmp_path / "app"
    launch_dir.mkdir()
    app_dir.mkdir()
    (launch_dir / "gunicorn.conf.py").write_text(
        f"chdir = {str(app_dir)!r}\\nworkers = 4\\n",
        encoding="utf-8",
    )
    (app_dir / "gunicorn.conf.py").write_text(
        "workers = 1\\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PWD", str(launch_dir))
    monkeypatch.chdir(app_dir)
    monkeypatch.setattr(sys, "argv", ["gunicorn", "app:app"])

    assert config_module._detect_worker_settings() == (4, False)
'''
if "def test_environment_does_not_let_gunicorn_workers_mask_web_concurrency" not in tests:
    tests += extra
tests_path.write_text(tests, encoding="utf-8")

Path(".github/workflows/_temporary_codex_fix.yml").unlink()
Path(".github/_tmp_codex_patch.py").unlink()
