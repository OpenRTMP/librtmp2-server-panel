from pathlib import Path


config_path = Path("config.py")
text = config_path.read_text()

old = '''def _expression_is_mutating_lazy_iterator(expr, operator_bindings):
    """Return True for a direct or saved map/filter iterator with a risky callback."""
    return _map_or_filter_lambda_mutates_when_consumed(
        expr,
        operator_bindings,
    ) or _lazy_iterator_alias_is_active(expr, operator_bindings)
'''
new = '''def _expression_is_mutating_lazy_iterator(
    expr,
    operator_bindings,
    active_names=None,
):
    """Return True for a risky lazy iterator without consuming it."""
    if _map_or_filter_lambda_mutates_when_consumed(expr, operator_bindings):
        return True
    if isinstance(expr, ast.Name):
        if active_names is not None:
            return expr.id in active_names
        return _lazy_iterator_alias_is_active(expr, operator_bindings)
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
'''
if old not in text:
    raise SystemExit("lazy iterator helper anchor not found")
text = text.replace(old, new, 1)

old = '''def _lazy_iterator_assignment_is_mutating(value, active_names, operator_bindings):
    """Return whether an assignment stores a risky lazy iterator."""
    if _map_or_filter_lambda_mutates_when_consumed(value, operator_bindings):
        return True
    return isinstance(value, ast.Name) and value.id in active_names
'''
new = '''def _lazy_iterator_assignment_is_mutating(value, active_names, operator_bindings):
    """Return whether an assignment stores a risky lazy iterator."""
    return _expression_is_mutating_lazy_iterator(
        value,
        operator_bindings,
        active_names,
    )
'''
if old not in text:
    raise SystemExit("lazy iterator assignment anchor not found")
text = text.replace(old, new, 1)
config_path.write_text(text)

tests = Path("tests/test_gunicorn_indirect_workers_bypass.py")
test_text = tests.read_text()
marker = "# Cursor consumed-generator follow-up regressions"
if marker not in test_text:
    test_text += r'''


# Cursor consumed-generator follow-up regressions
@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\nlist(x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nany(x for x in filter(lambda _: globals().update({'workers': 4}), [True]))\n",
        "workers = 1\nsorted(x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\nfor _ in (x for x in map(lambda _: globals().update({'workers': 4}), [1])):\n    pass\n",
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\nlist(gen)\n",
        "workers = 1\nit = map(lambda _: globals().update({'workers': 4}), [1])\ngen = (x for x in it)\nlist(gen)\n",
        "workers = 1\nlist(y for _ in [1] for y in map(lambda _: globals().update({'workers': 4}), [1]))\n",
    ],
)
def test_cursor_consumed_generator_over_mutating_lazy_iterator_is_dynamic(
    tmp_path,
    config_content,
):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, True)


@pytest.mark.parametrize(
    "config_content",
    [
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\ngen = (x for x in filter(lambda _: globals().update({'workers': 4}), [1]))\n",
        "workers = 1\ngen = (x for x in map(lambda _: globals().update({'workers': 4}), [1]))\ngen = ()\nlist(gen)\n",
    ],
)
def test_cursor_unconsumed_or_rebound_generator_stays_static(tmp_path, config_content):
    config_file = tmp_path / "gunicorn.conf.py"
    config_file.write_text(config_content, encoding="utf-8")
    assert config._workers_from_gunicorn_config_path(str(config_file)) == (1, False)
'''
    tests.write_text(test_text)
