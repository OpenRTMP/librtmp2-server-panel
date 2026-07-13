# AGENTS.md

## Cursor Cloud specific instructions

`librtmp2-server-panel` is a Flask web UI for `librtmp2-server`. Standard setup/run commands are in `README.md` — use those. A ready-to-use virtualenv lives at `venv/` (git-ignored); run tools via `venv/bin/python` / `venv/bin/pytest`.

Non-obvious notes for this environment:

- **Config validation fails fast at import** (`config.py`): `SECRET_KEY` must be ≥32 chars, `PASSWORD` ≥12 chars when login is enabled, and `LRTMP2_API_TOKEN` must be set — otherwise `app.py` / any `pytest` import raises before serving. The tests use fixed dummy values (`SECRET_KEY=test-secret-key-for-ci-validation-only-32chars`, `PASSWORD=test-password-for-ci-only`, `LRTMP2_API_TOKEN=test-api-token-for-ci-only`).
- **Single-process dev:** `python app.py` serves on `127.0.0.1:8000`. Set `RATELIMIT_STORAGE_URI=memory://` for local dev; Redis is only needed for multi-worker gunicorn rate limiting.
- **The panel is useless without a live `librtmp2-server`** — it is a thin REST client. Point `LRTMP2_API_URL` at the server (`http://localhost:8080`) and use its API token as `LRTMP2_API_TOKEN`.
- **Tests:** run from the repo root as `venv/bin/python -m pytest -m "not integration"` (CI uses `python -m pytest`). Bare `pytest` / `venv/bin/pytest` fails collecting `tests/test_lrtmp2_client.py` with `ModuleNotFoundError` because the repo root (holding `app.py` / `lrtmp2_client.py`) is only put on `sys.path` by the `python -m` form. Integration tests are gated by `RUN_INTEGRATION=1` and require a running server (`LRTMP2_API_URL` + `LRTMP2_API_TOKEN`); run them with `venv/bin/python -m pytest -m integration`.
