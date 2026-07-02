# Bug scan configuration

## SCAN_TARGET_OVERRIDE

Leave empty to follow the rotating module schedule in `bug-scan-progress.md`.
Set to a module name below to force a one-off scan of that module.

```
SCAN_TARGET_OVERRIDE=
```

## Modules (scan order)

1. `app.py` — Flask routes, auth, session handling, stream CRUD
2. `lrtmp2_client.py` — librtmp2-server REST API client
3. `config.py` — startup validation and environment configuration
4. `templates/` — Jinja2 templates (XSS, CSRF forms)
5. `static/js/` — frontend JavaScript (DOM injection, fetch logic)
