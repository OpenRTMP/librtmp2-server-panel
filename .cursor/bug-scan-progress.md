# Bug scan progress

Last scanned: lrtmp2_client.py — 2026-07-02

## Module checklist

- [x] `app.py` — Flask routes, auth, session handling, stream CRUD
- [x] `lrtmp2_client.py` — librtmp2-server REST API client
- [ ] `config.py` — startup validation and environment configuration
- [ ] `templates/` — Jinja2 templates (XSS, CSRF forms)
- [ ] `static/js/` — frontend JavaScript (DOM injection, fetch logic)

## Findings (2026-07-02 lrtmp2_client.py pass)

- **lrtmp2_client.py, all methods (`list_streams`, `create_stream`, `delete_stream`,
  `create_player`, `delete_player`, `stream_stats_by_id`, `health`, `stream_stats`)** —
  network-level failures from `requests` (connection refused, DNS failure,
  timeout — `requests.exceptions.RequestException`/`Timeout`) were never caught.
  Every `app.py` call site only catches `Lrtmp2ApiError`, so a librtmp2-server
  restart, network blip, or firewall drop would crash every panel route
  (`/`, `/streams/new`, `/streams/<id>/delete`, `.../stats.json`, ...) with an
  unhandled 500 instead of the existing graceful "API error" flash/response.
  Attacker angle: not directly exploitable for privilege escalation, but a
  trivially reachable DoS — any hiccup reaching the backend (or an attacker
  who can rate-limit/blackhole the backend connection) takes down the whole
  admin panel rather than degrading gracefully. Fixed by adding a
  `Lrtmp2Client._request()` wrapper that catches
  `requests.exceptions.Timeout`/`RequestException` and re-raises as
  `Lrtmp2ApiError`, used by every method.
- **`health()` / `stream_stats()`** — used `resp.raise_for_status()` directly,
  which raises `requests.exceptions.HTTPError` on non-2xx instead of the
  library's own `Lrtmp2ApiError` used everywhere else. Inconsistent with the
  rest of the client and would bypass the same catch-and-flash pattern if
  these methods are wired up to a route later. Fixed to use the same
  `resp.ok` + `_api_error()` path as the other methods (currently unused by
  `app.py`, but kept consistent for future callers).
- **Success-path `resp.json()` calls** — a 200 response with a malformed/non-JSON
  body (e.g. a proxy returning an HTML error page with a 200 status) would
  raise a raw `ValueError`/`JSONDecodeError` that no caller catches. Added a
  shared `_parse_json()` helper so malformed successful responses also
  surface as `Lrtmp2ApiError` instead of an unhandled 500.
- Reviewed but not a bug: `stream_id`/`player_id` are `urllib.parse.quote(...,
  safe='')`-encoded before being interpolated into the request path (defense
  in depth on top of `app.py`'s `STREAM_ID_RE`/`VIEWER_ID_RE` validation), so
  no path-traversal/injection route into the backend URL. All requests pass
  an explicit `timeout=self.timeout` (default 5s), so no unbounded hang. The
  Bearer token is only ever placed in the `Authorization` header (never
  logged, never put in a URL/query string), and `base_url`/`token` come from
  `config.py` (operator-controlled env vars), not from end-user input, so no
  SSRF vector here. No shared mutable state between requests beyond
  read-only `base_url`/`token`/`timeout`, so no TOCTOU/race risk from
  concurrent Flask workers using one `Lrtmp2Client` instance.
