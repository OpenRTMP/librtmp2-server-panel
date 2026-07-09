# Bug scan progress

Last scanned: lrtmp2_client.py — 2026-07-09

## Module checklist

- [x] `app.py` — Flask routes, auth, session handling, stream CRUD
- [x] `lrtmp2_client.py` — librtmp2-server REST API client
- [ ] `config.py` — startup validation and environment configuration
- [ ] `templates/` — Jinja2 templates (XSS, CSRF forms)
- [ ] `static/js/` — frontend JavaScript (DOM injection, fetch logic)

## Findings (2026-07-09 lrtmp2_client.py pass)

- **`delete_stream()` 202 polling / `wait_timeout=5`** — librtmp2-server returns
  HTTP 202 when a stream has active RTMP sessions and drains them asynchronously
  for up to 30s before finalizing the delete (or re-enabling the stream on
  timeout). The client only polled `list_streams()` for 5s, then returned without
  error. Scenario: operator deletes a live stream from the panel; the redirect
  shows no flash error, but the stream remains listed (and may be re-enabled by
  the server if sessions never drop). Impact: failed/incorrect delete appears
  successful — stream keys stay valid during incident response. Fixed by defaulting
  `wait_timeout` to 35s (server drain window + buffer) and raising
  `Lrtmp2ApiError` when the stream is still present after polling exhausts.
- Reviewed but not a bug: network/JSON errors already wrapped as `Lrtmp2ApiError`;
  path segments URL-encoded; Bearer token only in Authorization header; per-call
  timeouts; no shared mutable request state; `health()` intentionally unauthenticated
  per server API; `stream_stats()` unused by `app.py` (panel uses
  `stream_stats_by_id` with Bearer auth).

## Findings (2026-07-08 app.py pass)

- **`login_required` / `REQUIRE_LOGIN` default False** — `app.py` gates every
  admin route on `app.config["REQUIRE_LOGIN"]`, but `config.py`,
  `docker-compose.yml`, and `.env.example` all defaulted `REQUIRE_LOGIN` to
  `False` while gunicorn/Docker bind `0.0.0.0:8000`. Scenario: operator
  deploys with docker-compose defaults (or copies `.env.example` as-is) without
  explicitly enabling login — any remote host reaching port 8000 gets full
  unauthenticated access to stream CRUD and all publish/play/stats keys.
  Impact: complete admin-panel compromise (create/delete streams, view secrets).
  Fixed by defaulting `REQUIRE_LOGIN` to `True` in config/docker-compose/
  `.env.example`, adding a startup warning in `app.py` when login is
  explicitly disabled, and regression tests for the secure default.
- Reviewed but not a bug: `session.clear()` on login changes the signed session
  cookie (no fixation). All POST routes use CSRF tokens. `stream_id`/`player_id`
  validated with strict regex before API calls. `login_required` wraps every
  sensitive route. `stream_stats` is behind auth with a scoped 300/min limit
  (supports ~15 streams polling every 3s). Security headers set on all
  responses. `hmac.compare_digest` used for credential checks.

## Findings (2026-07-06 static/js/ pass)

- **`scripts.js` `initializeStats()` / `loadStats()` + `app.py` default rate limit** —
  `initializeStats()` polls `/streams/<id>/stats.json` for every stream on the
  index page every 3 seconds (20 requests/min per stream). The route inherited
  Flask-Limiter's default `100 per minute` per IP. With 6+ streams the panel
  exceeds that budget within ~50s; further polls return HTTP 429, `loadStats()`
  treats non-OK responses as failures, and live stats permanently show
  "Stats not available" for operators managing multiple streams. Fixed by
  `@limiter.exempt` on `stream_stats` (endpoint is already behind
  `@login_required`).
- Reviewed but not a bug: `innerHTML` assignments escape `data.error` and
  `video.codec` via `escapeHtml()`; numeric fields are coerced with `Number()`
  before interpolation. `streamId` in fetch URLs comes from
  `data-stream-id="{{ stream.id }}"` (Jinja auto-escaped; validated server-side
  on the stats route). All POST forms in templates include CSRF tokens.
  `fetch()` uses same-origin defaults so session cookies are sent. No `|safe`
  filters or unescaped API strings in templates.

## Findings (2026-07-05 templates/ pass)

- No critical bugs found. All POST forms include `csrf_token`. User/API-derived
  strings are rendered with Jinja auto-escaping (verified for attribute and body
  contexts, including malicious `name`, `app`, and URL payloads). `Referrer-Policy:
  no-referrer` is set in `base.html` and via `set_security_headers` to avoid
  leaking stream keys in stats URL query strings.

## Findings (2026-07-03 config.py pass)

- **`_validate_config()` / `.env.example` placeholders** — Copy-pasting `.env.example`
  to `.env` without replacing `SECRET_KEY`, `PASSWORD`, or `LRTMP2_API_TOKEN`
  placeholders (`<generate-with-python3-secrets-token-hex-32>`, etc.) passed
  startup validation because only a small hard-coded blocklist was checked.
  Impact: documented placeholder values are effectively public secrets — an
  attacker can forge Flask sessions (known `SECRET_KEY`) or log in with the
  documented `PASSWORD`, gaining full admin access to stream CRUD. Fixed by
  `_is_insecure_secret()` that rejects blank values, known defaults, and any
  `<...>` placeholder pattern.
- **`_bool()` / `REQUIRE_LOGIN=`** — An empty `REQUIRE_LOGIN` env var (`""`) was
  parsed as `False`, silently disabling the login gate while operators expect
  the documented default of `True` (e.g. accidental `REQUIRE_LOGIN=` in `.env`).
  Impact: unauthenticated access to the entire admin panel (create/delete
  streams, view keys). Fixed by treating blank env values as unset so
  `REQUIRE_LOGIN` defaults to `True`.

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
