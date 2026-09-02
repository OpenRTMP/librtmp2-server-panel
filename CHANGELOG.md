# Changelog

All notable changes to this project will be documented in this file.

> ⚠️ **Alpha software.** `librtmp2-server-panel` is in active early development.
> It has **no fixed, stable release version yet** — everything below is
> pre-release (alpha) and configuration, routes, and behavior may change at any
> time without notice. Pin to a specific git commit if you depend on it.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
While in alpha the project has no fixed version; semantic-versioning guarantees
only begin at a future `1.0.0`.

## [Unreleased]

## [0.1.7] — 2026-09-02

### Security
- Startup validation of a referenced Gunicorn config's `workers` setting now
  detects indirect mutations — dict subscripts, `globals().update()`,
  match/case bodies, `__setitem__`, list/tuple unpacking, walrus
  expressions, for-loop rebinding, `exec`/`setattr`, import-time helper
  calls, and `configure()`/`on_starting()` hooks — so a dynamic worker count
  can no longer slip past the check and enable the `memory://` rate-limiter
  storage banned for multi-worker deployments.
- `TRUSTED_PROXY_IPS` rejects universal catch-all CIDRs (`0.0.0.0/0`,
  `::/0`, and `/1` ranges), which previously made every direct TCP peer
  look like a trusted proxy.
- Multi-worker deployments reject unsupported Redis session/rate-limiter
  URIs (`redis+cluster://`, `redis+unix://`) that `Flask-Limiter` accepts
  but that don't provide real cross-worker coordination.
- HTTPS `Referrer-Policy` response header aligned to `same-origin` (browsers
  prefer it over the template meta tag); the previous `no-referrer` header
  dropped `Referer` on same-origin form POSTs and broke
  `WTF_CSRF_SSL_STRICT` on HTTPS deployments.

### Fixed
- `delete_stream` client polling window aligned to the server's 300s
  (`DELETE_DRAIN_TIMEOUT`) async drain instead of the previous 35s, so
  operators deleting live streams no longer see a false failure while the
  server is still draining.
- Panel hardened against malformed upstream API responses: stream
  list/create responses are validated, request body size is capped, API
  player dicts are no longer mutated in place, and stats uptime formatting
  is guarded.
- CI/release supply-chain hardening: GitHub Actions pinned to full commit
  SHAs, locked `--only-binary` pip installs in CI/Docker, release workflow
  write permissions scoped to the package job, and Docker build context
  narrowed from `COPY . .` to explicit paths plus `.dockerignore`.

### Changed
- Changelog version `0.1.6` → `0.1.7`.

## [0.1.6] — 2026-08-10

### Added
- Optional cluster-aware management UI when the connected `librtmp2-server`
  reports `cluster.enabled=true` (overview, node list with READY/DRAINING/DOWN/
  ISOLATED badges, drain/resume/remove actions, stream owner/epoch placement).
- REST client methods for cluster status, nodes, streams, drain, resume, and
  remove. Standalone servers remain fully supported without cluster config.

### Fixed
- Health probe failures are no longer treated as confirmed standalone mode:
  Cluster navigation stays available and detection errors are surfaced instead
  of silently hiding cluster UI.
- Index lists streams before probing health so an unresponsive API host does
  not burn two client timeouts on every page load; stream-listing failures keep
  Cluster discoverable when cluster APIs may still work.
- Cluster overview fetches status and nodes independently so one failing call
  does not drop the other payload.
- Quorum display distinguishes unknown/unavailable status from confirmed
  quorum loss.
- Drain / resume / remove call the mutation endpoint directly instead of
  gating on a separate cluster-status probe; the server's own response is now
  the sole authority on whether the action is rejected.
- Node IDs are parsed with the same integer validation the API client uses.
- Index reuses the already-fetched health payload for RTMPS flags instead of
  issuing a second health request.
- Stream-placement (`/api/v1/cluster/streams`) failures are surfaced to
  operators instead of being swallowed.
- Aggregate cluster metrics are read from the normalized `status.load` object.
- Live stats keep cluster metric rows when the stream owner is unavailable
  (owner shown as unavailable; relay / `players_by_node` still rendered).
- Null / missing relay bandwidth is shown as unknown (`n/a`) instead of a
  misleading zero.
- Cluster overview reuses the `cluster_status()` response that already
  confirmed cluster mode is enabled instead of re-querying it and discarding
  that result on a transient second failure.
- Remove stays available for `down` / `isolated` / `leaving` nodes; only
  Drain and Resume are gated by node state.
- Index still loads stream placement (`/api/v1/cluster/streams`) when the
  health probe fails and treats a successful response as confirmed cluster
  mode, so owner/epoch and live cluster stats stay available during that
  partial outage.
- Cluster overview honors an authoritative `cluster_status().enabled=false`
  even when the earlier health probe still reported clustering enabled.
- Live stats fall back to `cluster_proxy.owner_node_id` when the root
  `owner_node_id` is JSON `null`, matching the existing relay normalization.

### Changed
- Integration CI always checks out `librtmp2-server` `main` (no same-named
  feature-branch coupling).
- Release version `0.1.5` → `0.1.6` (cluster UI + detection fixes).

## [0.1.5] — 2026-07-25

### Fixed
- Development Compose image references now use lowercase GHCR repository names,
  preventing Docker's `repository name must be lowercase` startup failure.
- Manually dispatched releases now create the requested tag from the exact
  workflow-selected commit when it does not exist yet. Source archives, GitHub
  Release metadata, and Docker images are pinned to that same commit; an
  existing tag that points elsewhere is rejected.
- Release runs for the same tag are serialized, and workflow-dispatch tag input
  is passed through the step environment instead of interpolated into shell code.
- Live statistics are polled only for the currently opened stream accordion,
  pause while the browser tab is hidden, prevent overlapping fetches, and abort
  stalled requests so polling can recover automatically.
- RTMP and RTMPS URLs now bracket IPv6 literals correctly.
- HTTPS deployments preserve same-origin referrers so Flask-WTF strict CSRF
  validation continues to accept legitimate form submissions.
- Reverse-proxy documentation now requires `X-Forwarded-For` and
  `X-Forwarded-Proto` to be normalized to matching trusted-value counts.

### Security
- Added opt-in `TRUSTED_PROXY_COUNT` handling for deployments behind trusted
  reverse proxies, so forwarded client IP and scheme headers are ignored by
  default and trusted only for an explicitly configured proxy-hop count.

## [0.1.4] — 2026-07-21

### Added
- Docker startup logs now print an OpenRTMP ASCII banner followed by the
  `librtmp2-server-panel` name and running image version. Release builds embed
  the workflow version; local builds without one are labelled `development`.

### Security
- Active panel sessions are invalidated when the configured username or
  password changes, preventing stolen session cookies from remaining valid
  after credential rotation.

## [0.1.3] — 2026-07-15

### Fixed
- Failed stream deletions now surface API errors to operators instead of only
  reporting that deletion started; failures are also logged with the affected
  stream ID for incident response and troubleshooting.
- The Docker image now runs Gunicorn with a threaded worker model and a 60-second
  timeout so a draining stream deletion cannot monopolize the panel's only
  request worker.
- `_detect_worker_count()` also parses `-w` / `--workers` from the gunicorn
  process command line (`sys.argv`), not only `GUNICORN_CMD_ARGS` and env
  vars, so the multi-worker `memory://` guard cannot be bypassed via
  `gunicorn --workers N app:app` or attached forms such as `-w2` / `-w=2`.
- `/streams/<id>/stats.json` now applies both a per-IP cap (300/min) and a
  per-stream cap (25/min); unauthenticated redirects and invalid stream IDs
  are exempt from the per-stream bucket so login redirects and junk paths
  do not pollute the rate-limit store.
- Startup rejects `RATELIMIT_STORAGE_URI=memory://` when multiple Gunicorn
  workers are configured (`WEB_CONCURRENCY`, `GUNICORN_WORKERS`, or
  `GUNICORN_CMD_ARGS`), preventing per-worker login rate-limit bypass.
- Docker Compose now passes `ALLOW_INSECURE_NO_LOGIN` through to the panel
  container.

### Security
- Panel sessions are now tracked with server-side tokens, so copied signed
  session cookies are invalidated immediately on logout or a subsequent login
  and only the latest session for an account remains active.
- Redis session-backend failures now fail closed and are logged. A failed login
  persistence attempt returns a controlled HTTP 503 without destroying an
  existing valid session, and session revocation uses an atomic compare-and-delete
  operation to avoid concurrent login/logout races.
- `REQUIRE_LOGIN=False` requires `ALLOW_INSECURE_NO_LOGIN=1` at startup,
  closing an accidental open-admin footgun.
- Panel session lifetime capped at 8 hours (`PERMANENT_SESSION_LIFETIME`).

### Changed
- Stats rate-limit decorators run after authentication checks via
  `exempt_when`, so unauthenticated polling does not consume login or
  per-stream buckets.
- Intentional CSRF disabling in isolated tests is annotated for SonarCloud
  S4502 so the security rating reflects production code rather than test-only
  configuration.

## [0.1.2] — 2026-07-12

### Fixed
- `Limiter` had no socket/connect timeout on its Redis backend. Since the
  rate limiter runs as a `before_request` hook for every route (not just
  `/login`), a Redis instance that's up but not responding (network
  stall, overload) would hang every Gunicorn worker indefinitely on any
  request. Added a 2s `socket_timeout`/`socket_connect_timeout`.

### Security
- Default Docker Compose stack now includes Redis and uses
  `RATELIMIT_STORAGE_URI=redis://redis:6379/0` so the `/login` rate limit is
  shared across Gunicorn workers instead of allowing `5 × worker_count`
  attempts per minute with in-memory storage

## [0.1.1] — 2026-07-10

### Security
- Reject panel passwords shorter than 12 characters at startup when
  `REQUIRE_LOGIN` is enabled, closing an online brute-force path against the
  default `admin` account
- Reject unrecognized `REQUIRE_LOGIN` values (e.g. a typo like `Tru`) at
  startup instead of silently falling back to disabling the login gate
- Require `SECRET_KEY` to be at least 32 characters at startup, blocking a
  trivially brute-forceable session-signing secret

## [0.1.0] — 2026-07-08

First tagged pre-release.

### Added
- Web-based control panel (Flask) for `librtmp2-server`
- Stream management: create and delete streams via the server's HTTP API,
  including optional operator-supplied custom publish/play keys
- Local SQLite store for created streams and their `publish_key` / `play_key` /
  `stats_key`, so publish/play/stats URLs can be rebuilt after creation
- Publish/play URL display with one-click copy, including `rtmps://` URLs
  when the connected `librtmp2-server` reports RTMPS enabled (via
  `/api/v1/health` and `LRTMP2_RTMPS_PORT`)
- Live stats view per stream
- Optional panel login (`REQUIRE_LOGIN`, `USERNAME` / `PASSWORD`), enabled by
  default on network-exposed deployments
- Configuration via environment variables / `.env` (API URL & token, public
  domain, RTMP/RTMPS port, default app name, session secret, DB path)
- Docker / docker-compose deployment and a local development workflow

### Security
- `REQUIRE_LOGIN` defaults to `True` so unauthenticated remote attackers can't
  reach the admin panel on a default deployment
- `SESSION_COOKIE_SECURE` auto-detected from the panel's own public URL, with
  an explicit override always taking precedence
- Startup config validation rejects missing, blank, or known-default secrets
  (`SECRET_KEY`, `PASSWORD`, `LRTMP2_API_TOKEN`)

### Planned
- Further UI polish once user feedback comes in from the first release

[Unreleased]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/OpenRTMP/librtmp2-server-panel/releases/tag/v0.1.0
