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

### Fixed
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
- `REQUIRE_LOGIN=False` requires `ALLOW_INSECURE_NO_LOGIN=1` at startup,
  closing an accidental open-admin footgun.
- Panel session lifetime capped at 8 hours (`PERMANENT_SESSION_LIFETIME`).

### Changed
- Stats rate-limit decorators run after authentication checks via
  `exempt_when`, so unauthenticated polling does not consume login or
  per-stream buckets.

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

[Unreleased]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/OpenRTMP/librtmp2-server-panel/releases/tag/v0.1.0
