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

[Unreleased]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OpenRTMP/librtmp2-server-panel/releases/tag/v0.1.0
