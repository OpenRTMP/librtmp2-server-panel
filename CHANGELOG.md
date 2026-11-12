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

## [0.1.16] — 2026-11-12

### Added
- Docker Hub images. The multi-arch build now also publishes
  `docker.io/openrtmp/librtmp2-server-panel` for release tags and the
  `latest`, `beta` and `alpha` channels, next to GHCR and Quay.
  `README.dockerhub.md` is the paste-ready repository description.

### Security
- The Gunicorn worker probe fails closed for serialization hooks
  (`pickle.dumps`, `copy.copy`, `copy.deepcopy`), custom async iterators,
  and namespace writes through `builtins.dict`, `dict.update`,
  `operator.call`/`setitem`/`methodcaller`, `getattr(globals(), ...)`,
  invoked `partial`/`reduce` helpers and `sys.modules`. A `memory://` rate
  limiter can no longer pass startup validation while a config raises the
  worker count behind the probe.
- Called config helpers are treated as possible writers. A `bind` or
  `wsgi_app` assigned in a direct, decorated, inherited, context-manager or
  transitive helper now reports the setting as unknown or present instead of
  absent, so the entrypoint no longer injects `0.0.0.0:8000` or `app:app`
  over the operator's config. A bare `global bind: list` annotation is not a
  write, and a deeply nested config returns unknown instead of exiting 1.
- A top-level literal `wsgi_app` is only final when it is a literal string;
  `None`, dynamic values, conditional assignments and imports keep the image
  default. `locals()` writes are only considered at module scope, and
  `wsgi_app` writes are evaluated in statement order, so a later
  unconditional literal or `del` supersedes earlier writes.
- The entrypoint bind probe recognises imported, destructured, loop, with,
  augmented and walrus targets, alias/partial/instance-method wrappers,
  BOM-prefixed configs and `--proxy-protocol` without a value, and follows
  Gunicorn's `-c`/config/environment precedence. Wildcard imports and
  recursion stay unknown. The image no longer overrides a supplied bind.

### Fixed
- Anonymous stats requests keep a rate limit when the stats view is exempt
  from the scoped authenticated budgets. The default budget applies only to
  unauthenticated requests, and a session or limiter outage reports the
  request as unauthenticated instead of removing the budget.
- Redis cluster limiter failures answer 503 instead of an unhandled 500
  (`RedisClusterException` is not a `RedisError`).
- A numeric `stream_id` of 0 is accepted as a real id in create-stream
  responses and cluster placement; an empty string falls back to the entry
  id instead of being treated as missing.
- An upstream stats 429 is surfaced as the panel's 429 with `Retry-After`,
  so the browser keeps the last good stats and pauses instead of showing a
  generic 502.
- A blank `RATELIMIT_STORAGE_URI` is normalised to `memory://` before
  Flask-Limiter reads it.
- The clipboard fallback restores focus after the textarea copy path, and
  the deprecated fallback is documented.

### Changed
- The image default bind moved out of the Dockerfile `CMD`, so Gunicorn's
  last-wins CLI layer cannot override `GUNICORN_CMD_ARGS` or
  `gunicorn.conf.py`; the entrypoint adds it only when the probe reports no
  bind.
- Dependency update: gunicorn 27.
- CI workflows pin third-party GitHub Actions to commit SHAs.

## [0.1.15] — 2026-11-06

### Security
- `SESSION_COOKIE_SECURE` defaults to enabled when neither `PANEL_PUBLIC_URL`
  nor `TRUSTED_PROXY_COUNT` indicates plain HTTP. Set
  `PANEL_ALLOW_INSECURE_HTTP=1` for a local HTTP setup; the bundled compose
  files do.
- The rate limiter keys on the proxy-appended value (the last
  `X-Forwarded-For` entry, or the header named by
  `TRUSTED_PROXY_CLIENT_IP_HEADER`), not on the position selected by
  `TRUSTED_PROXY_COUNT`, so an over-counted hop number can no longer let a
  client choose its own bucket.
- The Gunicorn worker gate now fails closed for the remaining import-time
  shapes that can raise the worker count behind `memory://` rate limiting:
  implicit dunder hooks on constructed classes (`__add__`, `__format__`,
  `__iter__`, `__bool__`, `__contains__`, `__eq__` and siblings, including
  inherited and in-place forms), `__del__`, `repr`/`str`/`bool`/`len`/`hash`,
  unary operators and `print`, `ClassName()()`, attribute reads on fresh
  instances, `asyncio.run` on custom awaitables, `round`, `math.trunc`,
  `math.floor` and `math.ceil`, deferred `type()` instantiation,
  `__getattr__`/`__getattribute__`/`__missing__`, trace/profile installers,
  and the remaining dict-mutator, pool/`ExitStack`/`partial` callback,
  conditional class, `type()`/`new_class` namespace and metaclass spellings.
  The scan also resolves aliased and annotation-only bindings and class
  attribute hooks in source order. An implicit config that may have chdir'd
  away from the current directory keeps the worker count dynamic instead of
  assuming a single worker.
- The entrypoint bind probe detects imported, destructured, loop/with/
  augmented/walrus and namespace-written `bind`/`wsgi_app` targets, including
  aliased imports and nested attribute writes, keeps an explicit app target
  when value-taking Gunicorn flags precede it, mirrors Gunicorn's config
  precedence (`-c`, `gunicorn.conf.py`, environment), accepts a BOM-prefixed
  config and an optional-value `--proxy-protocol`, and treats wildcard imports
  or recursion as unknown. The image default no longer overrides a supplied
  bind.

### Fixed
- The delete drain poll matches numeric upstream stream ids, and creating a
  stream whose id comes back as a number no longer reports it missing.
- The RTMPS badge comes from the same `/health` payload when the streams
  endpoint fails, instead of claiming RTMPS is disabled.
- Display names reject the whole Unicode `Cc` category (C0, DEL and the C1
  block), matching the server's `char::is_control` check.

### Changed
- The image runs Python 3.15, installs the Gunicorn config probe, and builds
  its hash-pinned wheels on the same Python minor as the runtime stage.
- The bundled compose files forward a configured
  `TRUSTED_PROXY_CLIENT_IP_HEADER` to the panel.
- Dependency updates: click 8.5.1, WTForms 3.3.2, pytest 9.2.0.

## [0.1.14] — 2026-11-01

### Security
- With `TRUSTED_PROXY_COUNT` set, the rate-limit client key fails closed when
  the WSGI environment carries no direct peer address: such requests share one
  `unknown` bucket instead of trusting a forwarded header that could not be
  checked against `TRUSTED_PROXY_IPS`.

### Added
- `LOG_LEVEL` (`0`-`3` like librtmp2-server, or a level name; default info)
  and a stderr log format with timestamps. Under Gunicorn the panel's own
  log lines were never printed before, because only Gunicorn's loggers were
  configured.
- Startup line with the API URL (userinfo dropped), login mode and log level.
- Logins (success and failure, with the client IP as resolved for rate
  limiting, so a spoofed `X-Forwarded-For` from an untrusted peer is not
  logged), logouts and stream,
  player and cluster-node changes are logged at info. Stream ids appear as
  the existing keyed `stream_tag`.
- Failed librtmp2-server API calls (timeout, unreachable, non-2xx status)
  are logged with the operation and duration, and every call is logged at
  debug. URLs are never logged, since stats URLs embed the stats key.

### Fixed
- Closed further Gunicorn worker-detection gaps so a memory-backed rate limit
  and a per-process session store are refused whenever a config can raise the
  worker count at import time. The gate now also covers a delegating
  `SimpleNamespace` (including aliased constructors and the `__setitem__`,
  `__ior__` and `setdefault` delegations), a bound `partial(globals().update)`,
  the unbound `dict.update` form, a `map`/`filter` consumer whose callback
  mutates the namespace, guarded `ThreadPool`/`Future` imports, a
  function-local asyncio task factory, a named mutating callback, a
  `type(...)`-created dict subclass, a metaclass that explicitly runs the
  initializer, a descriptor `__set_name__` hook, the enum member shapes
  (tuple targets, module-level aliases and subscripted access), the indirect
  dispatch forms (`getattr`, `__getattribute__`, `operator.methodcaller`,
  `operator.attrgetter`, `type(obj).m(obj)` and `Cls.__dict__['m'](obj)`), an
  unresolvable callee that receives the module namespace, and a Gunicorn
  launch whose configuration file cannot be located while the inherited
  working directory shows that the config changed the launch directory.
- The Gunicorn worker scan also catches workers mutations hidden in
  `builtins.dict.__setitem__`, a metaclass `__prepare__` or `__getitem__`,
  Enum member `__init__` and `_generate_next_value_`, nested `Outer.Inner()`
  constructors, instance subscript side effects, `operator.call(partial(...))`
  (also walrus-bound, via `getattr`, `object.__getattribute__` or
  `types.MethodType`), named `weakref.finalize` callbacks, context-manager
  entry and exit hooks (`__enter__`/`__exit__`, `__aenter__`/`__aexit__`,
  including a direct `asyncio.run(obj.__aenter__())`), `@contextmanager`
  methods, `ExitStack.enter_context`, `enter_async_context` and
  `contextlib.closing()`.
- The upstream per-stream stats read now uses a timeout that fits the
  browser's abort window, so an abandoned request no longer keeps an
  upstream read (and a worker thread) alive.
- The player list no longer offers a delete action for the stream's default
  play key, which the server deliberately protects.
- The container entrypoint now starts the default command when it is called
  without arguments and handles a flag-first invocation.

### Changed
- Dependency updates: WTForms 3.3.1, certifi 2026.10.23, Deprecated 3.0.1,
  wrapt 2.5.2.
- CI: the reusable Docker workflow declares only the Quay credentials it
  needs; docker/login-action v4.7.0 and a newer setup-python pin.

## [0.1.13] — 2026-10-21

### Security
- Closed further Gunicorn worker-detection gaps so a memory-backed rate limit
  and per-process session store are refused whenever a config can raise the
  worker count at import time. The gate now also covers `operator.setitem` on
  `sys.modules[__name__].__dict__`, `builtins.getattr`/`type.mro`, alternate
  MRO constructor dispatch, metaclasses and aliases, `ChainMap`, partial and
  thread-pool callback forms, annotated or computed `chdir`, namespace passing
  to unknown callables, and additional conditional/shadowed bindings.
- Trusted-proxy matching normalizes IPv4-mapped IPv6 peers and rejects
  v4-mapped catch-all proxy ranges, so a dual-stack listener cannot bypass the
  per-client rate-limit key or trust an over-broad proxy entry.

### Fixed
- The dashboard stats poller handles HTTP 429 with a per-container backoff
  (honoring `Retry-After` when present) while keeping the last good stats
  instead of replacing the pane with an error.
- A rate-limit storage outage answers with the controlled 503 used for session
  store outages instead of an unhandled 500; stream-stat reads use the admin
  timeout budget, and null stream/player keys are normalized.
- Additional Gunicorn scanner gaps were closed for MRO/constructor dispatch,
  `builtins.getattr`/`type.mro`, compound-block class metadata, heapq/sched
  callbacks, saved callback containers, and `operator.attrgetter`/`__call__`
  spellings.

### Changed
- Internal Sonar-driven refactor: proxy candidate helpers always return
  same-length tuples, high-complexity scanner functions were split into focused
  helpers, unused parameters were removed, and the stats handler uses optional
  chaining. No behavior change.
- Dependency update: certifi 2026.10.19.

## [0.1.12] — 2026-10-14

### Security
- The Gunicorn worker-count gate now treats additional import-time ways of changing `workers` as dynamic, including class introspection and rebinds inside functions. A memory-backed rate limit is still refused when the config can raise the worker count.
- The runtime-hook detector now recognizes the same namespace updates as the worker-count gate, while the builtin or imported name still refers to the real mutator. A rebound name is not treated as installing a hook.

### Fixed
- Unauthenticated requests for JSON routes now receive a machine-readable 401 instead of an HTML login redirect. The dashboard stats poller sends the operator to the login page in that case.

### Changed
- Python 3.15 for CI, locked dependencies, and the Docker base image.

## [0.1.11] — 2026-10-10

### Security
- The Gunicorn `workers` scanner, which keeps `RATELIMIT_STORAGE_URI=memory://`
  and the per-process session store from running under a multi-worker
  Gunicorn, now catches many more indirect ways a config can change the worker
  count at import time and fails closed on them: frame globals
  (`inspect.stack()`, `sys._getframe()`, `f_globals`), import hooks and
  import-time callbacks, inherited and `super()` hooks, class bodies, instance
  methods and properties, descriptors, enum aliases,
  `operator.attrgetter('__dict__')`, `locals()`/`vars()`, walrus and lambda
  forms, `with` and `match` targets, config class constructors (also when the
  class is reached through `getattr()`, `operator.attrgetter()`,
  `object.__getattribute__()`, `__mro__`, a container subscript or
  `types.new_class()`) and named callbacks passed to builtins that consume them
  eagerly.
- The same guard now also reads the worker count the way Gunicorn does from
  the command line and the environment: compact config flags (`-cPATH`,
  `-c=PATH`) and integer spellings such as `-w 1_6` or `WEB_CONCURRENCY=1_6`
  no longer slip past it.

### Fixed
- The panel failed to start when a Gunicorn config shadowed and later
  restored the builtin `dict`, because the scanner crashed with a
  `TypeError` instead of returning a verdict.
- Scanner false positives: a `workers` annotation without a value, descriptor
  reads, true enum members, subclass attributes and later rebinding of
  imported names are no longer treated as dynamic worker counts.
- The dashboard no longer returns HTTP 500 when the server reports an upstream
  or player entry with a `null` id: such upstreams are skipped, and such
  players are listed without a delete link.
- Cluster view: mistyped or non-object node entries and cluster-level metrics
  are normalized before rendering, and proxied publisher statistics are shown
  instead of "offline". An object or array `stream_id` in
  `/api/v1/cluster/streams` is skipped instead of failing the dashboard with
  HTTP 500.
- Deleting a stream or a player and the cluster node actions (drain, resume,
  remove) use a longer timeout (30 s), because the server answers only after
  its per-peer cluster calls; deleting a stream waits for the server's full
  drain window before reporting failure.
- POST routes have their default rate limits again.
- Forms no longer fail with a bare "The CSRF token has expired" HTTP 400 page
  once the dashboard has been open for more than an hour. Form tokens now stay
  valid as long as the login itself (8 hours), and a rejected form changes
  nothing and sends the operator back to the dashboard, or to the login page,
  with a message.
- The Logout button is no longer shown when `REQUIRE_LOGIN=False`.

### Changed
- The Docker image is based on `python:3.14-alpine` instead of the floating
  `python:alpine` tag, so a new Python release cannot break the wheel-only
  build unannounced. The build stage no longer installs an unused Rust and C
  toolchain and the runtime image no longer adds the `openssl` command-line
  tool, which makes the multi-architecture build faster and the image smaller.
- Every dependency, including transitive ones, is now locked with hashes in
  `requirements.txt` (runtime) and `requirements-dev.txt` (tests), generated
  from `requirements.in`. The Docker image and the test and release workflows
  install from these files with `--require-hashes`, so CI tests exactly what
  the image ships (it previously tested Gunicorn 26.0.0 while the image had
  26.2.0) and dependency installs are reproducible. All workflow actions are pinned
  to commit SHAs.
- Runtime dependency `redis` updated from 7.4.1 to 8.1.0.

### Documentation
- The README dashboard screenshot is re-taken from the current panel against a
  real librtmp2-server with a live stream and three players.

### Accessibility
- The login page no longer autofocuses the username field.

## [0.1.10] — 2026-09-28

### Security
- Hardened the Gunicorn `workers` scanner against additional builtins-module indirection that could execute mutating generators at import time, including `builtins.sum(...)`, `builtins.getattr(...)`, `builtins.__dict__['sum'](...)`, and `importlib.import_module('builtins').sum(...)`. These paths now correctly fail closed so hidden multi-worker configurations cannot bypass the `RATELIMIT_STORAGE_URI=memory://` and per-process session-store safeguards.

### Fixed
- Made builtins and `importlib` resolution source-order aware so later rebinding of imported module aliases no longer causes false positives.
- Respect shadowing of builtin `getattr` while still recognizing module-qualified `builtins.getattr`, and corrected the importlib alias/event binding slots used by the scanner.
- Added regression coverage for the newly detected bypasses and shadowing/rebinding cases.

### Changed
- Changelog version `0.1.9` → `0.1.10`.

## [0.1.9] — 2026-09-23

### Security
- Further hardened Gunicorn `workers` mutation detection so import-time worker-count changes hidden behind thread pools, `Thread.run()`, `asyncio.to_thread()`, `threading.Timer`, and `Future.add_done_callback()` are treated as dynamic instead of being accepted as a static single-worker configuration. This keeps the `RATELIMIT_STORAGE_URI=memory://` and per-process session-store safeguards fail-closed for additional callback and concurrency patterns.

### Fixed
- Improved the worker-mutation scanner's handling of callback bindings, imports, aliases, nested control flow, and async/threaded execution paths, with regression coverage for the newly detected bypass techniques.
- Refactored the expanded Gunicorn AST scanner to keep its complexity and maintainability checks within project limits while preserving the security behavior.

### Documentation
- Added a real dashboard screenshot to the README, showing an expanded stream with publish/play URLs and live stream statistics.
- Marked the `lrtmp2_client.py` bug-scan pass as completed in the repository's scan-progress documentation.

### Changed
- Changelog version `0.1.8` → `0.1.9`.

## [0.1.8] — 2026-09-18

### Security
- Continued hardening of the Gunicorn `workers`-mutation AST scan added in
  `0.1.7`: dozens of further indirect-mutation techniques are now detected
  and fail closed instead of being read as a static single-worker config —
  module/instance dict and namespace updates via `operator`/`functools`
  helpers, `exec`/`eval`/`type()`-based execution, `ChainMap`/
  `SimpleNamespace`/dataclass/metaclass side effects, decorators,
  comprehension and context-manager side effects, and Gunicorn's
  auto-loaded `gunicorn.conf.py` when no explicit `-c`/`--config` is
  passed. Without this, `RATELIMIT_STORAGE_URI=memory://` and per-process
  session stores could keep running under a deployment that Gunicorn was
  actually forking into multiple workers, defeating the shared login
  rate limit and session invalidation guards.
- Unscannable Gunicorn `--config` specs (`python:MODULE` targets, a
  missing `file:PATH`, or a relative `-c` resolved after `chdir`) now fail
  closed instead of being treated as a single-worker deployment.
- Redis error logs no longer include raw session values or unsanitized
  usernames.

### Fixed
- Narrowed the worker-mutation scanner to cut false positives it had
  picked up while being extended: unrelated local `dict.update()` calls
  and unbound `dict.update(globals(), ...)` invocations are no longer
  misflagged as dynamic worker mutations.
- The live stats endpoint no longer loses its dedicated per-IP/per-stream
  rate limit when exempted from Flask-Limiter's global `default_limits`;
  it previously either double-counted against the global cap (blocking
  live stats for six or more expanded streams) or, once exempted, dropped
  its own cap entirely.
- `delete_stream` now retries transient `list_streams` errors during the
  server's drain window instead of surfacing a false delete failure on a
  single timeout or connection error.
- Frontend accessibility and maintainability fixes: labeled login form
  inputs, semantic copy buttons, improved stream page accessibility, and
  preserved CSRF initialization, `create_stream` template constants, and
  the cluster-owner fallback check while addressing Sonar findings.

### Added
- MIT `LICENSE` file.

### Changed
- Changelog version `0.1.7` → `0.1.8`.

## [0.1.7] — 2026-09-03

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

[Unreleased]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.16...HEAD
[0.1.16]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/OpenRTMP/librtmp2-server-panel/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/OpenRTMP/librtmp2-server-panel/releases/tag/v0.1.0
