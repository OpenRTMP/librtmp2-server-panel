import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
from functools import wraps
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.constants import ExemptionScope
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config, RATELIMIT_MEMORY_URI, client_ip_for_rate_limit
from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client
from session_store import (
    SessionBackendUnavailable,
    create_session_store,
    session_is_valid,
)

# Captured at import time so tests that `patch("app.Lrtmp2Client")` to mock
# the API client (the pattern used throughout this test suite) don't also
# replace this static, data-only helper with a MagicMock — an unconfigured
# MagicMock call is truthy, which would make every cluster-enabled check
# below always report "enabled" regardless of the mocked health payload.
_cluster_enabled_from_health = Lrtmp2Client.cluster_enabled_from_health


STREAM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
APP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
VIEWER_ID_RE = re.compile(r"^vi_[0-9a-f]{32}$")
DISPLAY_NAME_MAX_LEN = 128
MIN_ACCESS_KEY_LEN = 32
CLUSTER_TEMPLATE = "cluster.html"
INDEX_HTML = "index.html"
CREATE_STREAM_HTML = "create_stream.html"
ERR_INVALID_STREAM_ID = "Invalid stream ID"

ACCESS_KEY_HELP = (
    f"Must be {MIN_ACCESS_KEY_LEN}-63 characters and use only letters, numbers, dots, "
    "underscores, or hyphens."
)
DIRECT_REMOTE_ADDR_KEY = "openrtmp.direct_remote_addr"
# Gunicorn's default Docker CMD uses gthread with four threads. Each draining
# delete can block a thread for up to DELETE_STREAM_DRAIN_WAIT_SECONDS while
# polling librtmp2-server, so cap concurrent drain operations and leave worker
# threads available for login, navigation, and stats polling.
MAX_CONCURRENT_STREAM_DELETE_DRAINS = 2
_stream_delete_drain_slots = threading.BoundedSemaphore(MAX_CONCURRENT_STREAM_DELETE_DRAINS)


class _PreserveDirectRemoteAddr:
    """Record the TCP peer address before ProxyFix may replace REMOTE_ADDR."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ[DIRECT_REMOTE_ADDR_KEY] = environ.get("REMOTE_ADDR", "")
        return self.app(environ, start_response)


def _is_valid_stream_id(value):
    return bool(STREAM_ID_RE.fullmatch(value or ""))


def _is_valid_app_name(value):
    return bool(APP_NAME_RE.fullmatch(value or ""))


def _is_valid_viewer_id(value):
    return bool(VIEWER_ID_RE.fullmatch(value or ""))


def _is_valid_display_name(value):
    if not isinstance(value, str) or not value:
        return False
    if len(value) > DISPLAY_NAME_MAX_LEN:
        return False
    return all(ord(ch) >= 32 and ord(ch) != 127 for ch in value)


def _is_valid_access_key(value):
    return _is_valid_stream_id(value) and len(value) >= MIN_ACCESS_KEY_LEN


def _optional_form_value(raw):
    if raw is None:
        return None
    stripped = str(raw).strip()
    return stripped or None


def _format_url_host(value):
    """Return a hostname/IP suitable for the authority component of an RTMP URL.

    IPv6 literals must be enclosed in brackets. Existing bracketed IPv6 values
    are normalized without double-bracketing; DNS names and IPv4 addresses are
    returned unchanged.
    """
    host = str(value or "").strip()
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return host
    if parsed.version == 6:
        return f"[{candidate}]"
    return candidate


def _credential_fingerprint(secret_key, username, password, api_token):
    """Stable marker for the active login credentials bound to a session.

    This is a keyed MAC, not a password-storage digest: SECRET_KEY is the
    HMAC key, so the fingerprint can't be brute-forced offline into the
    username/password even if it leaked. CodeQL's weak-sensitive-data-hashing
    query doesn't model HMAC's keyed construction and flags the password
    reaching hashlib.sha256 as if this were a fast, unkeyed password hash.
    """
    material = f"{username}\0{password}\0{api_token}"
    return hmac.new(
        secret_key.encode(),
        material.encode(),  # codeql[py/weak-sensitive-data-hashing]
        hashlib.sha256,
    ).hexdigest()


def _validate_optional_access_keys(publish_key, play_key, stats_key):
    fields = (
        ("publish_key", publish_key),
        ("play_key", play_key),
        ("stats_key", stats_key),
    )
    provided = []
    for label, value in fields:
        if value is None:
            continue
        if not _is_valid_access_key(value):
            return f"{label}: {ACCESS_KEY_HELP}"
        provided.append(value)
    if len(provided) != len(set(provided)):
        return "publish_key, play_key, and stats_key must be distinct when provided."
    return None


def _normalize_streams_list(streams):
    """Return a list of stream dicts; tolerate malformed API payloads."""
    if isinstance(streams, list):
        return [item for item in streams if isinstance(item, dict)]
    return []


def _append_api_error(current, error):
    text = str(error)
    return text if current is None else f"{current}; {text}"


def _configure_proxy(app):
    trusted_proxy_count = app.config["TRUSTED_PROXY_COUNT"]
    if trusted_proxy_count:
        # Only trust forwarded client IP and scheme information from the exact
        # number of proxies configured by the operator. Keep this disabled by
        # default because trusting forwarded headers while port 8000 is directly
        # reachable would allow clients to spoof their source address.
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxy_count,
            x_proto=trusted_proxy_count,
        )
        app.logger.warning(
            "Forwarded client IP/scheme headers are trusted because "
            "TRUSTED_PROXY_COUNT is enabled. Ensure the panel is reachable "
            "only through the configured proxies."
        )

    # Must wrap the outermost app.wsgi_app so it captures the real TCP peer
    # address before ProxyFix overwrites REMOTE_ADDR from X-Forwarded-For.
    app.wsgi_app = _PreserveDirectRemoteAddr(app.wsgi_app)


def _configure_security_defaults(app):
    if app.config["RATELIMIT_STORAGE_URI"] == RATELIMIT_MEMORY_URI:
        app.logger.warning(
            f"RATELIMIT_STORAGE_URI={RATELIMIT_MEMORY_URI} is per worker process; "
            "use a shared backend such as redis:// for multi-worker deployments"
        )
    if not app.config["REQUIRE_LOGIN"]:
        app.logger.warning(
            "REQUIRE_LOGIN=False: the panel admin UI is open without authentication. "
            "Only disable login on trusted local networks."
        )

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=app.config["SESSION_COOKIE_SECURE"],
        PERMANENT_SESSION_LIFETIME=app.config["SESSION_LIFETIME"],
    )


class _PanelRuntime:
    """Request handlers and helpers bound to one Flask application instance."""

    def __init__(self, app):
        self.app = app
        self.client = Lrtmp2Client(
            app.config["LRTMP2_API_URL"],
            app.config["LRTMP2_API_TOKEN"],
        )
        self.session_store = create_session_store(app.config["RATELIMIT_STORAGE_URI"])
        self.limiter = Limiter(
            key_func=self._rate_limit_remote_addr,
            app=app,
            default_limits=["100 per minute"],
            storage_uri=app.config["RATELIMIT_STORAGE_URI"],
            # Bound how long a rate-limit check can block on the storage backend.
            # Without this, a Redis instance that's up but not responding hangs
            # every Gunicorn worker indefinitely. Ignored by memory://.
            storage_options={"socket_timeout": 2, "socket_connect_timeout": 2},
        )

    def register_post_csrf(self):
        self._register_stats_rate_limits()
        self.app.after_request(self.set_security_headers)
        self._register_routes()

    def _rate_limit_remote_addr(self):
        """Rate-limit by real client IP, ignoring spoofed XFF from untrusted peers."""
        direct = request.environ.get(DIRECT_REMOTE_ADDR_KEY) or ""
        return client_ip_for_rate_limit(
            direct_addr=direct,
            forwarded_addr=get_remote_address(),
            trusted_proxy_count=self.app.config["TRUSTED_PROXY_COUNT"],
            trusted_networks=self.app.config["TRUSTED_PROXY_NETWORKS"],
        )

    def _stats_rate_limit_key(self):
        """Per-stream bucket so polling many streams does not share one global cap."""
        stream_id = ""
        if request.view_args:
            stream_id = request.view_args.get("stream_id", "") or ""
        return f"{self._rate_limit_remote_addr()}:{stream_id}"

    @staticmethod
    def _login_post_rate_limit():
        # Intentionally empty. Flask-Limiter performs the check in before_request.
        pass

    def _register_login_rate_limit(self):
        # Enforce the login POST cap before CSRF validation. Flask-WTF rejects
        # missing tokens before the login view runs, so a route-level limit would
        # otherwise not count those attempts.
        hook = self.limiter.limit(
            "5 per minute",
            methods=["POST"],
            exempt_when=lambda: request.endpoint != "login",
        )(self._login_post_rate_limit)
        self.app.before_request(hook)

    def _session_ttl_seconds(self):
        return int(self.app.permanent_session_lifetime.total_seconds())

    def _revoke_session_token(self, *, fail_closed=False):
        token = session.pop("session_token", None)
        username = session.get("username")
        if not token or not username:
            return
        try:
            self.session_store.revoke(username, token)
        except SessionBackendUnavailable:
            if fail_closed:
                session["session_token"] = token
                raise

    def _establish_logged_in_session(self):
        token = secrets.token_hex(32)
        username = self.app.config["USERNAME"]
        # Persist the replacement token before touching the browser session. If
        # Redis is unavailable, the caller can return a controlled 503 while
        # preserving any currently valid login.
        self.session_store.replace_user_session(
            username,
            token,
            self._session_ttl_seconds(),
        )
        session.clear()
        session.permanent = True
        session["logged_in"] = True
        session["username"] = username
        session["session_token"] = token
        session["credential_fp"] = _credential_fingerprint(
            self.app.config["SECRET_KEY"],
            username,
            self.app.config["PASSWORD"],
            self.app.config["LRTMP2_API_TOKEN"],
        )

    def _session_is_authenticated(self, *, fail_closed=False):
        if not session.get("logged_in"):
            return False
        expected_fp = _credential_fingerprint(
            self.app.config["SECRET_KEY"],
            self.app.config["USERNAME"],
            self.app.config["PASSWORD"],
            self.app.config["LRTMP2_API_TOKEN"],
        )
        stored_fp = session.get("credential_fp")
        if not isinstance(stored_fp, str) or not hmac.compare_digest(stored_fp, expected_fp):
            self._revoke_session_token(fail_closed=fail_closed)
            session.clear()
            return False
        token = session.get("session_token")
        username = session.get("username")
        if not token or not username:
            session.clear()
            return False
        if not session_is_valid(
            self.session_store,
            username,
            token,
            fail_closed=True,
        ):
            self._revoke_session_token(fail_closed=fail_closed)
            session.clear()
            return False
        return True

    def login_required(self, view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not self.app.config["REQUIRE_LOGIN"]:
                return view_func(*args, **kwargs)
            try:
                if not self._session_is_authenticated():
                    return redirect(url_for("login"))
            except SessionBackendUnavailable:
                self.app.logger.exception(
                    "Session backend unavailable during auth check"
                )
                return (
                    "Authentication service temporarily unavailable. "
                    "Please try again.",
                    503,
                )
            return view_func(*args, **kwargs)

        return wrapped

    def _stats_per_stream_rate_limit_exempt(self):
        if self.app.config["REQUIRE_LOGIN"]:
            try:
                if not self._session_is_authenticated():
                    return True
            except SessionBackendUnavailable:
                return True
        if not request.view_args:
            return False
        raw = request.view_args.get("stream_id", "") or ""
        return not _is_valid_stream_id(raw)

    def _stats_ip_rate_limit_exempt(self):
        if not self.app.config["REQUIRE_LOGIN"]:
            return False
        try:
            return not self._session_is_authenticated()
        except SessionBackendUnavailable:
            return True

    @staticmethod
    def _stream_stats_route_rate_limit_exempt():
        return request.endpoint != "stream_stats"

    @staticmethod
    def _stream_stats_rate_limit():
        # Intentionally empty: Flask-Limiter enforces both limits via decorators.
        pass

    def _register_stats_rate_limits(self):
        stats_ip_limit = f"{self.app.config['STATS_RATE_LIMIT_PER_IP']} per minute"
        stats_stream_limit = (
            f"{self.app.config['STATS_RATE_LIMIT_PER_STREAM']} per minute"
        )
        hook = self.limiter.limit(
            stats_stream_limit,
            key_func=self._stats_rate_limit_key,
            exempt_when=lambda: self._stream_stats_route_rate_limit_exempt()
            or self._stats_per_stream_rate_limit_exempt(),
        )(self._stream_stats_rate_limit)
        hook = self.limiter.limit(
            stats_ip_limit,
            key_func=self._rate_limit_remote_addr,
            exempt_when=lambda: self._stream_stats_route_rate_limit_exempt()
            or self._stats_ip_rate_limit_exempt(),
        )(hook)
        self.app.before_request(hook)

    def rtmps_from_health(self, health):
        """Derive RTMPS flags from an already-fetched /health payload."""
        configured_port = str(self.app.config.get("LRTMP2_RTMPS_PORT") or "")
        if not isinstance(health, dict) or not health.get("rtmps_enabled"):
            return False, configured_port or "1936"
        reported_port = str(health.get("rtmps_port") or "")
        return True, configured_port or reported_port or "1936"

    def rtmps_health(self):
        """Fetch /health and return RTMPS availability plus public port."""
        try:
            health = self.client.health()
        except Lrtmp2ApiError:
            return self.rtmps_from_health(None)
        return self.rtmps_from_health(health)

    def build_urls(self, stream, rtmps_on, rtmps_port):
        domain = _format_url_host(self.app.config["LRTMP2_DOMAIN"])
        port = self.app.config["LRTMP2_RTMP_PORT"]
        app_name = stream["app"]
        publish_url = f"rtmp://{domain}:{port}/{app_name}"  # nosonar python:S5332
        raw_players = stream.get("players")
        if not isinstance(raw_players, list):
            raw_players = []
        players = [dict(player) for player in raw_players if isinstance(player, dict)]
        stream["players"] = players
        self._add_player_urls(players, domain, port, app_name, rtmps_on, rtmps_port)
        first_play_key = self._first_play_key(stream, players)
        urls = {
            "publish_url": publish_url,
            "publish_key": stream.get("publish_key", ""),
            "play_url": f"rtmp://{domain}:{port}/{app_name}/{first_play_key}",  # nosonar python:S5332
            "play_key": first_play_key,
            "rtmps_enabled": rtmps_on,
            "stats_url": (
                f"{self.app.config['LRTMP2_STATS_URL']}/stats?"
                f"{urlencode({'key': stream.get('stats_key', '')})}"
            ),
        }
        if rtmps_on:
            urls["publish_url_tls"] = f"rtmps://{domain}:{rtmps_port}/{app_name}"
            urls["play_url_tls"] = (
                f"rtmps://{domain}:{rtmps_port}/{app_name}/{first_play_key}"
            )
        return urls

    @staticmethod
    def _add_player_urls(players, domain, port, app_name, rtmps_on, rtmps_port):
        for player in players:
            player["play_url"] = f"rtmp://{domain}:{port}/{app_name}/{player.get('play_key', '')}"  # nosonar python:S5332
            if rtmps_on:
                player["play_url_tls"] = (
                    f"rtmps://{domain}:{rtmps_port}/{app_name}/"
                    f"{player.get('play_key', '')}"
                )

    @staticmethod
    def _first_play_key(stream, players):
        if players:
            return players[0].get("play_key", "")
        return stream.get("play_key", "") or ""

    def login(self):
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user_ok = hmac.compare_digest(username, self.app.config["USERNAME"])
            pass_ok = hmac.compare_digest(password, self.app.config["PASSWORD"])
            if user_ok and pass_ok:
                return self._complete_login()
            error = "Invalid credentials"
        return render_template("login.html", error=error)

    def _complete_login(self):
        try:
            self._establish_logged_in_session()
        except SessionBackendUnavailable:
            self.app.logger.exception("Session backend unavailable during login")
            error = "Authentication service temporarily unavailable. Please try again."
            return render_template("login.html", error=error), 503
        return redirect(url_for("index"))

    def logout(self):
        validation_error = self._validate_logout_session()
        if validation_error is not None:
            return validation_error
        try:
            self._revoke_session_token(fail_closed=True)
        except SessionBackendUnavailable:
            self.app.logger.exception(
                "Session backend unavailable during logout for user %s",
                session.get("username"),
            )
            session["flash_error"] = (
                "Could not complete logout because the authentication service "
                "is temporarily unavailable. Your session is still active; "
                "please try again."
            )
            return redirect(url_for("index"))
        session.clear()
        return redirect(url_for("login"))

    def _validate_logout_session(self):
        try:
            if self.app.config["REQUIRE_LOGIN"] and not self._session_is_authenticated(
                fail_closed=True
            ):
                return redirect(url_for("login"))
        except SessionBackendUnavailable:
            username = session.get("username")
            self.app.logger.exception(
                "Session backend unavailable during logout validation for user %s",
                username,
            )
            error = (
                "Could not complete logout because the authentication service "
                "is temporarily unavailable. Your session is still active; "
                "please try again."
            )
            return render_template(
                INDEX_HTML,
                streams=[],
                api_error=None,
                flash_error=error,
                rtmps_enabled=False,
            ), 503
        return None

    @staticmethod
    def set_security_headers(response):
        # Match templates/base.html meta referrer policy. Browsers prefer the HTTP
        # header over the meta tag; no-referrer would omit Referer on same-origin
        # form POSTs and break WTF_CSRF_SSL_STRICT on HTTPS deployments.
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if response.content_type and (
            "text/html" in response.content_type
            or "application/json" in response.content_type
        ):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    def detect_cluster(self):
        """Return (enabled, health_or_none, detect_error_or_none)."""
        try:
            health = self.client.health()
        except Lrtmp2ApiError as exc:
            return False, None, str(exc)
        return _cluster_enabled_from_health(health), health, None

    def index(self):
        flash_error = session.pop("flash_error", None)
        try:
            streams = _normalize_streams_list(self.client.list_streams())
        except Lrtmp2ApiError as exc:
            return self._render_index_api_failure(flash_error, exc)

        cluster_on, health, detect_error = self.detect_cluster()
        rtmps_on, rtmps_port = self.rtmps_from_health(health)
        cluster_on, cluster_status_unknown, api_error = self._resolve_cluster_status(
            cluster_on,
            detect_error,
        )
        cluster_by_stream, api_error = self._load_cluster_stream_map(
            cluster_on,
            api_error,
        )
        self._decorate_streams(
            streams,
            rtmps_on,
            rtmps_port,
            cluster_on,
            cluster_by_stream,
        )
        return render_template(
            INDEX_HTML,
            streams=streams,
            api_error=api_error,
            flash_error=flash_error,
            rtmps_enabled=rtmps_on,
            cluster_enabled=cluster_on,
            cluster_status_unknown=cluster_status_unknown,
            show_cluster_nav=cluster_on or cluster_status_unknown,
        )

    def _render_index_api_failure(self, flash_error, exc):
        # Resolve cluster via health so confirmed standalone does not keep a
        # Cluster nav link. Health failure stays "unknown" (nav stays).
        cluster_on, _, detect_error = self.detect_cluster()
        cluster_status_unknown = bool(detect_error)
        return render_template(
            INDEX_HTML,
            streams=[],
            api_error=str(exc),
            flash_error=flash_error,
            rtmps_enabled=False,
            cluster_enabled=cluster_on,
            cluster_status_unknown=cluster_status_unknown,
            show_cluster_nav=cluster_on or cluster_status_unknown,
        )

    def _resolve_cluster_status(self, cluster_on, detect_error):
        api_error = detect_error
        cluster_status_unknown = bool(detect_error)
        if not cluster_status_unknown:
            return cluster_on, False, api_error
        try:
            status = self.client.cluster_status()
        except Lrtmp2ApiError as exc:
            return cluster_on, True, _append_api_error(api_error, exc)
        if isinstance(status, dict) and "enabled" in status:
            return bool(status.get("enabled")), False, api_error
        return cluster_on, True, api_error

    def _load_cluster_stream_map(self, cluster_on, api_error):
        if not cluster_on:
            return {}, api_error
        try:
            entries = self.client.cluster_streams() or []
        except Lrtmp2ApiError as exc:
            return {}, _append_api_error(api_error, exc)
        cluster_by_stream = {}
        for entry in entries:
            sid = entry.get("stream_id") or entry.get("id")
            if sid:
                cluster_by_stream[sid] = entry
        return cluster_by_stream, api_error

    def _decorate_streams(
        self,
        streams,
        rtmps_on,
        rtmps_port,
        cluster_on,
        cluster_by_stream,
    ):
        for stream in streams:
            stream.update(self.build_urls(stream, rtmps_on, rtmps_port))
            if cluster_on:
                stream["cluster"] = cluster_by_stream.get(stream.get("id"), {})

    def cluster_overview(self):
        flash_error = session.pop("flash_error", None)
        cluster_on, health, detect_error = self.detect_cluster()
        api_errors = [detect_error] if detect_error else []
        cluster, early_response, cluster_on = self._verify_cluster_status(
            cluster_on,
            detect_error,
            flash_error,
            api_errors,
        )
        if early_response is not None:
            return early_response
        cluster, nodes = self._load_cluster_details(
            cluster_on,
            detect_error,
            health,
            cluster,
            api_errors,
        )
        cluster_enabled = self._resolve_cluster_enabled(
            cluster,
            nodes,
            cluster_on,
            detect_error,
        )
        return render_template(
            CLUSTER_TEMPLATE,
            cluster_enabled=cluster_enabled,
            cluster=cluster,
            nodes=nodes,
            flash_error=flash_error,
            api_error="; ".join(api_errors) if api_errors else None,
        )

    def _verify_cluster_status(
        self,
        cluster_on,
        detect_error,
        flash_error,
        api_errors,
    ):
        if cluster_on or detect_error:
            return None, None, cluster_on
        try:
            status = self.client.cluster_status()
        except Lrtmp2ApiError as exc:
            response = render_template(
                CLUSTER_TEMPLATE,
                cluster_enabled=False,
                cluster=None,
                nodes=[],
                flash_error=flash_error,
                api_error=str(exc),
            )
            return None, response, cluster_on
        if isinstance(status, dict) and status.get("enabled"):
            api_errors.append(
                "Health probe reports standalone but cluster API is enabled."
            )
            return status, None, True
        response = render_template(
            CLUSTER_TEMPLATE,
            cluster_enabled=False,
            cluster=None,
            nodes=[],
            flash_error=flash_error,
            api_error=None,
        )
        return None, response, cluster_on

    def _load_cluster_details(
        self,
        cluster_on,
        detect_error,
        health,
        cluster,
        api_errors,
    ):
        if not (cluster_on or detect_error):
            return cluster, []
        if cluster is None:
            cluster = self._load_cluster_status(health, api_errors)
        try:
            nodes = self.client.cluster_nodes() or []
        except Lrtmp2ApiError as exc:
            api_errors.append(str(exc))
            nodes = []
        return cluster, nodes

    def _load_cluster_status(self, health, api_errors):
        try:
            return self.client.cluster_status()
        except Lrtmp2ApiError as exc:
            api_errors.append(str(exc))
            return (health or {}).get("cluster")

    @staticmethod
    def _resolve_cluster_enabled(cluster, nodes, cluster_on, detect_error):
        if isinstance(cluster, dict) and "enabled" in cluster:
            return bool(cluster.get("enabled"))
        if not cluster_on and detect_error:
            return bool(cluster) or bool(nodes)
        return cluster_on

    def _cluster_node_action(self, node_id, action):
        try:
            parsed_id = int(str(node_id), 10)
        except (TypeError, ValueError):
            session["flash_error"] = "Invalid node ID"
            return redirect(url_for("cluster_overview"))
        try:
            action_map = {
                "drain": self.client.cluster_drain_node,
                "resume": self.client.cluster_resume_node,
                "remove": self.client.cluster_remove_node,
            }
            handler = action_map.get(action)
            if handler is None:
                session["flash_error"] = "Unknown cluster action"
            else:
                handler(parsed_id)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("cluster_overview"))

    def cluster_drain_node(self, node_id):
        return self._cluster_node_action(node_id, "drain")

    def cluster_resume_node(self, node_id):
        return self._cluster_node_action(node_id, "resume")

    def cluster_remove_node(self, node_id):
        return self._cluster_node_action(node_id, "remove")

    def create_stream(self):
        form = self._default_stream_form()
        if request.method != "POST":
            return render_template(CREATE_STREAM_HTML, error=None, form=form)

        values, form = self._submitted_stream_form()
        error = self._stream_form_error(values)
        if error:
            return render_template(CREATE_STREAM_HTML, error=error, form=form)

        created_id, error = self._create_stream(values)
        if created_id:
            return redirect(url_for("stream_created", stream_id=created_id))
        return render_template(CREATE_STREAM_HTML, error=error, form=form)

    def _default_stream_form(self):
        return {
            "id": "",
            "name": "",
            "app": self.app.config["LRTMP2_APP"],
            "publish_key": "",
            "play_key": "",
            "stats_key": "",
        }

    def _submitted_stream_form(self):
        stream_id = (request.form.get("id") or secrets.token_hex(8)).strip()
        name = (request.form.get("name") or stream_id).strip()
        app_name = (
            request.form.get("app") or self.app.config["LRTMP2_APP"]
        ).strip()
        publish_key = _optional_form_value(request.form.get("publish_key"))
        play_key = _optional_form_value(request.form.get("play_key"))
        stats_key = _optional_form_value(request.form.get("stats_key"))
        values = {
            "stream_id": stream_id,
            "name": name,
            "app_name": app_name,
            "publish_key": publish_key,
            "play_key": play_key,
            "stats_key": stats_key,
        }
        form = {
            "id": request.form.get("id", "").strip(),
            "name": request.form.get("name", "").strip(),
            "app": app_name,
            "publish_key": publish_key or "",
            "play_key": play_key or "",
            "stats_key": stats_key or "",
        }
        return values, form

    @staticmethod
    def _stream_form_error(values):
        if not _is_valid_stream_id(values["stream_id"]):
            return (
                "Stream ID must be 1-63 characters and use only letters, "
                "numbers, dots, underscores, or hyphens."
            )
        if not _is_valid_app_name(values["app_name"]):
            return (
                "RTMP app must be 1-63 characters and use only letters, "
                "numbers, dots, underscores, or hyphens."
            )
        if not _is_valid_display_name(values["name"]):
            return (
                "Name must be 1-128 characters and must not contain "
                "control characters."
            )
        return _validate_optional_access_keys(
            values["publish_key"],
            values["play_key"],
            values["stats_key"],
        )

    def _create_stream(self, values):
        try:
            result = self.client.create_stream(
                values["stream_id"],
                values["name"],
                values["app_name"],
                publish_key=values["publish_key"],
                play_key=values["play_key"],
                stats_key=values["stats_key"],
            )
        except Lrtmp2ApiError as exc:
            return None, str(exc)
        created_id = result.get("id") if isinstance(result, dict) else None
        if not created_id:
            return None, "Server returned an invalid create-stream response."
        return created_id, None

    def stream_created(self):
        stream_id = request.args.get("stream_id", "")
        if not _is_valid_stream_id(stream_id):
            return redirect(url_for("index"))
        try:
            streams = _normalize_streams_list(self.client.list_streams())
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
            return redirect(url_for("index"))
        stream = next((item for item in streams if item.get("id") == stream_id), None)
        if not stream:
            session["flash_error"] = (
                f"Stream '{stream_id}' was created but is not listed yet. "
                "Check the overview."
            )
            return redirect(url_for("index"))
        rtmps_on, rtmps_port = self.rtmps_health()
        stream = dict(stream, **self.build_urls(stream, rtmps_on, rtmps_port))
        return render_template("stream_created.html", stream=stream)

    def add_player(self, stream_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = ERR_INVALID_STREAM_ID
            return redirect(url_for("index"))
        name = (request.form.get("name") or "").strip() or None
        play_key = _optional_form_value(request.form.get("play_key"))
        error = self._player_form_error(name, play_key)
        if error:
            session["flash_error"] = error
            return redirect(url_for("index"))
        try:
            self.client.create_player(stream_id, name=name, play_key=play_key)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    @staticmethod
    def _player_form_error(name, play_key):
        if name is not None and not _is_valid_display_name(name):
            return "Name must be 1-128 characters and must not contain control characters."
        if play_key is not None and not _is_valid_access_key(play_key):
            return f"play_key: {ACCESS_KEY_HELP}"
        return None

    def delete_player(self, stream_id, player_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = ERR_INVALID_STREAM_ID
            return redirect(url_for("index"))
        if not _is_valid_viewer_id(player_id):
            session["flash_error"] = "Invalid player ID"
            return redirect(url_for("index"))
        try:
            self.client.delete_player(stream_id, player_id)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    def delete_stream(self, stream_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = ERR_INVALID_STREAM_ID
            return redirect(url_for("index"))
        try:
            if not _stream_delete_drain_slots.acquire(blocking=False):
                session["flash_error"] = (
                    "Too many stream deletions are already in progress. "
                    "Please wait and try again."
                )
                return redirect(url_for("index"))
            try:
                self.client.delete_stream(stream_id)
            finally:
                _stream_delete_drain_slots.release()
        except Lrtmp2ApiError as exc:
            self._handle_delete_stream_error(stream_id, exc)
        return redirect(url_for("index"))

    def _handle_delete_stream_error(self, stream_id, exc):
        # Log a keyed correlation tag instead of the raw user-controlled
        # stream_id (SonarCloud pythonsecurity:S5145).
        stream_tag = hmac.new(
            self.app.config["SECRET_KEY"].encode(),
            stream_id.encode(),
            hashlib.sha256,
        ).hexdigest()[:12]
        self.app.logger.warning(
            "Delete stream failed (stream_tag=%s): %s",
            stream_tag,
            exc,
        )
        session["flash_error"] = str(exc)

    def stream_stats(self, stream_id):
        if not _is_valid_stream_id(stream_id):
            return jsonify({"error": ERR_INVALID_STREAM_ID}), 400
        try:
            return jsonify(self.client.stream_stats_by_id(stream_id))
        except Lrtmp2ApiError:
            return jsonify({"error": "Failed to fetch stats"}), 502

    def _add_protected_rule(self, rule, endpoint, view_func, methods):
        self.app.add_url_rule(
            rule,
            endpoint=endpoint,
            view_func=self.login_required(view_func),
            methods=methods,
        )

    def _register_routes(self):
        self.app.add_url_rule(
            "/login",
            endpoint="login",
            view_func=self.login,
            methods=["GET", "POST"],
        )
        self.app.add_url_rule(
            "/logout",
            endpoint="logout",
            view_func=self.logout,
            methods=["POST"],
        )
        self._add_protected_rule("/", "index", self.index, ["GET"])
        self._add_protected_rule(
            "/cluster",
            "cluster_overview",
            self.cluster_overview,
            ["GET"],
        )
        self._add_protected_rule(
            "/cluster/nodes/<node_id>/drain",
            "cluster_drain_node",
            self.cluster_drain_node,
            ["POST"],
        )
        self._add_protected_rule(
            "/cluster/nodes/<node_id>/resume",
            "cluster_resume_node",
            self.cluster_resume_node,
            ["POST"],
        )
        self._add_protected_rule(
            "/cluster/nodes/<node_id>/remove",
            "cluster_remove_node",
            self.cluster_remove_node,
            ["POST"],
        )
        self._add_protected_rule(
            "/streams/new",
            "create_stream",
            self.create_stream,
            ["GET", "POST"],
        )
        self._add_protected_rule(
            "/streams/created",
            "stream_created",
            self.stream_created,
            ["GET"],
        )
        self._add_protected_rule(
            "/streams/<stream_id>/players/new",
            "add_player",
            self.add_player,
            ["POST"],
        )
        self._add_protected_rule(
            "/streams/<stream_id>/players/<player_id>/delete",
            "delete_player",
            self.delete_player,
            ["POST"],
        )
        self._add_protected_rule(
            "/streams/<stream_id>/delete",
            "delete_stream",
            self.delete_stream,
            ["POST"],
        )

        stats_view = self.login_required(self.stream_stats)
        stats_view = self.limiter.exempt(flags=ExemptionScope.DEFAULT)(stats_view)
        self.app.add_url_rule(
            "/streams/<stream_id>/stats.json",
            endpoint="stream_stats",
            view_func=stats_view,
            methods=["GET"],
        )


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    _configure_proxy(app)
    _configure_security_defaults(app)
    runtime = _PanelRuntime(app)
    runtime._register_login_rate_limit()
    CSRFProtect(app)
    runtime.register_post_csrf()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
