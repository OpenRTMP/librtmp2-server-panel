import hmac
import re
import secrets
from functools import wraps
from urllib.parse import urlencode

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from config import Config
from lrtmp2_client import Lrtmp2Client, Lrtmp2ApiError


STREAM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
APP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
VIEWER_ID_RE = re.compile(r"^vi_[0-9a-f]{32}$")
DISPLAY_NAME_MAX_LEN = 128
ACCESS_KEY_HELP = (
    "Must be 1-63 characters and use only letters, numbers, dots, "
    "underscores, or hyphens."
)


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
    return _is_valid_stream_id(value)


def _optional_form_value(raw):
    if raw is None:
        return None
    stripped = str(raw).strip()
    return stripped or None


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


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf = CSRFProtect(app)

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["100 per minute"],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    )

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=app.config["SESSION_COOKIE_SECURE"],
    )

    client = Lrtmp2Client(app.config["LRTMP2_API_URL"], app.config["LRTMP2_API_TOKEN"])

    def login_required(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if app.config["REQUIRE_LOGIN"] and not session.get("logged_in"):
                return redirect(url_for("login"))
            return view_func(*args, **kwargs)
        return wrapped

    def rtmps_health():
        """Return RTMPS availability and the public RTMPS port to advertise.

        RTMPS enablement is read live from /api/v1/health, but URLs must use
        the panel's public port config first. That preserves Docker/NAT/reverse
        proxy mappings such as public 443 -> server bind 1936. The server's
        reported bind port is only used as a fallback when the public config is
        empty or missing.
        """
        configured_port = str(app.config.get("LRTMP2_RTMPS_PORT") or "")
        try:
            health = client.health()
        except Lrtmp2ApiError:
            return False, configured_port or "1936"
        if not health.get("rtmps_enabled"):
            return False, configured_port or "1936"
        reported_port = str(health.get("rtmps_port") or "")
        return True, configured_port or reported_port or "1936"

    def build_urls(stream, rtmps_on, rtmps_port):
        domain = app.config["LRTMP2_DOMAIN"]
        port = app.config["LRTMP2_RTMP_PORT"]
        app_name = stream["app"]
        publish_url = f"rtmp://{domain}:{port}/{app_name}"
        players = stream.get("players") or []
        for player in players:
            player["play_url"] = f"rtmp://{domain}:{port}/{app_name}/{player.get('play_key', '')}"
            if rtmps_on:
                player["play_url_tls"] = (
                    f"rtmps://{domain}:{rtmps_port}/{app_name}/{player.get('play_key', '')}"
                )
        first_play_key = ""
        if players:
            first_play_key = players[0].get("play_key", "")
        elif stream.get("play_key"):
            first_play_key = stream["play_key"]
        urls = {
            "publish_url": publish_url,
            "publish_key": stream.get("publish_key", ""),
            "play_url": f"rtmp://{domain}:{port}/{app_name}/{first_play_key}",
            "play_key": first_play_key,
            "rtmps_enabled": rtmps_on,
            "stats_url": (
                f"{app.config['LRTMP2_STATS_URL']}/stats?"
                f"{urlencode({'key': stream.get('stats_key', '')})}"
            ),
        }
        if rtmps_on:
            urls["publish_url_tls"] = f"rtmps://{domain}:{rtmps_port}/{app_name}"
            urls["play_url_tls"] = f"rtmps://{domain}:{rtmps_port}/{app_name}/{first_play_key}"
        return urls

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user_ok = hmac.compare_digest(username, app.config["USERNAME"])
            pass_ok = hmac.compare_digest(password, app.config["PASSWORD"])
            if user_ok and pass_ok:
                session.clear()
                session["logged_in"] = True
                session["_csrf_token"] = secrets.token_hex(32)
                return redirect(url_for("index"))
            error = "Invalid credentials"
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.route("/")
    @login_required
    def index():
        flash_error = session.pop("flash_error", None)
        try:
            streams = client.list_streams()
        except Lrtmp2ApiError as exc:
            return render_template(
                "index.html",
                streams=[],
                api_error=str(exc),
                flash_error=flash_error,
                rtmps_enabled=False,
            )
        rtmps_on, rtmps_port = rtmps_health()
        for stream in streams:
            stream.update(build_urls(stream, rtmps_on, rtmps_port))
        return render_template(
            "index.html",
            streams=streams,
            flash_error=flash_error,
            rtmps_enabled=rtmps_on,
        )

    @app.route("/streams/new", methods=["GET", "POST"])
    @login_required
    def create_stream():
        error = None
        form = {
            "id": "",
            "name": "",
            "app": app.config["LRTMP2_APP"],
            "publish_key": "",
            "play_key": "",
            "stats_key": "",
        }
        if request.method == "POST":
            stream_id = (request.form.get("id") or secrets.token_hex(8)).strip()
            name = (request.form.get("name") or stream_id).strip()
            app_name = (request.form.get("app") or app.config["LRTMP2_APP"]).strip()
            publish_key = _optional_form_value(request.form.get("publish_key"))
            play_key = _optional_form_value(request.form.get("play_key"))
            stats_key = _optional_form_value(request.form.get("stats_key"))
            form = {
                "id": request.form.get("id", "").strip(),
                "name": request.form.get("name", "").strip(),
                "app": app_name,
                "publish_key": publish_key or "",
                "play_key": play_key or "",
                "stats_key": stats_key or "",
            }
            if not _is_valid_stream_id(stream_id):
                error = (
                    "Stream ID must be 1-63 characters and use only letters, "
                    "numbers, dots, underscores, or hyphens."
                )
            elif not _is_valid_app_name(app_name):
                error = (
                    "RTMP app must be 1-63 characters and use only letters, "
                    "numbers, dots, underscores, or hyphens."
                )
            elif not _is_valid_display_name(name):
                error = (
                    "Name must be 1-128 characters and must not contain "
                    "control characters."
                )
            elif (key_error := _validate_optional_access_keys(
                publish_key, play_key, stats_key
            )):
                error = key_error
            else:
                try:
                    result = client.create_stream(
                        stream_id,
                        name,
                        app_name,
                        publish_key=publish_key,
                        play_key=play_key,
                        stats_key=stats_key,
                    )
                    return redirect(url_for("stream_created", stream_id=result["id"]))
                except Lrtmp2ApiError as exc:
                    error = str(exc)
        return render_template(
            "create_stream.html",
            error=error,
            form=form,
        )

    @app.route("/streams/created")
    @login_required
    def stream_created():
        stream_id = request.args.get("stream_id", "")
        if not _is_valid_stream_id(stream_id):
            return redirect(url_for("index"))
        try:
            streams = client.list_streams()
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
            return redirect(url_for("index"))
        stream = next((s for s in streams if s.get("id") == stream_id), None)
        if not stream:
            session["flash_error"] = (
                f"Stream '{stream_id}' was created but is not listed yet. "
                "Check the overview."
            )
            return redirect(url_for("index"))
        rtmps_on, rtmps_port = rtmps_health()
        stream = dict(stream, **build_urls(stream, rtmps_on, rtmps_port))
        return render_template("stream_created.html", stream=stream)

    @app.route("/streams/<stream_id>/players/new", methods=["POST"])
    @login_required
    def add_player(stream_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = "Invalid stream ID"
            return redirect(url_for("index"))
        name = (request.form.get("name") or "").strip() or None
        play_key = _optional_form_value(request.form.get("play_key"))
        if name is not None and not _is_valid_display_name(name):
            session["flash_error"] = (
                "Name must be 1-128 characters and must not contain control characters."
            )
            return redirect(url_for("index"))
        if play_key is not None and not _is_valid_access_key(play_key):
            session["flash_error"] = f"play_key: {ACCESS_KEY_HELP}"
            return redirect(url_for("index"))
        try:
            client.create_player(stream_id, name=name, play_key=play_key)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    @app.route("/streams/<stream_id>/players/<player_id>/delete", methods=["POST"])
    @login_required
    def delete_player(stream_id, player_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = "Invalid stream ID"
            return redirect(url_for("index"))
        if not _is_valid_viewer_id(player_id):
            session["flash_error"] = "Invalid player ID"
            return redirect(url_for("index"))
        try:
            client.delete_player(stream_id, player_id)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    @app.route("/streams/<stream_id>/delete", methods=["POST"])
    @login_required
    def delete_stream(stream_id):
        if not _is_valid_stream_id(stream_id):
            session["flash_error"] = "Invalid stream ID"
            return redirect(url_for("index"))
        try:
            client.delete_stream(stream_id)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    @app.route("/streams/<stream_id>/stats.json")
    @limiter.exempt
    @login_required
    def stream_stats(stream_id):
        if not _is_valid_stream_id(stream_id):
            return jsonify({"error": "Invalid stream ID"}), 400
        try:
            return jsonify(client.stream_stats_by_id(stream_id))
        except Lrtmp2ApiError:
            return jsonify({"error": "Failed to fetch stats"}), 502

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
