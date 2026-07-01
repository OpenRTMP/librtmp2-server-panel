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


def _is_valid_stream_id(value):
    return bool(STREAM_ID_RE.fullmatch(value or ""))


def _is_valid_app_name(value):
    return bool(APP_NAME_RE.fullmatch(value or ""))


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf = CSRFProtect(app)

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["100 per minute"],
        storage_uri="memory://",
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

    def build_urls(stream):
        domain = app.config["LRTMP2_DOMAIN"]
        port = app.config["LRTMP2_RTMP_PORT"]
        app_name = stream["app"]
        return {
            "publish_url": f"rtmp://{domain}:{port}/{app_name}",
            "publish_key": stream.get("publish_key", ""),
            "play_url": (
                f"rtmp://{domain}:{port}/{app_name}/{stream.get('play_key', '')}"
            ),
            "stats_url": (
                f"{app.config['LRTMP2_STATS_URL']}/stats?"
                f"{urlencode({'key': stream.get('stats_key', '')})}"
            ),
        }

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

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

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
            )
        for stream in streams:
            stream.update(build_urls(stream))
        return render_template("index.html", streams=streams, flash_error=flash_error)

    @app.route("/streams/new", methods=["GET", "POST"])
    @login_required
    def create_stream():
        error = None
        if request.method == "POST":
            stream_id = (request.form.get("id") or secrets.token_hex(8)).strip()
            name = (request.form.get("name") or stream_id).strip()
            app_name = (request.form.get("app") or app.config["LRTMP2_APP"]).strip()
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
            else:
                try:
                    result = client.create_stream(stream_id, name, app_name)
                    session["created_stream"] = result
                    return redirect(url_for("stream_created"))
                except Lrtmp2ApiError as exc:
                    error = str(exc)
        return render_template(
            "create_stream.html",
            error=error,
            default_app=app.config["LRTMP2_APP"],
        )

    @app.route("/streams/created")
    @login_required
    def stream_created():
        stream = session.pop("created_stream", None)
        if not stream:
            return redirect(url_for("index"))
        stream = dict(stream, **build_urls(stream))
        return render_template("stream_created.html", stream=stream)

    @app.route("/streams/<stream_id>/delete", methods=["POST"])
    @login_required
    def delete_stream(stream_id):
        try:
            client.delete_stream(stream_id)
        except Lrtmp2ApiError as exc:
            session["flash_error"] = str(exc)
        return redirect(url_for("index"))

    @app.route("/streams/<stream_id>/stats.json")
    @login_required
    def stream_stats(stream_id):
        try:
            return jsonify(client.stream_stats_by_id(stream_id))
        except Lrtmp2ApiError:
            return jsonify({"error": "Failed to fetch stats"}), 502

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
