import hmac
import secrets
from functools import wraps
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from config import Config
from store import Store
from lrtmp2_client import Lrtmp2Client, Lrtmp2ApiError


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # CSRF protection for all POST forms
    csrf = CSRFProtect(app)

    # Rate limiting: 100/min default, 5/min for login
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["100 per minute"],
        storage_uri="memory://",
    )

    # Secure session cookie settings
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )

    store = Store(app.config["PANEL_DB_PATH"])
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
            "publish_key": stream["publish_key"],
            "play_url": f"rtmp://{domain}:{port}/{app_name}/{stream['play_key']}",
            "stats_url": f"{app.config['LRTMP2_API_URL']}/stats?key={stream['stats_key']}",
        }

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            # Timing-safe comparison to prevent timing attacks
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
        streams = [dict(s, **build_urls(s)) for s in store.list_streams()]
        return render_template("index.html", streams=streams)

    @app.route("/streams/new", methods=["GET", "POST"])
    @login_required
    def create_stream():
        error = None
        if request.method == "POST":
            stream_id = request.form.get("id") or secrets.token_hex(8)
            name = request.form.get("name") or stream_id
            app_name = request.form.get("app") or app.config["LRTMP2_APP"]
            try:
                result = client.create_stream(stream_id, name, app_name)
                store.add_stream(
                    stream_id=result["id"],
                    name=result["name"],
                    app=result["app"],
                    publish_key=result["publish_key"],
                    play_key=result["play_key"],
                    stats_key=result["stats_key"],
                )
                return redirect(url_for("index"))
            except Lrtmp2ApiError as exc:
                error = str(exc)
        return render_template(
            "create_stream.html",
            error=error,
            default_app=app.config["LRTMP2_APP"],
        )

    @app.route("/streams/<stream_id>/delete", methods=["POST"])
    @login_required
    def delete_stream(stream_id):
        try:
            client.delete_stream(stream_id)
        except Lrtmp2ApiError:
            pass
        store.delete_stream(stream_id)
        return redirect(url_for("index"))

    @app.route("/streams/<stream_id>/stats.json")
    @login_required
    def stream_stats(stream_id):
        stream = store.get_stream(stream_id)
        if not stream:
            return jsonify({"error": "Stream not found"}), 404
        try:
            return jsonify(client.stream_stats(stream["stats_key"]))
        except Exception:
            return jsonify({"error": "Failed to fetch stats"}), 502

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
