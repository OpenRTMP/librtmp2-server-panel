# librtmp2-server-panel

![GitHub Release](https://img.shields.io/github/v/release/OpenRTMP/librtmp2-server-panel)
![Language](https://img.shields.io/badge/language-Python-orange)

A web-based control panel for [librtmp2-server](https://github.com/OpenRTMP/librtmp2-server). Manage streams, copy publish/play URLs, and view live stats through a simple UI.

The panel reads streams, keys, and stats directly from the server REST API. Keys are shown blurred in the overview and can be copied on click.

## Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Description | Required |
|----------|-------------|----------|
| `LRTMP2_API_URL` | Base URL of librtmp2-server's HTTP API (`http.bind`; server-side / internal) | Yes |
| `LRTMP2_STATS_URL` | Browser-reachable HTTP API URL for copied stats links (defaults to `LRTMP2_API_URL`) | No |
| `LRTMP2_API_TOKEN` | Bearer token from librtmp2-server (printed once on first server startup, stored in its SQLite DB) | Yes |
| `LRTMP2_DOMAIN` | Public host/IP clients use to reach the RTMP listener | Yes |
| `LRTMP2_RTMP_PORT` | RTMP port (`rtmp.bind` port), default `1935` | No |
| `LRTMP2_APP` | Default RTMP app name for new streams, default `live` | No |
| `REQUIRE_LOGIN` | Enable panel login (`True`/`False`, default `True`) | No |
| `USERNAME` / `PASSWORD` | Panel admin credentials | If login enabled |
| `SECRET_KEY` | Flask session secret | Yes |
| `RATELIMIT_STORAGE_URI` | Shared rate-limit store for multi-worker Gunicorn (`redis://…`; docker-compose defaults to Redis) | No |

## Quick Start (Docker Compose)

```bash
git clone https://github.com/OpenRTMP/librtmp2-server-panel.git
cd librtmp2-server-panel
cp .env.example .env   # set PASSWORD, SECRET_KEY, LRTMP2_DOMAIN, etc.
docker compose up -d server
docker logs librtmp2-server   # copy the generated API token
# paste token into .env as LRTMP2_API_TOKEN=
docker compose up -d panel
```

The server generates its API token **once** on first startup, stores it in SQLite (`/data/server.db`), and prints it to the log. It cannot be set via config or environment. The panel only needs the token in `.env` so it can call the REST API.

Open `http://localhost:8000`.

## Quick Start (prebuilt image)

Prebuilt multi-arch images (`amd64`/`arm64`/`riscv64`) are published to
`ghcr.io/openrtmp/librtmp2-server-panel` on every release — no local build
needed. Assumes a [librtmp2-server](https://github.com/OpenRTMP/librtmp2-server#docker)
container is already running and you've copied its API token from `docker logs`:

```bash
docker run -d \
  --name librtmp2-server-panel \
  -p 8000:8000 \
  -e LRTMP2_API_URL=http://<server-host>:8080 \
  -e LRTMP2_DOMAIN=<public-host-or-ip> \
  -e LRTMP2_API_TOKEN=<token-from-server-logs> \
  -e PASSWORD=<panel-password-12-chars-or-more> \
  -e SECRET_KEY=<random-32-plus-char-secret> \
  ghcr.io/openrtmp/librtmp2-server-panel:latest
```

Available tags: `latest`, `beta`, `alpha`, and pinned versions (e.g. `0.1.3` /
`v0.1.3`). Without `RATELIMIT_STORAGE_URI` the `/login` rate limit is
per-worker in-memory; use `docker compose up -d` (see above) for the Redis-backed,
production-ready multi-worker setup.

## Local Development

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit values
export $(grep -v '^#' .env | xargs)
python3 app.py
```

## Features

- Create/delete streams against librtmp2-server's REST API
- One-click copy for publish URL, stream key, play URL, and stats URL
- Live per-stream stats (bitrate, resolution, codec, uptime, RTT) polled from `/stats?key=...`
- Optional login gate for the whole panel, enabled by default on network-exposed deployments
