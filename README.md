# librtmp2-server-panel

A web-based control panel for [librtmp2-server](https://github.com/OpenRTMP/librtmp2-server). Manage streams, copy publish/play URLs, and view live stats through a simple UI.

## Why a local database?

`librtmp2-server` only returns `publish_key` / `play_key` / `stats_key` once, at stream creation time (`POST /api/v1/streams`) — by design, nobody can list existing keys afterwards. The panel therefore stores created streams and their keys locally (SQLite) so it can rebuild publish/play/stats URLs later. Deleting a stream in the panel also deletes it on the server.

## Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Description | Required |
|----------|-------------|----------|
| `LRTMP2_API_URL` | Base URL of librtmp2-server's HTTP API (`http.bind`) | Yes |
| `LRTMP2_API_TOKEN` | Token printed by `librtmp2-server` on first startup and stored in its SQLite DB | Yes |
| `LRTMP2_DOMAIN` | Public host/IP clients use to reach the RTMP listener | Yes |
| `LRTMP2_RTMP_PORT` | RTMP port (`rtmp.bind` port), default `1935` | No |
| `LRTMP2_APP` | Default RTMP app name for new streams, default `live` | No |
| `REQUIRE_LOGIN` | Enable panel login (`True`/`False`) | No |
| `USERNAME` / `PASSWORD` | Panel admin credentials | If login enabled |
| `SECRET_KEY` | Flask session secret | Yes |
| `PANEL_DB_PATH` | SQLite file path for stored stream keys | No |

## Quick Start (Docker Compose)

```bash
git clone https://github.com/OpenRTMP/librtmp2-server-panel.git
cd librtmp2-server-panel
# edit docker-compose.yml with your librtmp2-server URL/token/domain
docker compose up -d
```

Open `http://localhost:8000`.

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
- Live per-stream stats (bitrate, resolution, codec, uptime) polled from `/stats?key=...`
- Optional login gate for the whole panel
