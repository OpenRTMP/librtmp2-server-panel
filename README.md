# librtmp2-server-panel

[![Project status: alpha](https://img.shields.io/badge/status-alpha-red)](https://openrtmp.org/)
![GitHub Release](https://img.shields.io/github/v/release/OpenRTMP/librtmp2-server-panel)
![Language](https://img.shields.io/badge/language-Python-orange)

A web control panel for [librtmp2-server](https://github.com/OpenRTMP/librtmp2-server). Create streams, copy OBS/playback URLs, manage keys, and view live bitrate, codec, resolution, RTT, uptime, and viewer statistics.

> **Project status:** active alpha. Use it for evaluation, development, and tested self-hosted deployments. Pin image versions and validate your complete workflow before critical production use.

- Website: [openrtmp.org](https://openrtmp.org/)
- Five-minute guide: [openrtmp.org/quickstart/](https://openrtmp.org/quickstart/)
- Server: [OpenRTMP/librtmp2-server](https://github.com/OpenRTMP/librtmp2-server)

## Start the full stack in five minutes

The standalone quickstart uses prebuilt server and panel images. It does **not** require a neighboring `librtmp2-server` source checkout.

Requirements: Docker with Docker Compose, OpenSSL, and Python 3 for secret generation.

```bash
git clone https://github.com/OpenRTMP/librtmp2-server-panel.git
cd librtmp2-server-panel

API_TOKEN="$(openssl rand -hex 32)"
PANEL_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
PANEL_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"

cat > .env <<EOF
LRTMP2_API_TOKEN=${API_TOKEN}
LRTMP2_DOMAIN=localhost
LRTMP2_STATS_URL=http://localhost:8080
USERNAME=admin
PASSWORD=${PANEL_PASSWORD}
SECRET_KEY=${PANEL_SECRET}
REQUIRE_LOGIN=True
EOF

docker compose -f compose.quickstart.yml up -d
printf 'Panel: http://localhost:8000\nLogin: admin\nPassword: %s\n' "${PANEL_PASSWORD}"
```

Open `http://localhost:8000`, sign in, and create a stream. The panel then shows the exact publish, playback, and statistics URLs.

For OBS, the default values are:

- Server: `rtmp://localhost:1935/live`
- Stream key: the generated `publish_key` shown by the panel

Health checks:

```bash
curl http://localhost:8080/api/v1/health
docker compose -f compose.quickstart.yml ps
```

Stop the stack without deleting its SQLite data:

```bash
docker compose -f compose.quickstart.yml down
```

For an internet-facing deployment, replace `localhost` with the public hostname, put the HTTP services behind HTTPS, restrict port `8080`, and pin the server/panel image tags instead of tracking `latest`.

## API token behavior

`LRTMP2_API_TOKEN` is shared by the panel and server. On the server's first startup, the process environment value is stored in SQLite. If no value is supplied, the server generates a token and prints it once to its logs.

The server intentionally does not read this secret from its normal server `.env` configuration file. Docker Compose passes it as a real process environment variable. After the database has been initialized, changing only the Compose `.env` value does not automatically rotate the token stored in SQLite.

## Configuration

Copy `.env.example` to `.env` for a manual setup and adjust:

| Variable | Description | Required |
|----------|-------------|----------|
| `LRTMP2_API_URL` | Internal/server-side base URL of librtmp2-server | Yes outside the quickstart stack |
| `LRTMP2_STATS_URL` | Browser-reachable API URL used in copied stats links | No |
| `LRTMP2_API_TOKEN` | Shared bearer token seeded into the server on first startup | Yes |
| `LRTMP2_DOMAIN` | Public host/IP clients use for RTMP URLs | Yes |
| `LRTMP2_RTMP_PORT` | Public RTMP port, default `1935` | No |
| `LRTMP2_RTMPS_PORT` | Public RTMPS port, default `1936` | No |
| `LRTMP2_APP` | Default RTMP application, default `live` | No |
| `REQUIRE_LOGIN` | Enable panel login, default `True` | No |
| `USERNAME` / `PASSWORD` | Panel administrator credentials | When login is enabled |
| `SECRET_KEY` | Flask session secret | Yes |
| `RATELIMIT_STORAGE_URI` | Shared Flask-Limiter backend; quickstart uses Redis | No |
| `PANEL_PUBLIC_URL` | Public panel URL, used for secure-cookie detection | No |
| `SESSION_COOKIE_SECURE` | Force secure cookies when served over HTTPS | No |

## Source-development stack

The repository's `docker-compose.yml` is intended for development and builds the server from a sibling checkout:

```text
parent/
├── librtmp2-server/
└── librtmp2-server-panel/
```

```bash
cd parent
git clone https://github.com/OpenRTMP/librtmp2-server.git
git clone https://github.com/OpenRTMP/librtmp2-server-panel.git
cd librtmp2-server-panel
cp .env.example .env
# Set LRTMP2_API_TOKEN, PASSWORD, SECRET_KEY, and LRTMP2_DOMAIN.
docker compose up -d
```

Use `compose.quickstart.yml` when you only want the published images.

## Run only the panel

When a server already exists:

```bash
docker run -d \
  --name librtmp2-server-panel \
  -p 8000:8000 \
  -e LRTMP2_API_URL=http://<server-host>:8080 \
  -e LRTMP2_DOMAIN=<public-host-or-ip> \
  -e LRTMP2_API_TOKEN=<server-token> \
  -e PASSWORD=<panel-password-12-chars-or-more> \
  -e SECRET_KEY=<random-32-plus-char-secret> \
  ghcr.io/openrtmp/librtmp2-server-panel:latest
```

Prebuilt multi-architecture images are published for `amd64`, `arm64`, and `riscv64`. Available tags include release versions and the moving `latest`, `beta`, and `alpha` channels.

## Local Python development

```bash
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit the required values, then:
python3 app.py
```

## Features

- Create and delete streams through the server REST API
- Copy publish URL, stream key, play URL, and stats URL
- Live per-stream bitrate, resolution, codec, uptime, RTT, and viewer statistics
- Blurred key display with explicit copy actions
- Login protection, CSRF protection, rate limiting, and encrypted key storage
- RTMP and conditional RTMPS URL generation based on live server health data

## Support and contributing

Use [GitHub Issues](https://github.com/OpenRTMP/librtmp2-server-panel/issues) for reproducible bugs and feature requests. General architecture and usage discussions belong in [OpenRTMP Discussions](https://github.com/OpenRTMP/librtmp2/discussions).

Contributions are welcome. Please include reproduction steps, screenshots for UI changes, and tests where practical.
