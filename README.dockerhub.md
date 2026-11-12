# librtmp2-server-panel

Web UI for [librtmp2-server](https://hub.docker.com/r/openrtmp/librtmp2-server):
stream management, live stats, publish/play URLs and cluster status.

Source, full documentation and issue tracker:
**[github.com/OpenRTMP/librtmp2-server-panel](https://github.com/OpenRTMP/librtmp2-server-panel)**

> **Alpha software.** Test before relying on it in production.

The panel is a thin REST client — it needs a running `librtmp2-server` and that
server's API token. Nothing works without them.

## Quick start (existing server)

```bash
docker run -d \
  --name librtmp2-server-panel \
  -p 8000:8000 \
  -e LRTMP2_API_URL=http://<server-host>:8080 \
  -e LRTMP2_STATS_URL=http://<server-host>:8080 \
  -e LRTMP2_DOMAIN=<public-host-or-ip> \
  -e LRTMP2_API_TOKEN=<server-token> \
  -e PASSWORD=<panel-password-12-chars-or-more> \
  -e SECRET_KEY=<random-32-plus-char-secret> \
  openrtmp/librtmp2-server-panel:latest
```

Open `http://localhost:8000` and log in with `USERNAME` (default `admin`) and
`PASSWORD`.

`LRTMP2_STATS_URL` is the server URL the **browser** can reach; it is used for
copied stats links. Leave it unset if it equals `LRTMP2_API_URL` from the
browser's point of view.

## Full stack (server + panel + Redis)

Copy the quickstart compose file and its `.env` template, then start both
containers with prebuilt images:

```bash
curl -LO https://raw.githubusercontent.com/OpenRTMP/librtmp2-server-panel/main/compose.quickstart.yml
curl -LO https://raw.githubusercontent.com/OpenRTMP/librtmp2-server-panel/main/.env.example
mv .env.example .env      # fill in API token, PASSWORD and SECRET_KEY
docker compose -f compose.quickstart.yml up -d
```

To use Docker Hub instead of GHCR, replace the two `image:` lines with
`openrtmp/librtmp2-server:latest` and `openrtmp/librtmp2-server-panel:latest`.

## Supported tags and architectures

- `latest`, `beta`, `alpha` — moving channels
- `0.1.15`, `v0.1.15` — pinned releases (both spellings are published)
- `linux/amd64`, `linux/arm64`, `linux/riscv64`

Mirrors: `ghcr.io/openrtmp/librtmp2-server-panel` and
`quay.io/openrtmp/librtmp2-server-panel`.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP | Panel UI (Gunicorn, `gthread`, 4 threads) |

## Configuration

| Variable | Required | Purpose |
|----------|----------|---------|
| `LRTMP2_API_URL` | yes | Server REST API, reachable from the panel container |
| `LRTMP2_API_TOKEN` | yes | Server API token (must match the server) |
| `LRTMP2_STATS_URL` | no | Server URL used in copied stats links (browser-reachable) |
| `LRTMP2_DOMAIN` | no | Public host/IP used in generated RTMP/RTMPS URLs (default `localhost`) |
| `LRTMP2_RTMP_PORT` / `LRTMP2_RTMPS_PORT` | no | Ports used in generated URLs (`1935` / `1936`) |
| `LRTMP2_APP` | no | Default RTMP application name (default `live`) |
| `USERNAME` / `PASSWORD` | yes* | Panel login (password ≥ 12 characters) |
| `SECRET_KEY` | yes | Session signing key, ≥ 32 characters |
| `REQUIRE_LOGIN` | no | `True` by default; `False` requires `ALLOW_INSECURE_NO_LOGIN=1` |
| `RATELIMIT_STORAGE_URI` | no | Rate-limit store; `redis://…` for multi-worker, `memory://` for single process |
| `PANEL_PUBLIC_URL` | no | Public panel URL; drives `SESSION_COOKIE_SECURE` auto-detection |
| `SESSION_COOKIE_SECURE` | no | Force secure cookies; set for HTTPS deployments |
| `PANEL_ALLOW_INSECURE_HTTP` | no | `1` permits plain-HTTP serving (default in the quickstart) |
| `TRUSTED_PROXY_COUNT` / `TRUSTED_PROXY_IPS` | no | Enable and scope `X-Forwarded-*` handling |

\* Required while `REQUIRE_LOGIN` is enabled (the default).

The container validates configuration at startup and exits with a clear error
when a required value is missing or too short.

Full variable reference:
[`.env.example`](https://github.com/OpenRTMP/librtmp2-server-panel/blob/main/.env.example)
· [README](https://github.com/OpenRTMP/librtmp2-server-panel#readme)

## Reverse proxy notes

For HTTPS behind nginx/Caddy/Traefik:

1. Set `PANEL_PUBLIC_URL=https://panel.example.com` (or `SESSION_COOKIE_SECURE=true`).
2. Set `PANEL_ALLOW_INSECURE_HTTP=0`.
3. Set `TRUSTED_PROXY_COUNT=1` and `TRUSTED_PROXY_IPS` to the proxy network.
4. Do not strip the `Host` header.

## Health and safety

- Built-in healthcheck: `GET http://localhost:8000/login`
- Runs as the unprivileged user `openrtmp`
- Session cookies signed with `SECRET_KEY`; rate limiting via Redis in the compose stack

## License

MIT — see [LICENSE](https://github.com/OpenRTMP/librtmp2-server-panel/blob/main/LICENSE).
