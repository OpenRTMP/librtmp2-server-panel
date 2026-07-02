from urllib.parse import quote

import requests


class Lrtmp2ApiError(Exception):
    pass


def _api_error(resp, operation):
    """Return a user-safe error; log details only in the exception message prefix."""
    msg = f"{operation} failed (HTTP {resp.status_code})"
    try:
        body = resp.json()
    except ValueError:
        return Lrtmp2ApiError(msg)
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return Lrtmp2ApiError(f"{operation} failed: {err['message']}")
        if isinstance(err, str) and err:
            return Lrtmp2ApiError(f"{operation} failed: {err}")
    return Lrtmp2ApiError(msg)


class Lrtmp2Client:
    """Thin client for the librtmp2-server REST API."""

    def __init__(self, base_url, token, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def health(self):
        resp = requests.get(f"{self.base_url}/api/v1/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def list_streams(self):
        resp = requests.get(
            f"{self.base_url}/api/v1/streams", headers=self._headers(), timeout=self.timeout
        )
        if not resp.ok:
            raise _api_error(resp, "list_streams")
        return resp.json()

    def create_stream(self, stream_id, name, app):
        resp = requests.post(
            f"{self.base_url}/api/v1/streams",
            headers=self._headers(),
            json={"id": stream_id, "name": name, "app": app},
            timeout=self.timeout,
        )
        if not resp.ok:
            raise _api_error(resp, "create_stream")
        return resp.json()

    def delete_stream(self, stream_id):
        resp = requests.delete(
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not resp.ok and resp.status_code != 404:
            raise _api_error(resp, "delete_stream")

    def create_player(self, stream_id, name=None):
        payload = {}
        if name:
            payload["name"] = name
        resp = requests.post(
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/players",
            headers=self._headers(),
            json=payload,
            timeout=self.timeout,
        )
        if not resp.ok:
            raise _api_error(resp, "create_player")
        return resp.json()

    def delete_player(self, stream_id, player_id):
        resp = requests.delete(
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/players/{quote(player_id, safe='')}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not resp.ok and resp.status_code != 404:
            raise _api_error(resp, "delete_player")

    def stream_stats(self, stats_key):
        resp = requests.get(
            f"{self.base_url}/stats", params={"key": stats_key}, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    def stream_stats_by_id(self, stream_id):
        resp = requests.get(
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/stats",
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not resp.ok:
            raise _api_error(resp, "stream_stats_by_id")
        return resp.json()
