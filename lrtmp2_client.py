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


def _parse_json(resp, operation):
    """Parse a successful response body, surfacing malformed JSON as an API error
    instead of letting a raw ValueError escape to the caller."""
    try:
        return resp.json()
    except ValueError as exc:
        raise Lrtmp2ApiError(
            f"{operation} failed: received an invalid response from librtmp2-server"
        ) from exc


class Lrtmp2Client:
    """Thin client for the librtmp2-server REST API."""

    def __init__(self, base_url, token, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def _request(self, request_func, url, operation, **kwargs):
        """Perform an HTTP request, translating network-level failures (connection
        refused, DNS failure, timeout, ...) into Lrtmp2ApiError so callers only ever
        need to catch one exception type instead of the request crashing the panel."""
        try:
            return request_func(url, timeout=self.timeout, **kwargs)
        except requests.exceptions.Timeout as exc:
            raise Lrtmp2ApiError(
                f"{operation} failed: librtmp2-server did not respond in time"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise Lrtmp2ApiError(
                f"{operation} failed: could not reach librtmp2-server"
            ) from exc

    def health(self):
        resp = self._request(requests.get, f"{self.base_url}/api/v1/health", "health")
        if not resp.ok:
            raise _api_error(resp, "health")
        return _parse_json(resp, "health")

    def list_streams(self):
        resp = self._request(
            requests.get,
            f"{self.base_url}/api/v1/streams",
            "list_streams",
            headers=self._headers(),
        )
        if not resp.ok:
            raise _api_error(resp, "list_streams")
        return _parse_json(resp, "list_streams")

    def create_stream(self, stream_id, name, app):
        resp = self._request(
            requests.post,
            f"{self.base_url}/api/v1/streams",
            "create_stream",
            headers=self._headers(),
            json={"id": stream_id, "name": name, "app": app},
        )
        if not resp.ok:
            raise _api_error(resp, "create_stream")
        return _parse_json(resp, "create_stream")

    def delete_stream(self, stream_id):
        resp = self._request(
            requests.delete,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}",
            "delete_stream",
            headers=self._headers(),
        )
        if not resp.ok and resp.status_code != 404:
            raise _api_error(resp, "delete_stream")

    def create_player(self, stream_id, name=None):
        payload = {}
        if name:
            payload["name"] = name
        resp = self._request(
            requests.post,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/players",
            "create_player",
            headers=self._headers(),
            json=payload,
        )
        if not resp.ok:
            raise _api_error(resp, "create_player")
        return _parse_json(resp, "create_player")

    def delete_player(self, stream_id, player_id):
        resp = self._request(
            requests.delete,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/players/{quote(player_id, safe='')}",
            "delete_player",
            headers=self._headers(),
        )
        if not resp.ok and resp.status_code != 404:
            raise _api_error(resp, "delete_player")

    def stream_stats(self, stats_key):
        resp = self._request(
            requests.get,
            f"{self.base_url}/stats",
            "stream_stats",
            params={"key": stats_key},
        )
        if not resp.ok:
            raise _api_error(resp, "stream_stats")
        return _parse_json(resp, "stream_stats")

    def stream_stats_by_id(self, stream_id):
        resp = self._request(
            requests.get,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/stats",
            "stream_stats_by_id",
            headers=self._headers(),
        )
        if not resp.ok:
            raise _api_error(resp, "stream_stats_by_id")
        return _parse_json(resp, "stream_stats_by_id")
