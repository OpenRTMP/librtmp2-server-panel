import time
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

    def _request_json(self, request_func, url, operation, **kwargs):
        """_request + the raise-on-error/parse-JSON sequence shared by every
        endpoint that returns a body (i.e. everything but the 404-tolerant
        deletes, which need their own status handling)."""
        resp = self._request(request_func, url, operation, **kwargs)
        if not resp.ok:
            raise _api_error(resp, operation)
        return _parse_json(resp, operation)

    def health(self):
        return self._request_json(
            requests.get, f"{self.base_url}/api/v1/health", "health"
        )

    def list_streams(self):
        return self._request_json(
            requests.get,
            f"{self.base_url}/api/v1/streams",
            "list_streams",
            headers=self._headers(),
        )

    def create_stream(
        self,
        stream_id,
        name,
        app,
        publish_key=None,
        play_key=None,
        stats_key=None,
    ):
        payload = {"id": stream_id, "name": name, "app": app}
        if publish_key:
            payload["publish_key"] = publish_key
        if play_key:
            payload["play_key"] = play_key
        if stats_key:
            payload["stats_key"] = stats_key
        return self._request_json(
            requests.post,
            f"{self.base_url}/api/v1/streams",
            "create_stream",
            headers=self._headers(),
            json=payload,
        )

    def delete_stream(self, stream_id, wait_timeout=5, poll_interval=0.5):
        """Delete a stream. librtmp2-server may accept the request with `202`
        and finish the delete asynchronously (draining active RTMP sessions
        first) — poll until the stream actually disappears from the list so
        callers can rely on the stream being gone once this returns, rather
        than racing the background delete. Best-effort: if the delete is
        still pending after `wait_timeout` seconds, this returns anyway and
        the caller will see the stream reappear as still-present.
        """
        resp = self._request(
            requests.delete,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}",
            "delete_stream",
            headers=self._headers(),
        )
        if not resp.ok and resp.status_code != 404:
            raise _api_error(resp, "delete_stream")
        if resp.status_code == 202:
            deadline = time.monotonic() + wait_timeout
            while time.monotonic() < deadline:
                streams = self.list_streams()
                if not any(s.get("id") == stream_id for s in streams):
                    break
                time.sleep(poll_interval)

    def create_player(self, stream_id, name=None, play_key=None):
        payload = {}
        if name:
            payload["name"] = name
        if play_key:
            payload["play_key"] = play_key
        return self._request_json(
            requests.post,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/players",
            "create_player",
            headers=self._headers(),
            json=payload,
        )

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
        return self._request_json(
            requests.get,
            f"{self.base_url}/stats",
            "stream_stats",
            params={"key": stats_key},
        )

    def stream_stats_by_id(self, stream_id):
        return self._request_json(
            requests.get,
            f"{self.base_url}/api/v1/streams/{quote(stream_id, safe='')}/stats",
            "stream_stats_by_id",
            headers=self._headers(),
        )
