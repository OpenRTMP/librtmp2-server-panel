import requests


class Lrtmp2ApiError(Exception):
    pass


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
        resp.raise_for_status()
        return resp.json()

    def create_stream(self, stream_id, name, app):
        resp = requests.post(
            f"{self.base_url}/api/v1/streams",
            headers=self._headers(),
            json={"id": stream_id, "name": name, "app": app},
            timeout=self.timeout,
        )
        if not resp.ok:
            raise Lrtmp2ApiError(f"create_stream failed: HTTP {resp.status_code} {resp.text}")
        return resp.json()

    def delete_stream(self, stream_id):
        resp = requests.delete(
            f"{self.base_url}/api/v1/streams/{stream_id}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not resp.ok and resp.status_code != 404:
            raise Lrtmp2ApiError(f"delete_stream failed: HTTP {resp.status_code} {resp.text}")

    def stream_stats(self, stats_key):
        resp = requests.get(
            f"{self.base_url}/stats", params={"key": stats_key}, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()
