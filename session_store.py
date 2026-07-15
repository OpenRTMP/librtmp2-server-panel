import threading
import time
from urllib.parse import urlparse

_REDIS_SCHEMES = frozenset({"redis", "rediss"})


class MemorySessionStore:
    """Per-process session token store for single-worker dev deployments."""

    def __init__(self):
        self._tokens = {}
        self._active_by_user = {}
        self._lock = threading.Lock()

    def replace_user_session(self, username, token, ttl_seconds):
        with self._lock:
            old = self._active_by_user.get(username)
            if old:
                self._tokens.pop(old, None)
            expiry = time.monotonic() + ttl_seconds
            self._tokens[token] = expiry
            self._active_by_user[username] = token

    def is_valid(self, username, token):
        with self._lock:
            active = self._active_by_user.get(username)
            if active != token:
                return False
            expiry = self._tokens.get(token)
            if expiry is None:
                return False
            if time.monotonic() > expiry:
                self._tokens.pop(token, None)
                if self._active_by_user.get(username) == token:
                    del self._active_by_user[username]
                return False
            return True

    def revoke(self, username, token):
        with self._lock:
            if self._active_by_user.get(username) == token:
                del self._active_by_user[username]
            self._tokens.pop(token, None)


class RedisSessionStore:
    """Shared session token store for multi-worker deployments."""

    def __init__(self, storage_uri):
        import redis

        self._client = redis.from_url(
            storage_uri,
            socket_timeout=2,
            socket_connect_timeout=2,
        )
        self._token_prefix = "panel:session:"
        self._user_prefix = "panel:session-user:"

    def replace_user_session(self, username, token, ttl_seconds):
        user_key = f"{self._user_prefix}{username}"
        old = self._client.get(user_key)
        if old:
            old_token = old.decode() if isinstance(old, bytes) else old
            self._client.delete(f"{self._token_prefix}{old_token}")
        pipe = self._client.pipeline()
        pipe.setex(f"{self._token_prefix}{token}", ttl_seconds, "1")
        pipe.setex(user_key, ttl_seconds, token)
        pipe.execute()

    def is_valid(self, username, token):
        try:
            user_key = f"{self._user_prefix}{username}"
            active = self._client.get(user_key)
            if active is None:
                return False
            active_token = active.decode() if isinstance(active, bytes) else active
            if active_token != token:
                return False
            return bool(self._client.exists(f"{self._token_prefix}{token}"))
        except Exception:
            return False

    def revoke(self, username, token):
        try:
            user_key = f"{self._user_prefix}{username}"
            active = self._client.get(user_key)
            if active is not None:
                active_token = active.decode() if isinstance(active, bytes) else active
                if active_token == token:
                    self._client.delete(user_key)
            self._client.delete(f"{self._token_prefix}{token}")
        except Exception:
            return


def create_session_store(storage_uri):
    scheme = urlparse(storage_uri).scheme
    if scheme in _REDIS_SCHEMES:
        return RedisSessionStore(storage_uri)
    return MemorySessionStore()
