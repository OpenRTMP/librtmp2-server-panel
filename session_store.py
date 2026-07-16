import logging
import threading
import time
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_REDIS_SCHEMES = frozenset({"redis", "rediss"})
_REVOKE_SESSION_SCRIPT = """
local active = redis.call("GET", KEYS[1])
if active == ARGV[1] then
    redis.call("DEL", KEYS[1])
end
redis.call("DEL", KEYS[2])
return 1
""".strip()


class SessionBackendUnavailable(RuntimeError):
    """Raised when the shared session backend cannot persist a login."""


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

        self._redis_error = redis.exceptions.RedisError
        self._client = redis.from_url(
            storage_uri,
            socket_timeout=2,
            socket_connect_timeout=2,
        )
        self._token_prefix = "panel:session:"
        self._user_prefix = "panel:session-user:"

    def replace_user_session(self, username, token, ttl_seconds):
        user_key = f"{self._user_prefix}{username}"
        try:
            old = self._client.get(user_key)
            old_token = old.decode() if isinstance(old, bytes) else old

            # redis-py pipelines are transactional by default. Publish the new
            # token and user mapping together, then remove the previous token in
            # the same transaction so readers never observe a half-written login.
            pipe = self._client.pipeline()
            pipe.setex(f"{self._token_prefix}{token}", ttl_seconds, "1")
            pipe.setex(user_key, ttl_seconds, token)
            if old_token:
                pipe.delete(f"{self._token_prefix}{old_token}")
            pipe.execute()
        except self._redis_error as exc:
            logger.error(
                "Failed to persist Redis session for user %s",
                username,
                exc_info=True,
            )
            raise SessionBackendUnavailable("Session backend unavailable") from exc

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
        except self._redis_error:
            logger.warning(
                "Failed to validate Redis session for user %s; denying access",
                username,
                exc_info=True,
            )
            return False

    def revoke(self, username, token):
        user_key = f"{self._user_prefix}{username}"
        token_key = f"{self._token_prefix}{token}"
        try:
            # Compare and delete entirely inside Redis so a concurrent login
            # cannot have its newly written user mapping removed by an old logout.
            self._client.eval(
                _REVOKE_SESSION_SCRIPT,
                2,
                user_key,
                token_key,
                token,
            )
        except self._redis_error as exc:
            logger.error(
                "Failed to revoke Redis session for user %s",
                username,
                exc_info=True,
            )
            raise SessionBackendUnavailable("Session backend unavailable") from exc


def create_session_store(storage_uri):
    scheme = urlparse(storage_uri).scheme
    if scheme in _REDIS_SCHEMES:
        return RedisSessionStore(storage_uri)
    return MemorySessionStore()
