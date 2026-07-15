import sys
from unittest.mock import MagicMock, call, patch

from session_store import MemorySessionStore, RedisSessionStore, create_session_store


def _make_redis_store(uri="redis://redis:6379/0"):
    client = MagicMock()
    redis_module = MagicMock()
    redis_module.from_url.return_value = client
    with patch.dict(sys.modules, {"redis": redis_module}):
        store = RedisSessionStore(uri)
    return store, client, redis_module


def test_memory_store_replaces_previous_session_for_user():
    store = MemorySessionStore()

    with patch("session_store.time.monotonic", return_value=100.0):
        store.replace_user_session("admin", "old-token", 60)
        store.replace_user_session("admin", "new-token", 60)

    with patch("session_store.time.monotonic", return_value=101.0):
        assert store.is_valid("admin", "new-token") is True
        assert store.is_valid("admin", "old-token") is False


def test_memory_store_expires_and_removes_session():
    store = MemorySessionStore()

    with patch("session_store.time.monotonic", return_value=100.0):
        store.replace_user_session("admin", "token", 10)

    with patch("session_store.time.monotonic", return_value=111.0):
        assert store.is_valid("admin", "token") is False

    assert "admin" not in store._active_by_user
    assert "token" not in store._tokens


def test_memory_store_revoke_only_removes_matching_active_session():
    store = MemorySessionStore()

    with patch("session_store.time.monotonic", return_value=100.0):
        store.replace_user_session("admin", "token", 60)

    store.revoke("admin", "different-token")
    with patch("session_store.time.monotonic", return_value=101.0):
        assert store.is_valid("admin", "token") is True

    store.revoke("admin", "token")
    assert store.is_valid("admin", "token") is False


def test_redis_store_uses_bounded_connection_timeouts():
    _store, _client, redis_module = _make_redis_store("rediss://redis:6379/1")

    redis_module.from_url.assert_called_once_with(
        "rediss://redis:6379/1",
        socket_timeout=2,
        socket_connect_timeout=2,
    )


def test_redis_store_replaces_previous_token_and_sets_ttls():
    store, client, _redis_module = _make_redis_store()
    client.get.return_value = b"old-token"
    pipeline = client.pipeline.return_value

    store.replace_user_session("admin", "new-token", 300)

    client.get.assert_called_once_with("panel:session-user:admin")
    client.delete.assert_called_once_with("panel:session:old-token")
    pipeline.setex.assert_has_calls(
        [
            call("panel:session:new-token", 300, "1"),
            call("panel:session-user:admin", 300, "new-token"),
        ]
    )
    pipeline.execute.assert_called_once_with()


def test_redis_store_validates_user_mapping_and_token_key():
    store, client, _redis_module = _make_redis_store()
    client.get.return_value = b"token"
    client.exists.return_value = 1

    assert store.is_valid("admin", "token") is True
    client.get.assert_called_once_with("panel:session-user:admin")
    client.exists.assert_called_once_with("panel:session:token")

    client.reset_mock()
    client.get.return_value = b"different-token"
    assert store.is_valid("admin", "token") is False
    client.exists.assert_not_called()


def test_redis_store_fails_closed_when_backend_is_unavailable():
    store, client, _redis_module = _make_redis_store()
    client.get.side_effect = RuntimeError("redis unavailable")

    assert store.is_valid("admin", "token") is False

    # Revocation is best-effort and must not break logout when Redis is down.
    store.revoke("admin", "token")


def test_redis_store_revoke_deletes_active_mapping_and_token():
    store, client, _redis_module = _make_redis_store()
    client.get.return_value = b"token"

    store.revoke("admin", "token")

    client.delete.assert_has_calls(
        [
            call("panel:session-user:admin"),
            call("panel:session:token"),
        ]
    )


def test_create_session_store_selects_backend_from_uri_scheme():
    assert isinstance(create_session_store("memory://"), MemorySessionStore)

    with patch.dict(sys.modules, {"redis": MagicMock()}):
        assert isinstance(create_session_store("redis://redis:6379/0"), RedisSessionStore)
        assert isinstance(create_session_store("rediss://redis:6379/0"), RedisSessionStore)
