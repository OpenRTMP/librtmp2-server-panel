import logging
import sys
from unittest.mock import MagicMock, call, patch

import pytest

from session_store import (
    MemorySessionStore,
    RedisSessionStore,
    SessionBackendUnavailable,
    create_session_store,
)


class FakeRedisError(Exception):
    pass


def _make_redis_store(uri="redis://redis:6379/0"):
    client = MagicMock()
    redis_module = MagicMock()
    redis_module.exceptions.RedisError = FakeRedisError
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


def test_redis_store_replaces_previous_token_atomically_and_sets_ttls():
    store, client, _redis_module = _make_redis_store()
    client.get.return_value = b"old-token"
    pipeline = client.pipeline.return_value

    store.replace_user_session("admin", "new-token", 300)

    client.get.assert_called_once_with("panel:session-user:admin")
    pipeline.setex.assert_has_calls(
        [
            call("panel:session:new-token", 300, "1"),
            call("panel:session-user:admin", 300, "new-token"),
        ]
    )
    pipeline.delete.assert_called_once_with("panel:session:old-token")
    pipeline.execute.assert_called_once_with()


def test_redis_store_login_write_failure_is_logged_and_raised(caplog):
    store, client, _redis_module = _make_redis_store()
    client.get.side_effect = FakeRedisError("redis unavailable")

    with caplog.at_level(logging.ERROR, logger="session_store"):
        with pytest.raises(SessionBackendUnavailable):
            store.replace_user_session("admin", "new-token", 300)

    assert "Failed to persist Redis session for user admin" in caplog.text


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


def test_redis_store_validation_fails_closed_and_logs(caplog):
    store, client, _redis_module = _make_redis_store()
    client.get.side_effect = FakeRedisError("redis unavailable")

    with caplog.at_level(logging.WARNING, logger="session_store"):
        assert store.is_valid("admin", "token") is False

    assert "Failed to validate Redis session for user admin" in caplog.text


def test_redis_store_revoke_uses_atomic_server_side_compare_and_delete():
    store, client, _redis_module = _make_redis_store()
    client.get.side_effect = AssertionError(
        "revoke must not read the active mapping outside the atomic script"
    )

    store.revoke("admin", "old-token")

    client.get.assert_not_called()
    client.pipeline.assert_not_called()
    client.eval.assert_called_once()

    script, key_count, user_key, token_key, token = client.eval.call_args.args
    assert key_count == 2
    assert user_key == "panel:session-user:admin"
    assert token_key == "panel:session:old-token"
    assert token == "old-token"
    assert 'redis.call("GET", KEYS[1])' in script
    assert "if active == ARGV[1] then" in script
    assert 'redis.call("DEL", KEYS[1])' in script
    assert 'redis.call("DEL", KEYS[2])' in script


def test_redis_store_revoke_failure_is_best_effort_and_logged(caplog):
    store, client, _redis_module = _make_redis_store()
    client.eval.side_effect = FakeRedisError("redis unavailable")

    with caplog.at_level(logging.WARNING, logger="session_store"):
        store.revoke("admin", "token")

    assert "Failed to revoke Redis session for user admin" in caplog.text


def test_create_session_store_selects_backend_from_uri_scheme():
    assert isinstance(create_session_store("memory://"), MemorySessionStore)

    with patch("session_store.RedisSessionStore") as redis_store_cls:
        assert create_session_store("redis://redis:6379/0") is redis_store_cls.return_value
        assert create_session_store("rediss://redis:6379/0") is redis_store_cls.return_value
