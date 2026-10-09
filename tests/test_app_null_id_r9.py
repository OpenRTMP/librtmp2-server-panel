"""App-side null-id rendering regressions from the round-9 review follow-up.

index.html and cluster.html interpolate upstream ``id`` values into
``url_for()``, so a JSON-null id used to raise werkzeug BuildError and turn the
whole page into an HTTP 500. Only ids that cannot fill a URL rule may be
dropped: a numeric or boolean upstream id is a usable id and keeps rendering.
"""

import contextlib
import os
from unittest.mock import patch

import pytest
from flask_test_utils import configure_testing_app


def _login(client):
    client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )


def _stream_row(stream_id, players=None):
    return {
        "id": stream_id,
        "name": "Camera",
        "app": "live",
        "publish_key": "pub_k",
        "play_key": "pl_k",
        "stats_key": "st_k",
        "players": list(players or []),
        "enabled": True,
        "created_at": 1,
    }


@contextlib.contextmanager
def _panel_client(monkeypatch, streams, nodes=None, cluster_enabled=False):
    """Yield a logged-in test client whose API returns the supplied payloads."""
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "rtmps_enabled": False,
            "cluster": {
                "enabled": cluster_enabled,
                "quorum": True,
                "leader_id": 1,
            },
        }
        mock_client.list_streams.return_value = streams
        mock_client.cluster_status.return_value = {"enabled": cluster_enabled}
        mock_client.cluster_nodes.return_value = list(nodes or [])

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)
        yield client


def test_index_renders_stream_with_null_id(monkeypatch):
    streams = [_stream_row(None), _stream_row("stream42")]

    with _panel_client(monkeypatch, streams) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert b"/streams/stream42/players/new" in response.data
    # The null id never reaches url_for(), so no URL is built from it.
    assert b"/streams/None/" not in response.data


@pytest.mark.parametrize("stream_id", [123, 4.5, True, "stream-42"])
def test_index_renders_stream_with_scalar_id(monkeypatch, stream_id):
    streams = [_stream_row(stream_id)]

    with _panel_client(monkeypatch, streams) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert b"Camera" in response.data
    assert f"/streams/{stream_id}/players/new".encode() in response.data


def test_normalize_streams_list_keeps_scalar_ids():
    import app as app_module

    streams = [
        {"id": "stream42"},
        {"id": 123},
        {"id": 4.5},
        {"id": True},
        {"id": None},
        {"id": {"nested": 1}},
        {"id": ["a"]},
        {"id": ("a",)},
        "not-a-dict",
    ]

    assert app_module._normalize_streams_list(streams) == [
        {"id": "stream42"},
        {"id": 123},
        {"id": 4.5},
        {"id": True},
    ]


def test_cluster_renders_node_with_null_id(monkeypatch):
    nodes = [
        {"id": 2, "name": "node-2", "role": "follower", "state": "ready"},
        {"id": None, "name": "node-ghost", "role": "follower", "state": "ready"},
    ]

    with _panel_client(monkeypatch, [], nodes=nodes, cluster_enabled=True) as client:
        response = client.get("/cluster")

    assert response.status_code == 200
    assert b"node-2" in response.data
