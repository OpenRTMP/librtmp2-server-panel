import os
from unittest.mock import patch

from flask_test_utils import configure_testing_app


def _login(client):
    client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )


def test_index_hides_cluster_ui_when_standalone(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "status": "ok",
            "rtmps_enabled": False,
            "cluster": {"enabled": False},
        }
        mock_client.list_streams.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/")
        assert r.status_code == 200
        assert b"Cluster mode" not in r.data
        assert b'href="/cluster"' not in r.data


def test_index_shows_cluster_nav_and_stream_owner(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "status": "ok",
            "rtmps_enabled": False,
            "cluster": {
                "enabled": True,
                "node_id": 2,
                "role": "follower",
                "leader_id": 1,
                "quorum": True,
                "state": "ready",
            },
        }
        mock_client.list_streams.return_value = [
            {
                "id": "stream42",
                "name": "Camera",
                "app": "live",
                "publish_key": "pub_k",
                "play_key": "pl_k",
                "stats_key": "st_k",
                "players": [],
                "enabled": True,
                "created_at": 1,
            }
        ]
        mock_client.cluster_streams.return_value = [
            {
                "stream_id": "stream42",
                "owner_node_id": 1,
                "epoch": 18,
                "subscribed_nodes": [2, 3],
                "standby_nodes": [3],
                "cluster_players": 105,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/")
        assert r.status_code == 200
        assert b"Cluster mode" in r.data
        assert b"Ownership epoch" in r.data
        assert b"18" in r.data
        assert b"Owner node" in r.data


def test_cluster_overview_standalone_message(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"status": "ok", "cluster": {"enabled": False}}

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"standalone mode" in r.data


def test_cluster_overview_renders_nodes_and_states(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "status": "ok",
            "cluster": {"enabled": True, "quorum": True, "leader_id": 1},
        }
        mock_client.cluster_status.return_value = {
            "enabled": True,
            "cluster_id": "cid-1",
            "node_id": 2,
            "node_name": "node-2",
            "role": "follower",
            "leader_id": 1,
            "term": 28,
            "quorum": True,
            "state": "ready",
            "voter_count": 3,
            "learner_count": 0,
            "healthy_nodes": 2,
            "unavailable_nodes": 1,
            "total_publishers": 8,
            "total_players": 74,
            "total_rx_mbps": 120.3,
            "total_tx_mbps": 642.7,
        }
        mock_client.cluster_nodes.return_value = [
            {
                "id": 1,
                "name": "node-1",
                "role": "leader",
                "voter": True,
                "state": "ready",
                "healthy": True,
                "rx_mbps": 10.0,
                "tx_mbps": 20.0,
                "capacity_mbps": 1000,
                "publishers": 2,
                "players": 5,
                "last_heartbeat": "now",
            },
            {
                "id": 2,
                "name": "node-2",
                "role": "follower",
                "voter": True,
                "state": "draining",
                "healthy": True,
                "rx_mbps": 810.0,
                "tx_mbps": 810.0,
                "capacity_mbps": 1000,
                "publishers": 3,
                "players": 40,
            },
            {
                "id": 3,
                "name": "node-3",
                "role": "follower",
                "voter": True,
                "state": "down",
                "healthy": False,
                "rx_mbps": 0,
                "tx_mbps": 0,
                "capacity_mbps": 1000,
                "publishers": 0,
                "players": 0,
            },
            {
                "id": 4,
                "name": "node-4",
                "role": "learner",
                "voter": False,
                "state": "isolated",
                "healthy": False,
                "rx_mbps": 0,
                "tx_mbps": 0,
                "capacity_mbps": 1000,
                "publishers": 0,
                "players": 0,
            },
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"cid-1" in r.data
        assert b"Quorum OK" in r.data
        assert b"node-1" in r.data
        assert b"READY" in r.data
        assert b"DRAINING" in r.data
        assert b"DOWN" in r.data
        assert b"ISOLATED" in r.data
        assert b"Drain" in r.data
        assert b"Resume" in r.data
        assert b"Remove" in r.data


def test_cluster_overview_quorum_lost(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True, "quorum": False}}
        mock_client.cluster_status.return_value = {
            "enabled": True,
            "quorum": False,
            "state": "isolated",
            "leader_id": None,
        }
        mock_client.cluster_nodes.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"Quorum lost" in r.data


def test_cluster_api_error_on_overview(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True, "quorum": True}}
        mock_client.cluster_status.side_effect = Lrtmp2ApiError("cluster_status failed")
        mock_client.cluster_nodes.side_effect = Lrtmp2ApiError("cluster_nodes failed")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"cluster_status failed" in r.data


def test_cluster_drain_action(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True}}
        mock_client.cluster_status.return_value = {"enabled": True, "quorum": True}
        mock_client.cluster_nodes.return_value = []
        mock_client.cluster_drain_node.return_value = {"ok": True}

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/drain", follow_redirects=True)
        assert r.status_code == 200
        mock_client.cluster_drain_node.assert_called_once_with("2")
