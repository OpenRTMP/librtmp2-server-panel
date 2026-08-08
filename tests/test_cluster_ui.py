import os
from unittest.mock import patch

from flask_test_utils import configure_testing_app


def _login(client):
    client.post(
        "/login",
        data={"username": "admin", "password": os.environ["PASSWORD"]},
    )


def test_index_lists_streams_before_health(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        call_order = []

        def list_streams():
            call_order.append("list_streams")
            raise Lrtmp2ApiError("streams down")

        def health():
            call_order.append("health")
            return {"status": "ok", "cluster": {"enabled": False}}

        mock_client.list_streams.side_effect = list_streams
        mock_client.health.side_effect = health

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/")
        assert r.status_code == 200
        assert b"streams down" in r.data
        assert call_order == ["list_streams"]
        assert mock_client.health.call_count == 0
        assert b'href="/cluster"' in r.data
        assert b"Cluster status unavailable" in r.data


def test_index_surfaces_cluster_detection_failure(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.list_streams.return_value = []
        mock_client.health.side_effect = Lrtmp2ApiError("health timeout")
        mock_client.cluster_streams.side_effect = Lrtmp2ApiError("cluster_streams down")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/")
        assert r.status_code == 200
        assert b"health timeout" in r.data
        assert b"cluster_streams down" in r.data
        assert b"Cluster status unavailable" in r.data
        assert b'href="/cluster"' in r.data
        assert b"Cluster mode" not in r.data


def test_index_loads_placement_when_health_unknown(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.side_effect = Lrtmp2ApiError("health timeout")
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
                "subscribed_nodes": [2],
                "standby_nodes": [],
                "cluster_players": 3,
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
        assert b"health timeout" in r.data
        assert b"Cluster mode" in r.data
        assert b"Cluster status unavailable" not in r.data
        assert b"Ownership epoch" in r.data
        assert b"18" in r.data
        assert b'data-cluster="1"' in r.data
        assert mock_client.cluster_streams.call_count == 1


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
        # detect_cluster health reused for RTMPS — no second /health probe
        assert mock_client.health.call_count == 1


def test_index_surfaces_cluster_streams_error(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "status": "ok",
            "rtmps_enabled": False,
            "cluster": {"enabled": True, "quorum": True},
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
        mock_client.cluster_streams.side_effect = Lrtmp2ApiError("cluster_streams failed")

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/")
        assert r.status_code == 200
        assert b"cluster_streams failed" in r.data
        assert b"Camera" in r.data
        assert b"Cluster mode" in r.data


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


def test_cluster_overview_quorum_unknown_when_absent(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True}}
        mock_client.cluster_status.return_value = {
            "enabled": True,
            "state": "ready",
            "leader_id": 1,
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
        assert b"Quorum unknown" in r.data
        assert b"Quorum lost" not in r.data
        assert b"Quorum OK" not in r.data


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
        assert b"cluster_nodes failed" in r.data
        assert b"standalone mode" not in r.data


def test_cluster_health_failure_not_standalone(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.side_effect = Lrtmp2ApiError("health timed out")
        mock_client.cluster_status.return_value = {
            "enabled": True,
            "cluster_id": "cid-1",
            "quorum": True,
        }
        mock_client.cluster_nodes.return_value = [
            {
                "id": 1,
                "name": "node-1",
                "role": "leader",
                "voter": True,
                "state": "ready",
                "healthy": True,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"health timed out" in r.data
        assert b"standalone mode" not in r.data
        assert b"node-1" in r.data
        mock_client.cluster_status.assert_called_once()
        mock_client.cluster_nodes.assert_called_once()


def test_cluster_health_failure_with_explicitly_disabled_status(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.side_effect = Lrtmp2ApiError("health timed out")
        mock_client.cluster_status.return_value = {"enabled": False}
        mock_client.cluster_nodes.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"health timed out" in r.data
        assert b"Quorum" not in r.data
        assert b"standalone mode" not in r.data


def test_cluster_status_failure_still_loads_nodes(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {
            "cluster": {"enabled": True, "quorum": True, "leader_id": 1}
        }
        mock_client.cluster_status.side_effect = Lrtmp2ApiError("cluster_status failed")
        mock_client.cluster_nodes.return_value = [
            {
                "id": 1,
                "name": "node-1",
                # "follower", not "leader": the template hides drain/resume/
                # remove actions for the leader node, and this test checks
                # that those actions render for a normal member.
                "role": "follower",
                "voter": True,
                "state": "ready",
                "healthy": True,
            }
        ]

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.get("/cluster")
        assert r.status_code == 200
        assert b"cluster_status failed" in r.data
        assert b"node-1" in r.data
        assert b"Drain" in r.data


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
        mock_client.cluster_drain_node.assert_called_once_with(2)


def test_cluster_resume_and_remove_actions(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True}}
        mock_client.cluster_status.return_value = {"enabled": True, "quorum": True}
        mock_client.cluster_nodes.return_value = []
        mock_client.cluster_resume_node.return_value = {"ok": True}
        mock_client.cluster_remove_node.return_value = {"ok": True}

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/resume", follow_redirects=True)
        assert r.status_code == 200
        mock_client.cluster_resume_node.assert_called_once_with(2)

        r = client.post("/cluster/nodes/3/remove", follow_redirects=True)
        assert r.status_code == 200
        mock_client.cluster_remove_node.assert_called_once_with(3)


def test_cluster_drain_attempts_mutation_when_health_fails(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.side_effect = Lrtmp2ApiError("health timed out")
        mock_client.cluster_drain_node.return_value = {"ok": True}
        mock_client.cluster_status.return_value = {"enabled": True, "quorum": True}
        mock_client.cluster_nodes.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/drain", follow_redirects=False)
        assert r.status_code in (302, 303)
        mock_client.cluster_drain_node.assert_called_once_with(2)
        # Mutation must not wait on a health probe (redirect target may probe).
        assert mock_client.health.call_count == 0


def test_cluster_drain_rejects_when_cluster_status_disabled(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": False}}
        mock_client.cluster_status.return_value = {"enabled": False}
        mock_client.cluster_drain_node.side_effect = Lrtmp2ApiError(
            "cluster_drain_node failed: cluster mode is disabled"
        )

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/drain", follow_redirects=True)
        assert r.status_code == 200
        # The mutation endpoint itself is the authority on whether cluster mode
        # is enabled — it must be called directly rather than gated on a
        # separate status probe that can time out independently.
        mock_client.cluster_drain_node.assert_called_once_with(2)
        assert b"cluster mode is disabled" in r.data


def test_cluster_overview_requires_login(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
    application = app_module.create_app()
    application.config["TESTING"] = True
    client = application.test_client()
    r = client.get("/cluster")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_cluster_drain_requires_csrf_when_enabled(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.cluster_status.return_value = {"enabled": True}

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = True
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/drain")
        assert r.status_code == 400
        mock_client.cluster_drain_node.assert_not_called()


def test_cluster_drain_calls_api_even_when_health_says_standalone(monkeypatch):
    from lrtmp2_client import Lrtmp2ApiError

    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": False}}
        mock_client.cluster_status.return_value = {"enabled": True, "quorum": True}
        mock_client.cluster_drain_node.return_value = {"ok": True}

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/2/drain", follow_redirects=True)
        assert r.status_code == 200
        mock_client.cluster_drain_node.assert_called_once_with(2)


def test_cluster_overview_reads_load_object_metrics(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True}}
        mock_client.cluster_status.return_value = {
            "enabled": True,
            "quorum": True,
            "cluster_id": "c1",
            "load": {
                "total_publishers": 12,
                "total_players": 34,
                "total_rx_mbps": 1.5,
                "total_tx_mbps": 2.5,
            },
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
        assert b">12<" in r.data
        assert b">34<" in r.data
        assert b"1.5 Mbps" in r.data
        assert b"2.5 Mbps" in r.data


def test_cluster_invalid_node_id_redirects(monkeypatch):
    with patch("app.Lrtmp2Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.health.return_value = {"cluster": {"enabled": True}}
        mock_client.cluster_status.return_value = {"enabled": True, "quorum": True}
        mock_client.cluster_nodes.return_value = []

        import app as app_module

        monkeypatch.setattr(app_module.Config, "SESSION_COOKIE_SECURE", False)
        application = app_module.create_app()
        configure_testing_app(application)
        client = application.test_client()
        _login(client)

        r = client.post("/cluster/nodes/\u00b2/drain", follow_redirects=True)
        assert r.status_code == 200
        assert b"Invalid node ID" in r.data
        mock_client.cluster_drain_node.assert_not_called()
