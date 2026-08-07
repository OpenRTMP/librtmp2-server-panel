from unittest.mock import patch

import pytest

from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client


def test_cluster_enabled_from_health_standalone():
    assert Lrtmp2Client.cluster_enabled_from_health({"status": "ok"}) is False
    assert Lrtmp2Client.cluster_enabled_from_health({"cluster": {"enabled": False}}) is False
    assert Lrtmp2Client.cluster_enabled_from_health(None) is False


def test_cluster_enabled_from_health_clustered():
    assert (
        Lrtmp2Client.cluster_enabled_from_health(
            {"status": "ok", "cluster": {"enabled": True, "node_id": 2}}
        )
        is True
    )


def test_cluster_status_calls_endpoint():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = {
            "enabled": True,
            "cluster_id": "abc",
            "leader_id": 1,
            "quorum": True,
        }
        result = client.cluster_status()
    assert result["leader_id"] == 1
    assert mock_get.call_args.args[0].endswith("/api/v1/cluster")
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer tok"


def test_cluster_nodes_and_streams():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = [{"id": 1, "state": "ready"}]
        nodes = client.cluster_nodes()
        streams = client.cluster_streams()
    assert nodes[0]["id"] == 1
    assert streams[0]["id"] == 1
    paths = [c.args[0] for c in mock_get.call_args_list]
    assert paths[0].endswith("/api/v1/cluster/nodes")
    assert paths[1].endswith("/api/v1/cluster/streams")


def test_cluster_drain_resume_remove():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.post") as mock_post, patch(
        "lrtmp2_client.requests.delete"
    ) as mock_delete:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"ok": True}
        mock_delete.return_value.ok = True
        mock_delete.return_value.status_code = 200
        mock_delete.return_value.content = b'{"ok":true}'
        mock_delete.return_value.json.return_value = {"ok": True}
        client.cluster_drain_node(2)
        client.cluster_resume_node(2)
        client.cluster_remove_node(3)
    assert "/drain" in mock_post.call_args_list[0].args[0]
    assert "/resume" in mock_post.call_args_list[1].args[0]
    assert mock_delete.call_args.args[0].endswith("/api/v1/cluster/nodes/3")


def test_cluster_api_error_propagates():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = False
        mock_get.return_value.status_code = 503
        mock_get.return_value.json.return_value = {
            "error": {"message": "quorum lost"}
        }
        with pytest.raises(Lrtmp2ApiError, match="quorum lost"):
            client.cluster_status()
