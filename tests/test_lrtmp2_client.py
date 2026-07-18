from unittest.mock import patch

import pytest
import requests

from lrtmp2_client import Lrtmp2ApiError, Lrtmp2Client


def test_health_sends_bearer_token():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = {
            "status": "ok",
            "rtmps_enabled": True,
            "rtmps_port": 1936,
        }
        result = client.health()
    assert result["status"] == "ok"
    assert mock_get.call_args.kwargs.get("headers", {}).get("Authorization") == "Bearer tok"


def test_create_stream_posts_json_payload():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"id": "s1"}
        client.create_stream("s1", "Name", "live", publish_key="pub_key_with_sufficient_length_here01")
    payload = mock_post.call_args.kwargs["json"]
    assert payload["id"] == "s1"
    assert payload["publish_key"] == "pub_key_with_sufficient_length_here01"
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer tok"


def test_create_player_posts_optional_fields():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"id": "vi_abc"}
        client.create_player("stream1", name="Guest", play_key="play_key_with_sufficient_length_here01")
    payload = mock_post.call_args.kwargs["json"]
    assert payload["name"] == "Guest"
    assert payload["play_key"] == "play_key_with_sufficient_length_here01"


def test_delete_stream_treats_404_as_success():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete:
        mock_delete.return_value.ok = False
        mock_delete.return_value.status_code = 404
        client.delete_stream("missing")


def test_delete_stream_polls_until_gone_on_202():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete, patch(
        "lrtmp2_client.requests.get"
    ) as mock_get, patch("lrtmp2_client.time.sleep") as mock_sleep:
        mock_delete.return_value.ok = True
        mock_delete.return_value.status_code = 202

        still_present = type("R", (), {"ok": True, "json": lambda self: [{"id": "s1"}]})()
        gone = type("R", (), {"ok": True, "json": lambda self: []})()
        mock_get.return_value = still_present
        mock_get.side_effect = [still_present, gone]

        client.delete_stream("s1", wait_timeout=5, poll_interval=0.1)

    assert mock_get.call_count == 2
    mock_sleep.assert_called_once()


def test_delete_stream_202_raises_when_still_present_after_timeout():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete, patch(
        "lrtmp2_client.requests.get"
    ) as mock_get, patch("lrtmp2_client.time.sleep") as mock_sleep, patch(
        "lrtmp2_client.time.monotonic"
    ) as mock_monotonic:
        mock_delete.return_value.ok = True
        mock_delete.return_value.status_code = 202
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = [{"id": "s1"}]

        # Simulate the clock advancing past the deadline after two polls, so
        # the while loop actually iterates before giving up (rather than
        # exiting immediately, which wouldn't exercise the polling/timeout
        # logic at all).
        mock_monotonic.side_effect = [0, 1, 2, 10]

        with pytest.raises(Lrtmp2ApiError, match="still present"):
            client.delete_stream("s1", wait_timeout=5, poll_interval=0.1)

    assert mock_get.call_count == 3
    assert mock_sleep.call_count == 2


def test_delete_stream_raises_on_server_error():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.delete") as mock_delete:
        mock_delete.return_value.ok = False
        mock_delete.return_value.status_code = 500
        mock_delete.return_value.json.return_value = {
            "error": {"message": "internal error"}
        }
        with pytest.raises(Lrtmp2ApiError, match="internal error"):
            client.delete_stream("s1")


def test_stream_stats_uses_key_query_param():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = {"live": False}
        client.stream_stats("stats_key_with_sufficient_length_here01")
    assert mock_get.call_args.kwargs["params"]["key"] == "stats_key_with_sufficient_length_here01"


def test_http_error_body_string_error():
    client = Lrtmp2Client("http://example.test", "tok")
    with patch("lrtmp2_client.requests.get") as mock_get:
        mock_get.return_value.ok = False
        mock_get.return_value.status_code = 403
        mock_get.return_value.json.return_value = {"error": "forbidden"}
        with pytest.raises(Lrtmp2ApiError, match="forbidden"):
            client.list_streams()


def test_request_exception_wrapped():
    client = Lrtmp2Client("http://example.test", "tok", timeout=1)
    with patch(
        "lrtmp2_client.requests.get",
        side_effect=requests.exceptions.ConnectionError("refused"),
    ):
        with pytest.raises(Lrtmp2ApiError, match="could not reach"):
            client.health()
