"""Verify the real-capture gate and the aggregate message sent to Claude."""

import io
import json
import unittest
from unittest.mock import patch

from experiments import verify_claude_traffic as probe


def packet(source, destination, at=101, length=84):
    return {"source": source, "destination": destination, "at": at, "bytes": length, "protocol": "ICMP"}


class TestClaudeTraffic(unittest.TestCase):
    def test_only_fresh_bidirectional_headers_count(self):
        outgoing = packet(probe.SENSOR, probe.SERVER)
        incoming = packet(probe.SERVER, probe.SENSOR, length=96)
        excluded = [packet(probe.SERVER, probe.SENSOR, at=95),
                    packet(probe.SENSOR, "192.0.2.50"), {**incoming, "protocol": "TCP"}]
        first = {"state": "live", "interface": "s1-eth2", "rows": [outgoing, incoming] + excluded}
        complete = {**first, "rows": [outgoing, incoming] * 3 + excluded}
        with (
            patch.object(probe, "read_capture", side_effect=[first, first, first, complete]) as read,
            patch.object(probe, "time", return_value=100),
            patch.object(probe, "sleep"),
            patch("builtins.print"),
        ):
            observed = probe.observe_exchange(5174)
        self.assertEqual(read.call_count, 4)
        self.assertEqual(observed, {
            "protocol": "ICMP",
            "observed_packets": {"to_server": 3, "from_server": 3},
            "observed_wire_bytes": {"to_server": 252, "from_server": 288},
        })

    def test_stopped_collector_and_unrelated_port_prevent_cloud_request(self):
        cases = [("stopped", "s1-eth2", "Collector is stopped"), ("live", "s1-eth3", "protected-server path")]
        for state, port, message in cases:
            with (
                self.subTest(state=state, port=port),
                patch.dict(probe.os.environ, {"ANTHROPIC_API_KEY": "fixture-key", "ANTHROPIC_MODEL": "fixture"}),
                patch.object(probe, "read_capture", return_value={"state": state, "interface": port, "rows": []}),
                patch.object(probe, "ask_claude") as send,
                patch("sys.argv", ["verify"]),
                patch("sys.stderr", new_callable=io.StringIO) as stderr,
                patch("builtins.print"),
            ):
                with self.assertRaises(SystemExit):
                    probe.main()
                send.assert_not_called()
                self.assertIn(message, stderr.getvalue())

    def test_message_contains_aggregate_counts_and_uses_configured_model(self):
        measurements = {"protocol": "ICMP", "observed_packets": {"to_server": 3, "from_server": 3},
                        "observed_wire_bytes": {"to_server": 252, "from_server": 252}}
        response = io.BytesIO(json.dumps({"model": "fixture-model", "id": "fixture-id",
                                         "content": [{"type": "text", "text": "Six packets observed."}]}).encode())
        response.status = 200
        with patch.object(probe, "HTTPSConnection") as https:
            connection = https.return_value
            connection.getresponse.return_value = response
            result = probe.ask_claude(measurements, "fixture-model", "fixture-key")
        https.assert_called_once_with("api.anthropic.com", timeout=20)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("POST", "/v1/messages"))
        self.assertEqual(kwargs["headers"]["x-api-key"], "fixture-key")
        body = json.loads(kwargs["body"])
        self.assertEqual(body["model"], "fixture-model")
        content = body["messages"][0]["content"]
        self.assertIn(json.dumps(measurements), content)
        for private_value in (probe.SENSOR, probe.SERVER, "fixture-key"):
            self.assertNotIn(private_value, content)
        self.assertEqual(result["message_id"], "fixture-id")
        self.assertEqual(result["summary"], "Six packets observed.")
        connection.close.assert_called_once()

    def test_invalid_header_error_omits_key(self):
        with patch.object(probe, "HTTPSConnection") as connect:
            with self.assertRaisesRegex(ValueError, "ANTHROPIC_API_KEY") as error:
                probe.ask_claude({}, "fixture-model", "private-fixture\nvalue")
            self.assertNotIn("private-fixture", str(error.exception))
            connect.assert_not_called()
