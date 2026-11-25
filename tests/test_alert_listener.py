"""
tests/test_alert_listener.py

Unit tests for Suricata eve.json alert normalization and deduplication.
Verifies compliance with:
- PDF Page 7 schema and validation requirements
- Directionality checks (never assume src_ip is the attacker)
- Deduplication of repeated burst alerts
- Safe skip of malformed lines and non-alert records
"""

import json
import unittest
from sensors.alert_listener.listener import EveAlertListener, NormalizedAlert


class TestEveAlertListener(unittest.TestCase):

    def setUp(self):
        self.listener = EveAlertListener(dedup_window_s=2.0)

    def test_normalize_valid_alert(self):
        raw_eve = {
            "timestamp": "2026-11-08T05:00:00.123456+0000",
            "flow_id": 987654321,
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "src_port": 54321,
            "dest_ip": "198.51.100.20",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 1000001,
                "rev": 1,
                "signature": "THREAT_ISOLATION_MALICIOUS_PAYLOAD_DETECTED",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1
            }
        }
        alert = self.listener.process_line(json.dumps(raw_eve))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "alert")
        self.assertEqual(alert.signature_id, 1000001)
        self.assertEqual(alert.subject_ip, "192.0.2.10")
        self.assertEqual(alert.subject_status, "validated_client_origin")

    def test_ignore_non_alert_events(self):
        # Stats / Flow records must be ignored
        flow_record = {"event_type": "flow", "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20"}
        alert = self.listener.process_line(json.dumps(flow_record))
        self.assertIsNone(alert)

    def test_skip_malformed_json_safely(self):
        alert = self.listener.process_line("{ malformed json string ... ")
        self.assertIsNone(alert)

    def test_deduplicate_repeated_bursts(self):
        raw_eve = {
            "flow_id": 111,
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "alert": {"signature_id": 1000001, "signature": "ATTACK"}
        }
        # First alert is accepted
        first = self.listener.process_line(json.dumps(raw_eve))
        self.assertIsNotNone(first)

        # Immediate duplicate alert within dedup_window is suppressed
        second = self.listener.process_line(json.dumps(raw_eve))
        self.assertIsNone(second)


if __name__ == '__main__':
    unittest.main()

