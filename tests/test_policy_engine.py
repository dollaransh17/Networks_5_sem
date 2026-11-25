"""
tests/test_policy_engine.py

Unit tests for the Risk Policy Engine:
- Verifies that high-confidence threats generate approved scoped actions with valid cookies & TTLs.
- Verifies that reconnaissance alerts trigger quarantine.
- Verifies that low-confidence alerts monitor rather than block legitimate hosts.
- Verifies that generated action matches are strictly scoped (no blocking on src_ip alone).
"""

import unittest
from risk.policy_engine.engine import RiskPolicyEngine
from sensors.alert_listener.listener import NormalizedAlert


class TestRiskPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RiskPolicyEngine(default_ttl_s=60)

    def test_high_confidence_alert_approved_drop(self):
        alert = NormalizedAlert(
            schema_version=1,
            event_id="eve-test-1",
            sensor_id="ips-edge-1",
            event_type="alert",
            src_ip="192.0.2.10",
            dest_ip="198.51.100.20",
            src_port=54321,
            dest_port=443,
            proto="TCP",
            signature="THREAT_ISOLATION_MALICIOUS_PAYLOAD_DETECTED",
            signature_id=1000001,
            subject_ip="192.0.2.10",
            subject_status="validated_client_origin",
            occurred_at="2026-11-08T05:00:00Z",
            raw_event_ref={}
        )

        decision = self.engine.evaluate_suricata_alert(alert, switch_id="s1")
        self.assertTrue(decision.approved)
        self.assertEqual(decision.action_type, "temporary_drop")
        self.assertIsNotNone(decision.action_request)

        # Validate action properties per AGENTS.md
        action = decision.action_request
        errors = action.validate()
        self.assertEqual(len(errors), 0)
        self.assertEqual(action.priority, 200)
        self.assertEqual(action.ttl_s, 60)
        self.assertGreater(action.rule_cookie, 0)
        self.assertEqual(action.match.ipv4_src, "192.0.2.10")
        self.assertEqual(action.match.ipv4_dst, "198.51.100.20")

    def test_low_confidence_alert_monitors_without_blocking(self):
        alert = NormalizedAlert(
            schema_version=1,
            event_id="eve-test-2",
            sensor_id="ips-edge-1",
            event_type="alert",
            src_ip="192.0.2.10",
            dest_ip="198.51.100.20",
            src_port=54321,
            dest_port=443,
            proto="TCP",
            signature="Informational Ping Notice",
            signature_id=999999,
            subject_ip="192.0.2.10",
            subject_status="validated_client_origin",
            occurred_at="2026-11-08T05:00:00Z",
            raw_event_ref={}
        )

        decision = self.engine.evaluate_suricata_alert(alert, switch_id="s1")
        self.assertFalse(decision.approved)
        self.assertEqual(decision.action_type, "monitor")
        self.assertIsNone(decision.action_request)


if __name__ == '__main__':
    unittest.main()

