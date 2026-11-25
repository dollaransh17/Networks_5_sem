"""
tests/test_enforcement_types.py

Unit tests for enforcement request validation:
- Enforce AGENTS.md rule: Do not block on src_ip alone.
- Require positive TTL (expiry) and cookie.
"""

import unittest
from controller.ryu_app.enforcement_types import (
    EnforcementMatch,
    EnforcementActionRequest
)


class TestEnforcementTypes(unittest.TestCase):

    def test_reject_src_ip_alone(self):
        """Must reject match that only contains ipv4_src."""
        broad_match = EnforcementMatch(ipv4_src="192.0.2.10")
        req = EnforcementActionRequest(
            incident_id="inc-1",
            action_id="act-1",
            switch_id="s1",
            match=broad_match,
            rule_cookie=1001,
            ttl_s=60
        )
        errors = req.validate()
        self.assertTrue(any("Match scope too broad" in e for e in errors))

    def test_accept_scoped_match(self):
        """Accepts match when scoped with destination and protocol."""
        scoped_match = EnforcementMatch(
            ipv4_src="192.0.2.10",
            ipv4_dst="198.51.100.20",
            ip_proto=6,
            tcp_dst=22
        )
        req = EnforcementActionRequest(
            incident_id="inc-1",
            action_id="act-1",
            switch_id="s1",
            match=scoped_match,
            rule_cookie=1001,
            ttl_s=60
        )
        errors = req.validate()
        self.assertEqual(len(errors), 0)

    def test_require_ttl_and_cookie(self):
        scoped_match = EnforcementMatch(ipv4_src="192.0.2.10", tcp_dst=80)
        req = EnforcementActionRequest(
            incident_id="inc-1",
            action_id="act-1",
            switch_id="s1",
            match=scoped_match,
            rule_cookie=0,  # Invalid
            ttl_s=-5        # Invalid
        )
        errors = req.validate()
        self.assertTrue(any("rule_cookie" in e for e in errors))
        self.assertTrue(any("ttl_s" in e for e in errors))


if __name__ == '__main__':
    unittest.main()

