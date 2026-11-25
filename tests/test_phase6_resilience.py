"""
tests/test_phase6_resilience.py

Phase 6: Unit Tests for Switch Reconciler and Adaptive Poller
References: PRD (Section 5, Phase 6), PLAN.md, AGENTS.md, TESTING.md

Verifies:
1. Reconciler correctly identifies active vs expired rules from SQLite.
2. Adaptive poller operates at 2.0s baseline.
3. Adaptive poller drops to 500ms (0.5s) upon rate surge or AI anomaly.
4. Adaptive poller returns to 2.0s after calm cooldown.
5. Adaptive poller activates backpressure throttling when switch RTT is high.
"""

import sys
import os
import sqlite3
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.ryu_app.reconciler import SwitchReconciler, FlowRuleRecord
from controller.ryu_app.adaptive_poller import AdaptivePoller


class TestAdaptivePoller:
    def test_baseline_interval(self):
        """Calm traffic remains at 2.0s polling interval."""
        poller = AdaptivePoller(base_interval_s=2.0, surge_interval_s=0.5)
        interval = poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert interval == 2.0
        assert poller.get_state().is_surge_mode is False

    def test_rate_surge_accelerates_to_500ms(self):
        """Traffic over 1,000 pkt/s drops polling interval to 500ms immediately."""
        poller = AdaptivePoller(base_interval_s=2.0, surge_interval_s=0.5, rate_surge_threshold_pkts_s=1000.0)
        interval = poller.evaluate_cycle(observed_packet_rate=5000.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert interval == 0.5
        assert poller.get_state().is_surge_mode is True

    def test_ai_anomaly_triggers_surge_mode(self):
        """An AI anomaly drops polling interval to 500ms even with moderate packet rate."""
        poller = AdaptivePoller(base_interval_s=2.0, surge_interval_s=0.5)
        interval = poller.evaluate_cycle(observed_packet_rate=120.0, is_ai_anomaly=True, last_request_rtt_s=0.02)
        assert interval == 0.5
        assert poller.get_state().is_surge_mode is True

    def test_calm_cooldown_returns_to_baseline(self):
        """After 3 calm cycles, polling interval returns to 2.0s."""
        poller = AdaptivePoller(base_interval_s=2.0, surge_interval_s=0.5, calm_cycles_needed=3)
        # Surge cycle
        poller.evaluate_cycle(observed_packet_rate=10000.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert poller.get_state().is_surge_mode is True

        # Cycle 1 calm
        poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert poller.get_state().is_surge_mode is True

        # Cycle 2 calm
        poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert poller.get_state().is_surge_mode is True

        # Cycle 3 calm -> cooldown complete
        interval = poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
        assert interval == 2.0
        assert poller.get_state().is_surge_mode is False

    def test_backpressure_throttling(self):
        """When switch RTT exceeds 300ms, backpressure throttles polling."""
        poller = AdaptivePoller(rtt_backpressure_threshold_s=0.300)
        interval = poller.evaluate_cycle(observed_packet_rate=5000.0, is_ai_anomaly=False, last_request_rtt_s=0.450)
        assert interval >= 2.0
        state = poller.get_state()
        assert state.backpressure_active is True
        assert state.throttled_samples == 1


class TestSwitchReconciler:
    def test_reconcile_handles_missing_db(self, tmp_path):
        """Reconciler handles absent DB gracefully without throwing exceptions."""
        reconciler = SwitchReconciler(db_path=str(tmp_path / "nonexistent.db"))
        summary = reconciler.reconcile()
        assert summary.active_in_db == 0
        assert summary.reinstalled_count == 0

    def test_marks_expired_actions(self, tmp_path):
        """Actions past their TTL are marked 'expired' in SQLite."""
        db_path = str(tmp_path / "test_reconcile.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                switch_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                rule_cookie INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                ttl_s INTEGER NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        # Insert an action created 2 hours ago with ttl 60s
        cur.execute("""
            INSERT INTO actions VALUES
            ('act-old', 'inc-old', 's1', 'temporary_drop', 4099, 200, 60, 'effect_observed', '2026-11-08T00:00:00Z')
        """)
        conn.commit()
        conn.close()

        reconciler = SwitchReconciler(db_path=db_path, switch_id="s1")
        summary = reconciler.reconcile()

        assert summary.expired_count == 1

        # Check DB updated
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT state FROM actions WHERE id = 'act-old'")
        row = cur.fetchone()
        conn.close()
        assert row[0] == "expired"

