#!/usr/bin/env python3
"""
experiments/verify_stage6.py

Phase 6: Resilience, Switch Reconciliation & Adaptive Telemetry Verification
References: PRD (Section 5, Phase 6), PLAN.md, AGENTS.md, TESTING.md

Verifies:
  [TEST 1/4] Adaptive Telemetry Polling: 2.0s baseline -> 500ms surge -> calm cooldown.
  [TEST 2/4] Controller Backpressure Protection: Prevents queue starvation under high switch RTT (> 300ms).
  [TEST 3/4] Switch Flow Reconciliation: Identifies expired vs active rules and synchronizes state with SQLite.
  [TEST 4/4] Component Latency Measurement: Measures XGBoost inference and evidence sealing.
"""

import sys
import os
import time
import sqlite3
import tempfile
import shutil
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.ryu_app.adaptive_poller import AdaptivePoller
from controller.ryu_app.reconciler import SwitchReconciler
from ai.models.xgboost_classifier import XGBoostThreatClassifier
import numpy as np


def run_tests():
    print("=" * 65)
    print("   STAGE 6: RESILIENCE, RECONCILIATION & ADAPTIVE POLLING")
    print("=" * 65)

    passed = 0
    total = 4

    # -------------------------------------------------------------
    # TEST 1: Adaptive Polling State Machine
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 1/4] Verifying adaptive telemetry polling (2.0s -> 500ms -> cooldown)... ")
    sys.stdout.flush()

    poller = AdaptivePoller(base_interval_s=2.0, surge_interval_s=0.5, rate_surge_threshold_pkts_s=1000.0)

    # 1. Calm state
    i_calm = poller.evaluate_cycle(observed_packet_rate=100.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
    # 2. Surge state
    i_surge = poller.evaluate_cycle(observed_packet_rate=3000.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
    # 3. Calm 1, 2, 3
    poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
    poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)
    i_restored = poller.evaluate_cycle(observed_packet_rate=50.0, is_ai_anomaly=False, last_request_rtt_s=0.01)

    if i_calm == 2.0 and i_surge == 0.5 and i_restored == 2.0:
        print("PASS (Normal: 2.0s, Surge: 0.5s, Restored: 2.0s)")
        passed += 1
    else:
        print(f"FAIL (calm={i_calm}, surge={i_surge}, restored={i_restored})")

    # -------------------------------------------------------------
    # TEST 2: Controller Backpressure Protection
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 2/4] Testing backpressure protection against high switch RTT (>300ms)... ")
    sys.stdout.flush()

    # High RTT 450ms
    i_backpressure = poller.evaluate_cycle(observed_packet_rate=5000.0, is_ai_anomaly=False, last_request_rtt_s=0.450)
    state = poller.get_state()

    if i_backpressure >= 2.0 and state.backpressure_active is True and state.throttled_samples > 0:
        print(f"PASS (Backpressure throttled poll to {i_backpressure:.2f}s to protect controller)")
        passed += 1
    else:
        print(f"FAIL (backpressure_active={state.backpressure_active}, interval={i_backpressure})")

    # -------------------------------------------------------------
    # TEST 3: Switch Flow Reconciler
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 3/4] Verifying switch state reconciler with SQLite audit store... ")
    sys.stdout.flush()

    temp_dir = tempfile.mkdtemp(prefix="stage6_reconcile_")
    db_path = os.path.join(temp_dir, "incident_store.db")

    try:
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
        created_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO actions VALUES ('act-1', 'inc-1', 's1', 'temporary_drop', 4096, 200, 60, 'effect_observed', ?)",
            (created_at,),
        )
        conn.commit()
        conn.close()

        reconciler = SwitchReconciler(db_path=db_path, switch_id="s1")
        summary = reconciler.reconcile()

        # Check DB state
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT state FROM actions WHERE id = 'act-1'")
        st = cur.fetchone()[0]
        conn.close()

        if summary.expired_count == 1 and st == "expired":
            print(f"PASS (Identified expired rule act-1, transitioned state to 'expired')")
            passed += 1
        else:
            print(f"FAIL (expired_count={summary.expired_count}, state={st})")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # -------------------------------------------------------------
    # TEST 4: Component Latency Measurement Benchmark
    # -------------------------------------------------------------
    sys.stdout.write("[TEST 4/4] Benchmarking XGBoost inference and evidence sealing... ")
    sys.stdout.flush()

    # Measure AI inference latency
    xgb = XGBoostThreatClassifier()
    test_vec = np.array([25000.0, 1_500_000.0, 60.0, 40000.0, 2_400_000.0, 1.5], dtype=np.float32)
    pred = xgb.predict(test_vec) if xgb.load() else None
    inference = "unavailable" if pred is None or pred.inference_time_s is None else f"{pred.inference_time_s * 1000:.2f}ms"

    try:
        from audit.sealer.key_manager import KeyManager
        from audit.sealer.sealer import EvidenceSealer
    except ModuleNotFoundError as error:
        if error.name != "cryptography":
            raise
        print(f"FAIL (XGBoost inference: {inference}; evidence sealing requires cryptography)")
    else:
        with tempfile.TemporaryDirectory() as td:
            km = KeyManager(key_dir=os.path.join(td, "keys"))
            sealer = EvidenceSealer(db_path=os.path.join(td, "db.sqlite"), spool_dir=os.path.join(td, "spool"), key_manager=km)
            t0 = time.monotonic()
            sealer.seal_incident("inc-bench-01", {"subject_ip": "192.0.2.10", "action": "temporary_drop"})
            t_seal = (time.monotonic() - t0) * 1000

        ok = pred is not None and pred.inference_time_s is not None
        print(f"{'PASS' if ok else 'FAIL'} (XGBoost inference: {inference}; evidence sealing: {t_seal:.2f}ms)")
        passed += int(ok)

    print("=" * 65)
    print(f"   SUMMARY: {passed} / {total} tests passed")
    print("=" * 65)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

