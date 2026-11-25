#!/usr/bin/env python3
"""
sensors/alert_listener/daemon.py

Phase 3: EVE Alert Listener Daemon & Live Forwarder to Risk Policy Engine
References: PRD (Section 5, MVP 4 & 5), PDF Section 6 & 7, AGENTS.md, API.md

Key Responsibilities:
1. Safely tails Suricata's eve.json in real time (handles rotation, truncation).
2. Filters for 'alert' records and validates that the origin is known (does not assume src_ip is attacker).
3. Deduplicates repeat alerts in a rolling time window.
4. Passes the validated NormalizedAlert to the Risk Policy Engine.
5. If approved, installs the scoped mitigation rule on switch s1 (F3).
6. Records the policy decision and the result of requesting the rule.
"""

import argparse
import os
import sys
import time
from dataclasses import asdict
from typing import Optional

# Ensure project root is in sys.path
_proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _proj_root not in sys.path:
    sys.path.insert(0, _proj_root)

from sensors.alert_listener.listener import EveAlertListener
from risk.policy_engine.engine import RiskPolicyEngine
from audit.logger.incident_logger import IncidentLogger
from controller.ryu_app.enforcement_types import ActionState
from controller.ryu_app.ovs_actions import execute_flow_mod


def tail_eve(filepath: str, from_start: bool = False):
    """Read complete EVE records, reopening the path after rotation."""
    start_at_end = not from_start
    while True:
        try:
            source = open(filepath, "rb")
        except FileNotFoundError:
            start_at_end = False
            time.sleep(0.1)
            continue

        with source:
            if start_at_end:
                source.seek(0, os.SEEK_END)
                start_at_end = False
            opened = os.fstat(source.fileno())
            while True:
                offset = source.tell()
                line = source.readline()
                if line.endswith(b"\n"):
                    yield line.decode("utf-8", errors="replace")
                    continue
                source.seek(offset)
                try:
                    current = os.stat(filepath)
                except FileNotFoundError:
                    current = None
                if current is not None:
                    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                        break
                    if current.st_size < offset:
                        source.seek(0)
                        continue
                time.sleep(0.1)


def run_pipeline(
    eve_path: str = "/var/log/suricata/eve.json",
    from_start: bool = False,
    *,
    logger: Optional[IncidentLogger] = None,
):
    print("=================================================================")
    print("   PHASE 3: SURICATA EVE -> RISK ENGINE -> OVS ENFORCEMENT")
    print("=================================================================")
    print(f"[*] Monitoring EVE log: {eve_path}")

    listener = EveAlertListener(eve_path=eve_path, dedup_window_s=5.0)
    risk_engine = RiskPolicyEngine(default_ttl_s=60)
    if logger is None:
        logger = IncidentLogger()

    print("[*] Pipeline active. Listening for threats...")

    for raw_line in tail_eve(eve_path, from_start=from_start):
        alert = listener.process_line(raw_line)
        if not alert:
            continue

        print(f"\n[ALERT_DETECTED] Sig: '{alert.signature}' (ID: {alert.signature_id}) | Subject: {alert.subject_ip} -> Dest: {alert.dest_ip}")

        decision = risk_engine.evaluate_suricata_alert(alert, switch_id="s1")
        req = decision.action_request if decision.approved else None
        incident_id = req.incident_id if req is not None else None
        if req is not None:
            logger.log_incident_creation(incident_id, req.match.ipv4_src, req.match.ipv4_dst)

        logger.log_event(
            event_id=alert.event_id,
            incident_id=incident_id,
            sensor_id=alert.sensor_id,
            event_type="suricata_alert",
            source="suricata",
            payload={
                "signature": alert.signature,
                "signature_id": alert.signature_id,
                "subject_ip": alert.subject_ip,
                "dest_ip": alert.dest_ip,
                "subject_status": alert.subject_status
            },
            evidence_ref=str(alert.raw_event_ref)
        )

        logger.log_event(
            event_id=decision.decision_id,
            incident_id=incident_id,
            sensor_id="risk-policy",
            event_type=ActionState.DECISION_CREATED.value,
            source="risk-policy",
            payload={
                "action_id": req.action_id if req else None,
                "action_type": decision.action_type,
                "approved": decision.approved,
                "reason": decision.reason,
                "match": asdict(req.match) if req else None,
            },
            evidence_ref=alert.event_id,
        )
        print(f"[RISK_DECISION] Decision: {decision.action_type.upper()} | Approved: {decision.approved} | Reason: {decision.reason}")

        if req is None:
            continue

        action_fields = {
            "action_id": req.action_id, "incident_id": req.incident_id, "switch_id": req.switch_id,
            "action_type": req.action_type, "rule_cookie": req.rule_cookie, "priority": req.priority,
            "ttl_s": req.ttl_s,
        }
        logger.log_action_transition(**action_fields, new_state=ActionState.ACTION_REQUESTED.value)
        state = ActionState.RULE_PROCESSED if execute_flow_mod(req) else ActionState.FAILED
        logger.log_action_transition(**action_fields, new_state=state.value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read Suricata EVE alerts and apply the lab policy.")
    parser.add_argument("eve_path", nargs="?", default="/var/log/suricata/eve.json")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--audit-dir", default="audit/spool")
    args = parser.parse_args()
    logger = IncidentLogger(
        db_path=os.path.join(args.audit_dir, "incident_store.db"),
        spool_path=os.path.join(args.audit_dir, "events.jsonl"),
    )
    run_pipeline(args.eve_path, args.from_start, logger=logger)

