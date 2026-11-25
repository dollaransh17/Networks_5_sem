"""
controller/ryu_app/reconciler.py

Phase 6.2: Switch State & Flow Reconciliation Worker
References: PRD (Section 5, Phase 6), PLAN.md, AGENTS.md, DATABASE.md

Key Responsibilities:
1. Reconciles intended mitigation actions (from Incident Store SQLite) against
   actual live OpenFlow rules installed on OVS datapath s1.
2. Handles Switch Restart / Controller Reconnection:
   - When a switch reconnects (or on periodic audit), checks if intended active rules
     are missing from the switch.
   - If missing and not expired, re-installs them with original cookie, priority, and remaining TTL.
   - If expired, marks action state as 'expired' in the SQLite store.
3. Reports rules on the switch that have no corresponding record in SQLite.
"""

import json
import logging
import subprocess
import sqlite3
import time
import os
import re
import sys
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass

if not __package__:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from controller.ryu_app.enforcement_types import EnforcementActionRequest, EnforcementMatch
from controller.ryu_app.ovs_actions import execute_flow_mod

LOGGER = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "audit", "spool", "incident_store.db")
)


@dataclass
class FlowRuleRecord:
    cookie: int
    table: int
    priority: int
    duration_s: float
    hard_timeout: int
    n_packets: int
    n_bytes: int
    match: str
    actions: str


@dataclass
class ReconcileSummary:
    switch_id: str
    active_in_db: int
    installed_on_switch: Optional[int]
    reinstalled_count: int
    expired_count: int
    orphaned_count: Optional[int]
    timestamp: float


class SwitchReconciler:
    """
    Audits and syncs intended active mitigation rules with actual switch state.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, switch_id: str = "s1"):
        self.db_path = db_path
        self.switch_id = switch_id

    def get_live_switch_flows(self) -> Optional[List[FlowRuleRecord]]:
        """
        Dumps live OpenFlow 1.3 flows from OVS and parses flow records.
        """
        cmd = ["ovs-ofctl", "dump-flows", self.switch_id, "-O", "OpenFlow13"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            LOGGER.warning("Switch state unavailable for %s: %s", self.switch_id, error)
            return None

        flows = []
        for line in res.stdout.strip().split("\n"):
            line = line.strip()
            if not line or "OFPST_FLOW" in line:
                continue

            # Parse fields: cookie=0x1002, duration=15.2s, priority=200 ... actions=drop
            cookie_match = re.search(r"cookie=(0x[0-9a-fA-F]+|[0-9]+)", line)
            priority_match = re.search(r"priority=([0-9]+)", line)
            hard_match = re.search(r"hard_timeout=([0-9]+)", line)
            dur_match = re.search(r"duration=([0-9.]+)s", line)
            pkts_match = re.search(r"n_packets=([0-9]+)", line)
            bytes_match = re.search(r"n_bytes=([0-9]+)", line)
            actions_match = re.search(r"actions=(.+)$", line)

            if not priority_match:
                continue

            raw_cookie = cookie_match.group(1) if cookie_match else "0"
            cookie_val = int(raw_cookie, 16) if "0x" in raw_cookie else int(raw_cookie)
            prio = int(priority_match.group(1))

            # Skip table-miss (priority=0)
            if prio == 0:
                continue

            flows.append(FlowRuleRecord(
                cookie=cookie_val,
                table=0,
                priority=prio,
                duration_s=float(dur_match.group(1)) if dur_match else 0.0,
                hard_timeout=int(hard_match.group(1)) if hard_match else 0,
                n_packets=int(pkts_match.group(1)) if pkts_match else 0,
                n_bytes=int(bytes_match.group(1)) if bytes_match else 0,
                match=line.split("actions=")[0].strip() if "actions=" in line else "",
                actions=actions_match.group(1).strip() if actions_match else "",
            ))

        return flows

    def reconcile(self) -> ReconcileSummary:
        """
        Executes a reconciliation pass:
        1. Reads active intended actions from SQLite.
        2. Dumps live switch flows.
        3. Re-installs any active rules missing from the switch.
        4. Updates state for expired actions.
        """
        if not os.path.exists(self.db_path):
            return ReconcileSummary(
                switch_id=self.switch_id, active_in_db=0, installed_on_switch=0,
                reinstalled_count=0, expired_count=0, orphaned_count=0, timestamp=time.time()
            )

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Fetch actions that are intended to be active
        cur.execute("""
            SELECT id, incident_id, switch_id, action_type, rule_cookie, priority, ttl_s, state, created_at
            FROM actions
            WHERE switch_id = ? AND state IN ('effect_observed', 'rule_processed', 'action_requested')
        """, (self.switch_id,))
        intended_actions = cur.fetchall()

        live_flows = self.get_live_switch_flows()
        live_cookies = {flow.cookie for flow in live_flows or ()}

        reinstalled = 0
        expired = 0
        now = time.time()

        for act in intended_actions:
            act_id, inc_id, sw_id, act_type, cookie, prio, ttl_s, state, created_iso = act

            try:
                created = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
                if created.tzinfo is None or created.timestamp() > now:
                    raise ValueError("Expected a UTC-offset timestamp in the past")
            except (TypeError, ValueError) as error:
                LOGGER.warning("Cannot determine expiry for action %s: %s", act_id, error)
                continue

            expires_at = created.timestamp() + ttl_s
            if expires_at <= now and cookie not in live_cookies:
                cur.execute("UPDATE actions SET state = 'expired' WHERE id = ? AND state = ?", (act_id, state))
                expired += cur.rowcount
                continue

            if live_flows is None or cookie in live_cookies or state == "action_requested":
                continue

            remaining_ttl = int(expires_at - time.time())
            if remaining_ttl <= 0:
                continue
            match = self._recorded_match(cur, inc_id, act_id)
            if match is None:
                LOGGER.warning("Cannot restore action %s without an approved match", act_id)
                continue
            request = EnforcementActionRequest(
                incident_id=inc_id, action_id=act_id, switch_id=sw_id, match=match,
                action_type=act_type, priority=prio, ttl_s=remaining_ttl, rule_cookie=cookie,
            )
            if execute_flow_mod(request):
                reinstalled += 1

        conn.commit()
        conn.close()

        # Identify orphaned rules (rules on switch whose cookie is not in SQLite)
        known_cookies = {act[4] for act in intended_actions}
        orphaned = None if live_flows is None else len(live_cookies - known_cookies - {0})

        return ReconcileSummary(
            switch_id=self.switch_id,
            active_in_db=len(intended_actions),
            installed_on_switch=None if live_flows is None else len(live_flows),
            reinstalled_count=reinstalled,
            expired_count=expired,
            orphaned_count=orphaned,
            timestamp=now,
        )

    @staticmethod
    def _recorded_match(cursor, incident_id: str, action_id: str) -> Optional[EnforcementMatch]:
        for (raw_payload,) in cursor.execute("""
            SELECT payload FROM events WHERE incident_id = ? AND event_type = 'decision_created'
        """, (incident_id,)):
            try:
                payload = json.loads(raw_payload)
                if payload.get("action_id") == action_id and payload.get("approved") is True:
                    return EnforcementMatch(**payload["match"])
            except (AttributeError, KeyError, TypeError, ValueError):
                LOGGER.warning("Invalid audit payload for incident %s", incident_id)
        return None


if __name__ == "__main__":
    reconciler = SwitchReconciler()
    summary = reconciler.reconcile()
    print(f"Reconcile Complete: active_db={summary.active_in_db}, live_switch={summary.installed_on_switch}, "
          f"reinstalled={summary.reinstalled_count}, expired={summary.expired_count}, orphaned={summary.orphaned_count}")

