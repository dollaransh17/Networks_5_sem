#!/usr/bin/env python3
"""
audit/logger/incident_logger.py

Phase 3: Local Incident Logger
References: PRD (Section 5, MVP 6), DATABASE.md, PDF Section 12 & 13

Key Responsibilities:
1. Implements local append-only event logging for the full action lifecycle:
   decision_created -> action_requested -> controller_accepted -> rule_processed -> effect_observed -> expired/reverted
2. Separates event sources cleanly:
   - "gateway_deny" != "suricata_drop" != "ovs_block"
3. Preserves evidence links without fabricating AI scores:
   - Alert-only records maintain model_score = None (never fake confidence).
4. Persists structured incident records locally in SQLite (`audit/spool/incident_store.db`)
   as well as a durable JSONL spool (`audit/spool/events.jsonl`).
"""

import json
import os
import sqlite3
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict


class IncidentLogger:
    def __init__(self, db_path: str = "audit/spool/incident_store.db",
                 spool_path: str = "audit/spool/events.jsonl"):
        self.db_path = db_path
        self.spool_path = spool_path

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_sqlite()

    def _init_sqlite(self):
        """Initializes local SQLite schema per DATABASE.md."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Incidents table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                subject_ip TEXT NOT NULL,
                target_ip TEXT,
                status TEXT NOT NULL CHECK(status IN ('open','contained','reverted','closed')),
                opened_at TEXT NOT NULL
            )
        """)

        # Append-only events table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                sensor_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                evidence_ref TEXT,
                schema_version INTEGER DEFAULT 1,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)

        # Actions lifecycle table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                switch_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                rule_cookie INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                ttl_s INTEGER NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        """)

        conn.commit()
        conn.close()

    def log_incident_creation(self, incident_id: str, subject_ip: str, target_ip: str) -> bool:
        """Records initial incident container."""
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO incidents (id, subject_ip, target_ip, status, opened_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, subject_ip, target_ip, "open", now_iso)
        )
        conn.commit()
        conn.close()
        return True

    def log_event(self, event_id: str, incident_id: Optional[str], sensor_id: str,
                  event_type: str, source: str, payload: Dict[str, Any],
                  evidence_ref: Optional[str] = None) -> bool:
        """
        Appends an event to the local database and JSONL spool.
        Rule: Append-only. Never update or rewrite past event records.
        """
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload_str = json.dumps(payload)

        # 1. Append to SQLite (idempotent for re-delivered event_ids)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """INSERT OR IGNORE INTO events (id, incident_id, sensor_id, event_type, source, occurred_at, payload, evidence_ref, schema_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (event_id, incident_id, sensor_id, event_type, source, now_iso, payload_str, evidence_ref)
        )
        conn.commit()
        conn.close()

        # 2. Append to JSONL durable spool
        spool_record = {
            "schema_version": 1,
            "event_id": event_id,
            "incident_id": incident_id,
            "sensor_id": sensor_id,
            "event_type": event_type,
            "source": source,
            "occurred_at": now_iso,
            "payload": payload,
            "evidence_ref": evidence_ref
        }
        with open(self.spool_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(spool_record) + "\n")

        return True

    def log_action_transition(self, action_id: str, incident_id: str, switch_id: str,
                              action_type: str, rule_cookie: int, priority: int,
                              ttl_s: int, new_state: str) -> bool:
        """
        Records an enforcement lifecycle state change.
        """
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Insert or update action state
        cur.execute(
            """INSERT INTO actions (id, incident_id, switch_id, action_type, rule_cookie, priority, ttl_s, state, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET state=excluded.state""",
            (action_id, incident_id, switch_id, action_type, rule_cookie, priority, ttl_s, new_state, now_iso)
        )

        # Also append an event for complete audit timeline
        cur.execute(
            """INSERT INTO events (id, incident_id, sensor_id, event_type, source, occurred_at, payload, schema_version)
               VALUES (?, ?, 'controller', ?, 'sdn-controller', ?, ?, 1)""",
            (f"act-evt-{uuid_hex()}", incident_id, f"action_{new_state}", now_iso,
             json.dumps({"action_id": action_id, "state": new_state, "cookie": rule_cookie}))
        )

        conn.commit()
        conn.close()
        return True


def uuid_hex():
    import uuid
    return uuid.uuid4().hex[:8]


if __name__ == "__main__":
    logger = IncidentLogger()
    print(f"[+] IncidentLogger initialized. Store: {logger.db_path}")

