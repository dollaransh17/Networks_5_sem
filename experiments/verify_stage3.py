#!/usr/bin/env python3
"""Verify EVE replay, scoped rule readback, and the audit trail in the Linux lab."""

import json
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"


def verify_replay(directory: Path) -> None:
    flow_id = time.time_ns()
    alert = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": CLIENT_IP,
        "src_port": 45678,
        "dest_ip": SERVER_IP,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": 1000001, "signature": "Lab detection fixture"},
    }
    eve_file = directory / "eve.json"
    eve_file.write_text(json.dumps(alert) + "\n", encoding="utf-8")
    proc = subprocess.Popen([
        sys.executable, "-u", str(PROJECT_ROOT / "sensors/alert_listener/daemon.py"),
        str(eve_file), "--from-start", "--audit-dir", str(directory),
    ], cwd=PROJECT_ROOT)
    try:
        check_audit_and_switch(directory / "incident_store.db", f"eve-{flow_id}-1000001", proc)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def check_audit_and_switch(db_file: Path, event_id: str, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    pending_states = {"action_requested", "controller_accepted"}
    action = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Alert daemon exited with status {proc.returncode}")
        if db_file.is_file():
            with closing(sqlite3.connect(db_file.resolve().as_uri() + "?mode=ro", uri=True)) as db:
                ready = db.execute("SELECT 1 FROM sqlite_master WHERE name = 'actions'").fetchone()
                if ready:
                    action = db.execute("""
                        SELECT a.id, a.incident_id, a.rule_cookie, a.priority, a.ttl_s, a.state
                        FROM events e JOIN actions a ON a.incident_id = e.incident_id
                        WHERE e.id = ? AND e.event_type = 'suricata_alert'
                    """, (event_id,)).fetchone()
                    if action is not None and action[-1] not in pending_states:
                        if action[-1] != "rule_processed":
                            raise RuntimeError(f"Rule installation ended in state {action[-1]}")
                        break
        time.sleep(0.1)
    else:
        raise RuntimeError(f"Timed out waiting for action linked to {event_id}")

    action_id, incident_id, cookie, priority, ttl, _ = action
    print("PASS EVE replay created a linked action")
    output = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        capture_output=True, text=True, check=True, timeout=5,
    ).stdout
    required = {
        f"cookie={cookie:#x}", f"priority={priority}", f"hard_timeout={ttl}",
        "tcp", f"nw_src={CLIENT_IP}", f"nw_dst={SERVER_IP}", "tp_dst=443", "actions=drop",
    }
    if not any(required.issubset(re.split(r"[,\s]+", line)) for line in output.splitlines()):
        raise RuntimeError(f"Readback did not contain the expected scoped rule for cookie {cookie:#x}")
    print(f"PASS Switch readback matched scoped drop {cookie:#x}")

    with closing(sqlite3.connect(db_file)) as db:
        events = db.execute("""
            SELECT event_type, payload FROM events
            WHERE incident_id = ? ORDER BY rowid
        """, (incident_id,)).fetchall()
    timeline = [kind for kind, payload in events if json.loads(payload).get("action_id") == action_id]
    if timeline != ["decision_created", "action_action_requested", "action_rule_processed"]:
        raise RuntimeError(f"Incomplete action timeline: {timeline}")
    print("PASS Audit records decision, request, and rule processing")


def run() -> int:
    try:
        with TemporaryDirectory(prefix="sdn-stage3-") as temp:
            verify_replay(Path(temp))
    except (OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
