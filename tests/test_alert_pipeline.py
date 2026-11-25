"""Exercise the alert and audit path against a temporary SQLite store."""

import io
import json
import sqlite3
import subprocess
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from audit.logger.incident_logger import IncidentLogger
from controller.ryu_app.reconciler import SwitchReconciler
from sensors.alert_listener.daemon import run_pipeline, tail_eve


class TestAlertPipeline(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.db_path = str(root / "incidents.db")
        self.eve_path = root / "eve.json"
        self.logger = IncidentLogger(self.db_path, str(root / "events.jsonl"))
        self.alert = {
            "flow_id": 17,
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "proto": "TCP",
            "dest_port": 8443,
            "alert": {"signature_id": 1000001, "signature": "Lab detection fixture"},
        }

    def replay(self, records, switch_command):
        with (
            patch("sensors.alert_listener.daemon.tail_eve", return_value=iter(records)),
            patch("controller.ryu_app.ovs_actions.subprocess.run", switch_command),
            redirect_stdout(io.StringIO()),
        ):
            run_pipeline(logger=self.logger)

    def test_tails_complete_records_across_rotation_and_truncation(self):
        first = '{"message":"before rotation"}\n'
        second = '{"message":"after rotation"}\n'
        third = '{}\n'
        self.eve_path.write_text(first, encoding="utf-8")
        with closing(tail_eve(str(self.eve_path), from_start=True)) as records:
            self.assertEqual(next(records), first)
            self.eve_path.rename(self.eve_path.with_suffix(".old"))
            self.eve_path.write_text(second, encoding="utf-8")
            self.assertEqual(next(records), second)
            self.eve_path.write_text(third, encoding="utf-8")
            self.assertEqual(next(records), third)

    def test_waits_for_partial_record_to_finish(self):
        self.eve_path.write_text('{"message":', encoding="utf-8")

        def finish_record(_):
            with self.eve_path.open("a", encoding="utf-8") as eve:
                eve.write('"complete"}\n')

        with (
            patch("sensors.alert_listener.daemon.time.sleep", side_effect=finish_record) as wait,
            closing(tail_eve(str(self.eve_path), from_start=True)) as records,
        ):
            self.assertEqual(next(records), '{"message":"complete"}\n')
            wait.assert_called_once()

    def test_logs_linked_installation_without_claiming_traffic_was_blocked(self):
        line = json.dumps(self.alert)
        switch = Mock(return_value=subprocess.CompletedProcess([], 0))
        self.replay([line, line], switch)
        switch.assert_called_once()
        command = switch.call_args.args[0]
        with closing(sqlite3.connect(self.db_path)) as db:
            action_id, incident_id, cookie, state = db.execute(
                "SELECT id, incident_id, rule_cookie, state FROM actions"
            ).fetchone()
            events = db.execute(
                "SELECT event_type, incident_id, payload FROM events ORDER BY rowid"
            ).fetchall()
        self.assertIn(f"cookie={cookie},priority=200,hard_timeout=60,", command[-1])
        self.assertTrue(command[-1].endswith("tcp,nw_src=192.0.2.10,nw_dst=198.51.100.20,tp_dst=8443,actions=drop"))
        self.assertEqual(state, "rule_processed")
        self.assertEqual(
            [(kind, inc) for kind, inc, _ in events],
            [(kind, incident_id) for kind in (
                "suricata_alert", "decision_created", "action_action_requested", "action_rule_processed",
            )],
        )
        decision = json.loads(events[1][2])
        self.assertEqual(decision["action_id"], action_id)
        self.assertEqual(decision["match"]["tcp_dst"], 8443)

    def test_records_switch_command_failure(self):
        switch = Mock(side_effect=FileNotFoundError("ovs-ofctl"))
        self.replay([json.dumps(self.alert)], switch)
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT state FROM actions").fetchone(), ("failed",))

    def test_malformed_and_ambiguous_records_do_not_install_rules(self):
        reflected = dict(self.alert, src_ip=self.alert["dest_ip"], dest_ip=self.alert["src_ip"])
        unscoped = dict(self.alert, flow_id=18, dest_port=None)
        records = ["null", "[]", json.dumps(dict(self.alert, alert=[])), json.dumps(reflected), json.dumps(unscoped)]
        switch = Mock()
        self.replay(records, switch)
        switch.assert_not_called()
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 4)

    def test_reconcile_uses_recorded_port_and_remaining_timeout(self):
        self.replay([json.dumps(self.alert)], Mock(return_value=subprocess.CompletedProcess([], 0)))
        with (
            patch.object(SwitchReconciler, "get_live_switch_flows", return_value=[]),
            patch("controller.ryu_app.reconciler.execute_flow_mod", return_value=True) as install,
        ):
            summary = SwitchReconciler(db_path=self.db_path).reconcile()
        self.assertEqual(summary.reinstalled_count, 1)
        request = install.call_args.args[0]
        self.assertEqual(request.match.tcp_dst, 8443)
        self.assertTrue(0 < request.ttl_s <= 60)

    def test_reconcile_skips_unavailable_switch_and_legacy_scope(self):
        self.replay([json.dumps(self.alert)], Mock(return_value=subprocess.CompletedProcess([], 0)))
        with (
            patch.object(SwitchReconciler, "get_live_switch_flows", return_value=None),
            patch("controller.ryu_app.reconciler.execute_flow_mod") as install,
        ):
            summary = SwitchReconciler(db_path=self.db_path).reconcile()
        install.assert_not_called()
        self.assertIsNone(summary.installed_on_switch)
        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute("DELETE FROM events WHERE event_type = 'decision_created'")
        with (
            patch.object(SwitchReconciler, "get_live_switch_flows", return_value=[]),
            patch("controller.ryu_app.reconciler.execute_flow_mod") as install,
            self.assertLogs("controller.ryu_app.reconciler", level="WARNING"),
        ):
            summary = SwitchReconciler(db_path=self.db_path).reconcile()
        install.assert_not_called()
        self.assertEqual(summary.reinstalled_count, 0)
