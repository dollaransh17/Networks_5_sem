"""Regression coverage for the console's read-only audit timeline."""

import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from audit.logger.incident_logger import IncidentLogger
from backend.store import read_overview


class TestAuditActivity(unittest.TestCase):
    def test_missing_store_has_no_chart_data(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "missing.db"
            overview = read_overview(path)
            self.assertEqual(overview["audit_store"], "waiting")
            self.assertIsNone(overview["activity"])
            self.assertFalse(path.exists())

    def test_rollup_uses_all_events_within_the_time_window(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "store.db"
            IncidentLogger(db_path=str(path), spool_path=str(root / "events.jsonl"))
            records = (
                [("outside", "gateway", "2026-11-20T08:59:59Z")]
                + [(f"gateway-{index}", "gateway", "2026-11-20T09:00:00Z") for index in range(10)]
                + [("alert", "suricata", "2026-11-20T10:05:00+01:00")]
                + [("last", "switch-counter", "2026-11-20T09:59:59Z")]
                + [("future", "gateway", "2026-11-20T10:00:00Z")]
                + [("malformed", "gateway", "bad timestamp")]
            )
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.executemany(
                    "INSERT INTO events (id, source, occurred_at, sensor_id, event_type, payload) "
                    "VALUES (?, ?, ?, 'test', 'recorded', '{}')",
                    records,
                )
                observed_at = connection.execute("SELECT strftime('%s', '2026-11-20T10:00:00Z')").fetchone()[0]

            original = path.read_bytes()
            overview = read_overview(path, observed_at=int(observed_at))
            activity = overview["activity"]
            self.assertEqual(activity["bucket_seconds"], 300)
            self.assertEqual([bucket["count"] for bucket in activity["buckets"]], [10, 1] + [0] * 9 + [1])
            self.assertEqual(activity["sources"], {"gateway": 10, "suricata": 1, "switch-counter": 1})
            self.assertEqual(len(overview["events"]), 8)
            self.assertEqual(path.read_bytes(), original)
