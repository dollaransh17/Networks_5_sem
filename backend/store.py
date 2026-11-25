"""Read the existing incident store without creating or modifying it."""

import sqlite3
from contextlib import closing
from time import time


BUCKET_SECONDS = 300
BUCKET_COUNT = 12


def activity_window(observed_at, groups):
    """Build an hour of five-minute buckets from grouped audit records."""
    first = observed_at - BUCKET_SECONDS * BUCKET_COUNT
    buckets = [{"start_at": first + index * BUCKET_SECONDS, "count": 0} for index in range(BUCKET_COUNT)]
    sources = {}
    for index, source, count in groups:
        buckets[index]["count"] += count
        sources[source] = sources.get(source, 0) + count
    return {"as_of": observed_at, "bucket_seconds": BUCKET_SECONDS, "buckets": buckets, "sources": sources}


def read_overview(path, observed_at=None):
    if not path.is_file():
        return {"audit_store": "waiting", "counts": None, "incidents": [], "events": [], "activity": None}

    observed_at = int(time()) if observed_at is None else observed_at
    first = observed_at - BUCKET_SECONDS * BUCKET_COUNT

    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        counts = dict(connection.execute("""
            SELECT (SELECT COUNT(*) FROM incidents) AS incidents,
                   (SELECT COUNT(*) FROM events) AS events,
                   (SELECT COUNT(*) FROM actions) AS actions
        """).fetchone())
        incidents = connection.execute("""
            SELECT id, subject_ip, target_ip, status, opened_at
            FROM incidents ORDER BY opened_at DESC, rowid DESC LIMIT 12
        """).fetchall()
        events = connection.execute("""
            SELECT id, event_type, source, occurred_at
            FROM events ORDER BY occurred_at DESC, rowid DESC LIMIT 8
        """).fetchall()
        groups = read_activity_groups(connection, observed_at)
        history = None
        if not groups and counts["events"]:
            latest = connection.execute("""
                SELECT MAX(CAST(strftime('%s', occurred_at) AS INTEGER))
                FROM events WHERE CAST(strftime('%s', occurred_at) AS INTEGER) < ?
            """, (first,)).fetchone()[0]
            if latest is not None:
                history_end = latest + 1
                history = activity_window(history_end, read_activity_groups(connection, history_end))

    return {
        "audit_store": "ready",
        "counts": counts,
        "incidents": [dict(row) for row in incidents],
        "events": [dict(row) for row in events],
        "activity": activity_window(observed_at, groups),
        **({"historical_activity": history} if history else {}),
    }


def read_activity_groups(connection, observed_at):
    first = observed_at - BUCKET_SECONDS * BUCKET_COUNT
    return connection.execute("""
        WITH timed_events AS (
            SELECT CAST(strftime('%s', occurred_at) AS INTEGER) AS event_at, source FROM events
        )
        SELECT (event_at - ?) / ? AS bucket, source, COUNT(*)
        FROM timed_events WHERE event_at >= ? AND event_at < ?
        GROUP BY bucket, source
    """, (first, BUCKET_SECONDS, first, observed_at)).fetchall()
