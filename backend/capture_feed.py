"""Validate collector reports and expose bounded snapshots to the console."""

import json
from collections import deque
from threading import Lock
from time import monotonic

from lab.packet_capture import LAB_PORTS, MAX_ROWS


MAX_MESSAGE = 16_384
MAX_TIMESTAMP = 8.64e12  # JavaScript Date range in seconds.


def valid_number(value):
    return type(value) in (int, float) and 0 <= value <= 2**53 - 1


def valid_count(value):
    return type(value) is int and valid_number(value)


def clean_header(row):
    if not isinstance(row, dict):
        return None
    timestamp, length = row.get("at"), row.get("bytes")
    if not valid_number(timestamp) or timestamp > MAX_TIMESTAMP or not valid_count(length):
        return None
    addresses = {key: row.get(key) for key in ("source", "destination", "protocol")}
    if not all(isinstance(value, str) and 0 < len(value) <= 64 for value in addresses.values()):
        return None
    ports = {}
    for key in ("source_port", "destination_port"):
        value = row.get(key)
        ports[key] = value if valid_count(value) and value <= 65535 else None
    return {"at": timestamp, "bytes": length, **addresses, **ports}


class CaptureFeed:
    def __init__(self, configured=False):
        self.configured = configured
        self.lock = Lock()
        self.interface = None
        self.updated = None
        self.ended = False
        self.sequence = None
        self.intervals = deque(maxlen=60)
        self.rows = deque(maxlen=100)

    def read(self, stream):
        try:
            while line := stream.readline(MAX_MESSAGE + 1):
                if len(line) > MAX_MESSAGE:
                    while line and not line.endswith("\n"):
                        line = stream.readline(MAX_MESSAGE + 1)
                    continue
                try:
                    self.record(json.loads(line))
                except (ValueError, RecursionError):
                    continue
        finally:
            with self.lock:
                self.ended = True

    def record(self, batch):
        if not isinstance(batch, dict):
            return
        interface, timestamp, elapsed = (batch.get(key) for key in ("interface", "at", "elapsed"))
        if interface not in LAB_PORTS or not valid_number(timestamp) or timestamp > MAX_TIMESTAMP:
            return
        if not valid_number(elapsed) or not 0.001 <= elapsed <= 120:
            return
        counts = {key: batch.get(key) for key in ("packets", "bytes", "headers_omitted")}
        if not all(valid_count(count) for count in counts.values()) or counts["headers_omitted"] > counts["packets"]:
            return
        dropped, sequence, offset = (batch.get(key) for key in ("kernel_dropped", "sequence", "offset_s"))
        if dropped is not None and not valid_count(dropped):
            return
        if sequence is not None and (not valid_count(sequence) or sequence == 0):
            return
        if offset is not None and (not valid_number(offset) or offset < elapsed):
            return
        raw_rows = batch.get("rows")
        if not isinstance(raw_rows, list):
            return
        rows = [row for raw in raw_rows[:MAX_ROWS] if (row := clean_header(raw)) is not None]
        rows = rows[:counts["packets"] - counts["headers_omitted"]]
        counts["headers_omitted"] = counts["packets"] - len(rows)

        with self.lock:
            if self.interface != interface:
                self.intervals.clear()
                self.rows.clear()
                self.sequence = None
            previous = self.intervals[-1] if self.intervals else None
            previous_offset = previous["offset_s"] if previous else 0
            if sequence is not None and self.sequence is not None and sequence <= self.sequence:
                return
            if offset is None:
                offset = previous_offset + elapsed
                gap = previous and abs(timestamp - elapsed - previous["at"]) > 0.5
            else:
                delta = offset - elapsed - previous_offset
                if previous and delta < -0.001:
                    return
                gap = previous and delta > 0.05
            sequence_gap = sequence is not None and self.sequence is not None and sequence != self.sequence + 1
            self.sequence = sequence
            self.interface = interface
            self.updated = monotonic()
            self.intervals.append({
                "at": timestamp, "elapsed": elapsed, "offset_s": offset, "sequence": sequence,
                "gap": bool(gap or sequence_gap), "kernel_dropped": dropped, **counts,
            })
            self.rows.extend(rows)

    def snapshot(self):
        with self.lock:
            if not self.configured:
                state = "disabled"
            elif self.ended:
                state = "stopped"
            elif self.updated is None:
                state = "waiting"
            else:
                state = "live" if monotonic() - self.updated < 4 else "stale"
            return {
                "state": state, "interface": self.interface,
                "intervals": list(self.intervals), "rows": list(reversed(self.rows)),
            }
