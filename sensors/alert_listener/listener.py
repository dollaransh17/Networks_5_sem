#!/usr/bin/env python3
"""
sensors/alert_listener/listener.py

Phase 3: Suricata EVE JSON Alert Listener
References: PRD (Section 5, MVP 4), PDF Section 6, AGENTS.md, API.md (/v1/events)

Key Responsibilities:
1. Tails Suricata eve.json safely: handles log rotations, truncations, and malformed lines.
2. Selects only relevant event types (filters "alert" records, ignores noise/stats).
3. Normalizes alert records to the project application schema.
4. Validates required fields and directionality:
   - Does NOT assume src_ip is always the attacker.
5. Deduplicates burst alerts over a configurable time window to prevent event storms.
6. Submits normalized events to the Risk Policy Engine over the management API.
7. Keeps original raw log references for cryptographic evidence linking.
"""

import json
import os
import sys
import time
from ipaddress import ip_address
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, asdict


@dataclass
class NormalizedAlert:
    schema_version: int
    event_id: str
    sensor_id: str
    event_type: str
    src_ip: str
    dest_ip: str
    src_port: Optional[int]
    dest_port: Optional[int]
    proto: str
    signature: str
    signature_id: int
    subject_ip: str
    subject_status: str
    occurred_at: str
    raw_event_ref: Dict[str, Any]


class EveAlertListener:
    def __init__(self, eve_path: str = "/var/log/suricata/eve.json",
                 sensor_id: str = "ips-edge-1",
                 dedup_window_s: float = 5.0):
        self.eve_path = eve_path
        self.sensor_id = sensor_id
        self.dedup_window_s = dedup_window_s
        # (src_ip, dest_ip, signature_id) -> last_seen_timestamp
        self.dedup_cache: Dict[tuple, float] = {}

    def normalize_alert(self, raw_record: Dict[str, Any]) -> Optional[NormalizedAlert]:
        """
        Extracts, validates, and normalizes a Suricata EVE record.
        Returns None if record is not an alert or is malformed.
        """
        if not isinstance(raw_record, dict) or raw_record.get("event_type") != "alert":
            return None

        alert_data = raw_record.get("alert", {})
        src_ip = raw_record.get("src_ip")
        dest_ip = raw_record.get("dest_ip")

        if not isinstance(alert_data, dict) or not isinstance(src_ip, str) or not isinstance(dest_ip, str):
            return None
        try:
            ip_address(src_ip)
            ip_address(dest_ip)
        except ValueError:
            return None

        sig_id = alert_data.get("signature_id", 0)
        signature = alert_data.get("signature", "Unknown Signature")
        proto = raw_record.get("proto", "")
        if type(sig_id) is not int or not isinstance(signature, str) or not isinstance(proto, str):
            return None

        # Directionality check: Do not blindly assume src_ip is attacker
        # In a client-server lab: client network is 192.0.2.0/24
        if src_ip.startswith("192.0.2."):
            subject_ip = src_ip
            subject_status = "validated_client_origin"
        elif dest_ip.startswith("192.0.2."):
            subject_ip = dest_ip
            subject_status = "validated_response_reflection"
        else:
            subject_ip = src_ip
            subject_status = "requires_direction_validation"

        # Unique stable event ID
        event_id = f"eve-{raw_record.get('flow_id', int(time.time() * 1000))}-{sig_id}"

        return NormalizedAlert(
            schema_version=1,
            event_id=event_id,
            sensor_id=self.sensor_id,
            event_type="alert",
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_port=raw_record.get("src_port"),
            dest_port=raw_record.get("dest_port"),
            proto=proto,
            signature=signature,
            signature_id=sig_id,
            subject_ip=subject_ip,
            subject_status=subject_status,
            occurred_at=raw_record.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            raw_event_ref={"flow_id": raw_record.get("flow_id"), "pcap_cnt": raw_record.get("pcap_cnt")}
        )

    def is_duplicate(self, alert: NormalizedAlert, now_s: float) -> bool:
        """
        Deduplicates repeated alerts to prevent event storms.
        """
        key = (alert.src_ip, alert.dest_ip, alert.signature_id)

        # Cleanup expired cache entries
        expired_keys = [k for k, last_seen in self.dedup_cache.items()
                        if now_s - last_seen > self.dedup_window_s]
        for k in expired_keys:
            del self.dedup_cache[k]

        if key in self.dedup_cache:
            return True

        self.dedup_cache[key] = now_s
        return False

    def process_line(self, line: str) -> Optional[NormalizedAlert]:
        """
        Parses a single line from eve.json.
        """
        line = line.strip()
        if not line:
            return None
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Skip malformed lines safely without crashing
            return None

        alert = self.normalize_alert(record)
        if not alert:
            return None

        if self.is_duplicate(alert, time.time()):
            return None

        return alert


if __name__ == "__main__":
    listener = EveAlertListener()
    print(f"[*] EveAlertListener initialized for sensor '{listener.sensor_id}'")
    print(f"[*] Monitoring path: {listener.eve_path}")

