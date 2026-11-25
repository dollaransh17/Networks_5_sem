"""Verify capture metadata, bounded history, and lab status with controlled fixtures."""

import io
import json
import socket
import struct
import unittest
from threading import Event
from unittest.mock import Mock, patch

from backend import lab_monitor
from backend.capture_feed import CaptureFeed
from lab.packet_capture import LAB_PORTS, attached_to_lab, packet_header


class TestPacketHeaders(unittest.TestCase):
    def test_vlan_ipv4_tcp_keeps_only_headers(self):
        ethernet = bytes.fromhex("00112233445566778899aabb810000250800")
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
            socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20"),
        )
        header = packet_header(ethernet + ip + struct.pack("!HH", 50321, 443) + b"fixture body", 1200, 1.5)
        self.assertEqual(header, {
            "at": 1.5, "source": "192.0.2.10", "destination": "198.51.100.20",
            "source_port": 50321, "destination_port": 443, "protocol": "TCP", "bytes": 1200,
        })

    def test_noninitial_fragment_does_not_treat_data_as_ports(self):
        frame = bytearray.fromhex("00112233445566778899aabb0800450000180000000140110000c000020ac633641400350035")
        header = packet_header(frame, len(frame), 2)
        self.assertEqual(header["protocol"], "UDP")
        self.assertIsNone(header["source_port"])
        self.assertIsNone(packet_header(frame[:10], 10, 2))

    def test_capture_port_must_belong_to_s1(self):
        with patch("lab.packet_capture.subprocess.run", return_value=Mock(stdout="s1\n")) as ovs:
            self.assertTrue(attached_to_lab("s1-eth1"))
            self.assertIn("port-to-br", ovs.call_args.args[0])


class TestCaptureFeed(unittest.TestCase):
    def test_history_is_bounded_and_disconnect_is_explicit(self):
        batches = []
        for index in range(105):
            batches.append(json.dumps({
                "interface": "s1-eth1", "at": index, "elapsed": 1.25, "packets": 2, "bytes": 100,
                "headers_omitted": 1, "kernel_dropped": 0, "rows": [
                    {"at": index, "source": "192.0.2.10", "destination": "198.51.100.20",
                     "source_port": 123, "destination_port": 443, "protocol": "TCP", "bytes": 100,
                     "payload": "never returned"},
                ],
            }))
        feed = CaptureFeed(configured=True)
        feed.read(io.StringIO("x" * 17_000 + "\n{invalid}\n" + "\n".join(batches)))
        result = feed.snapshot()
        self.assertEqual(result["state"], "stopped")
        self.assertEqual(len(result["rows"]), 100)
        self.assertEqual(len(result["intervals"]), 60)
        self.assertEqual(result["rows"][0]["at"], 104)
        self.assertNotIn("payload", result["rows"][0])
        self.assertEqual(result["intervals"][-1]["elapsed"], 1.25)

    def test_live_zero_packet_interval_and_stale_feed_are_distinct(self):
        feed = CaptureFeed(configured=True)
        self.assertEqual(feed.snapshot()["state"], "waiting")
        with patch("backend.capture_feed.monotonic", return_value=10) as clock:
            feed.record({"interface": "s1-eth1", "at": 100, "elapsed": 1.0, "packets": 0,
                         "bytes": 0, "headers_omitted": 0, "kernel_dropped": None, "rows": []})
            self.assertEqual(feed.snapshot()["state"], "live")
            clock.return_value = 15
            self.assertEqual(feed.snapshot()["state"], "stale")
        self.assertEqual(CaptureFeed().snapshot()["state"], "disabled")

    def test_monotonic_offsets_survive_wall_clock_changes_and_report_gaps(self):
        feed = CaptureFeed(configured=True)
        batch = {"interface": "s1-eth1", "elapsed": 1, "packets": 0, "bytes": 0,
                 "headers_omitted": 0, "kernel_dropped": None, "rows": []}
        feed.record({**batch, "sequence": 1, "offset_s": 1, "at": 100})
        feed.record({**batch, "sequence": 2, "offset_s": 2, "at": 80})
        feed.record({**batch, "sequence": 2, "offset_s": 2, "at": 81})
        feed.record({**batch, "sequence": 4, "offset_s": 4, "at": 82})
        history = feed.snapshot()["intervals"]
        self.assertEqual([row["offset_s"] for row in history], [1, 2, 4])
        self.assertEqual([row["gap"] for row in history], [False, False, True])

    def test_bad_header_does_not_hide_valid_interval_counts(self):
        feed = CaptureFeed(configured=True)
        feed.record({"interface": "s1-eth1", "at": 100, "elapsed": 1, "packets": 1, "bytes": 64,
                     "headers_omitted": 0, "kernel_dropped": 0, "rows": [None]})
        snapshot = feed.snapshot()
        self.assertEqual(snapshot["state"], "live")
        self.assertEqual(snapshot["intervals"][0]["headers_omitted"], 1)
        self.assertEqual(snapshot["rows"], [])


class TestLabStatus(unittest.TestCase):
    def test_snapshot_is_available_while_a_single_probe_is_in_flight(self):
        started, release, completed = Event(), Event(), Event()
        checks = lab_monitor.LabChecks()
        original_publish = checks._publish

        def probe():
            started.set()
            release.wait(2)
            return {name: lab_monitor.service("observed", "Fixture evidence") for name in lab_monitor.SERVICES}

        def publish(status):
            original_publish(status)
            completed.set()

        with (patch.object(lab_monitor, "check_lab", side_effect=probe) as check,
              patch.object(checks, "_publish", side_effect=publish)):
            try:
                self.assertIsNone(checks.snapshot()["ryu"]["checked_at"])
                self.assertTrue(started.wait(1))
                self.assertIsNone(checks.snapshot()["ryu"]["checked_at"])
                self.assertEqual(check.call_count, 1)
            finally:
                release.set()
            self.assertTrue(completed.wait(1))
            self.assertEqual(checks.snapshot()["ryu"]["state"], "observed")
            self.assertIsNotNone(checks.snapshot()["ryu"]["checked_at"])

    def test_connected_controller_must_belong_to_the_lab_bridge(self):
        commands = [["python", "/bin/ryu-manager", "controller/ryu_app/sdn_controller.py"],
                    ["python3", "lab/topology/mininet_topo.py"],
                    ["suricata", "--af-packet=ips-eth0", "--af-packet=ips-eth1"]]
        ids = [["uuid", name] for name in LAB_PORTS]
        ports = [{"_uuid": key, "name": name} for key, name in zip(ids, LAB_PORTS)]
        bridges = [{"protocols": "OpenFlow13", "ports": ["set", ids], "controller": ["uuid", "lab"]}]
        controllers = [{"_uuid": ["uuid", "other"], "is_connected": True, "target": "tcp:127.0.0.1:6653"},
                       {"_uuid": ["uuid", "lab"], "is_connected": False, "target": "tcp:127.0.0.1:6653"}]
        with (patch.object(lab_monitor.sys, "platform", "linux"), patch.object(lab_monitor, "process_commands", return_value=commands),
              patch.object(lab_monitor, "ovs_tables", return_value=(bridges, ports, controllers)),
              patch.object(lab_monitor.Path, "is_file", return_value=True), patch.object(lab_monitor.os, "access", return_value=True)):
            result = lab_monitor.check_lab()
            self.assertEqual(result["ryu"]["state"], "pending")
            self.assertTrue(all(result[key]["state"] == "observed" for key in ("ovs", "mininet", "suricata")))
            controllers[1]["is_connected"] = True
            self.assertEqual(lab_monitor.check_lab()["ryu"]["state"], "observed")
