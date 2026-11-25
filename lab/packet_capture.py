"""Read packet headers from one named Mininet switch port and emit JSON batches."""

import argparse
import json
import socket
import struct
import subprocess
import sys
from time import monotonic, time


LAB_PORTS = ("s1-eth1", "s1-eth2", "s1-eth3")
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6
HEADER_BYTES = 128
MAX_ROWS = 24
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
VLAN_TYPES = {0x8100, 0x88A8}


def packet_header(frame, wire_bytes, timestamp):
    """Extract addressing and protocol fields, including VLAN and fragmented IP."""
    if len(frame) < 14:
        return None
    kind = int.from_bytes(frame[12:14], "big")
    offset = 14
    while kind in VLAN_TYPES:
        if offset + 4 > len(frame):
            return None
        kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4

    source_port = destination_port = None
    if kind == 0x0800 and len(frame) >= offset + 20:
        header = frame[offset:]
        length = (header[0] & 15) * 4
        if header[0] >> 4 != 4 or length < 20 or length > len(header):
            return None
        source = socket.inet_ntop(socket.AF_INET, header[12:16])
        destination = socket.inet_ntop(socket.AF_INET, header[16:20])
        number = header[9]
        first_fragment = not (int.from_bytes(header[6:8], "big") & 0x1FFF)
        if first_fragment and number in (6, 17) and len(header) >= length + 4:
            source_port, destination_port = struct.unpack_from("!HH", header, length)
        protocol = PROTOCOLS.get(number, f"IPv4 ({number})")
    elif kind == 0x86DD and len(frame) >= offset + 40:
        header = frame[offset:]
        if header[0] >> 4 != 6:
            return None
        source = socket.inet_ntop(socket.AF_INET6, header[8:24])
        destination = socket.inet_ntop(socket.AF_INET6, header[24:40])
        number = header[6]
        if number in (6, 17) and len(header) >= 44:
            source_port, destination_port = struct.unpack_from("!HH", header, 40)
        protocol = PROTOCOLS.get(number, f"IPv6 ({number})")
    else:
        source = frame[6:12].hex(":")
        destination = frame[:6].hex(":")
        protocol = "ARP" if kind == 0x0806 else f"EtherType 0x{kind:04x}"

    return {
        "at": timestamp, "source": source, "destination": destination,
        "source_port": source_port, "destination_port": destination_port,
        "protocol": protocol, "bytes": wire_bytes,
    }


def attached_to_lab(interface):
    result = subprocess.run(
        ["ovs-vsctl", "--timeout=2", "port-to-br", interface],
        capture_output=True, text=True, timeout=3, check=True,
    )
    return result.stdout.strip() == "s1"


def capture(interface):
    # A zero protocol leaves reception disabled until bind selects the exact lab port.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as receiver:
        interface_index = socket.if_nametoindex(interface)
        receiver.bind((interface, ETH_P_ALL))
        buffer = bytearray(HEADER_BYTES)
        origin = started = monotonic()
        sequence = 0
        rows = []
        packets = octets = 0
        while True:
            remaining = 1 - (monotonic() - started)
            if remaining > 0:
                receiver.settimeout(remaining)
                try:
                    length, _, _, _ = receiver.recvmsg_into([buffer], 0, socket.MSG_TRUNC)
                except TimeoutError:
                    continue
                packets += 1
                octets += length
                if len(rows) < MAX_ROWS:
                    row = packet_header(buffer[:min(length, HEADER_BYTES)], length, time())
                    if row is not None:
                        rows.append(row)
                continue

            now = monotonic()
            if socket.if_nametoindex(interface) != interface_index:
                raise OSError("The lab port was replaced. Start a new capture after the lab is ready.")
            try:
                _, dropped = struct.unpack("=II", receiver.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
            except OSError:
                dropped = None
            sequence += 1
            print(json.dumps({
                "interface": interface, "at": time(), "elapsed": now - started, "packets": packets,
                "sequence": sequence, "offset_s": now - origin,
                "bytes": octets, "kernel_dropped": dropped, "headers_omitted": packets - len(rows),
                "rows": rows,
            }), flush=True)
            started, rows, packets, octets = now, [], 0, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", choices=LAB_PORTS, default=LAB_PORTS[0])
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.exit(1, "Packet capture requires the isolated Linux Mininet lab.\n")
    try:
        if not attached_to_lab(args.interface):
            parser.exit(1, "The capture interface must belong to the lab bridge s1.\n")
        capture(args.interface)
    except (BrokenPipeError, KeyboardInterrupt):
        return
    except (OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Unable to capture on {args.interface}: {error}\n")


if __name__ == "__main__":
    main()
