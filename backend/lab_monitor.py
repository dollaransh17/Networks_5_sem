"""Read and cache evidence about the local Mininet lab services."""

import json
import logging
import math
import os
import subprocess
import sys
from pathlib import Path
from threading import Lock, Thread
from time import monotonic, time

from lab.packet_capture import LAB_PORTS


SERVICES = ("ryu", "mininet", "ovs", "suricata")
LOGGER = logging.getLogger(__name__)


def service(state, detail):
    return {"state": state, "detail": detail}


def process_commands(proc=Path("/proc")):
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            with (entry / "cmdline").open("rb") as source:
                args = source.read(4096).rstrip(b"\0").decode(errors="replace").split("\0")
        except OSError:
            continue
        if args and args[0]:
            yield args


def ovs_tables():
    result = subprocess.run(
        ["ovs-vsctl", "--timeout=2", "--format=json",
         "--", "--columns=ports,protocols,controller", "find", "Bridge", "name=s1",
         "--", "--columns=_uuid,name", "list", "Port",
         "--", "--columns=_uuid,target,is_connected", "list", "Controller"],
        capture_output=True, text=True, timeout=3, check=True,
    )
    decoder = json.JSONDecoder()
    remaining = result.stdout
    tables = []
    for _ in range(3):
        table, end = decoder.raw_decode(remaining.lstrip())
        remaining = remaining.lstrip()[end:]
        tables.append([dict(zip(table["headings"], row)) for row in table["data"]])
    return tables


def ovs_set(value):
    if isinstance(value, list) and value and value[0] == "set":
        return value[1]
    return [value]


def check_lab():
    if sys.platform != "linux":
        unavailable = service("unavailable", "Start the isolated Linux lab to verify this service.")
        return {name: unavailable.copy() for name in SERVICES}

    try:
        commands = list(process_commands())
    except OSError:
        commands = []
    names = [[Path(arg).name for arg in args] for args in commands]
    ryu_found = any("ryu-manager" in args[:2] and "sdn_controller.py" in args for args in names)
    mininet_found = any("mininet_topo.py" in args and args[0].startswith("python") for args in names)
    ips_found = any(
        Path(args[0]).name == "suricata"
        and all(interface in args or f"--af-packet={interface}" in args for interface in ("ips-eth0", "ips-eth1"))
        for args in commands
    )
    ryu = service("pending", "Controller process found. OpenFlow connection unverified." if ryu_found
                  else "Lab Ryu process not detected.")
    mininet = service("pending", "Launcher found. Lab links unverified." if mininet_found
                      else "Lab topology launcher not detected.")
    suricata = service("pending", "Suricata on both lab interfaces was not detected.")
    if ips_found:
        eve = Path("/var/log/suricata/eve.json")
        if eve.is_file() and os.access(eve, os.R_OK):
            suricata = service("observed", "Process found on both lab interfaces. EVE log is readable.")
        else:
            suricata = service("pending", "Process found on both interfaces. EVE log is unreadable.")

    try:
        bridges, ports, controllers = ovs_tables()
        ovs = service("pending", "OVSDB responded. Lab bridge s1 is absent.")
        if bridges:
            bridge = bridges[0]
            protocols = ovs_set(bridge["protocols"])
            bridge_ports = ovs_set(bridge["ports"])
            linked = {row["name"] for row in ports if row["_uuid"] in bridge_ports}
            ovs = service("observed", "Bridge s1 found with OpenFlow 1.3 configured.") if "OpenFlow13" in protocols else (
                service("pending", "Bridge s1 found. OpenFlow 1.3 configuration unverified."))
            if mininet_found and set(LAB_PORTS) <= linked:
                mininet = service("observed", "Launcher and all three s1 lab ports found.")
            controller_ids = ovs_set(bridge["controller"])
            connected = any(
                row["_uuid"] in controller_ids and row["target"] == "tcp:127.0.0.1:6653"
                and row["is_connected"] is True for row in controllers
            )
            if connected and ryu_found:
                ryu = service("observed", "Lab Ryu process found. OVS reports an active controller connection.")
    except FileNotFoundError:
        ovs = service("unavailable", "ovs-vsctl is unavailable.")
    except (subprocess.SubprocessError, OSError, ValueError, KeyError, TypeError):
        ovs = service("unavailable", "Could not read the local OVS database.")

    return {"ryu": ryu, "mininet": mininet, "ovs": ovs, "suricata": suricata}


def check_docker_lab(container):
    result = subprocess.run(
        ["docker", "exec", "-w", "/project", container, "python3", "-B", "-c",
         "import json; from backend.lab_monitor import check_lab; print(json.dumps(check_lab()))"],
        capture_output=True, text=True, timeout=5, check=True,
    )
    return json.loads(result.stdout)


class LabChecks:
    def __init__(self, container=None):
        self.container = container
        self.lock = Lock()
        self.checked_at = -math.inf
        self.running = False
        self.status = {name: {**service("pending", "Waiting for the first lab check."), "checked_at": None}
                       for name in SERVICES}

    def snapshot(self):
        with self.lock:
            status = self.status
            should_refresh = not self.running and monotonic() - self.checked_at >= 5
            if should_refresh:
                self.running = True
        if should_refresh:
            try:
                Thread(target=self._refresh, name="lab-probe", daemon=True).start()
            except RuntimeError:
                LOGGER.exception("Unable to start the lab probe")
                self._publish({name: service("unavailable", "Could not start the local service check.") for name in SERVICES})
        return status

    def _refresh(self):
        try:
            status = check_docker_lab(self.container) if self.container else check_lab()
        except (OSError, subprocess.SubprocessError, ValueError):
            status = {name: service("unavailable", "Could not query the Docker lab.") for name in SERVICES}
        except Exception:
            LOGGER.exception("Lab service check failed")
            status = {name: service("unavailable", "The local service check failed.") for name in SERVICES}
        self._publish(status)

    def _publish(self, status):
        checked_at = time()
        with self.lock:
            self.status = {name: {**item, "checked_at": checked_at} for name, item in status.items()}
            self.checked_at = monotonic()
            self.running = False

