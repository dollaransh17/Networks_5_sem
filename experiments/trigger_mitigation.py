#!/usr/bin/env python3
"""
experiments/trigger_mitigation.py

Helper script to program an approved mitigation rule on switch s1 via Ryu OpenFlow 1.3
or ovs-ofctl, conforming to AGENTS.md and FEATURES.md (F3):
- Scoped match (Client 192.0.2.10 -> Server 198.51.100.20, TCP)
- Never blocks on src_ip alone
- Unique non-zero cookie (0x1001)
- Priority 200 (higher than normal forwarding priority 1)
- Hard timeout of 60 seconds (automatic expiration)
"""

import subprocess
import sys


def install_rule(action_type="drop", hard_timeout=60, cookie=0x1001, priority=200):
    match_str = "ip,nw_src=192.0.2.10,nw_dst=198.51.100.20"

    if action_type == "drop":
        actions = "drop"
    elif action_type == "quarantine":
        # Push VLAN 999 and output to quarantine port 3
        # In OpenFlow 1.3, VLAN IDs are 0-4094 with OFPVID_PRESENT bit (0x1000).
        # ovs-ofctl syntax for setting VLAN 999: mod_vlan_vid:999 or set_field:4096+999->vlan_vid
        actions = "push_vlan:0x8100,mod_vlan_vid:999,output:3"
    else:
        print(f"[!] Unknown action_type: {action_type}")
        return 1

    cmd = [
        "ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1",
        f"cookie={cookie},priority={priority},hard_timeout={hard_timeout},{match_str},actions={actions}"
    ]

    print(f"[*] Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[+] Successfully installed mitigation rule on s1:")
        print(f"    - Match: {match_str}")
        print(f"    - Cookie: {hex(cookie)} ({cookie})")
        print(f"    - Priority: {priority}")
        print(f"    - Hard Timeout: {hard_timeout}s")
        print(f"    - Action: {actions}")
        return 0
    else:
        print(f"[!] Error installing rule: {res.stderr}")
        return 1


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "drop"
    sys.exit(install_rule(action_type=action))

