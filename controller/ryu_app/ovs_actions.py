"""Install approved, scoped OpenFlow actions in the local OVS lab."""

import subprocess
from ipaddress import IPv4Address

from controller.ryu_app.enforcement_types import EnforcementActionRequest


def execute_flow_mod(action_req: EnforcementActionRequest) -> bool:
    """
    Programs the scoped mitigation rule on switch s1 via OpenFlow 1.3.
    """
    match = action_req.match
    if (
        action_req.validate()
        or match.ip_proto != 6
        or any(value is not None for value in (match.tcp_src, match.udp_src, match.udp_dst, match.ingress_port))
        or (match.tcp_dst is not None and (type(match.tcp_dst) is not int or not 1 <= match.tcp_dst <= 65535))
    ):
        print(f"[ENFORCE_FAIL] Unsupported or invalid scope for {action_req.action_id}.")
        return False
    try:
        src_ip = IPv4Address(match.ipv4_src)
        dst_ip = IPv4Address(match.ipv4_dst)
    except ValueError:
        print(f"[ENFORCE_FAIL] Expected two IPv4 endpoints for {action_req.action_id}.")
        return False

    match_parts = ["tcp", f"nw_src={src_ip}", f"nw_dst={dst_ip}"]
    if match.tcp_dst is not None:
        match_parts.append(f"tp_dst={match.tcp_dst}")
    if action_req.action_type == "temporary_drop":
        if match.tcp_dst is None:
            print(f"[ENFORCE_FAIL] Expected a TCP destination port for {action_req.action_id}.")
            return False
        actions = "drop"
    elif action_req.action_type == "quarantine":
        actions = "push_vlan:0x8100,mod_vlan_vid:999,output:3"
    else:
        print(f"[ENFORCE_FAIL] Unsupported action type: {action_req.action_type}.")
        return False

    cmd = [
        "ovs-ofctl", "-O", "OpenFlow13", "add-flow", action_req.switch_id,
        f"cookie={action_req.rule_cookie},priority={action_req.priority},"
        f"hard_timeout={action_req.ttl_s},{','.join(match_parts)},actions={actions}"
    ]

    print(f"[SDN_ENFORCE] Executing OpenFlow mitigation rule: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[ENFORCE_FAIL] {action_req.action_id}: {error}")
        return False
    if res.returncode:
        print(f"[ENFORCE_FAIL] {action_req.action_id}: ovs-ofctl exited {res.returncode}: {res.stderr.strip()}")
    return res.returncode == 0
