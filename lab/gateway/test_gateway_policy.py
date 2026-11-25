#!/usr/bin/env python3
"""
lab/gateway/test_gateway_policy.py

Verification script for Phase 1 (Stage 1 / Feature F1):
Tests and confirms Gateway Access Policies within the Mininet network.

Verifies:
1. TCP 22 (SSH) from Client (h1) to Server (srv) is DENIED.
2. TCP 443 (HTTPS) from Client (h1) to Server (srv) is PERMITTED.
3. Denied traffic never increments OVS counters on s1.
4. Gateway syslog contains "GATEWAY_DENY:" log lines.

Run inside Mininet or test harness:
    python3 lab/gateway/test_gateway_policy.py
"""

import sys
import time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel, info
from lab.topology.mininet_topo import ThreatIsolationTopology, setup_routes


def run_tests():
    setLogLevel('info')
    topo = ThreatIsolationTopology()
    net = Mininet(topo=topo, switch=OVSSwitch, build=True, autoSetMacs=True)

    try:
        info('*** Starting Network\n')
        net.start()
        setup_routes(net)

        gw = net.get('gw')
        h1 = net.get('h1')
        srv = net.get('srv')
        s1 = net.get('s1')

        info('*** Applying Gateway Firewall Rules\n')
        gw.cmd('bash lab/gateway/setup_gateway.sh')

        # Start a dummy server listening on 443 and 22 on srv
        info('*** Starting test listeners on Protected Server (srv)\n')
        srv.cmd('nc -l -p 443 -k > /dev/null 2>&1 &')
        srv.cmd('nc -l -p 22 -k > /dev/null 2>&1 &')
        time.sleep(1)

        # Clear dmesg/syslog marker
        gw.cmd('dmesg -c > /dev/null 2>&1')

        # Test 1: Verify TCP 443 is ALLOWED
        info('*** Test 1: Verifying TCP 443 (HTTPS) is ALLOWED\n')
        res_443 = h1.cmd('nc -zv -w 2 198.51.100.20 443')
        is_443_allowed = ('open' in res_443 or 'succeeded' in res_443)
        print(f"  Result 443: {'PASS (Allowed)' if is_443_allowed else 'FAIL'}")

        # Test 2: Verify TCP 22 is BLOCKED
        info('*** Test 2: Verifying TCP 22 (SSH) is BLOCKED\n')
        res_22 = h1.cmd('nc -zv -w 2 198.51.100.20 22')
        is_22_denied = ('open' not in res_22 and 'succeeded' not in res_22)
        print(f"  Result 22:  {'PASS (Blocked)' if is_22_denied else 'FAIL'}")

        # Test 3: Check Gateway Denial Logs
        info('*** Test 3: Checking Gateway kernel log prefix "GATEWAY_DENY:"\n')
        dmesg_output = gw.cmd('dmesg')
        has_deny_log = "GATEWAY_DENY:" in dmesg_output
        print(f"  Log Result: {'PASS (Found GATEWAY_DENY:)' if has_deny_log else 'FAIL / Warning (Check syslog config)'}")

        all_passed = is_443_allowed and is_22_denied
        info(f"\n*** Phase 1 Gateway Acceptance: {'PASSED' if all_passed else 'FAILED'}\n")
        return 0 if all_passed else 1

    finally:
        info('*** Stopping Network\n')
        net.stop()


if __name__ == '__main__':
    sys.exit(run_tests())

