#!/usr/bin/env bash
# experiments/verify_stage1.sh
#
# Automated verification for Stage 1 / Feature F1 (Access Gateway Policy)
# Tests against the active Mininet network created by lab/topology/mininet_topo.py
#
# Uses Mininet's 'm' utility / ip netns exec to run commands inside node namespaces.
#
# Acceptance Criteria checked:
#   1. Test Client (h1) CAN ping the Gateway (gw)
#   2. Test Client (h1) CANNOT connect to Protected Server (srv) on TCP 22
#   3. Test Client (h1) CAN connect to Protected Server (srv) on TCP 443
#   4. Dropped packets appear in gateway's logs with "GATEWAY_DENY:" prefix

set -u

echo "================================================================="
echo "   STAGE 1 / F1 ACCEPTANCE VERIFICATION"
echo "================================================================="

# Locate node execution wrapper (m utility or ip netns)
exec_node() {
    local node="$1"
    shift
    if command -v m >/dev/null 2>&1; then
        m "$node" "$@"
    else
        # Fallback to ip netns if mininet utility 'm' is not in PATH
        ip netns exec "$node" "$@"
    fi
}

# Pre-check: Ensure nodes are running
if ! exec_node h1 ip addr show >/dev/null 2>&1; then
    echo "[FAIL] Mininet network does not appear to be running or nodes (h1, gw, srv) are not found."
    echo "       Please start 'sudo python3 lab/topology/mininet_topo.py' in another terminal first."
    exit 1
fi

TOTAL_TESTS=4
PASSED_TESTS=0

# Ensure dummy listeners exist on Protected Server (srv) for ports 22 and 443
exec_node srv pkill -f "nc -l -p (22|443)" 2>/dev/null || true
exec_node srv bash -c 'nohup nc -l -k -p 22 >/dev/null 2>&1 &'
exec_node srv bash -c 'nohup nc -l -k -p 443 >/dev/null 2>&1 &'
sleep 1

# Clear dmesg buffer on gw to isolate test log output
exec_node gw dmesg -c >/dev/null 2>&1 || true

# -----------------------------------------------------------------
# Test 1: Test Client CAN ping the Gateway
# -----------------------------------------------------------------
echo -n "[TEST 1/4] Client (h1) ping Gateway (192.0.2.1)... "
if exec_node h1 ping -c 2 -W 2 192.0.2.1 >/dev/null 2>&1; then
    echo "PASS"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL"
fi

# -----------------------------------------------------------------
# Test 2: Test Client CANNOT connect to Protected Server on TCP 22 (SSH)
# -----------------------------------------------------------------
echo -n "[TEST 2/4] Client (h1) connect to Server:22 (SSH should be DENIED)... "
if exec_node h1 nc -zv -w 2 198.51.100.20 22 >/dev/null 2>&1; then
    echo "FAIL (Connection succeeded; expected denial)"
else
    echo "PASS (Connection blocked as expected)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# -----------------------------------------------------------------
# Test 3: Test Client CAN connect to Protected Server on TCP 443 (HTTPS)
# -----------------------------------------------------------------
echo -n "[TEST 3/4] Client (h1) connect to Server:443 (HTTPS should be PERMITTED)... "
if exec_node h1 nc -zv -w 3 198.51.100.20 443 >/dev/null 2>&1; then
    echo "PASS"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL"
fi

# -----------------------------------------------------------------
# Test 4: Verify dropped packets appear in gateway's logs with "GATEWAY_DENY:" prefix
# -----------------------------------------------------------------
echo -n "[TEST 4/4] Gateway log inspection for 'GATEWAY_DENY:' prefix... "
GW_LOGS=$(exec_node gw dmesg 2>/dev/null || true)
if [ -z "$GW_LOGS" ]; then
    # Fallback to checking kernel/syslog if dmesg buffer in namespace was empty
    GW_LOGS=$(exec_node gw grep -m 1 "GATEWAY_DENY:" /var/log/syslog /var/log/kern.log 2>/dev/null || true)
fi

if echo "$GW_LOGS" | grep -q "GATEWAY_DENY:"; then
    echo "PASS"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL (No 'GATEWAY_DENY:' found in gateway logs)"
fi

# Cleanup listeners on srv
exec_node srv pkill -f "nc -l -k -p (22|443)" 2>/dev/null || true

echo "================================================================="
echo "   SUMMARY: $PASSED_TESTS / $TOTAL_TESTS passed"
echo "================================================================="

if [ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]; then
    exit 0
else
    exit 1
fi

