#!/usr/bin/env bash
# experiments/verify_stage2.sh
#
# Automated verification for Stage 2 / Features F2 & F3
# (OVS Telemetry, Ryu Polling & Scoped Enforcement)
# References: AGENTS.md, ARCHITECTURE.md, FEATURES.md (F2, F3)

set -u

echo "================================================================="
echo "   STAGE 2: OVS TELEMETRY & ENFORCEMENT VERIFICATION"
echo "================================================================="

# Helper function to run commands inside node namespaces or via 'm'
exec_node() {
    local node="$1"
    shift
    if command -v m >/dev/null 2>&1; then
        m "$node" "$@"
    else
        ip netns exec "$node" "$@"
    fi
}

# -----------------------------------------------------------------
# Pre-flight Check: Topology & Switch
# -----------------------------------------------------------------
if ! ovs-vsctl br-exists s1 2>/dev/null; then
    echo "[FAIL] Switch 's1' was not found on the system."
    echo ""
    echo "Please ensure the lab environment is running:"
    echo "  Terminal 1 (Ryu Controller):"
    echo "    ryu-manager controller/ryu_app/sdn_controller.py"
    echo "  Terminal 2 (Mininet Topology):"
    echo "    sudo python3 lab/topology/mininet_topo.py"
    echo ""
    exit 1
fi

TOTAL_TESTS=3
PASSED_TESTS=0

# -----------------------------------------------------------------
# Step 1: Baseline Flow Check (Table-Miss Entry)
# -----------------------------------------------------------------
echo -n "[TEST 1/3] Verifying OpenFlow 1.3 table-miss rule on s1... "
FLOWS_INIT=$(ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null || true)

if echo "$FLOWS_INIT" | grep -q "priority=0"; then
    echo "PASS (Table-miss entry found)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL (Priority 0 table-miss flow not found on s1)"
fi

# -----------------------------------------------------------------
# Step 2: Generate Traffic & Verify OVS Counter Increments (F2)
# -----------------------------------------------------------------
echo -n "[TEST 2/3] Generating traffic & verifying OVS flow counters... "

# Start temporary listener on protected server (srv)
exec_node srv bash -c 'nohup nc -l -k -p 443 >/dev/null 2>&1 &' 2>/dev/null || true
sleep 1

# Generate traffic from Client (h1) to Server (srv)
for i in {1..5}; do
    exec_node h1 bash -c 'echo "PING_TEST" | nc -w 1 198.51.100.20 443 >/dev/null 2>&1' || true
done
sleep 2

FLOWS_AFTER=$(ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null || true)
exec_node srv pkill -f "nc -l -k -p 443" 2>/dev/null || true

# Look for packet count > 0 on non-zero priority flows or overall datapath packets
if echo "$FLOWS_AFTER" | grep -qE "n_packets=[1-9][0-9]*"; then
    echo "PASS (OVS active counters observed)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL (No packet counter increments observed in dump-flows)"
    echo "--- Current Flows ---"
    echo "$FLOWS_AFTER"
fi

# -----------------------------------------------------------------
# Step 3: Mitigation Rule Installation Verification (F3)
# -----------------------------------------------------------------
echo -n "[TEST 3/3] Testing scoped mitigation rule installation (cookie=0x1001)... "
python3 experiments/trigger_mitigation.py drop >/dev/null 2>&1 || true

FLOWS_MITIGATION=$(ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null || true)

if echo "$FLOWS_MITIGATION" | grep -q "cookie=0x1001" && echo "$FLOWS_MITIGATION" | grep -q "hard_timeout=60"; then
    echo "PASS (Mitigation rule installed with correct cookie & hard_timeout)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "FAIL (Scoped mitigation rule missing from flow table)"
fi

echo "================================================================="
echo "   SUMMARY: $PASSED_TESTS / $TOTAL_TESTS passed"
echo "================================================================="

echo ""
echo "================================================================="
echo "   HOW TO MANUALLY TEST & OBSERVE TELEMETRY:"
echo "================================================================="
echo "1. Check active OpenFlow 1.3 flows anytime:"
echo "     sudo ovs-ofctl dump-flows s1 -O OpenFlow13"
echo ""
echo "2. Trigger an immediate scoped DROP mitigation rule:"
echo "     python3 experiments/trigger_mitigation.py drop"
echo ""
echo "3. Trigger a VLAN 999 QUARANTINE rule:"
echo "     python3 experiments/trigger_mitigation.py quarantine"
echo ""
echo "4. Watch the hard_timeout countdown and automatic expiry in dump-flows!"
echo "================================================================="

if [ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]; then
    exit 0
else
    exit 1
fi

