# DEBUGGING: Systematic process

Do not guess; do not rewrite large parts of the code. Labs involve several moving parts, so isolate by plane first.

## Paste into your AI assistant
```
Error / logs: [PASTE FULL ERROR OR LOG LINES]
What I was doing: [STEPS] | Expected: [EXPECTED] | Actual: [ACTUAL]
Component: [gateway | Suricata | OVS | Ryu | listener | risk engine | AI | logger | sealer | cloud]
Versions: [kernel, OVS, Ryu, Suricata, Python]
```

## Process
1. **Read the error** and explain it plainly. Identify which plane failed (data, control, AI/application, evidence).
2. **List 3 likely root causes**, ranked.
3. **Confirm the top cause before changing anything**: `ovs-ofctl dump-flows`, Ryu logs, EVE tail, TShark at two points, queue depth.
4. **Smallest fix**: show only changed lines.
5. **Explain why and prevent**: add a regression test to TESTING.md.

Rules: check against ARCHITECTURE.md, DATABASE.md, API.md; stay in scope; ask when unsure.

## Quick checks by symptom
| Symptom | First checks |
|---|---|
| Rule "installed" but traffic still passes | Priority/table vs normal forwarding; match fields; readback; counters |
| Wrong host blocked | Match too broad; NAT mapping; subject validation |
| Suricata alert but no drop | Passive vs inline mode; drop rule; both directions through sensor |
| Rates look wrong/negative | Counter reset; hard-coded interval; sample timestamps |
| Polling falls behind | Reply size, outstanding requests, queue depth; back off |
| Duplicate rules after restart | Missing reconcile; idempotency on action_id |
| Verification fails | Canonicalization mismatch; wrong key ID; nonce/AAD mismatch |
| CloudWatch empty | Publisher redaction/permissions; cloud not on the block path anyway |
