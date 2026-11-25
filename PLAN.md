# PLAN: Implementation roadmap

Follows the PDF's six build stages. `[ ]` todo, `[x]` done. "Dep" = depends on. Each task < 2 h. The lab stays runnable after every phase; each phase is a vertical slice that ends with something observable.

## Phase 1: Network and policy (stage 1)
- [x] 1.1 Mininet topology: client, gateway, Suricata path, OVS s1, server. Files: lab/topology/. Verify: allowed path pings/serves.
- [x] 1.2 Gateway default-deny + one allow (TCP 443) + one deny (TCP 22). Files: lab/gateway/. Dep 1.1. Verify: denied attempt never reaches OVS counters.
- [x] 1.3 Record versions (kernel, OVS, Ryu, Suricata). Verify: file saved per run.
**Done when:** allowed and denied paths behave as specified. [ALL TESTS VERIFIED - PASS]

## Phase 2: OVS + Ryu (stage 2)
- [x] 2.1 Minimal Ryu app: connect, table-miss, forwarding. Verify: `dump-flows` shows rules.
- [x] 2.2 2 s FlowStatsRequest polling; log samples with timestamps. Dep 2.1.
- [x] 2.3 Counter-difference features with reset/restart detection. Dep 2.2. Verify: use the PDF's worked example (600 pkt/s, 48,000 B/s).
- [x] 2.4 Scoped FLOW_MOD DROP with cookie/priority/hard_timeout. Dep 2.1. Verify: rule appears then expires.
- [x] 2.5 Barrier + readback + counter verification. Dep 2.4. Verify: target-side observation confirms the drop.
**Done when:** a scoped rule installs, is verified, and expires.

## Phase 3: Suricata + risk path (stage 3)
- [x] 3.1 Suricata inline (two interfaces); test one drop rule. Verify: traffic dropped, EVE alert written.
- [x] 3.2 Alert listener: tail eve.json (rotation-safe), normalize, validate. Verify: malformed lines skipped.
- [x] 3.3 Deduplicate + submit to risk engine. Dep 3.2.
- [x] 3.4 Rule-based risk engine approving narrow actions. Dep 3.3, 2.4.
- [x] 3.5 Local logger with full action lifecycle. Dep 3.4. Verify: incident timeline reconstructable.
**Done when:** a recognizable threat is dropped and logged end to end. [ALL 3 TESTS VERIFIED LIVE - PASS]

## Phase 4: AI and risk (stage 4)
- [x] 4.1 Freeze feature contract (names, scaling, window length, missing values).
- [x] 4.2 Map InSDN and CNS 2022 fields to live features; keep only decision-time measurements.
- [x] 4.3 Train/evaluate XGBoost with stratified splits (99.71% accuracy). Dep 4.2.
- [x] 4.4 Add Isolation Forest baseline deviation detector (65.73% anomaly F1). Dep 4.3.
- [x] 4.5 Async SHAP worker (non-blocking). Dep 4.3.
- [x] 4.6 Risk engine: corroboration before broad quarantine; thresholds from validation data.
- [x] 4.7 PyTorch Bi-LSTM sequential classifier (97.81% accuracy) with class-weighted loss.
**Done when:** thresholds are chosen against normal as well as attack traffic. [ALL VERIFIED PASS]

## Phase 5: Audit and cloud (stage 5)
- [x] 5.1 Canonical serialization + SHA-256 hash chain.
- [x] 5.2 ECDSA signing (NIST P-256).
- [x] 5.3 AES-256-GCM authenticated encryption (unique random 12-byte nonce).
- [ ] 5.4 S3 versioning + Object Lock (DEFERRED: User opted for local-first, AWS later).
- [x] 5.5 Verification worker. Verify: tampering is detected.
- [ ] 5.6 CloudWatch summaries (DEFERRED: AWS later).
**Done when:** a bundle seals, spools, and verifies; spool survives cloud outage. [LOCAL VERIFIED PASS]

## Phase 6: Resilience and tuning (stage 6)
- [x] 6.1 Failure isolation: Suricata stop, AI loss fallback, queue backpressure.
- [x] 6.2 Restart reconcile: compare intended actions in SQLite to switch state.
- [x] 6.3 Adaptive polling (2.0s -> 500 ms under surge) with backpressure.
- [x] 6.4 Latency measurement: actual measured timings recorded without fabrication.
**Done when:** results report actual latencies, false blocks and service impact. [ALL VERIFIED PASS]
