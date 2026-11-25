# PRD: AI-Driven SDN Threat Isolation

**Status:** Draft v1 · **Date:** 8 November 2026
**Source:** `SDN_Threat_Isolation_Detailed_Architecture.pdf` (5 Nov 2026, "Team handoff"). Tags: [P1] original slides, [P2] earlier handoff, [C] chat discussion. Items not in that PDF are marked *(assumption)*.
**Honest status:** the PDF is a design specification. Access-control/Suricata integration, adaptive polling and the combined logger are *proposals*; no code, running configuration or measurements exist yet.

## 1. Problem statement
Harmful traffic often reaches a target before it is noticed, and containment takes too long. The project does not claim to predict every attack. It aims to **reduce harmful traffic reaching the target and shorten time to containment** by combining: least-privilege access control, inline inspection (Suricata), behaviour analysis of OVS counters (XGBoost, Bi-LSTM, Isolation Forest), one risk-controlled Ryu-to-OVS enforcement interface, and an independent tamper-evident evidence pipeline.

Main rule: *prevent locally, detect through two complementary paths, enforce through one risk-controlled Ryu-to-OVS interface, send evidence to the cloud separately.*

## 2. Target users
| Persona | Need | Success looks like |
|---|---|---|
| **Dev, network security engineer (lab operator)** | Run and tune the stack; roll back wrong blocks | Scoped, expiring rules with a one-step rollback |
| **Priya, incident responder / auditor** | Reconstruct what happened and trust the record | Linked incident timeline; sealed bundle verifies |
| **Dr. Rao, researcher / evaluator** | Show an experimentally supported reduction in exposure | Reproducible runs with timestamped containment data |

## 3. Goals
- G1: Deny unauthorized connections early (default deny, rate limits) at an access gateway.
- G2: Inspect permitted traffic with inline Suricata; keep EVE alerts flowing to a risk engine.
- G3: Read OVS counters via Ryu; compute rate features from counter differences.
- G4: Enforce only approved, scoped, expiring OpenFlow actions; verify their effect.
- G5: Preserve verifiable incident evidence (hash chain, ECDSA, AES-256-GCM, S3 Object Lock).
- G6: Keep local protection independent of cloud availability.
- G7: Measure detection, decision, enforcement and end-to-end containment latency separately.

## 4. Non-goals
- Universal or zero-day protection claims; novelty claims from combining existing tools.
- Claims of hardware TCAM or wire-speed performance from a Mininet/OVS setup.
- Decrypting encrypted payloads; replacing Wireshark/ClamAV roles.
- Running both Ryu and ONOS on one switch (Ryu chosen for the concrete path).
- Production deployment; the target is an **isolated, authorized lab**.
- Treating the "under 15 ms" slide claim as true before timestamped experiments.

## 5. Features
### MVP (must-have): build stages 1-3 plus local logging
1. **Lab topology + access policy:** Mininet/OVS with gateway rules (default deny) verified for allowed and denied paths.
2. **OVS + Ryu telemetry:** 2 s FlowStatsRequest polling; counter-difference features using actual elapsed time; handle resets/restarts.
3. **Scoped enforcement:** FLOW_MOD DROP with cookie, priority, timeout; barrier + readback + counter verification; manual rollback.
4. **Suricata inline + EVE alert listener:** read, normalize, validate, deduplicate; submit to the risk engine.
5. **Risk policy engine (rule-based):** approves narrow, expiring actions; escalates ambiguous cases.
6. **Local incident logger:** append-only events with the action lifecycle (decision_created -> ... -> action_expired_or_reverted).

### V2 (should-have)
- Three-model AI: XGBoost (known patterns), Bi-LSTM (sequences), Isolation Forest (baseline deviation), with a frozen feature contract.
- Asynchronous SHAP/LIME explanation worker attached to the same incident.
- Adaptive polling (500 ms test configuration for a narrowed suspicious set).
- Crypto sealer (SHA-256 chain, ECDSA, AES-256-GCM), S3 Object Lock, verification worker.
- CloudWatch summaries/metrics and alarms.
- VLAN 999 quarantine with its own restrictive forwarding policy.

### Later (nice-to-have)
SageMaker training/registry/deployment with rollback; ClamAV at a file-upload boundary; Wireshark capture automation for validation; persistence/reconciliation across controller restarts; segmentation/inspection steering for internal OVS traffic.

*Open question: "AI-driven" is in the title, but the MVP above is not yet AI-driven (the PDF's build order puts AI at stage 4). Decide whether to move XGBoost into the MVP.*

## 6. User stories
- As Dev, I want a scoped DROP rule with an expiry, so that a wrong block fixes itself.
- As Dev, I want one-step rollback, so that an incorrect quarantine is quickly undone.
- As Dev, I want Suricata alerts to reach the risk engine without waiting for the next poll, so that response is faster.
- As Priya, I want a linked incident timeline, so that I can see decision, request, acceptance, effect and expiry.
- As Priya, I want sealed evidence that I can verify, so that I can detect later tampering.
- As Priya, I want separate records for an alert, a drop and a quarantine, so that outcomes are not confused.
- As Dr. Rao, I want four separate latency measurements, so that I can state exactly what improved.
- As Dr. Rao, I want comparable configurations (baseline, +access rules, +Suricata, +adaptive polling), so that each addition's contribution is isolated.

## 7. Key user flows
**A: Unauthorized SSH.** Device hits TCP 22 -> gateway denies -> never reaches OVS -> gateway event logged.
**B: Recognizable threat on an allowed service.** Passes gateway -> inline Suricata drops + writes EVE -> listener validates subject -> risk engine approves temporary OVS rule -> Ryu FLOW_MOD + barrier/readback -> logger appends events.
**C: Suspicious behaviour (V2).** OVS counters -> Ryu polling -> features -> models -> risk engine chooses monitor / rate limit / quarantine -> Ryu enforces -> verification -> detailed explanation attached later.
**D: Rollback.** Operator removes the exact rule by cookie/action ID -> restoration verified -> event appended.

## 8. Success metrics
No target numbers are set because nothing is measured yet *(do not invent them)*. Report: detection / decision / enforcement / end-to-end latency (median and tail); attack traffic reaching target before containment; precision, recall, false positives on realistic normal traffic; false blocks and incorrect-quarantine duration; legitimate throughput/latency/loss; CPU/RAM, queue depth, OpenFlow bytes; audit duplicates/losses and verification failures.

## 9. Risks, assumptions, open questions
**Risks:** broad source-IP blocks hitting shared addresses; NAT hiding the real subject; encrypted payloads invisible to Suricata; internal OVS traffic bypassing the gateway/IPS; polling backlog slowing response; feature mismatch between training and live data; leaked captures containing credentials.
**Assumptions:** isolated Linux/Mininet lab; 16 GB RAM prototype host (not a capacity guarantee); one switch per Ryu path.
**Open questions & resolution:** fail-closed vs fail-open for Suricata; enforcement endpoint and authentication choice; Bi-LSTM resolved using PyTorch; decision-time features frozen to 6-contract metrics; InSDN and CNS 2022 column mappings resolved; S3 retention mode and period.
