# TESTING: AI-Driven SDN Threat Isolation

## Verification results

Run date 2026-11-20, macOS 15.4.1 arm64, disposable project copy.

| Check | Result |
|---|---|
| Standard-library tests, Python 3.13.7 | 31 passed, 0 skipped, 0 failed. Includes eight console simulation and API tests and seven alert pipeline tests. |
| Full pytest suite, Python 3.13.7 | Collection could not start because pytest was unavailable. |
| Stage 3 replay, Python 3.13.7 | The real daemon processed a synthetic EVE record and the verifier checked the audit trail and exact rule readback using a simulated `ovs-ofctl` command. |
| Synthetic training, Python 3.13.7 | XGBoost, Isolation Forest, and Bi-LSTM produced model artifacts in a disposable copy. The summary identified the synthetic dataset and labeled macro F1 and anomaly F1 separately. |
| Stage 4, Python 3.13.7 | All four checks passed with trained synthetic models. The six SHAP values and baseline reconstructed the predicted class margin. |
| Stage 5, Python 3.12.13 and 3.14.8 | All four checks passed in eight consecutive runs with cryptography 50.0.2 on 3.12.13 and in a separate run with cryptography 46.0.6 on 3.14.8. The Python 3.13.7 runner could not import cryptography. |
| Stage 6, Python 3.13.7 | Three of four checks passed: polling, backpressure, and SQLite reconciliation. XGBoost returned a prediction and timing in the fourth check, which could not seal evidence without cryptography. |
| Prediction evidence round trip | A real XGBoost prediction from Python 3.13.7 was sealed and verified on Python 3.12.13. Decryption recovered the exact payload, and the authentication tag, hash, and signature all verified. The single-interpreter Stage 6 check remains pending. |
| Console backend, Python 3.13.7 | In-process HTTP requests confirmed both SQLite states, all four simulations, three release-model predictions for the example flow, and HTTP 400 for missing, negative, and fractional packet counts. The populated fixture was unchanged. |
| Standalone browser preview | Verified the desktop 3D topology and component details, sample activity, workload burst and steady-load results, and three recorded model predictions in Brave. |
| Simulation rendering | With a simulated DOM, slow-switch replay drew both chart series and showed backoff followed by baseline. Counter-restart replay drew both series and showed a missing rate at reset followed by recovery for both strategies. |
| Topology fallback | A JavaScript smoke check simulated an unavailable Three.js import and confirmed that rotate, drag, reset, and component selection update the properties used by the diagram. |
| Live browser session | Pending. The shell could not bind the loopback listener. |
| Live Linux lab | Pending. This session could not reach the local virtualization daemons. Live latency, false blocks, and service impact are unmeasured. |

On 2026-11-21, the redesigned standalone export passed a simulated-DOM check for navigation, audit filtering and refresh, fallback topology selection and drag, all four replay summaries and charts, strategy filtering, and recorded predictions.

The audit and playback update passed 33 standard-library tests. An in-process HTTP check confirmed that the next overview response included a newly committed SQLite event. Simulated browser checks covered timed refresh, stale data and recovery, all three chart metrics, play, pause, seek, and the gap at a counter reset. Brave displayed the sample audit timeline and source breakdown.

The Live lab update passed 39 standard-library tests on macOS. Offline fixtures exercised capture-header parsing, bounded history, controller association, and Ryu reconnect cleanup. In-process HTTP and simulated browser checks confirmed service states, packet rates, recent headers, and collector disconnect handling. The Linux packet socket and live Ryu, Mininet, Open vSwitch, and Suricata checks remain pending because the virtualization sockets were inaccessible.

After separating the service and capture paths, 42 standard-library tests passed. Fixtures verified nonblocking service checks, wall-clock jumps, duplicate and missing reports, and malformed headers. A simulated browser check verified independent polling, packet display pause and resume, graph gaps, and cancellation when leaving Live lab.

The earlier replay-based 3D server room passed 41 browser checks covering all four workloads, playback controls, reduced motion, connection errors and recovery, and collector fixtures on all three switch ports. Layout checks covered widths from 320 to 1280 pixels. A second browser test exercised 20 orbit positions at each of six widths and selected all five racks. It reproduced a protected-server roof obscured by the sticky header at 900 pixels. All 37 checks passed after the scroll-offset fix.

Across two timed runs, all 325 in-process responses from the scenario catalog and four workload endpoints matched the exported preview. An eight-worker run also returned consistent results for 120 concurrent workload requests.

The standard-library suite passed 46 tests, including four checks of the Claude traffic verifier. These cover duplicate capture snapshots, disabled forwarding to Claude when the collector is stopped or monitoring another port, aggregate-only message content, and redaction of malformed credential values. Live Mininet capture and an actual Anthropic response still require the [connected lab procedure](SETUP.md#test-haiku-with-protected-server-traffic).

The continuous traffic model passed four Node tests covering sustained input, queue limits, destination changes and frame-independent packet accounting. A controlled-clock browser run passed 15 checks, including bursts, two destinations, queue overflow and drainage, navigation, capture switching and a 36-second uninterrupted simulation interval. Run the model checks with `node --test tests/room_traffic.test.cjs`.

## Priorities (critical first)
1. Enforcement correctness and rollback. 2. No fake outcomes (requested != blocked). 3. Safe failure modes. 4. Timing measurements. 5. Detection quality. 6. Evidence integrity.

## Test cases per feature
### Access gateway
| Scenario | Input | Expected |
|---|---|---|
| Unauthorized SSH | TCP 22 from ordinary device | Denied; absent from OVS counters; gateway event logged |
| Authorized HTTPS | TCP 443 from permitted source | Allowed |
| Rate limit | Burst above tested baseline | Limited, service remains available |
### Telemetry/features
| Scenario | Input | Expected |
|---|---|---|
| Worked example | 1,000/80,000 at t1; 1,300/104,000 at t2 (0.5 s) | 600 pkt/s, 48,000 B/s |
| Counter reset | Switch restart | Sample flagged invalid, no negative rate |
| Missing sample | Skipped poll | Uses actual elapsed time or marks gap |
### Enforcement
| Scenario | Input | Expected |
|---|---|---|
| Scoped DROP | Valid action | Rule with cookie/timeout; effect verified |
| Duplicate request | Same action_id | No duplicate rule (409/idempotent) |
| Too-broad scope | Source-IP only on shared address | 422 rejected/escalated |
| Rollback | Operator request | Exact rule removed; restoration verified |
| Controller restart | Active rule | Reconcile; no unlimited duplicates |
### Suricata + listener
| Scenario | Input | Expected |
|---|---|---|
| Inline drop | Matching traffic | Dropped; EVE alert; separate event types |
| Non-alert EVE records | flow/protocol records | Not treated as block requests |
| Malformed/rotated log | Bad line; rotation | Skipped; read position kept |
| Alert storm | Repeated identical alerts | Deduplicated; bounded queue |
| NAT / response packet | Subject ambiguous | Escalate, no blind block |
### AI/risk (V2)
| Scenario | Input | Expected |
|---|---|---|
| Feature parity | Train vs live features | Identical definitions/scaling/window |
| No future leakage | Time-split data | Evaluation uses only past observations |
| AI unavailable | Service down | Marked unavailable, no fabricated score |
| Outlier only | Isolation Forest hit | Monitor/limit, not broad quarantine |
### Evidence (V2)
| Scenario | Input | Expected |
|---|---|---|
| Seal and verify | Valid bundle | All checks pass |
| Tamper | Modified ciphertext/record | Verification fails and reports where |
| Nonce reuse guard | Two encryptions | Distinct nonces |
| Cloud outage | S3 down | Spooled, later delivered once |

## Negative and failure tests (one at a time, then combinations)
Suricata stop (verify chosen fail policy and no accidental uninspected route), Ryu disconnect (baseline policy, no silent unrestricted forwarding), AI timeout, disk full (loss recorded), clock skew, replayed/expired action request, unauthorized API call (401/403).

## Evaluation experiments
Compare: baseline OVS+Ryu+periodic AI -> +access rules -> +inline Suricata -> +adaptive polling. Same topology/workloads. Repeat across attack-start phases relative to the poll cycle. Report four latencies (median + tail), traffic reaching target, precision/recall/false positives, false blocks, throughput, CPU/RAM, audit loss. The "<15 ms" claim stays unverified until timestamped data supports a defined boundary.

## Data and mocking
Isolated lab, disposable targets, bounded rates. Use documentation IPs (192.0.2.x, 198.51.100.x). Mock S3/CloudWatch with stubs; replay recorded EVE lines for the listener.

## Coverage targets
Every decision-table row in the risk engine has a test; every lifecycle state transition tested; every failure row in the PDF's section 17 exercised.

## Offline commands

Prepare the test environment and synthetic artifacts using the [offline setup](SETUP.md#run-the-offline-verification-suite).

```bash
# Run the offline unit tests and Stage 4–6 verifiers.
.venv/bin/python experiments/run_all_tests.py

# Run the unit test suite on its own.
.venv/bin/python -m pytest tests/
```

## Browser checks

At a 900-pixel viewport width, scroll the 3D room into view, select the protected server roof and confirm **Inspect device** shows **Protected server**. Orbit through a full revolution using the arrow controls, reset the view, and repeat at phone width. Use **Simulations** for generated traffic and **Live lab** for switch capture. Only fresh collector reports should light the observed link. A paused or disconnected collector should retain its last measurements and clear the active link.

Start the [console](SETUP.md#run-the-local-console) with `--database` pointing to an absent file and check the waiting state. Restart with a populated test copy, then check the counts, incident rows, recent activity, and **Refresh**.

- In **Overview**, select a topology component from the map and from its button, then rotate, drag, and reset the view. Check the same controls with the interactive diagram when Three.js is unavailable.
- With the backend running against a disposable audit store, append an event and confirm that the timeline and source count update on the next automatic refresh.
- Run all four simulations and inspect the summary, totals, chart, and **Poll by poll** table. Filter the table by strategy. Look for surge and cooldown, matching steady-load results, slow-switch backoff, and a missing rate followed by recovery at counter reset.
- Switch the chart between polling interval, packet rate, and reply latency. Confirm that the packet-rate trace breaks at a counter reset.
- Wait for all three release models, select **Use example**, and check all three results. Submit with a missing, negative, or fractional count and confirm that the form prevents each submission.
- Use the keyboard to navigate sections and controls at desktop and narrow viewport widths. Check the chart, scrollable table, and browser console.

## Live Linux lab

From the project root in the [isolated Linux VM](SETUP.md#run-the-live-sdn-lab), start the Ryu controller and the project topology. Use a disposable spool for the verifiers.

Run the [packet capture smoke check](SETUP.md#watch-live-packet-headers) with the observer bound to `s1-eth1`. Confirm that the port and controller association match the lab and that the UI records the known ICMP exchange. Stop the collector and confirm that the console displays the disconnect and retains the last received headers.

Pause the packet display while the collector receives lab traffic. Confirm that the table remains stable, service check timestamps advance independently, and resuming displays the latest retained interval and headers.

```bash
sudo bash experiments/verify_stage1.sh
sudo python3 experiments/verify_stage2_runner.py
sudo python3 experiments/verify_stage3.py
```

Stage 3 replays a synthetic EVE record and checks the exact cookie, match, priority, and timeout in the switch readback. Its audit check covers the linked alert, decision, request, and `rule_processed` state. Confirm inline inspection, the rule's effect, expiry, and rollback with independent packet or counter evidence in the isolated lab.

For restart recovery, verify that the reconciler restores a missing active rule only when the switch responds and the audit trail contains the approved match. Confirm that the restored rule uses the remaining lifetime. Older records without a saved match require operator review.

## Manual QA checklist
- [ ] Allowed/denied paths verified
- [ ] Rule scope, cookie, expiry visible in `dump-flows`
- [ ] Rollback works
- [ ] Failure policies behave as decided
- [ ] No cloud dependency on the local block path
- [ ] Evidence verifies; tamper detected
- [ ] No secrets or captures with credentials committed
