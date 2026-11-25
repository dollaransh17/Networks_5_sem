# SDN Threat Isolation Handoff

The local operator console passed in-process backend checks and the standalone preview passed desktop checks in Brave. The remaining work is to run the full offline suite with pytest and cryptography, verify the live console in a browser, and verify the defensive workflows in an isolated Linux lab.

## Latest repairs and verification

- The console now uses an amber circuit-board theme. Live lab shows the configured switch path and highlights the selected port while capture reports arrive. The regenerated standalone preview displayed the new layout in Brave. A simulated browser check covered all three ports, pause and resume, stale reports, and the restart message when the script is missing.
- The running process on port 5174 returned 404 for `/live_lab.js`. The current backend served the script and both Live lab endpoints in process. Restart the existing backend to load the current routes. This session could not bind a replacement loopback listener or connect to the Linux virtualization daemons.
- On macOS 15.4.1 arm64, 31 standard-library tests passed. Stage 4 passed all four checks with synthetic models. XGBoost's built-in TreeSHAP produced six contributions that reconstructed the predicted class margin.
- The EVE daemon handles rotation and partial lines, rejects malformed data, and monitors ambiguous direction. It links the alert, decision, and actual requested match. The Stage 3 verifier passed through the real daemon and SQLite with a simulated switch command. The daemon records `rule_processed` on successful installation. The live recheck still needs independent dataplane evidence for the effect.
- The topology now explicitly configures OpenFlow 1.3 on the switch and gives the server and quarantine namespaces on-link routes to the lab gateway. The reconciler uses the exact approved match and remaining lifetime to restore rules. These paths still need verification in Linux with real OVS.
- Stage 5 passed eight consecutive standalone runs in Python 3.12.13 with cryptography 50.0.2 after correcting the tamper fixture to flip a decoded ciphertext byte. Stage 6 passed the polling, backpressure, and SQLite checks and returned a real inference timing. The combined check still needs cryptography in the model environment. PyPI access and local socket access were denied.
- Fresh synthetic training produced artifacts for all three models in a disposable copy and printed the dataset and F1 type in the evaluation summary. A real XGBoost prediction from Python 3.13.7 passed sealing and verification in Python 3.12.13 and decrypted to the original payload. Stage 5 also passed on Python 3.14.8 with cryptography 46.0.6.
- The standalone export includes the latest topology, four simulations, and three recorded model predictions. Brave showed the 3D topology, component details, workload burst and steady-load results, and example flow results. A JavaScript smoke check exercised the fallback diagram controls with Three.js unavailable.
- A simulated-DOM check verified chart updates and detail rows for slow-switch backoff and counter-restart recovery. The remaining desktop and narrow-viewport checks still need a browser session.

## Verified before the continuation

| Area | Result |
| --- | --- |
| Automated tests | 24 `unittest` cases passed, including all eight simulation and simulation API tests. |
| Console backend | In-process request checks passed for the static assets, health, four simulations, flow validation, and the SQLite overview. The overview correctly handled an absent database and read a populated test database without modifying it. |
| Flow check | All three bundled models loaded and returned predictions for the example flow. |
| Frontend | A JavaScript smoke test exercised navigation, scenario selection and retry, chart updates, and flow submission using a simulated DOM and recorded API responses. |
| Stage 4 | XGBoost and Isolation Forest model loading, inference, and risk corroboration passed after training temporary synthetic models. The SHAP spool check was blocked by the missing `shap` package. |
| Stage 5 | All four checks passed using an available Python runtime with `cryptography`, including ciphertext tamper and missing-bundle detection. |
| Stage 6 | Polling, backpressure, and SQLite reconciliation passed. The verifier now fails its inference check when XGBoost returns no prediction or timing. Missing-model, missing-prediction, and successful-return cases were checked. The successful-return case used a stub. |

The console's loopback socket could not bind in this session. Access to the Docker and Multipass sockets was also denied.

## 1. Finish offline verification

Use a disposable project copy with Python 3.11–3.13 and package access. Stage 4 writes synthetic risk decisions to the local audit spool. The command below generates the model files expected by the Stage 4 and Stage 6 verifiers. The bundled console model files are listed separately in the [setup guide](SETUP.md#enable-flow-checks).

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt pytest cryptography
.venv/bin/python experiments/train_models.py --synthetic --samples 1000 --no-bilstm
.venv/bin/python experiments/run_all_tests.py
```

- [ ] Confirm pytest exits successfully and record the actual number of passed, skipped, and failed tests.
- [x] Confirm Stage 4 produces a SHAP explanation in its test spool and passes all four checks.
- [ ] Confirm Stage 5 passes in the same environment used by the full runner.
- [ ] Confirm Stage 6 passes as an integrated run with the trained model and the cryptography dependency. The standalone XGBoost prediction and its timing are recorded above.

## 2. Verify the console in a browser

From the project root on a machine that permits loopback listeners, start the backend with `.venv/bin/python -m backend.server` and open `http://127.0.0.1:8080`.

- [ ] In **Overview**, check the waiting state with an absent database. Restart with `--database` pointed at a populated test copy and verify counts, incident rows, recent events, and **Refresh**.
- [ ] In **Simulations**, run Workload burst, Steady load, Slow switch, and Counter restart. Check the chart, totals, and **Poll by poll** table. Look for surge and cooldown during the burst, matching results under steady load, backoff on slow replies, and a missing rate at the counter reset followed by recovery.
- [ ] In **Flow check**, wait for model readiness, select **Use example**, and submit. Confirm three model results and verify that missing, negative, or fractional count inputs are rejected as appropriate.
- [ ] Check navigation, keyboard access, and chart and table readability at desktop and narrow viewport widths. Record any browser console errors.

## 3. Recheck the live defensive workflows

Use an isolated Linux VM with Mininet, OVS, Suricata, iptables, and the separate Ryu environment. Follow the project setup and use controlled lab fixtures or recorded EVE events for detection checks. [Setup guide](SETUP.md#run-the-live-sdn-lab), [test matrix](TESTING.md).

- [ ] Verify allowed and denied gateway paths with controlled policy probes. Confirm the deny is logged at the gateway and does not reach the downstream switch.
- [ ] Verify OpenFlow 1.3 connectivity and telemetry using known counter samples. Confirm rates use actual elapsed time and recover after a counter reset.
- [ ] Verify an approved temporary rule has the expected scope, cookie, priority, and timeout. Confirm rule installation, observed effect, expiry, rollback, and reconciliation after controller restart.
- [ ] Verify Suricata EVE ingestion, deduplication, and audit recording. Confirm the timeline identifies each source and records the requested, installed, and observed stages of enforcement.
- [ ] Verify the agreed behavior during a sensor outage, controller disconnect, AI unavailability, and slow switch replies. Record any lost coverage and confirm recovery.
- [ ] Record software versions and observed results, including latency boundaries, false blocks, and service impact. Use timestamped results for any end-to-end latency claim.

## 4. Close out the documentation

- [x] Replace stale counts and record the currently verified results in [README.md](README.md), [SETUP.md](SETUP.md), [TESTING.md](TESTING.md), and the labels in [experiments/run_all_tests.py](experiments/run_all_tests.py).
- [x] Document which model artifacts the console and offline verifiers use and how to start the live lab.
- [ ] Update the results and validate the setup commands when the full offline, browser, and Linux lab checks finish.

## Recorded roadmap items

- S3 versioning and Object Lock and CloudWatch summaries are deferred in the local-first plan. [PLAN.md](PLAN.md#phase-5-audit-and-cloud-stage-5).
- The proposed management API still needs an authentication decision. The live Suricata fail mode also needs a recorded decision before any deployment relies on it. [API.md](API.md#proposed-management-api), [ARCHITECTURE.md](ARCHITECTURE.md).
