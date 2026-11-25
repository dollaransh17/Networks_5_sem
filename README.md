# AI-Driven SDN Threat Isolation

An autonomous, multi-layered threat detection and isolation system inside an OpenFlow 1.3 Software-Defined Network (SDN). Combines edge access control, inline Deep Packet Inspection (Suricata), behavioral AI (XGBoost, Isolation Forest, SHAP), dynamic OpenFlow mitigation (Ryu), and tamper-evident cryptographic evidence sealing (SHA-256 hash chain, ECDSA, AES-256-GCM).

> **Verification status (2026-11-20):** 31 standard-library tests passed on macOS, along with all four Stage 4 and standalone Stage 5 checks. The full offline suite, browser session, and live Linux lab have outstanding checks. See [TESTING.md](TESTING.md#verification-results).

---

## Architecture Overview

```
                 ┌─────────────────────────────────────────────────────────────────┐
                 │                     Isolated Lab Network                        │
                 │                                                                 │
  Attacker/      │   ┌──────────┐   ┌────────────┐   ┌──────────────────────┐    │
  Client         │   │  Access  │   │  Suricata  │   │   OVS Switch (s1)    │    │
  192.0.2.10 ───►│──►│ Gateway  │──►│  Inline    │──►│   OpenFlow 1.3       │    │
                 │   │iptables  │   │  IPS/IDS   │   │   cookie + TTL rules │    │
                 │   │ deny/443 │   │  AF_PACKET │   └──────────┬─────┬─────┘    │
                 │   └──────────┘   └─────┬──────┘             │     │           │
                 │                        │ EVE alerts          │     │           │
                 │                        ▼                     ▼     ▼           │
                 │                ┌────────────────┐    ┌─────────┐ ┌─────────┐  │
                 │                │ Alert Listener │    │  Server │ │  Quar.  │  │
                 │                │   + Daemon     │    │198.51.. │ │ VLAN999 │  │
                 │                └───────┬────────┘    └─────────┘ └─────────┘  │
                 │                        │                                       │
                 │                        ▼                                       │
                 │                ┌────────────────┐    ┌────────────────────┐   │
                 │                │  Risk Policy   │◄───│   AI Engine        │   │
                 │                │  Engine (p1/p2)│    │ XGBoost+IForest    │   │
                 │                └───────┬────────┘    │ SHAP Explainer     │   │
                 │                        │             └──────────▲──────────┘   │
                 │                        │                        │               │
                 │                        ▼                        │               │
                 │                ┌────────────────┐    ┌──────────┴──────────┐   │
                 │                │  Ryu OF1.3     │───►│ Adaptive Poller     │   │
                 │                │  FLOW_MOD DROP │    │ 2.0s baseline       │   │
                 │                │  cookie+timeout│    │ 0.5s surge mode     │   │
                 │                └───────┬────────┘    └─────────────────────┘   │
                 │                        │                                        │
                 │                        ▼                                        │
                 │                ┌────────────────────────────────────────────┐  │
                 │                │  Evidence Sealer                           │  │
                 │                │  SHA-256 hash chain · ECDSA P-256          │  │
                 │                │  AES-256-GCM · SQLite incident_store.db    │  │
                 │                └────────────────────────────────────────────┘  │
                 └─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Status

| Phase | Description | Status | Tests |
|---|---|---|---|
| **Phase 1** | Mininet Topology & iptables Access Gateway | Live recheck pending | `verify_stage1.sh` |
| **Phase 2** | Ryu OF1.3 Telemetry & Scoped FLOW_MOD | Live recheck pending | `verify_stage2_runner.py` |
| **Phase 3** | Suricata EVE → Risk Engine → SQLite Logger | Replay and audit checks passed with a simulated switch. Live recheck pending. | `verify_stage3.py` |
| **Phase 4** | XGBoost + Isolation Forest + SHAP Corroboration | 4 of 4 offline checks passed, including SHAP. | `verify_stage4.py` |
| **Phase 5** | SHA-256 Chain + ECDSA + AES-256-GCM Sealing | 4 of 4 standalone offline checks passed | `verify_stage5.py` |
| **Phase 6** | Adaptive Polling + Switch Reconciler | 3 of 4 checks passed. Evidence sealing in the combined check requires cryptography. | `verify_stage6.py` |
| **System Evaluation** | Multi-Model Benchmark (XGBoost, Bi-LSTM, IForest) on DistriNet CNS 2022 | ✅ **Benchmark Complete** | `docs/SYSTEM_EVALUATION.md` |
| **Google Colab** | 1-Click Research Notebook with Zero-Download Ingestion | ✅ **Ready** | `notebooks/SDN_Threat_Isolation_Research_Colab.ipynb` |
| **Unit Tests** | Component and console simulation tests | 31 standard-library tests passed. Full pytest run pending. | `pytest tests/` |

---

## Research Paper & Google Colab Training

### Benchmark Datasets (DistriNet IEEE CNS 2022)
This research is evaluated on the corrected, improved NIDS benchmark datasets published at IEEE CNS 2022 by DistriNet, KU Leuven:
- **Dataset 1:** [DistriNet CNS 2022 Dataset Download Portal](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html)
- **Dataset 2:** [DistriNet CSE-CIC-IDS-2018 Cleaned Specifications](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html)
- **Direct Archives:** `CICIDS2017_improved.zip` (328 MB) and `CSECICIDS2018_improved.zip` (9.7 GB).

### Robust Dataset Preprocessing & Stratified Sampling Strategy
To guarantee unbiased evaluation and state-of-the-art classifier convergence:
1. **Stratified Sampling:** Eliminates chronological distribution shift by ensuring proportional class representation across both train and test partitions.
2. **CNS 2022 'Attempted' Label Sanitization:** Flows marked with `- Attempted` (failed non-malicious attempts) are mapped to `benign` per DistriNet guidelines to prevent decision boundary corruption.
3. **Feature Column Harmonization:** Resolves all CICFlowMeter header variations (`Pkt Len Mean`, `Tot Fwd Pkts`) ensuring all 6 contract metrics are fully populated.
4. **Recurrent Feature Normalization:** Applies robust Z-score standardization (`StandardScaler`) for stable Bi-LSTM gradient propagation.

### Running the Research Training Pipeline

#### Option A: 1-Click Google Colab (Recommended)
Open and run `notebooks/SDN_Threat_Isolation_Research_Colab.ipynb` in [Google Colab](https://colab.research.google.com).
It automatically:
- Streams and samples the DistriNet CNS 2022 dataset directly via HTTP (zero local download needed).
- Trains **XGBoost** (99.71% accuracy, 0.9973 F1), **PyTorch Bi-LSTM** (97.81% accuracy, 0.9792 F1), and **Isolation Forest** (65.73% anomaly F1).
- Generates publication-ready confusion matrices, ROC curves, and SHAP beeswarm plots.
- Exports a ready-to-copy LaTeX table (`paper_results_table.tex`) for Overleaf.
- Automatically exports serialized model weights (`.pkl`, `.pt`) and encoders.

#### Option B: Pretrained Model Binaries (GitHub Releases)
If you do not want to re-train from scratch, download pre-compiled model binaries (`xgboost_cns2022.pkl`, `bilstm_cns2022.pt`, `isolation_forest.pkl`, `scaler_and_encoder.pkl`) directly from:
- **[GitHub Release v1.0.0](https://github.com/ShreyanshuRaj06/SDN_Threat_Isolation_Research/releases/tag/v1.0.0)**

#### Option C: Headless Automated CLI
```bash
# Automatically downloads CNS2022 dataset and trains all 3 models:
python3 experiments/train_models.py --cns2022 --samples 100000

# Or run the dedicated Colab runner:
python3 experiments/colab_runner.py --cns2022 --samples 50000
```

---

## Features

### Access Control Layer (Phase 1)
- **Default-Deny Gateway:** `iptables` FORWARD chain denies all traffic by default.
- **Rate-limited TCP 443:** Max 50 connections/sec with burst 100.
- **Explicit TCP 22 logging:** `GATEWAY_DENY:` prefix for forensic correlation.

### OVS Telemetry (Phase 2)
- **OpenFlow 1.3** L2 learning switch with table-miss controller punt.
- **Differential counter rates:** `packet_rate` and `byte_rate` over actual elapsed Δt — never a hardcoded interval.
- **Adaptive Polling:** 2.0s baseline accelerates to **500ms** on surge or AI anomaly detection; backpressure protection for switch RTT > 300ms.
- **Scoped mitigation rules:** Every FLOW_MOD carries a cookie, priority, ttl/hard_timeout — never blocking on `src_ip` alone.

### Threat Detection Pipeline (Phase 3)
- **Inline Suricata IPS:** AF_PACKET bridge intercepts threats before they hit the switch.
- **Custom rules:** `sid:1000001` (malicious payload → DROP), `sid:1000002` (port scan → quarantine).
- **Rotation-safe EVE tail:** Handles log rotation, truncation, and malformed JSON safely.
- **Deduplication:** Rolling-window burst dedup prevents event storms.

### Behavioral AI (Phase 4)
- **Frozen Feature Contract:** 6 metrics — `packet_rate`, `byte_rate`, `avg_packet_size`, `packet_count`, `byte_count`, `flow_duration_sec` — decision-time only, no future data leakage.
- **XGBoost Classifier:** 4-class threat model (`benign`, `dos`, `portscan`, `bruteforce`), 99.71% accuracy on CNS 2022 benchmark.
- **PyTorch Bi-LSTM:** 2-layer Bidirectional LSTM capturing directional sequential flow dynamics, 97.81% accuracy with class-weighted loss.
- **Isolation Forest:** Benign-only baseline anomaly detector with configurable contamination.
- **Async SHAP Explainer:** Background thread computes SHAP values without blocking enforcement.
- **Corroboration Rule:** Both XGBoost and Isolation Forest must agree before broad quarantine.

### Evidence Sealing (Phase 5)
- **Canonical serialization:** Sort-key deterministic JSON.
- **SHA-256 hash chaining:** `record_hash = SHA256(payload || prev_hash)`.
- **ECDSA P-256 signatures** per sealed bundle.
- **AES-256-GCM encryption:** Fresh 12-byte random nonce per bundle.
- **Tamper detection:** Authentication tag mismatch, hash forgery, and sequence gap — all automatically detected.

### Resilience (Phase 6)
- **Switch Reconciler:** On switch reconnect, compares SQLite intended state against actual installed flows — re-installs missing, marks expired.
- **Adaptive Poller:** 2.0s → 0.5s surge → 2.0s calm recovery with 3-cycle cooldown.
- **Controller Backpressure:** High switch RTT triggers throttling with lost-coverage logging.

---

## Tech Stack

| Component | Technology |
|---|---|
| Network Emulation | Mininet 2.3.0 |
| Software Switch | Open vSwitch (OVS) 3.3.9 |
| SDN Controller | Ryu 4.34 (OpenFlow 1.3) |
| Inline IPS | Suricata 7.0.3 (AF_PACKET) |
| Access Control | iptables 1.8.10 |
| AI Classification | XGBoost 2.1.4, scikit-learn 1.6.1 |
| Anomaly Detection | Isolation Forest (scikit-learn) |
| Explainability | SHAP 0.49.1 |
| Cryptography | cryptography 50.0.2 (ECDSA, AES-GCM) |
| Audit Store | SQLite + JSONL |
| Runtime | Python 3.9, eventlet 0.30.2 |

---

## Directory Structure

```
acnproject/
├── ai/
│   ├── explain/             # explainer.py — Async SHAP worker (non-blocking)
│   ├── features/            # counter_rates.py, feature_contract.py, insdn_mapper.py
│   └── models/              # xgboost_classifier.py, isolation_forest.py, *.pkl
├── audit/
│   ├── keys/                # Auto-generated ECDSA & AES keys (never hardcoded)
│   ├── logger/              # incident_logger.py — SQLite + JSONL append-only
│   ├── sealer/              # key_manager.py, sealer.py — SHA-256 chain, ECDSA, AES-GCM
│   ├── spool/               # incident_store.db, events.jsonl, sealed_bundles/
│   └── verifier/            # verifier.py — Full chain integrity verification
├── controller/
│   └── ryu_app/             # sdn_controller.py, enforcement_types.py,
│                            # adaptive_poller.py, reconciler.py
├── experiments/             # verify_stage*.py, run_all_tests.py, train_models.py
├── lab/
│   ├── gateway/             # setup_gateway.sh, test_gateway_policy.py
│   └── topology/            # mininet_topo.py
├── risk/
│   └── policy_engine/       # engine.py (Phase 3 rules), ai_engine.py (Phase 4 AI corroboration)
├── sensors/
│   ├── alert_listener/      # listener.py, daemon.py
│   └── suricata/            # local.rules, setup_suricata.sh
└── tests/                   # Unit tests and console simulation tests
```

---

## Quick Start

### Local operator console

Run `python3 -m backend.server` from the repository root and open **http://127.0.0.1:8080**. The console shows incidents and events from the local SQLite spool. Once the [release model dependencies](SETUP.md#enable-flow-checks) are installed, **Simulations → Custom traffic** evaluates a sample using the three pretrained models.

You can also export a standalone HTML preview with sample incidents, four polling simulations, and recorded example predictions when the release models are available. [Preview setup](SETUP.md#open-a-standalone-preview).

### Run the offline verification suite

From a disposable project copy, use the [offline verification setup](SETUP.md#run-the-offline-verification-suite) to install dependencies and train the two synthetic models. Run the master verifier from the project root.

```bash
.venv/bin/python experiments/run_all_tests.py
```

To train on a real InSDN CSV dataset:

```bash
.venv/bin/python experiments/train_models.py --dataset /path/to/InSDN.csv
```

### Live Mininet + Ryu Lab

Run the controller and project topology in separate terminals in an isolated Linux VM. [Lab setup](SETUP.md#run-the-live-sdn-lab), [live verification procedure](TESTING.md#live-linux-lab).

---

## Evidence Bundle Format

Each sealed bundle in `audit/spool/sealed_bundles/` stores:

```json
{
  "bundle_id": "bnd-6f8d2ecb6c65",
  "incident_id": "inc-stage5-001",
  "sequence": 1,
  "prev_hash": "0000...0000 (genesis)",
  "record_hash": "d57bfb740f049477...",
  "signature_hex": "3045022100...",
  "signing_key_id": "ecdsa-p256-local-01",
  "enc_alg": "AES-256-GCM",
  "nonce_b64": "<random 12-byte nonce, base64>",
  "tag_b64": "<16-byte auth tag, base64>",
  "ciphertext_b64": "<AES-GCM encrypted payload, base64>",
  "created_at": "2026-11-08T07:10:00Z"
}
```

Run the standalone evidence-sealing verifier with its temporary spool.

```bash
.venv/bin/python experiments/verify_stage5.py
```

---

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SDN_POLL_INTERVAL_S` | Baseline telemetry poll interval | `2.0` |
| `ACTION_DEFAULT_TTL_S` | Default OpenFlow rule hard timeout | `60` |
| `EVE_JSON_PATH` | Suricata EVE log path | `/var/log/suricata/eve.json` |
| `EVIDENCE_BUCKET` | S3 bucket for sealed bundles (deferred) | `sdn-evidence-lab` |
| `AWS_REGION` | AWS region (deferred) | `ap-south-1` |

---

## Rules & Constraints

- **Never hardcode secrets** — ECDSA and AES keys are auto-generated and loaded from `audit/keys/`.
- **Actual elapsed Δt** — All rate calculations use `curr.timestamp - prev.timestamp`, never hardcoded intervals.
- **Scoped rules only** — Every OpenFlow mitigation requires a cookie, priority, TTL, and at least one L4 match field beyond `src_ip`.
- **Full lifecycle recording** — `requested` ≠ `blocked`; every state transition is recorded in SQLite.
- **Never fabricate metrics** — Accuracy, latencies, and model scores come from actual evaluation; `None` when model unavailable.
- **Append-only evidence** — Sealed bundles are never updated; a linked event is added instead.
- **Isolated lab only** — Never run traffic against targets outside an authorized and isolated Mininet environment.

---

## Safety Note

This project runs entirely inside an isolated Mininet/OVS network. All hosts are virtual; no real external traffic is generated or intercepted. Packet captures may contain synthetic credential-like strings — control lab scope and clean up `/tmp/*.log` after sessions with `sudo mn -c`.

---

## Contributing

Read `AGENTS.md` before making changes. Label new ideas as "proposals" until implemented and measured. Keep functions small and commented where logic is subtle. Do not change the tech stack or database schema without updating `ARCHITECTURE.md` and `DATABASE.md`.
