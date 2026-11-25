# System Evaluation & Benchmark Report: AI-Augmented SDN Threat Isolation

**Scope:** Technical Evaluation of Rate Telemetry, Multi-Model Behavioral Detection, and Scoped OpenFlow Mitigation  
**Benchmark Suite:** DistriNet IEEE CNS 2022 Corrected NIDS Benchmarks (CIC-IDS-2017 & CSE-CIC-IDS-2018)  
**System Layer:** Access Gateway + Inline Suricata IPS + OVS/Ryu Controller + Multi-Model AI + Cryptographic Audit Spool  

---

## 1. System Overview and Defense-in-Depth Objectives

This technical report details the experimental evaluation and benchmark performance of the autonomous Software-Defined Networking (SDN) threat isolation pipeline. The system operates inside an OpenFlow 1.3 data plane to shorten time-to-containment while preventing collateral disruption through four complementary paths:

1. **Path A (Access Control):** Edge gateway with stateful default-deny iptables rules filtering unauthorized traffic before reaching the virtual switch.
2. **Path B (Signature DPI):** Inline Suricata IPS performing deep packet inspection on permitted streams, dropping known exploit patterns and emitting structured EVE JSON events.
3. **Path C (Behavioral Telemetry):** Adaptive FlowStats polling (2.0s baseline / 500ms surge) computing differential rate features over actual measured intervals ($\Delta t$), evaluated through a three-tier AI risk engine.
4. **Path D (Cryptographic Evidence):** Independent, append-only incident timeline sealed via SHA-256 hash chains, ECDSA signatures, and AES-256-GCM authenticated encryption.

---

## 2. System Architecture & Component Interaction

```
+---------------------------------------------------------------------------------------------------+
|                                      DATA PLANE (Open vSwitch)                                    |
|                                                                                                   |
|  [Ingress Client] ---> [Access Gateway] ---> [Suricata IPS] ---> [OVS Switch] ---> [Protected]    |
|                          (Default-Deny)         (Inline DPI)       (Flow Counters)   (Server)     |
+-------------------------------------------------------------------|-------------------------------+
                                                                    | OpenFlow 1.3
                                                                    v
+---------------------------------------------------------------------------------------------------+
|                                  CONTROL PLANE (Ryu Controller)                                   |
|                                                                                                   |
|   +------------------------------------+          +-------------------------------------------+   |
|   | Adaptive FlowStats Poller (Delta t)|          | Scoped Reconciler & FlowMod Enforcer      |   |
|   | - 2s baseline / 500ms suspicious   |          | - Cookie, Priority, Hard Timeout (TTL)    |   |
|   +------------------|-----------------+          +---------------------^---------------------+   |
+----------------------|--------------------------------------------------|-------------------------+
                       | Counter Differences                              | Approved Action
                       v                                                  |
+-------------------------------------------------------------------------|-------------------------+
|                                    BEHAVIORAL AI & RISK ENGINE          |                         |
|                                                                         |                         |
|   +---------------------------+       +---------------------------------+---------------------+   |
|   | 6-Feature Contract Mapper | ----> | Multi-Model AI Decision Engine                        |   |
|   | - packet_rate, byte_rate  |       | 1. XGBoost (Known Threat Classification)              |   |
|   | - avg_packet_size, counts |       | 2. PyTorch Bi-LSTM (Temporal Sequential Dynamics)     |   |
|   | - flow_duration_sec       |       | 3. Isolation Forest (Unsupervised Baseline Deviation) |   |
|   +---------------------------+       +---------------------------------^---------------------+   |
|                                                                         |                         |
|   +---------------------------+                                         | Suricata EVE Event      |
|   | Fast Alert Listener       | ----------------------------------------+                         |
|   +---------------------------+                                                                   |
+---------------------------------------------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------------------------------------------+
|                                 CRYPTO EVIDENCE & AUDIT PIPELINE                                  |
|                                                                                                   |
|   [Incident Spool] ---> [SHA-256 Hash Chain] ---> [ECDSA Signature] ---> [S3 Object Lock Bucket]  |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Mathematical Formulation of the 6-Feature Contract

To guarantee decision-time validity (preventing future-data leakage from completed connection attributes), our feature extractor computes instantaneous rates exclusively from active OpenFlow counters over the measured elapsed interval $\Delta t = t_k - t_{k-1}$:

1. **Instantaneous Packet Rate ($R_p$):**
   $$R_p = \frac{\Delta \text{packet\_count}}{\Delta t} = \frac{P_k - P_{k-1}}{t_k - t_{k-1}} \quad [\text{pkts/sec}]$$

2. **Instantaneous Byte Rate ($R_b$):**
   $$R_b = \frac{\Delta \text{byte\_count}}{\Delta t} = \frac{B_k - B_{k-1}}{t_k - t_{k-1}} \quad [\text{bytes/sec}]$$

3. **Average Packet Size ($S_{\text{avg}}$):**
   $$S_{\text{avg}} = \begin{cases} \frac{\Delta \text{byte\_count}}{\Delta \text{packet\_count}} = \frac{B_k - B_{k-1}}{P_k - P_{k-1}} & \text{if } \Delta P > 0 \\ 0 & \text{otherwise} \end{cases} \quad [\text{bytes/packet}]$$

4. **Observed Cumulative Counters:**
   $$P_{\text{cum}} = P_k, \quad B_{\text{cum}} = B_k$$

5. **Flow Duration ($T_{\text{flow}}$):**
   $$T_{\text{flow}} = \text{duration\_sec} + (\text{duration\_nsec} \times 10^{-9}) \quad [\text{seconds}]$$

### Switch Reset & Counter Inversion Detection
If counters decrease ($P_k < P_{k-1}$ or $B_k < B_{k-1}$) due to switch restart, flow rule eviction, or counter roll-over:
$$\Delta P < 0 \lor \Delta B < 0 \implies \text{reset\_detected} = \text{True}, \quad \text{is\_valid} = \text{False}$$
No negative rates are emitted. The feature vector flags the reset and falls back to baseline policy rules.

---

## 4. Dataset Preprocessing & Benchmark Pipeline

### 4.1 Benchmark Selection: DistriNet IEEE CNS 2022
The models were evaluated using the corrected IEEE CNS 2022 dataset suite from DistriNet (KU Leuven: improved CIC-IDS-2017 and CSE-CIC-IDS-2018). This dataset corrects known flow construction errors, timestamp synchronization bugs, and misattributed attack labels from the legacy UNB captures.

### 4.2 Data Processing Rules
1. **Stratified Sampling:** Eliminates chronological distribution shift by ensuring proportional class representation across both train and test partitions.
2. **CNS 2022 'Attempted' Label Sanitization:** Flows marked with `- Attempted` (failed non-malicious attempts) exhibit benign physical network characteristics. Per DistriNet specifications, they are relabeled to `benign` to prevent decision boundary ambiguity.
3. **Feature Column Harmonization:** Maps header variations across releases (`Pkt Len Mean`, `Tot Fwd Pkts`) ensuring all 6 metrics are fully populated.
4. **Z-Score Normalization:** Fits a `StandardScaler` on training features for deep sequence stability in Bi-LSTM.
5. **Class-Weighted Loss Optimization:**
   $$w_c = \frac{N}{|\mathcal{C}| \cdot N_c}$$

---

## 5. Measured Empirical Evaluation Results

### 5.1 Multi-Model Performance Comparison (Google Colab Benchmark Run)

| Architecture | Test Accuracy | Macro F1 | Weighted F1 | Training Time (s) | Single-Vector Inference Latency (ms) | Operational Role |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **XGBoost (Decision Trees)** | **99.71%** | **0.9973** | **0.9971** | 3.48 s | **0.12 ms** | Supervised Known Threat Classification |
| **PyTorch Bi-LSTM** | **97.81%** | **0.9792** | **0.9781** | 41.57 s | **0.45 ms** | Sequential Directional Dynamics |
| **Isolation Forest (Unsupervised)** | N/A *(Baseline)* | **0.6573** *(Anomaly F1)* | N/A | 0.37 s | **0.08 ms** | Unsupervised Baseline Deviation Corroborator |

*Note on Isolation Forest:* As an unsupervised model trained strictly on benign baseline traffic with no attack exposure, multi-class accuracy is not applicable. Its 65.73% anomaly F1 score reflects genuine baseline deviation detection on unlabelled flows without payload inspection.

### 5.2 Feature Importance & SHAP Attribution
Using `TreeExplainer`, SHAP values reveal the key discriminators:
1. `packet_rate`: Primary discriminator for volumetric DoS/DDoS attacks.
2. `avg_packet_size`: Distinguishes brute force payloads from TCP SYN scanning probes.
3. `byte_rate`: Differentiates exfiltration and large downloads from low-rate port probing.
4. `flow_duration_sec`: Differentiates persistent brute force sessions from ephemeral scans.

---

## 6. Scoped Mitigation & Policy Enforcement Semantics

### 6.1 Mitigation Action Construction
To adhere to the core rule: **Never block on `src_ip` alone**, the policy engine generates an `EnforcementActionRequest` containing:

$$\text{Match} = \{ \text{ipv4\_src} = S, \, \text{ipv4\_dst} = D, \, \text{ip\_proto} = P, \, \text{tcp\_dst} / \text{udp\_dst} = \text{Port} \}$$

Every rule enforced by Ryu carries:
* A unique cryptographic rule cookie ($> 0$).
* Priority assignment ($200$ for drops, $150$ for quarantine).
* Hard timeout / expiring TTL (default $60$ seconds) ensuring autonomous recovery from false positives.

### 6.2 Barrier Verification & Audit Sealing
Following rule installation, Ryu issues an `OFPBarrierRequest`. Upon controller confirmation, counter readback verifies that switch TCAM table 0 is dropping targeted traffic. The transition `data_plane_effect_observed` is committed to the append-only SHA-256 / ECDSA hash chain audit spool.
