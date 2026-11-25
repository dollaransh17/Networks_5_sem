# SETUP: Run the lab locally

## Run the local console

From the repository root, start the Python backend. It serves the frontend on the same port.

```bash
python3 -m backend.server
```

Open **http://127.0.0.1:8080**. The console works on macOS and Linux with Python 3.10 or newer. It reads `audit/spool/incident_store.db` when the lab creates it. Use `--database /path/to/incident_store.db` to view a different store, or `--port 8081` if port 8080 is in use.

If Live lab reports that its script could not load after an update, stop the running backend and start it again with the same options before reloading the page. The backend reads its route list at startup.

**Overview** refreshes the local audit timeline and event-source counts every five seconds while the page is visible.

**Live lab** and **Simulations** share one continuous 3D traffic simulation. Choose an input rate or use **Send 20 packets** for a burst. The gateway forwards ten packets per simulated second and buffers up to 80. Heavy input fills the queue and overflows count as drops. **Manual** stops new automatic arrivals while queued and in-flight packets finish. Routing changes apply to new arrivals. The inspector counts deliveries to each host. Drag the scene to orbit or select a rack to inspect it.

In **Live lab**, the **3D switch capture** shows the collector’s monitored link in green. The link pulses when a new interval contains packets. Its rate uses the captured packet count and the measured duration. The collector status, recent headers and service checks appear on the same page. The standalone preview displays the unavailable capture state.

Open **Simulations** to compare fixed and adaptive polling under a workload burst, steady load, a slow switch, or a counter restart. Switch between polling interval, packet rate, and reply latency. The polling benchmark uses its own reference workload. Expand **Poll by poll** for the full run. The simulations work with the standard library and synthetic data on macOS and Linux.

### Use Claude Code with Haiku 4.5

Copy [`.env.example`](.env.example) to `.env` if you do not already have one. Set `ANTHROPIC_API_KEY` in your local `.env` and run `source .env && claude` from the project root. Claude Code reads `ANTHROPIC_MODEL` to select Haiku 4.5. The SDN console uses the local models described below. [Claude Code settings](https://code.claude.com/docs/en/settings)

### Explore the 3D topology

**Overview** renders the 3D device models in a local canvas. If the local Three.js package and WebGL are available, it uses the WebGL renderer. From the project root, run `npm install --prefix frontend` to enable that optional renderer. Select a device for its role, drag to orbit, or use **Rotate** and **Reset view**.

### Open a standalone preview

Export the console to a single HTML file and open it in a browser.

```bash
.venv/bin/python -m backend.export_preview ../SDN-console-preview.html
```

The preview includes sample audit records and all four simulated workloads. If the release models are available, **Simulations → Custom traffic** displays their recorded predictions for **Use example**. The preview uses the local canvas scene offline and loads the pinned Three.js renderer from jsDelivr when available. The local backend handles custom flows and reads the lab’s audit store.

### Enable flow checks

Use Python 3.11–3.13 with a separate virtual environment. Install the inference dependencies and put the four trusted release files in `ai/models/`.

1. Download `xgboost_cns2022.pkl`, `bilstm_cns2022.pt`, `isolation_forest.pkl`, and `scaler_and_encoder.pkl` from [GitHub Releases v1.0.0](https://github.com/ShreyanshuRaj06/SDN_Threat_Isolation_Research/releases/tag/v1.0.0).
2. Install the dependencies and start the console.

   ```bash
   python3 -m venv .venv
   .venv/bin/python -m pip install -r backend/requirements.txt
   .venv/bin/python -m backend.server
   ```

3. Open the printed URL while the models load. Under **Simulations → Custom traffic**, enter a packet count, size, and measurement window or select **Use example**. **Send burst and check models** becomes available after the models load.

XGBoost consumes raw features. Bi-LSTM and Isolation Forest use the supplied scaler. The classifiers use the supplied label encoder. On macOS, XGBoost may require `libomp` from Homebrew. Keep this environment separate from the older Python environment used by Ryu in the Linux lab.

## Run the offline verification suite

Use Python 3.11–3.13 in a disposable project copy. Stage 4 writes synthetic records to the audit spool. Training creates `ai/models/xgboost_model.pkl` and `ai/models/iforest_model.pkl` for Stage 4. Stage 6 uses the same synthetic XGBoost model.

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt pytest cryptography
.venv/bin/python experiments/train_models.py --synthetic --samples 1000 --no-bilstm
.venv/bin/python experiments/run_all_tests.py
```

The runner executes `pytest tests/` and the Stage 4–6 verifiers. Stage 4 uses XGBoost's built-in TreeSHAP support. The separate `shap` package is used for optional non-XGBoost explanations. The browser and live lab procedures are in [TESTING.md](TESTING.md).

## Run the live SDN lab

Use a disposable Linux VM for the project topology. The current verification status is recorded in [TESTING.md](TESTING.md#verification-results).

### Prerequisites

- Linux (Ubuntu LTS recommended). **Mac/Windows:** use a Linux VM, or WSL2 on Windows (OVS kernel features and inline Suricata can be limited there; a full VM is safer).
- Python 3 (a version supported by your Ryu release), pip, git.
- 16 GB RAM is a prototype host, not a capacity guarantee.
- Optional: AWS account (disposable) for Phase 5.

### 1. Clone and environment

```bash
git clone <your-repo-url> sdn-threat-isolation && cd sdn-threat-isolation
```

### 2. Install tools (Ubuntu)

The project uses a separate controller environment. This recipe assumes Python 3.9 with `venv` is available in the VM. Stage 1 also uses `nc` for its local test listeners and probes.

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch suricata iptables ethtool
python3.9 -m venv ~/ryu_venv
~/ryu_venv/bin/python -m pip install ryu==4.34 eventlet==0.30.2
```

### 3. Start the controller and lab

```bash
~/ryu_venv/bin/ryu-manager --ofp-listen-host 127.0.0.1 --ofp-tcp-listen-port 6653 controller/ryu_app/sdn_controller.py  # terminal 1
sudo python3 lab/topology/mininet_topo.py                         # terminal 2
```

Apply the access policy inside the gateway namespace from the Mininet CLI with `gw bash lab/gateway/setup_gateway.sh`. Before inline tests, check the Suricata configuration for both interfaces in the `ips` namespace and record the intended fail mode. The Stage 1–3 scripts use the gateway, Ryu, and the rule-based alert daemon without loading model artifacts.

### Watch live packet headers

In the same Linux VM, from the repository root, start the collector and console in a third terminal after the Mininet links are up. The collector needs access to the Linux packet socket. The console runs as your ordinary user.

```bash
sudo python3 -m lab.packet_capture --interface s1-eth1 | python3 -m backend.server --port 5174 --capture-stdin
```

Open **Live lab** at `http://127.0.0.1:5174/#live-lab` inside the VM. `s1-eth1` observes the switch side of the Suricata link. `s1-eth2` and `s1-eth3` select the protected server and quarantine links. The collector accepts these ports only and checks that the selected port belongs to `s1` before opening the socket. The console receives headers and measured intervals in memory. See [Linux packet socket documentation](https://man7.org/linux/man-pages/man7/packet.7.html) for the socket interface.

In the Mininet CLI, `ips ping -c 3 198.51.100.20` sends a small connectivity probe through the switch. Check for ICMP headers, a nonzero packet rate, and subsequent idle intervals. The service cards show process, bridge, or log evidence. Use the existing isolated-lab checks separately to verify gateway policy and Suricata inline behavior.

Use **Pause display** to inspect a stable packet table. The collector keeps running. **Resume display** loads the latest retained window.

### Test Haiku with protected-server traffic

On the Linux lab host, start the collector and console as above using `s1-eth1` or `s1-eth2`. In another terminal in the project directory run:

```bash
source .env
python3 -m experiments.verify_claude_traffic --port 5174
```

When the verifier starts waiting, run `ips ping -c 3 198.51.100.20` in the Mininet CLI. The verifier waits up to 30 seconds for three new ICMP headers in each direction between the sensor and protected server. It prints the observed counts and sends the protocol and packet and byte counts by direction to Anthropic. A successful result includes the returned model, message ID, and summary. [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create)

### 4. Inspect

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo tail -f /var/log/suricata/eve.json
```

### 5. Database, migrations, seed

The alert daemon initializes the SQLite store. See [DATABASE.md](DATABASE.md) for the schema and migration notes.

## Common errors and fixes
| # | Error | Fix |
|---|---|---|
| 1 | `mn: command not found` | Install `mininet`; open a new shell |
| 2 | `Exception: Could not find a default OpenFlow controller` | Start Ryu first or use `--controller=remote` |
| 3 | Switch connects, no flows | Match protocol version: `protocols=OpenFlow13` and a Ryu app using OFP 1.3 |
| 4 | `pip install ryu` fails / import errors | Use a Python version your Ryu supports; fresh venv |
| 5 | Port 6653 in use | `sudo lsof -i :6653`; stop the old controller |
| 6 | Stale Mininet state | `sudo mn -c` |
| 7 | `ovs-vsctl: database connection failed` | `sudo systemctl start openvswitch-switch` |
| 8 | Suricata runs but nothing is dropped | Passive mode only observes; configure inline IPS and `drop` rules, and ensure both directions traverse the sensor |
| 9 | eve.json missing/empty | Confirm EVE output is enabled in suricata.yaml and the path/permissions |
| 10 | Permission denied reading logs/pcaps | Run with proper group/sudo; never loosen permissions on captures with credentials |
| 11 | Wireshark sees nothing | Select the right interface; capture on veth/bridge in the lab |
