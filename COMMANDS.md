Here's a complete description of every command in your file:

---

## CyberSentinel AI — Command Reference Guide

---

### **Setup & Infrastructure**

```bash
cd ~/honeypot
```
Navigate to your project directory. All commands must be run from here — scripts use relative paths to find `cowrie-raw.json`, `ttp_records.json`, `features.json`, etc.

---

```bash
docker-compose up -d
```
Start the entire honeypot stack in detached (background) mode. Spins up 3 containers simultaneously:
- `honeypot-cowrie-1` — the fake SSH server that captures attacker sessions
- `honeypot-elasticsearch-1` — search database that stores all log events
- `honeypot-kibana-1` — visual dashboard at `http://10.0.2.15:5601`

The `-d` flag means it runs in the background so your terminal stays free.

---

```bash
sleep 15
```
Wait 15 seconds for all containers to fully initialize before sending any traffic. Cowrie needs time to bind to port 2222 and Elasticsearch needs time to start its indexing service. Running `attack.sh` before this causes connection refused errors.

---

### **Attack Simulation**

```bash
./attack.sh
```
Runs a realistic multi-phase attack simulation against the Cowrie honeypot. Executes three phases in sequence:
- **Phase 1 (Reconnaissance):** SSH login attempts with `whoami`, `id`, `uname -a`, `cat /etc/passwd` — triggers T1082 and T1087
- **Phase 2 (Tool Transfer):** Downloads a fake payload using `wget` — triggers T1105
- **Phase 3 (Execution):** Runs `chmod +x` and executes the payload — triggers T1204

All commands are recorded by Cowrie as if a real attacker typed them. This is what populates your `cowrie.json` log file.

---

```bash
sleep 5
```
Brief pause after `attack.sh` completes to let Cowrie finish writing all session events to disk before you copy the log file out. Without this, the last few events may be missing from the JSON.

---

### **Log Extraction**

```bash
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \
    ~/honeypot/cowrie-raw.json
```
Copies the Cowrie log file from **inside the Docker container** to your host machine. This is the critical step that was bugged early in the project — the host-mounted volume stays empty due to a path mismatch, so you must always use `docker cp` to get the real logs. The output file `cowrie-raw.json` contains one JSON event per line (JSONL format) covering connects, login attempts, commands, and file downloads.

---

```bash
wc -l ~/honeypot/cowrie-raw.json
```
Count the number of log lines in the raw Cowrie file. Each line is one event. A healthy simulation should produce 500–4000 lines depending on how many sessions `attack.sh` creates. If this returns 0 or a very small number, the `docker cp` failed or Cowrie hasn't written yet.

---

```bash
cat ~/honeypot/cowrie-raw.json | python3 -c "
import json, sys
from collections import Counter
events = Counter()
for line in sys.stdin:
    line = line.strip()
    if line:
        try:
            log = json.loads(line)
            events[log.get('eventid','unknown')] += 1
        except: pass
for e,c in events.most_common():
    print(f'{c:4d}  {e}')
"
```
Quick sanity check — counts how many of each event type are in the log. Output looks like:
```
 118  cowrie.command.input
  96  cowrie.client.var
  50  cowrie.session.connect
  48  cowrie.login.success
```
If `cowrie.command.input` count is 0, your attack simulation didn't produce command events. If `cowrie.session.connect` is 0, Cowrie wasn't running when `attack.sh` ran.

---

### **Core Pipeline**

```bash
./run_pipeline.sh
```
Runs the **complete CyberSentinel AI pipeline** in one command. Executes three steps sequentially:

**Step 1** — `docker cp` to pull fresh Cowrie logs into `cowrie-raw.json`

**Step 2** — `python3 ttp_extract.py` to parse sessions, classify them against MITRE ATT&CK, and write `ttp_records.json`. Outputs:
```
Total sessions found: 350
Sessions matching at least one technique: 350
T1110 — Brute Force: 210 sessions
T1082 — System Information Discovery: 70 sessions
```

**Step 3** — `python3 cybersentinel_skeleton.py` to run the 3-agent parallel scanner:
- Recon agent maps endpoints
- CVE-match agent queries NVD for real CVEs
- Logic/config agent identifies misconfigurations
- Orchestrator deduplicates and scores findings
- Outputs `cybersentinel_report.json` with ranked security findings

---

```bash
python3 parse_cowrie_logs.py
```
Parses `cowrie-raw.json` and ships all events to Elasticsearch for indexing. After this runs you can open Kibana at `http://10.0.2.15:5601` and search/visualize attack data. Creates an index named `cowrie-YYYY.MM.DD`. Also prints top attacking IPs, usernames tried, and passwords attempted.

---

### **LSTM Attack Progression Model**

```bash
python3 lstm_model.py --train
```
Trains the PyTorch LSTM sequence model on your `ttp_records.json` sessions. The model learns: given the first N MITRE techniques observed in a session, predict what technique comes next. Key details:
- Loads 20 real sessions + 63 targeted synthetic sequences
- Builds vocabulary of your 4–5 unique techniques
- Trains for 200 epochs with cosine LR schedule
- Saves best weights to `cybersentinel_lstm.pt`

Must be re-run whenever `ttp_records.json` changes (new sessions captured, new techniques detected). Output shows loss, test accuracy, and LR at each epoch.

---

```bash
python3 lstm_model.py --eval
```
Evaluates the trained LSTM on all sessions and prints:
- Overall accuracy vs random baseline (2.9× lift over 25% random)
- Per-technique accuracy breakdown with bar charts
- Confusion matrix showing which techniques the model confuses
- Infiltration probability calibration — compromise-stage sessions should score 45%+ higher than non-compromise sessions

---

```bash
python3 analyze.py
```
IOC (Indicator of Compromise) analysis script. Reads `cowrie-raw.json`, counts top attacking IPs, most-tried usernames and passwords, and most-executed commands. Also indexes 570 events into Elasticsearch. Use this to understand attacker behaviour patterns independently of MITRE classification.

---

```bash
python3 shap_explain.py --all --save
```
Runs SHAP-style explainability on every session in `ttp_records.json`. For each session:
- Uses LSTM attention weights to identify which techniques drove the prediction
- Uses gradient saliency as a second independent method
- Outputs top driver, infiltration probability, risk label
Saves results to `shap_all_sessions.json`. The `--save` flag writes the full explanation JSON. Prints top 5 highest-risk sessions in a table.

---

```bash
python3 lstm_model.py --forecast T1082 T1087 --k 3
```
K-step forward simulation starting from an observed sequence of T1082 → T1087. The LSTM rolls forward 3 steps, predicting:
- Step 1: most likely next technique (T1105 — Ingress Tool Transfer, 85% confidence)
- Step 2: technique after that (T1204 — User Execution, 90% confidence)
- Final infiltration probability: 98.8% CRITICAL

Change the sequence or `--k` value to simulate different attack starting points.

---

### **Real Packet Capture (Scapy)**

```bash
ip addr | grep -B4 '172.18.0.1'
```
Finds which network interface hosts the Docker bridge network (`172.18.0.1`). The interface name (e.g., `br-43684e179073`) varies between Docker installations and is needed for the Scapy capture command. The `-B4` flag shows 4 lines before the match so you see the interface name.

---

```bash
sudo python3 scapy_feature_extractor.py --capture --iface br-43684e179073 --port 2222
```
**Requires root (`sudo`) and a separate terminal.** Starts live packet capture on the Docker bridge interface, filtering for traffic to port 2222 (Cowrie). While this runs in one terminal, start `./attack.sh` in another terminal. When the attack finishes, press `Ctrl+C` here. Saves captured packets to `honeypot_capture.pcap`. Produces real packet-level features:
- Actual TTL values from IP headers (not hardcoded 64)
- Real TCP window sizes from SYN packets
- Genuine retransmission counts from duplicate sequence numbers
- Port scan signatures from destination port patterns

---

### **World Model Pipeline**

```bash
./run_pipeline.sh
```
Second run of the main pipeline — after Scapy capture. Re-runs with fresh Cowrie logs to pick up any new sessions from the attack simulation that ran alongside the Scapy capture.

---

```bash
./run_world_model_pipeline.sh
```
Runs the **complete world model pipeline** required by SIH26153. Five steps:

**Step 1** — `packet_capture.py --cowrie cowrie-raw.json` converts Cowrie sessions into 30-dimensional network feature vectors (syn_ratio, IAT mean/std/max, TTL, TCP window, payload size, port scan score, etc.)

**Step 2** — `cic_ids_loader.py --download` downloads Wednesday-14-02-2018 CIC-IDS-2018 CSV (341MB, SSH Brute Force day), converts 101 real T1110 flows, merges with honeypot features → combined dataset of 480 flows

**Step 3** — `world_model.py --train` trains the LSTM World Model on real 30-dimensional network features over 5-flow time windows. Learns P(S_t+1 | S_t) — state transition dynamics. 269,964 parameters, 100 epochs, F1=0.990

**Step 4** — `world_model.py --benchmark` trains Logistic Regression baseline on same features, compares: F1 0.778→0.933 (+15.5%), Precision 0.636→1.000, FPR 0.129→0.000. Saves `benchmark_results.json`

**Step 5** — `world_model.py --predict` runs inference on the 5 most recent flows and prints feature importance with attention weights

---

```bash
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture.pcap
```
Parses the saved PCAP file using Scapy's `rdpcap()`. Groups packets into bidirectional flows and extracts real packet-level features: TTL variance across the session, TCP window size from SYN headers, retransmission count from duplicate sequence numbers, payload size distribution, port scan score. Writes `packet_features.json` with 52 real flows from 725 captured packets.

---

```bash
python3 scapy_feature_extractor.py --merge --features features.json
```
Merges real Scapy packet-level features into `features.json`. For the 26 flows that match between the PCAP capture and the Cowrie sessions (matched by source port), overwrites the proxy-estimated TTL/window values with real measured values. The remaining 454 unmatched rows are transparently flagged as `unmatched_no_real_capture` — not silently faked. Outputs `features_with_real_packets.json`.

---

### **UI**

```bash
streamlit run streamlit_app.py
```
Launches the CyberSentinel AI web interface at `http://localhost:8501`. Opens automatically in your browser. Six pages:
- **Dashboard** — live metrics, technique frequency chart, tactic distribution, kill chain
- **Session Explorer** — click any session, see kill chain + LSTM prediction + SHAP explanation + infiltration gauge
- **Attack Predictor** — type any technique sequence, get live LSTM prediction with feature importance bars
- **K-Step Forecast** — enter starting sequence, see full predicted kill chain with ATT&CK tactic phase labels (Discovery → Command & Control → Execution) and infiltration probability progression chart
- **World Model** — benchmark comparison chart (LSTM vs LR baseline), live world model inference
- **Agent Findings** — ranked security report from 3-agent scanner with CVE details and Mistral-generated remediation

Keep this terminal open — closing it stops the app. Access from Windows host at `http://10.0.2.15:8501`.
