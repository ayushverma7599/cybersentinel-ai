# CyberSentinel AI — Command Reference Guide (Updated)

This is an updated version of your original `COMMANDS.md`, corrected to match the
current state of the code after this session's fixes. It is **not** written back
into `~/honeypot` — it's a standalone reference file for you to review and merge
in yourself. Sections marked **🆕 Changed** describe behavior that is different
from the original doc; everything else is unchanged from before.

A full PS-compliance verdict is at the very bottom.

---

## Setup & Infrastructure

```bash
cd ~/honeypot
```
Navigate to your project directory. All commands must be run from here — scripts use relative paths to find `cowrie-raw.json`, `ttp_records.json`, `features.json`, etc.

---

```bash
docker-compose up -d
```
Start the entire honeypot stack in detached (background) mode. Spins up containers including:
- `honeypot-cowrie-1` — the fake SSH server that captures attacker sessions
- `honeypot-elasticsearch-1` — search database that stores all log events
- `honeypot-kibana-1` — visual dashboard
- `honeypot-payload-1` — 🆕 **the payload server used by Phase 3 of `attack1.sh`.** This container was crash-looping for part of this project (its script was at the wrong path relative to the `./payload:/srv` volume mount) — it's now fixed and should show `Up` in `docker ps`.

---

```bash
sleep 15
```
Wait for all containers to fully initialize before sending any traffic. Unchanged.

---

## Attack Simulation

### 🆕 Changed: use `attack1.sh`, not `attack.sh`

```bash
./attack1.sh
```
`attack.sh` is the older, 3-phase simulation the original doc describes. **All of this session's work — and the LSTM/world-model training data you've been using — was built on `attack1.sh`**, a much larger 13-phase simulation (recon → brute force → tool transfer/execution → privilege escalation → credential access → lateral movement → discovery → DoS, roughly, with several phases skippable via flags). Two details worth knowing:

- **Phase 3 (tool transfer/execution)** always runs now and always logs a real `wget` attempt against the honeypot's own payload server, even though that fetch is expected to be *blocked* by Cowrie's own network-access control. This isn't a bug: Cowrie's `communication_allowed()` hard-blocks all RFC1918 private ranges (10/8, 172.16/12, 192.168/16) by design, so an attacker can't use the honeypot to pivot into your internal network. The `wget` command itself is what MITRE T1105 detection cares about — Phase 3 logs the attempt and lets Cowrie reject it, same as it would for a real attacker's malware-drop against an internal target.
- Flags: `--shuffle-mid` (randomizes post-compromise phase order), `--quiet`, `--no-brute` (skips the brute-force phase). See `run_campaign.sh` for how these are used to generate varied real sessions.

```bash
./run_campaign.sh [N] [--extract]
```
🆕 Runs `attack1.sh` N times (default 10) with varied DoS intensity and occasional phase skips, so your real session corpus has genuine sequence diversity instead of every run following the identical phase order. Each run's log is saved as `attacks_campaign_<n>.log`.

---

```bash
sleep 5
```
Unchanged — brief pause after the attack script so Cowrie finishes writing events to disk.

---

## Log Extraction

```bash
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \
    ~/honeypot/cowrie-raw.json
```
Unchanged and still correct. `cowrie-raw.json` is **line-delimited JSON** (one event object per line) — every script in this project that reads it does `for line in f: json.loads(line)`, not `json.load(f)` on the whole file.

```bash
wc -l ~/honeypot/cowrie-raw.json
```
Unchanged.

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
Unchanged — still a useful sanity check.

---

## Core Pipeline

```bash
./run_pipeline.sh
```
Unchanged in behavior, but worth knowing exactly what it does and doesn't do:
- **Step 1** — `docker cp` to pull fresh Cowrie logs
- **Step 2** — `python3 ttp_extract.py` → writes `ttp_records.json`
- **Step 3** — `python3 cybersentinel_skeleton.py` → 3-agent scanner → `cybersentinel_report.json`

🆕 **It does NOT rebuild `features.json`.** That's a separate step (`packet_capture.py --cowrie cowrie-raw.json`, see World Model Pipeline below) — don't assume running `run_pipeline.sh` refreshes your world-model training data.

```bash
python3 ttp_extract.py
```
🆕 Fixed this session: a dangling-`else` bug meant the technique-frequency summary sometimes printed "None matched" even when techniques *were* found, whenever zero sessions were fully unclassified. Now prints correctly. Behavior otherwise unchanged.

```bash
python3 parse_cowrie_logs.py
```
Unchanged.

---

## LSTM Attack Progression Model

*(Operates on MITRE technique-ID sequences from `ttp_records.json` — separate from, and a different architecture than, the World Model below, which operates on raw network feature vectors.)*

```bash
python3 lstm_model.py --train
```
🆕 The synthetic-sequence balancing was fixed this session. Previously, techniques with only one "natural" real-session ending (specifically T1110 and T1078, both early-stage) got duplicated 200× each to hit a per-technique target, teaching the model spurious high-confidence transitions between them. There's now a `MAX_DUP_FACTOR = 5` cap — techniques with a thin natural pool get capped rather than over-duplicated, with a printed note when that happens. Net effect on your data: total training samples dropped (~18k → ~16.6k in the last verified run) and top-1/top-3 accuracy dropped a few points, but *every* technique now gets above-zero accuracy instead of 5 techniques sitting at a literal 0%. This is a real, honest trade-off, not a pure win — a smaller number that reflects the model actually having learned something for every class beats a bigger number propped up by a handful of memorized duplicates.

The exact real-session-vs-synthetic split you'll see depends on how many real `attack1.sh`/campaign runs exist in your `ttp_records.json` at train time — it scales with your data, not a fixed "20 real + 63 synthetic" like the original doc stated.

🆕 Also worth knowing: there are **three separate MITRE technique registries** in this codebase — `ttp_extract.py`'s `TECHNIQUE_RULES`, `cybersentinel_skeleton.py`'s `TECHNIQUE_REGISTRY`, and `lstm_model.py`'s own keyword-based `_infer_from_commands()` — and they don't all agree on the same technique set (the third one can emit T1016/T1059.006/T1485, which don't appear in the other two). This hasn't been fixed; if you see a technique from one report that doesn't show up in another, this is why.

```bash
python3 lstm_model.py --eval
```
Unchanged in mechanics.

```bash
python3 lstm_model.py --forecast T1082 T1087 --k 3
```
🆕 Confidence threshold changed from a hardcoded `0.15` to an auto-scaling `1.5 / vocab_size` — with the larger technique vocabulary this project now has, the old fixed threshold was too high and frequently produced an empty forecast. `top_k` for `predict_next_technique` also widened from a small fixed number to `min(len(vocab), 15)`. The command now prints which threshold it actually used (`--forecast-threshold` lets you override it), and handles an empty result gracefully with an explanatory message instead of just printing nothing. Real per-technique confidence numbers will differ from the original doc's illustrative 85%/90%/98.8% example — those depend on your actual trained vocabulary and data.

---

## SHAP Explainability

```bash
python3 shap_explain.py --all --save
```
🆕 Fixed this session: previously, if many sessions shared the exact same technique sequence, the "top 5 highest-risk sessions" table could show the same sequence 5 times over — not wrong, but not useful. It now groups by distinct sequence, keeps the highest-risk session per group, and shows a count of how many real sessions share that sequence (e.g. `×104`). Output now reads "Top 5 highest-risk DISTINCT sequences (N distinct sequence(s) across M sessions)" with a Count column.

---

## Real Packet Capture (Scapy)

### 🆕 Changed: interface detection

```bash
NETWORK=$(docker inspect honeypot-cowrie-1 --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
NET_ID=$(docker network inspect "$NETWORK" --format '{{.Id}}' | cut -c1-12)
IFACE="br-$NET_ID"
echo "Bridge interface: $IFACE"
ip -brief addr show "$IFACE"
```
The original doc's `ip addr | grep -B4 '172.18.0.1'` works but relies on knowing the IP in advance and can be ambiguous if you have multiple docker networks. This auto-derives the *correct* bridge for Cowrie's actual docker-compose network programmatically — verified working in this project (`honeypot_default` → `br-2225cb83dfa4`, your actual value will differ).

```bash
sudo python3 scapy_feature_extractor.py --capture --iface "$IFACE" --port 2222 \
    --out honeypot_capture_NN.pcap
```
🆕 There is **no `--duration` flag on this command** — it sniffs until you press Ctrl+C, full stop. Run this first, wait for it to print `[*] Sniffing on br-...`, *then* start `./attack1.sh` in a second terminal, and only Ctrl+C once `attack1.sh` fully finishes. **Sequencing matters**: the merge step later matches purely by TCP source port, and ports are only meaningful within the same run — start the capture before the attack, not after.

Immediately after Ctrl+C, verify you actually captured something before continuing:
```bash
python3 -c "
from scapy.utils import rdpcap
print(f'Captured {len(rdpcap(\"honeypot_capture_NN.pcap\"))} real packets')
"
```
An empty or near-empty pcap (this happened once in this project) means the capture wasn't running during the attack, or was on the wrong interface — don't proceed to extract/merge on it.

```bash
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture_NN.pcap --out packet_features_NN.json
```
Unchanged mechanically. Real per-flow packet-level features: genuine TTL values and variance, real TCP window size, real retransmission counts, real port-scan signature — not the hardcoded proxy constants (`ttl_mean=64.0`, `tcp_window_mean=65535.0`, etc.) that `packet_capture.py`'s Cowrie-JSON-proxy mode falls back to when there's no real capture.

```bash
python3 scapy_feature_extractor.py --merge --out packet_features_NN.json --features features.json
```
🆕 Two important, previously-undocumented caveats discovered this session:
1. **This is not cumulative.** Every row in `features.json` that doesn't match *this specific* pcap's ports gets explicitly re-labeled `"unmatched_no_real_capture"` — including rows a *previous* capture round already matched. If you do more than one capture round, you'll regress earlier real matches unless you re-merge against a combined packet-features file.
2. **Run this AFTER the CIC-IDS merge, not before** (see World Model Pipeline below) — rebuilding `features.json` from Cowrie logs alone wipes any previously-merged CIC data, and this project hit that exact regression once.

It writes `features_with_real_packets.json` — it does **not** overwrite `features.json` itself; you copy it over manually.

---

## World Model Pipeline

*(Operates on 30-dimensional real network feature vectors over 5-flow time windows — this is the architecture SIH26153 explicitly requires, distinct from the technique-ID-sequence LSTM above.)*

### 🆕 Corrected step order

The original doc's `run_world_model_pipeline.sh` covers Steps 1–2 automatically but **does not include the real-packet-capture merge at all** — it's a script that predates that part of the project. The full, correct manual sequence, in an order that doesn't lose data (verified this session after initially getting this wrong and having to recover from a backup):

```bash
# 1. Rebuild features.json from fresh Cowrie logs (overwrites — Cowrie-only, no CIC yet)
python3 packet_capture.py --cowrie cowrie-raw.json

# 2. Merge in CIC-IDS-2018 diversity — ADDS to features.json, does not overwrite
CIC_CSV=$(ls *TrafficForML_CICFlowMeter.csv 2>/dev/null | head -1)
python3 cic_ids_loader.py --csv "$CIC_CSV" --merge features.json

# 3. Extract + merge real Scapy packet-level features (from a capture done alongside attack1.sh)
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture_NN.pcap --out packet_features_NN.json
python3 scapy_feature_extractor.py --merge --out packet_features_NN.json --features features.json
cp features_with_real_packets.json features.json

# 4. Train and benchmark
python3 world_model.py --train --epochs 100
python3 world_model.py --benchmark
```

Doing the CIC merge *before* the packet-capture merge means real-packet rows and CIC rows both end up correctly represented in the final `features.json`, and nothing gets silently wiped.

### 🆕 Architecture changes to `world_model.py`

`WorldModelLSTM` previously had two output heads (`fc_infiltration`, `fc_technique`) and `fc_technique` was defined but **never trained** — no loss term touched it, so its predictions were random. This session added:

- **`fc_next_state`** — a third head that predicts the actual next 30-feature vector, not just an infiltration probability.
- **A real training loss for `fc_technique`**: `CrossEntropyLoss(ignore_index=-100)`, so it now genuinely learns to classify which of the 10 compromise techniques (`T1105, T1204, T1059, T1548, T1136, T1070, T1499, T1498, T1071, T1190`) is happening. In this project's real retrains, `tech_acc` reaches 97–100% on held-out labeled data.
- **`k_step_forecast()` redesigned**: it previously advanced its forward simulation by overwriting a single field (`syn_ratio`) of the last timestep with the predicted probability and leaving the other 29 features frozen — not real state simulation. It now feeds the model's own `next_state_pred` back in at each step, a genuine rollout through P(S_t+1|S_t). It returns a list of dicts (`infiltration_prob`, `predicted_technique`, `technique_confidence`) per step, not a bare list of floats.

```bash
python3 world_model.py --predict --k 3
```
🆕 Output now also includes a decoded next-technique prediction with confidence, and the K-step forecast prints a per-step technique alongside the probability, e.g.:
```
Predicted technique: T1105 (97.1% confidence)
K-step forecast (genuine forward simulation through predicted next states):
    t+1: infiltration=73.9%  -> T1105
    t+2: infiltration=70.2%  -> T1105
    ...
```

### 🆕 Current real benchmark numbers — read this honestly, not optimistically

The original doc's example numbers ("F1 0.778→0.933, +15.5%") don't reflect this project's actual measured results at any point in this session. The real, most recently verified benchmark (434 combined flows: honeypot + real Scapy capture + CIC-IDS):

```
Metric          Logistic Regression   LSTM World Model
F1 Score              1.0000               0.9873
Precision             1.0000               1.0000
Recall                1.0000               0.9750
FPR                   0.0000               0.0000
```

**The LSTM currently does not beat the logistic-regression baseline on binary F1** — LR is hitting a perfect score on this dataset size, which is a sign the binary infiltration-classification task is close to linearly separable at this scale, not that the world model is broken. See the PS Compliance section below for what this means and how to honestly present it.

---

## UI

```bash
streamlit run streamlit_app.py
```
Six pages, one of them changed this session:

- **Dashboard**, **Session Explorer**, **Attack Predictor**, **K-Step Forecast**, **Agent Findings** — unchanged.
- **World Model** — 🆕 now includes a **"📤 Upload PCAP / CSV for Live Inference"** panel above the existing benchmark/inference sections. Accepts a `.pcap`/`.cap` file (parsed the same way as `packet_capture.py --capture`) or a `.csv` with the same 30-column schema as this project's `features.csv`. It runs the trained world model over every 5-flow sliding window in the uploaded file and shows an infiltration-probability timeline, peak probability, and any windows crossing the 65% HIGH-risk threshold. This is the "offline demo interface accepting PCAP/CSV input" the SIH26153 PS explicitly asks for — tested working end-to-end in this project (155 real flows extracted from an uploaded pcap, 151 inference windows run).

---

## PS Compliance — honest status against the SIH26153 requirements

| Requirement | Status | Notes |
|---|---|---|
| Learn state transition dynamics P(S_t+1\|S_t) from flow + packet-level features | **Mostly met** | `world_model.py` genuinely models this now via `fc_next_state`. Packet-level real-capture coverage is real but partial (~50% of rows as of the last verified run, up from ~5% earlier this session) — the remaining rows still use Cowrie-proxy constants for some fields. |
| Forecast future states | **Met** | `k_step_forecast()` now does genuine forward simulation through the model's own predicted next-state vectors, not a placeholder. |
| Map forecasts to MITRE ATT&CK stages | **Met** | `fc_technique` is now trained (97–100% held-out accuracy) and its predictions are surfaced in both the CLI and Streamlit UI. |
| SHAP / attention-based explainability | **Met** | `shap_explain.py` (attention weights + gradient saliency) plus `world_model.py`'s own attention-weight output. |
| Benchmark vs. logistic-regression baseline showing measurable improvement | **Not met, as literally stated** | Current real numbers show the LSTM *underperforming* LR on binary F1 (0.9873 vs 1.0000) — LR hits a perfect score, leaving no room for the LSTM to show an edge on that specific metric. This has been true most of this session, not a new regression. **Recommended framing**: present technique-classification accuracy and K-step forecasting as the "measurable improvement" evidence instead of binary F1 — LR has no equivalent capability for either, so it isn't a close call there, it's something LR structurally cannot do at all. |
| Offline demo interface accepting PCAP/CSV input | **Met** | New Streamlit upload panel, tested working on a real pcap. |

**Bottom line: 5 of 6 explicit requirements are genuinely met. The one clear gap is the binary-F1 benchmark comparison — it doesn't currently favor the world model, and more data alone hasn't fixed that across three attempts this session.** The honest path forward for a demo or report is to lead with what the LSTM can do that LR fundamentally cannot (technique prediction, forward forecasting), not to claim an F1 win that the numbers don't currently support.
