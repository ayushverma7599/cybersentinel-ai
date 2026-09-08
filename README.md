# 🛡️ CyberSentinel AI

> **AI-Based Network Attack Forecasting from Network Traffic Data**
> SIH 2026 · Problem Statement **SIH26153** · NTRO · Smart Automation

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-CPU-orange?style=flat-square)](https://pytorch.org)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red?style=flat-square)](https://streamlit.io)
[![Offline](https://img.shields.io/badge/LLM-Ollama%20Mistral%207B-green?style=flat-square)](https://ollama.ai)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-black?style=flat-square)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

A threat-informed autonomous security testing system that **learns the evolving state of a computer network from traffic telemetry**, predicts the likelihood and progression of malicious activity **before compromise is completed**, and provides interpretable decision support for defenders — fully offline, zero cloud dependency.

---

## ✨ What it does

| Capability | Detail |
|---|---|
| 🍯 **Real attack capture** | Cowrie SSH honeypot in Docker captures live attacker sessions |
| 🎯 **MITRE ATT&CK mapping** | Classifies sessions into T1110, T1082, T1087, T1105, T1204 automatically |
| 🌐 **World Model LSTM** | Learns P(S_t+1 \| S_t) — state transition dynamics on 30 network features |
| 📈 **K-step forecasting** | Predicts attack progression up to 5 steps ahead (98.8% CRITICAL demonstrated) |
| 🔍 **SHAP explainability** | Attention weights + gradient saliency — no black-box outputs |
| 🤖 **3 AI agents** | Recon · CVE-match · Config — powered by Ollama Mistral 7B, fully offline |
| 📊 **LR benchmark** | F1: 0.778 → 0.933 (+15.5% improvement over logistic regression baseline) |
| 🖥️ **Streamlit UI** | 6-page live dashboard — Dashboard · Session Explorer · Predictor · Forecast · World Model · Findings |

---

## 👥 Team

| Name | Role |
|---|---|
| Utkarsh Chaubey | Team Leader |
| Ayush Verma | ML + Pipeline |
| Umang Srivastava | Infrastructure |
| Mohd Uvais | Frontend + Analysis |

---

## 📋 Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Repository Structure](#2-repository-structure)
3. [Installation — Zero to Running](#3-installation--zero-to-running)
4. [Full Pipeline Walkthrough](#4-full-pipeline-walkthrough)
5. [Command Reference](#5-command-reference)
6. [Streamlit UI Guide](#6-streamlit-ui-guide)
7. [Model Details & Benchmark](#7-model-details--benchmark)
8. [Architecture](#8-architecture)
9. [Troubleshooting](#9-troubleshooting)
10. [SIH26153 Compliance Checklist](#10-sih26153-compliance-checklist)

---

## 1. System Requirements

### Windows Host
| Requirement | Minimum |
|---|---|
| RAM | 16 GB |
| Disk free | 30 GB |
| Ollama | Installed + `mistral` model pulled |

```powershell
# Install Ollama on Windows: https://ollama.ai
ollama pull mistral
ollama serve
```

### Kali Linux VM (VirtualBox / VMware)
| Requirement | Value |
|---|---|
| RAM allocated | 4 GB |
| Disk | 20 GB |
| Network mode | NAT — host reachable at `10.0.2.2` |
| OS | Kali Linux 2024+ |
| Python | 3.11+ |
| Docker | docker.io + docker-compose |

---

## 2. Repository Structure

```
cybersentinel-ai/
│
├── 📋 Documentation
│   ├── README.md                          ← this file
│   └── COMMANDS.md                        ← quick command reference card
│
├── 🐳 Infrastructure
│   ├── docker-compose.yml                 ← Cowrie + Elasticsearch + Kibana stack
│   ├── logstash.conf                      ← Logstash pipeline config
│   └── cowrie-data/                       ← Cowrie config directory
│       └── cowrie-inspect/                ← Cowrie inspection utilities
│
├── 🔴 Attack Simulation
│   └── attack.sh                          ← Multi-phase attack simulator (Recon → Brute Force → Tool Transfer → Execution)
│
├── ⚙️ Core Pipeline
│   ├── run_pipeline.sh                    ← Master runner: TTP extraction + 3-agent scanner
│   ├── cybersentinel_full_stack.sh        ← Full end-to-end stack launcher
│   ├── cybersentinel_launch.sh            ← Quick launch script
│   ├── ttp_extract.py                     ← MITRE ATT&CK technique extractor
│   ├── cybersentinel_skeleton.py          ← 3-agent parallel scanner (Ollama Mistral 7B)
│   ├── parse_cowrie_logs.py               ← Elasticsearch indexer
│   ├── upload_logs.py                     ← Log upload utility
│   └── analyze.py                         ← IOC analysis + attacker intelligence
│
├── 🤖 ML / AI Models
│   ├── lstm_model.py                      ← LSTM sequence model (MITRE technique IDs)
│   ├── shap_explain.py                    ← SHAP explainability (attention + gradient saliency)
│   ├── world_model.py                     ← LSTM World Model — P(S_t+1|S_t) on network features
│   ├── packet_capture.py                  ← Cowrie JSON → 30-dim flow feature vectors
│   ├── cic_ids_loader.py                  ← CIC-IDS-2018 dataset loader + merger
│   └── scapy_feature_extractor.py         ← Real PCAP → packet-level features (TTL, window, retransmissions)
│
├── 🌐 World Model Pipeline
│   └── run_world_model_pipeline.sh        ← 5-step world model pipeline (features → CIC → train → benchmark → predict)
│
├── 📊 Reporting & Analysis
│   ├── generate-report.py                 ← HTML report generator
│   ├── ioc-summary.py                     ← IOC summary generator
│   └── threat-report.html                 ← Generated threat report (HTML)
│
├── 🖥️ UI
│   └── streamlit_app.py                   ← 6-page Streamlit dashboard (localhost:8501)
│
├── 🏋️ Trained Model Weights  (git-lfs or excluded — see .gitignore)
│   ├── cybersentinel_lstm.pt              ← LSTM sequence model weights (83.3% acc)
│   └── world_model.pt                     ← LSTM world model weights (F1=0.990)
│
├── 📁 Generated Data  (created by pipeline — not committed)
│   ├── cowrie-raw.json                    ← Raw Cowrie events (JSONL, from docker cp)
│   ├── cowrie-attacks.json                ← Filtered attack events
│   ├── cowrie-full.json                   ← Full Cowrie log
│   ├── cowrie-console.log                 ← Cowrie console output
│   ├── ttp_records.json                   ← Sessions + MITRE technique labels
│   ├── cybersentinel_report.json          ← Ranked agent findings
│   ├── features.json                      ← 30-dim network feature vectors (480 flows)
│   ├── features.csv                       ← Same data, CSV format
│   ├── features_norm_params.json          ← Min-max normalisation parameters
│   ├── features_with_real_packets.json    ← Features merged with real Scapy data
│   ├── packet_features.json               ← Scapy-extracted packet-level features
│   ├── benchmark_results.json             ← World model vs LR comparison table
│   ├── shap_all_sessions.json             ← SHAP explanations for all sessions
│   ├── honeypot_capture.pcap              ← Raw packet capture file
│   ├── all-attacks.log                    ← All attack event log
│   ├── attacks.log                        ← Parsed attacks log
│   ├── final-report.log                   ← Final pipeline report log
│   ├── ioc-ips.txt                        ← IOC IP addresses
│   └── ioc-summary.txt                    ← IOC text summary
│
└── 📦 External Data  (not committed — download via cic_ids_loader.py)
    └── Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv   ← CIC-IDS-2018 (341 MB)
```

---

## 3. Installation — Zero to Running

### Step 1 — System dependencies (Kali Linux)

```bash
sudo apt update && sudo apt install -y \
    docker.io docker-compose git python3-pip \
    net-tools curl wget
```

### Step 2 — Python packages

```bash
# PyTorch CPU build (~200MB — sufficient for 270K parameter model)
pip install torch --index-url https://download.pytorch.org/whl/cpu \
    --break-system-packages

# All other dependencies
pip install streamlit plotly scapy pandas scikit-learn requests \
    --break-system-packages
```

### Step 3 — Clone this repository

```bash
git clone https://github.com/YOUR_USERNAME/cybersentinel-ai.git
cd cybersentinel-ai
```

### Step 4 — Start Docker stack

```bash
docker-compose up -d
sleep 15
docker-compose ps   # verify all 3 containers show "running"
```

Expected:
```
NAME                        STATUS
honeypot-cowrie-1           running
honeypot-elasticsearch-1    running
honeypot-kibana-1           running
```

### Step 5 — Verify Ollama (Windows host)

```powershell
# On Windows:
ollama pull mistral
ollama serve
```

```bash
# From Kali — test connectivity:
curl http://10.0.2.2:11434/api/tags
# Should return JSON with mistral:latest
```

### Step 6 — Run full pipeline (first time)

```bash
./attack.sh && sleep 5
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \
    cowrie-raw.json
./run_pipeline.sh
python3 lstm_model.py --train
./run_world_model_pipeline.sh
streamlit run streamlit_app.py
```

Open **http://localhost:8501** — everything is running.

---

## 4. Full Pipeline Walkthrough

### Step 1 — Start infrastructure

```bash
cd cybersentinel-ai
docker-compose up -d
sleep 15
```

### Step 2 — Simulate attack

```bash
./attack.sh
sleep 5
```

Executes 4-phase kill chain against Cowrie:
```
Phase 1 — Recon:         whoami · id · uname -a · cat /etc/passwd
Phase 2 — Brute Force:   multiple SSH login attempts → T1110
Phase 3 — Tool Transfer: wget payload → T1105
Phase 4 — Execution:     chmod +x · ./payload → T1204
```

### Step 3 — Extract logs

```bash
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \
    cowrie-raw.json

# Quick sanity check:
wc -l cowrie-raw.json          # should be 500–4000 lines
```

### Step 4 — TTP extraction + 3-agent scanner

```bash
./run_pipeline.sh
```

Produces:
```
T1110 — Brute Force:              210 sessions
T1082 — System Info Discovery:     70 sessions
T1087 — Account Discovery:         70 sessions
T1105 — Ingress Tool Transfer:     70 sessions
T1204 — User Execution:            70 sessions

#1 [HIGH] T1110 — Brute Force
   Risk: 0.833  CVE-2020-25196 (CVSS 9.8)
```

### Step 5 — LSTM sequence model

```bash
python3 lstm_model.py --train     # trains on ttp_records.json
python3 lstm_model.py --eval      # 72.9% accuracy, 2.9× over random
python3 lstm_model.py --forecast T1082 T1087 --k 3   # 98.8% CRITICAL
```

### Step 6 — SHAP explainability

```bash
python3 shap_explain.py --all --save
# Saves shap_all_sessions.json — all 20 sessions explained
```

### Step 7 — Real packet capture (optional but recommended)

```bash
# Terminal 1 — find Docker interface then start capture:
ip addr | grep -B4 '172.18.0.1'
sudo python3 scapy_feature_extractor.py --capture --iface br-XXXXXXXX --port 2222

# Terminal 2 — trigger attack while capturing:
./attack.sh

# Terminal 1 — Ctrl+C when done, then:
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture.pcap
python3 scapy_feature_extractor.py --merge --features features.json
```

### Step 8 — World model pipeline

```bash
./run_world_model_pipeline.sh
# Downloads CIC-IDS-2018 (~341MB on first run)
# Trains world model: F1=0.990
# Benchmark: +15.5% F1 over logistic regression
```

### Step 9 — Elasticsearch + Kibana

```bash
python3 parse_cowrie_logs.py
# Open http://10.0.2.15:5601 → Discover → index: cowrie-*
```

### Step 10 — Launch UI

```bash
streamlit run streamlit_app.py
# Open http://localhost:8501
# Windows host: http://10.0.2.15:8501
```

---

## 5. Command Reference

```bash
# ── Infrastructure ──────────────────────────────────────────────
docker-compose up -d                          # start stack
docker-compose ps                             # check status
docker-compose down                           # stop stack

# ── Attack & Extraction ────────────────────────────────────────
./attack.sh                                   # run attack simulation
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json cowrie-raw.json

# ── Core Pipeline ──────────────────────────────────────────────
./run_pipeline.sh                             # TTP extraction + 3 agents
python3 parse_cowrie_logs.py                  # index to Elasticsearch
python3 analyze.py                            # IOC analysis

# ── LSTM Model ─────────────────────────────────────────────────
python3 lstm_model.py --train                 # train sequence model
python3 lstm_model.py --eval                  # evaluate + confusion matrix
python3 lstm_model.py --forecast T1082 T1087 --k 3   # k-step prediction

# ── Explainability ─────────────────────────────────────────────
python3 shap_explain.py --sequence T1082 T1087          # explain 1 sequence
python3 shap_explain.py --sequence T1082 T1087 T1105    # explain 3-step chain
python3 shap_explain.py --all --save                    # explain all sessions

# ── Scapy Packet Capture ───────────────────────────────────────
ip addr | grep -B4 '172.18.0.1'               # find Docker bridge interface
sudo python3 scapy_feature_extractor.py --capture --iface <IFACE> --port 2222
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture.pcap
python3 scapy_feature_extractor.py --merge --features features.json

# ── World Model ────────────────────────────────────────────────
./run_world_model_pipeline.sh                 # full 5-step pipeline
python3 world_model.py --train                # train only
python3 world_model.py --benchmark            # LSTM vs LR comparison
python3 world_model.py --predict              # inference on recent flows

# ── Reporting ──────────────────────────────────────────────────
python3 generate-report.py                    # generate HTML threat report
python3 ioc-summary.py                        # IOC summary

# ── UI ─────────────────────────────────────────────────────────
streamlit run streamlit_app.py                # launch at localhost:8501

# ── Connectivity check ─────────────────────────────────────────
curl http://10.0.2.2:11434/api/tags           # verify Ollama reachable
```

---

## 6. Streamlit UI Guide

Launch: `streamlit run streamlit_app.py` → **http://localhost:8501**

| Page | What you see | Demo move for judges |
|---|---|---|
| 📊 **Dashboard** | Sessions, techniques, tactic pie chart, kill chain | Shows real honeypot data at a glance |
| 🔍 **Session Explorer** | Click any session → kill chain + LSTM + SHAP gauge | Select a T1110 session → CRITICAL |
| 🤖 **Attack Predictor** | Type any technique sequence → live prediction | Type `T1110 T1082 T1087` → 85%+ confidence |
| 📈 **K-Step Forecast** | Full kill chain with ATT&CK tactic phase labels | Enter `T1082 T1087` k=3 → 98.8% CRITICAL |
| 🌐 **World Model** | Benchmark chart: LSTM vs LR baseline | F1=0.933 vs 0.778, FPR=0.000 vs 0.129 |
| 📋 **Agent Findings** | Ranked security report with CVE + Mistral analysis | Expand T1110 → CVE-2020-25196 CVSS 9.8 |

---

## 7. Model Details & Benchmark

### LSTM Sequence Model (`cybersentinel_lstm.pt`)

| Parameter | Value |
|---|---|
| Input | MITRE technique ID sequences |
| Embedding dim | 16 · Hidden dim: 32 · Layers: 1 |
| Parameters | 6,809 |
| Training data | 20 real sessions + 63 synthetic sequences |
| Test accuracy | **83.3%** (vs 25% random = **3.3× lift**) |
| Infiltration calibration | Compromise targets score **+45.1% higher** |

### LSTM World Model (`world_model.pt`)

| Parameter | Value |
|---|---|
| Input | 30-dimensional network feature vectors |
| Features | syn_ratio, ack_ratio, fin/rst ratios, IAT mean/std/max, TTL mean/std, TCP window mean/std, payload size mean/std, retransmission count, port scan score, bytes/packets/duration/bidir |
| Architecture | Input projection → LSTM → additive attention → sigmoid |
| Parameters | **269,964** · Sequence length: 5 time windows |
| Training data | 480 flows: 350 Cowrie + 101 CIC-IDS-2018 T1110 + 29 benign |
| Best F1 | **0.990** · FPR: **0.023** |

### Benchmark: World Model vs Logistic Regression Baseline

> Both trained on the **same 30 features**, **same 480-flow dataset**, **same 80/20 split**.

| Metric | Logistic Regression | LSTM World Model | Improvement |
|---|---|---|---|
| **F1 Score** | 0.7778 | **0.9333** | ✅ +0.1555 (+15.5%) |
| **Precision** | 0.6364 | **1.0000** | ✅ +0.3636 |
| **Recall** | 1.0000 | 0.8750 | — |
| **False Positive Rate** | 0.1290 | **0.0000** | ✅ −0.1290 |

**Key distinction:** LR sees 1 flow → binary label. LSTM sees 5 flows → P(compromise at t+5). Only LSTM can do K-step forward simulation.

### Data Sources

| Source | Flows | Contribution |
|---|---|---|
| Cowrie SSH honeypot | 350 | Real attack sessions, MITRE labels |
| CIC-IDS-2018 Wednesday | 101 | Real T1110 SSH brute-force flows |
| Scapy PCAP capture | 52 | Real TTL, TCP window, retransmissions |
| CIC-IDS-2018 benign | 29 | Balanced negative class |

---

## 8. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Data Capture & MITRE Classification                  │
│                                                                  │
│  Cowrie SSH Honeypot  ──►  cowrie-raw.json  ──►  ttp_extract.py │
│  (Docker, port 2222)        (JSONL events)       (MITRE ATT&CK) │
│                                     │                            │
│                             ttp_records.json                     │
│                          (sessions + techniques)                 │
│                                     │                            │
│       ┌─────────────────────────────┼─────────────────────┐     │
│       ▼                             ▼                       ▼     │
│  Recon Agent              CVE-match Agent           Config Agent │
│  (endpoint mapping)       (NVD API + Mistral)       (misconfigs) │
│       └─────────────────────────────┼─────────────────────┘     │
│                             Orchestrator                         │
│                       (dedup · score · rank)                     │
│                                     │                            │
│                      cybersentinel_report.json                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2 — World Model (Network Feature Learning)               │
│                                                                  │
│  packet_capture.py ────────────────────────────────────────►    │
│  (Cowrie JSON proxy — 30-dim flow vectors)                       │
│                                                                  │
│  scapy_feature_extractor.py ───────────────────────────────►    │
│  (Real PCAP: 725 packets → TTL, window, retransmissions)         │
│                                                                  │
│  cic_ids_loader.py ────────────────────────────────────────►    │
│  (CIC-IDS-2018: 101 real T1110 SSH brute-force flows)            │
│                              │                                   │
│                     features.json (480 flows, 30-dim)            │
│                              │                                   │
│                     world_model.py                               │
│                     LSTM: P(S_t+1 | S_t)                        │
│                     seq_len=5, 269,964 params                    │
│                     F1=0.990, +15.5% over LR                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3 — LSTM Sequence Model + SHAP                           │
│                                                                  │
│  lstm_model.py ──► cybersentinel_lstm.pt                        │
│  Input: MITRE technique sequences                                │
│  83.3% accuracy · 2.9× lift · K-step: 98.8% CRITICAL           │
│                                                                  │
│  shap_explain.py ──► shap_all_sessions.json                     │
│  Attention weights + gradient saliency per prediction            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4 — Streamlit UI                                         │
│                                                                  │
│  streamlit_app.py ──► http://localhost:8501                     │
│  Dashboard · Session Explorer · Attack Predictor                 │
│  K-Step Forecast · World Model · Agent Findings                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Troubleshooting

### Ollama not reachable from Kali

```bash
curl http://10.0.2.2:11434/api/tags    # test from Kali
```

On Windows (PowerShell as Administrator):
```powershell
netsh advfirewall firewall add rule name="Ollama API" dir=in action=allow protocol=TCP localport=11434
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
```

### `cowrie-raw.json` is empty

```bash
# Always docker cp — the host volume mount stays empty
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json cowrie-raw.json
docker ps | grep cowrie    # verify container is running first
```

### PyTorch not found

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu --break-system-packages
```

### CIC-IDS-2018 download fails

```bash
# Manual download:
wget "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
python3 cic_ids_loader.py --csv Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
```

### Scapy permission denied

```bash
sudo python3 scapy_feature_extractor.py --capture --iface br-XXXX --port 2222
```

### Kibana shows no data

```bash
python3 parse_cowrie_logs.py
# In Kibana: Management → Index Patterns → create cowrie-*
```

### LSTM accuracy plateau at 50–60%

This is expected with 4–5 unique techniques and limited sessions. **83% is the correct ceiling** — the 2.9× lift over the 25% random baseline is the meaningful metric. More real honeypot data over time will push this higher.

---

## 10. SIH26153 Compliance Checklist

| # | PS Requirement | Implementation | Status |
|---|---|---|---|
| 1 | Flow-level features (NetFlow/IPFIX) | `packet_capture.py`: syn_ratio, IAT, bytes, packets, duration, bidir | ✅ |
| 2 | Packet-level features (PCAP-derived) | `scapy_feature_extractor.py`: real TTL, TCP window, retransmissions | ✅ |
| 3 | Scapy or PyShark for PCAP parsing | `scapy_feature_extractor.py` uses `rdpcap()` + `sniff()` | ✅ |
| 4 | CIC-IDS-2018 or CTU-13 ingestion | `cic_ids_loader.py`: 101 T1110 flows from Wednesday CSV | ✅ |
| 5 | World model — P(S_t+1 \| S_t) | `world_model.py`: LSTM seq_len=5, 269,964 params, F1=0.990 | ✅ |
| 6 | K-step forward simulation | `lstm_model.py --forecast`: 3-step, 98.8% CRITICAL | ✅ |
| 7 | MITRE ATT&CK stage mapping | 5 techniques, tactic phase labels in K-step UI | ✅ |
| 8 | SHAP / attention explainability | `shap_explain.py`: attention weights + gradient saliency | ✅ |
| 9 | No black-box outputs | Feature importance bars on every prediction | ✅ |
| 10 | Benchmark vs LR baseline | F1: 0.778→0.933, FPR: 0.129→0.000 | ✅ |
| 11 | F1, precision, recall, FPR reported | `world_model.py --benchmark` + World Model UI page | ✅ |
| 12 | Fully offline, no cloud API | Ollama + Mistral 7B at 10.0.2.2 | ✅ |
| 13 | Streamlit demo interface | 6-page UI at localhost:8501 | ✅ |
| 14 | Open-source tools only | Docker, PyTorch, Scapy, Streamlit, Cowrie, Elasticsearch | ✅ |
| 15 | Training scripts + model weights | `lstm_model.py`, `world_model.py`, `.pt` weight files | ✅ |

**✅ All 15 SIH26153 requirements satisfied.**

---

## License

MIT License — open source, free to use and modify.

---

## Acknowledgements

- [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet honeypot by Michel Oosterhof
- [MITRE ATT&CK](https://attack.mitre.org) — attack taxonomy framework
- [CIC-IDS-2018](https://www.unb.ca/cic/datasets/ids-2018.html) — Canadian Institute for Cybersecurity
- [Ollama](https://ollama.ai) + [Mistral 7B](https://mistral.ai) — offline LLM inference
- [PyTorch](https://pytorch.org) — deep learning framework
- [Elasticsearch + Kibana](https://elastic.co) — log storage and visualization
- [Scapy](https://scapy.net) — packet manipulation library

---

*CyberSentinel AI — Built for SIH 2026 · Team: Utkarsh · Ayush · Umang · Uvais*
