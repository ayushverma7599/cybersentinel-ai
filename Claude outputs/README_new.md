# 🛡️ CyberSentinel AI

> **AI-Based Network Attack Forecasting from Network Traffic Data**
> SIH 2026 · Problem Statement **SIH26153** · Theme: Blockchain & Cybersecurity · PS Category: Software
> Team **Vertex**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-CPU-orange?style=flat-square)](https://pytorch.org)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-red?style=flat-square)](https://streamlit.io)
[![Offline](https://img.shields.io/badge/LLM-Ollama%20Mistral%207B-green?style=flat-square)](https://ollama.ai)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-black?style=flat-square)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

A threat-informed autonomous security system that **learns the evolving state of a network from traffic telemetry**, forecasts the progression of an attack **before compromise completes**, and gives defenders an interpretable, ranked, actionable report — **fully offline, zero cloud dependency**.

> **Security teams react *after* a breach. CyberSentinel forecasts the attack before it succeeds.**

---

## ✨ What it does

| Capability | Detail |
|---|---|
| 🍯 **Real attack capture** | Cowrie SSH honeypot in Docker captures live attacker sessions |
| 🎯 **MITRE ATT&CK mapping** | Classifies sessions into real ATT&CK techniques automatically (17 distinct techniques in the reference run) |
| 🌐 **World Model LSTM** | Learns P(Sₜ₊₁ \| Sₜ) — state-transition dynamics on 30 network features |
| 📈 **K-step forecasting** | Rolls the model forward to predict the attacker's next K moves |
| ⏱️ **Lead-time early warning** | Raises a correct alert **~24 flows earlier** than a static baseline |
| 🔍 **SHAP explainability** | Attention weights + gradient saliency — no black-box outputs |
| 🤖 **3 AI agents** | Recon · CVE-match · Config — powered by Ollama Mistral 7B, fully offline |
| 📊 **LR benchmark** | Honest LSTM-vs-Logistic-Regression comparison on identical data |
| 🖥️ **Streamlit UI** | 6-page live dashboard + PCAP upload for live inference |

---

## 📊 Verified results (latest clean end-to-end run)

**Reference run:** 155 attacker sessions → 17 MITRE ATT&CK techniques → 40 compromise-stage sessions → 17 ranked findings. Real packet capture matched **154/155 flows (99.4%)**. Combined training set: **46,083 flows** (Cowrie honeypot + all 10 CIC-IDS-2018 days).

### World Model vs Logistic Regression baseline
Same 30 features, same combined dataset, leakage-safe split, checkpoint selected on a **validation split** (not the test set), LSTM metrics reported as the **mean of 3 seeds**.

| Metric | Logistic Regression | LSTM World Model | Notes |
|---|---|---|---|
| F1 | **0.784** | 0.779 (±0.001) | tied on point classification |
| Precision | 0.744 | **0.815** | LSTM +7 pts |
| Recall | **0.828** | 0.746 | LR higher |
| False Positive Rate | 0.214 | **0.128** | LSTM ~40% fewer false alarms |
| **Lead-time (early warning)** | **1.5 flows** | **25.5 flows** | **LSTM warns ~24 flows earlier** (434 onsets) |

> **How to read this:** on raw F1 the two models are a tie — that is the *honest* result once test-set-peeking is removed. The World Model's value is the two things a static classifier **cannot do by construction**: **forecast future states (K-step)** and **raise an alert ~24 flows before compromise** (lead-time), plus a materially lower false-positive rate.

### Generalization (each attack category fully held out of training, 3 seeds)

| Held-out category | LR AUC | LSTM AUC (mean±std) | Verdict |
|---|---|---|---|
| DoS (T1499) | 0.861 | 0.862 ±0.036 | ✅ PASS |
| DDoS (T1498) | 0.846 | 0.906 ±0.002 | ✅ PASS |
| Brute Force (T1110) | 0.618 | 0.835 ±0.006 | 🟡 BORDERLINE |
| Web Attacks | 0.691 | 0.599 ±0.020 | 🟡 BORDERLINE |
| Infiltration (T1105) | 0.624 | 0.453 ±0.060 | ❌ FAIL |
| Botnet (T1071) | 0.859 | 0.308 ±0.023 | ❌ FAIL |

**2 pass / 2 borderline / 2 fail.** Disclosed honestly: on two fully-unseen categories (Infiltration, Botnet) the temporal model generalizes *worse* than the simple baseline — its sequence features overfit to trained categories. This is a real limitation, and reporting it is stronger than hiding it.

*Numbers vary slightly run to run with dataset composition and seed — the benchmark prints mean ± std so you always cite a range, not a single lucky figure.*

---

## 👥 Team Vertex

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
3. [Installation](#3-installation)
4. [Quick Start — Full End-to-End Run](#4-quick-start--full-end-to-end-run)
5. [Command Reference](#5-command-reference)
6. [Streamlit UI Guide](#6-streamlit-ui-guide)
7. [Model Details](#7-model-details)
8. [Architecture](#8-architecture)
9. [Troubleshooting](#9-troubleshooting)
10. [SIH26153 Compliance Checklist](#10-sih26153-compliance-checklist)

---

## 1. System Requirements

### Host (for Ollama / Mistral)
| Requirement | Minimum |
|---|---|
| RAM | 16 GB |
| Disk free | 30 GB (for full CIC-IDS-2018) |
| Ollama | Installed + `mistral` pulled |

```bash
# Install Ollama (https://ollama.ai), then:
ollama pull mistral
ollama serve
```

### Kali Linux VM
| Requirement | Value |
|---|---|
| RAM | 4 GB+ |
| Disk | 20 GB+ |
| Network | NAT — host reachable at `10.0.2.2` |
| Python | 3.11+ |
| Docker | docker.io + docker-compose |

---

## 2. Repository Structure

```
cybersentinel-ai/
│
├── Documentation
│   ├── README.md                       ← this file
│   └── COMMANDS.md                     ← full end-to-end command reference
│
├── Infrastructure
│   ├── docker-compose.yml              ← Cowrie + payload + Elasticsearch + Kibana
│   ├── payload_server.py               ← payload/exfil container endpoint (T1105/T1204/T1041)
│   └── logstash.conf                   ← Logstash pipeline config
│
├── Attack Simulation
│   ├── attack1.sh                      ← PRIMARY 13-phase / 16-technique simulator (self-captures pcap)
│   └── attack.sh                       ← simpler 4-phase simulator
│
├── Core Pipeline
│   ├── run_pipeline.sh                 ← TTP extraction + 3-agent scanner
│   ├── ttp_extract.py                  ← MITRE ATT&CK technique extractor
│   ├── cybersentinel_skeleton.py       ← 3-agent parallel scanner (Ollama Mistral 7B)
│   ├── parse_cowrie_logs.py            ← Elasticsearch indexer
│   └── analyze.py                      ← IOC analysis
│
├── ML / AI Models
│   ├── world_model.py                  ← LSTM World Model — P(Sₜ₊₁|Sₜ), benchmark, lead-time, predict
│   ├── generalization_test.py          ← held-out attack-category generalization test
│   ├── lstm_model.py                   ← LSTM technique-sequence model + K-step forecast
│   ├── shap_explain.py                 ← SHAP explainability (attention + gradient saliency)
│   ├── packet_capture.py               ← Cowrie JSON → 30-dim flow feature vectors
│   ├── scapy_feature_extractor.py      ← real PCAP → packet-level features
│   └── cic_ids_loader.py               ← CIC-IDS-2018 loader + merger
│
├── Data-build helpers
│   ├── build_real_features.sh          ← one-command aligned real-packet feature build
│   ├── merge_cic_data.sh               ← merge all 10 CIC days + train (auto-picks richest base)
│   └── audit_cic_labels.py             ← verifies no CIC label-mapping bugs
│
├── UI
│   └── streamlit_app.py                ← 6-page Streamlit dashboard (localhost:8501)
│
├── Trained weights  (large — .gitignore / git-lfs)
│   ├── world_model.pt                  ← LSTM world model weights
│   └── cybersentinel_lstm.pt           ← LSTM sequence model weights
│
└── Generated data  (created by the pipeline — not committed)
    ├── cowrie-raw.json                 ← raw Cowrie events (docker cp)
    ├── ttp_records.json                ← sessions + MITRE labels
    ├── cybersentinel_report.json       ← ranked agent findings
    ├── features_honeypot_fresh.json    ← honeypot-only flow features (this run)
    ├── features_with_real_packets.json ← honeypot features + real scapy packet data
    ├── features_all.json               ← FINAL combined set — train/benchmark/demo all use this
    ├── benchmark_results.json          ← LSTM-vs-LR + lead-time results
    ├── generalization_test_results.json← per-category held-out verdicts
    ├── shap_all_sessions.json          ← SHAP explanations
    └── honeypot_capture*.pcap          ← packet captures
```

External data (not committed): the 10 CIC-IDS-2018 day CSVs (~5 GB total), downloaded by `merge_cic_data.sh` / `cic_ids_loader.py`.

---

## 3. Installation

```bash
# System deps (Kali)
sudo apt update && sudo apt install -y docker.io docker-compose git python3-pip net-tools curl wget

# PyTorch (CPU build is enough)
pip install torch --index-url https://download.pytorch.org/whl/cpu --break-system-packages

# Everything else
pip install streamlit plotly scapy pandas scikit-learn requests --break-system-packages

# Clone
git clone https://github.com/YOUR_USERNAME/cybersentinel-ai.git
cd cybersentinel-ai

# Start the stack
docker-compose up -d && sleep 15
docker-compose ps          # cowrie, payload, elasticsearch, kibana should be running

# Verify offline LLM from Kali
curl http://10.0.2.2:11434/api/tags     # should list mistral:latest
```

---

## 4. Quick Start — Full End-to-End Run

This is the exact sequence used to produce the verified results above. Run from the repo root. **See [COMMANDS.md](COMMANDS.md) for the full annotated reference.**

```bash
# 1 — Infrastructure + attack (attack1.sh self-captures a matching pcap)
docker-compose up -d && sleep 15
docker-compose restart cowrie && sleep 10     # fresh log = one clean run in it
chmod +x attack1.sh build_real_features.sh
./attack1.sh

# 2 — Real packet features (one script, can't mix runs)
./build_real_features.sh                       # → features_with_real_packets.json (154/155 real)

# 3 — Core TTP pipeline + 3-agent scanner
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json cowrie-raw.json
./run_pipeline.sh
python3 parse_cowrie_logs.py
python3 analyze.py

# 4 — Technique-sequence LSTM + forecast + explainability
python3 lstm_model.py --train
python3 lstm_model.py --eval
python3 lstm_model.py --forecast T1082 T1087 --k 3
python3 shap_explain.py --all --save

# 5 — World Model (the PS-required part)
bash merge_cic_data.sh                                                       # → features_all.json (46k+ flows)
python3 world_model.py --benchmark --features features_all.json --repeat 3   # F1 mean±std + lead-time
python3 generalization_test.py --features features_all.json --repeat 3       # pass/borderline/FAIL
python3 world_model.py --predict --features features_all.json                # runs on real honeypot flows

# 6 — Verify + UI
python3 audit_cic_labels.py
curl -s http://10.0.2.2:11434/api/tags
streamlit run streamlit_app.py                 # http://localhost:8501
```

> `merge_cic_data.sh` and `--repeat 3` are the slow steps (full 10-day CIC merge; 3 LSTM trainings each). For a fast first pass, drop `--repeat 3`.

---

## 5. Command Reference

The complete, annotated command reference lives in **[COMMANDS.md](COMMANDS.md)**. Highlights:

```bash
# Infrastructure
docker-compose up -d / ps / down
docker-compose restart cowrie && sleep 10       # fresh Cowrie log

# Attack + capture (attack1.sh self-captures)
./attack1.sh
./build_real_features.sh                        # aligned real-packet feature build

# Core pipeline
./run_pipeline.sh                               # TTP extraction + 3 agents
python3 parse_cowrie_logs.py
python3 analyze.py

# Technique-sequence LSTM
python3 lstm_model.py --train
python3 lstm_model.py --eval
python3 lstm_model.py --forecast T1082 T1087 --k 3
python3 shap_explain.py --all --save

# World Model  (always pass --features features_all.json)
bash merge_cic_data.sh
python3 world_model.py --benchmark  --features features_all.json --repeat 3
python3 generalization_test.py      --features features_all.json --repeat 3
python3 world_model.py --predict    --features features_all.json   # --predict-source honeypot|any

# Audit / connectivity
python3 audit_cic_labels.py
curl http://10.0.2.2:11434/api/tags
```

---

## 6. Streamlit UI Guide

Launch `streamlit run streamlit_app.py` → **http://localhost:8501**

| Page | What you see |
|---|---|
| 📊 **Dashboard** | Sessions, techniques, tactic donut, reconstructed kill chain |
| 🔍 **Session Explorer** | Any session → sequence + LSTM next-step + SHAP gauge |
| 🤖 **Attack Predictor** | Type any technique sequence → live next-step prediction + drivers |
| 📈 **K-Step Forecast** | Roll the model forward K steps; infiltration-probability progression chart |
| 🌐 **World Model** | LSTM-vs-LR benchmark bars · **Upload PCAP for live inference** · Live World Model inference (real honeypot flows) |
| 📋 **Agent Findings** | Ranked findings from the 3-agent scanner, with CVE + Mistral analysis and remediation |

The World Model page loads `features_all.json` (the corrected combined dataset) and lets you upload a raw `.pcap` to run the trained model across sliding windows — genuine inference on traffic outside the training set.

---

## 7. Model Details

### LSTM World Model (`world_model.pt`) — the PS-required flow-level model
| Parameter | Value |
|---|---|
| Input | 30-dim network feature vectors (flow + packet level) |
| Architecture | input projection → 2-layer LSTM (hidden 128) → additive attention → sigmoid |
| Parameters | ~273,834 |
| Sequence length | 5 flows |
| Training data | 46,083 flows: Cowrie honeypot + all 10 CIC-IDS-2018 days |
| Selection | best epoch chosen on a **validation split**, reported on a held-out test set |
| Heads | infiltration probability · next-state vector · technique class |

### LSTM Sequence Model (`cybersentinel_lstm.pt`) — technique-ID forecasting
| Parameter | Value |
|---|---|
| Input | MITRE technique-ID sequences |
| Parameters | ~60,535 |
| Test top-1 | ~50% (12/24) vs 10% random = **5× lift** |
| Calibration | compromise targets score higher P(compromise) than non-compromise |
| K-step | `--forecast` rolls forward K steps (stochastic — numbers vary run to run) |

### Data sources & honesty notes
| Source | Contribution |
|---|---|
| Cowrie honeypot (`cowrie_proxy_imputed`) | Real attacker sessions + MITRE labels. Cowrie is an app-layer proxy with no packet visibility, so packet/TCP fields are **honestly imputed with fixed, real-data-grounded constants** (`COWRIE_PROXY_*` in `packet_capture.py`) — a constant carries zero discriminative signal, so it can't leak the label. |
| Real scapy capture (`real_scapy_capture`) | Genuinely measured TTL / TCP window / retransmissions / connection frequency — overrides imputed values wherever a real capture exists (154/155 flows in the reference run). |
| CIC-IDS-2018 (all 10 days) | External, independently-labeled data across all 6 attack categories + benign. |

---

## 8. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ PHASE 1 — Capture & MITRE Classification                     │
│ Cowrie honeypot ─► cowrie-raw.json ─► ttp_extract.py ─►       │
│                                       ttp_records.json        │
│        ┌───────────────┬───────────────┐                      │
│   Recon Agent     CVE Agent       Config Agent  (Mistral 7B)  │
│        └──────── Orchestrator (dedup·score·rank) ──────►       │
│                        cybersentinel_report.json              │
├──────────────────────────────────────────────────────────────┤
│ PHASE 2 — World Model (flow-level learning)                  │
│ packet_capture.py ┐                                           │
│ scapy_extractor   ├─► features_all.json (46k, 30-dim) ─►      │
│ cic_ids_loader    ┘        world_model.py                     │
│                            LSTM P(Sₜ₊₁|Sₜ), seq_len=5         │
│                            benchmark · lead-time · K-step     │
├──────────────────────────────────────────────────────────────┤
│ PHASE 3 — Technique-sequence LSTM + SHAP                     │
│ lstm_model.py ─► cybersentinel_lstm.pt (K-step forecast)      │
│ shap_explain.py ─► attention + gradient saliency             │
├──────────────────────────────────────────────────────────────┤
│ PHASE 4 — Streamlit UI (localhost:8501)                      │
│ Dashboard · Session Explorer · Attack Predictor ·            │
│ K-Step Forecast · World Model (+PCAP upload) · Findings      │
└──────────────────────────────────────────────────────────────┘
```

---

## 9. Troubleshooting

**Ollama not reachable from Kali** — `curl http://10.0.2.2:11434/api/tags`. On the host, serve with `OLLAMA_HOST=0.0.0.0 ollama serve` and allow port 11434 through the firewall.

**`cowrie-raw.json` empty** — always `docker cp` from the container (`docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json cowrie-raw.json`); the host volume stays empty.

**Real packet capture shows `0/155` matched** — the pcap and Cowrie log are from different runs. Use the aligned flow: `docker-compose restart cowrie && sleep 10` → `./attack1.sh` → `./build_real_features.sh`, nothing in between. Do **not** run a separate `scapy --capture`.

**attack1.sh Phase 3 skipped (payload unreachable)** — Cowrie's emulated `wget` can't always fetch from the payload container. Detection of T1105/T1204 still works from other command patterns; only the live file-transfer demo is affected. Diagnostic: `docker exec $(docker ps --format '{{.Names}}' | grep cowrie | head -1) wget -O- http://<payload-ip>:8000/payload.sh`.

**PyTorch missing** — `pip install torch --index-url https://download.pytorch.org/whl/cpu --break-system-packages`.

**Benchmark/generalization very slow** — `--repeat 3` trains the LSTM 3× (and 6× per category for generalization). Drop `--repeat` for a single-seed smoke run.

---

## 10. SIH26153 Compliance Checklist

| # | PS Requirement | Implementation | Status |
|---|---|---|---|
| 1 | Flow-level features (NetFlow/IPFIX) | `packet_capture.py`: syn/ack ratios, IAT, bytes, packets, duration, bidir | ✅ |
| 2 | Packet-level features (PCAP-derived) | `scapy_feature_extractor.py`: real TTL, TCP window, retransmissions (154/155 flows) | ✅ |
| 3 | Scapy / PyShark PCAP parsing | `scapy_feature_extractor.py` (`rdpcap` + `sniff`) | ✅ |
| 4 | CIC-IDS-2018 / CTU-13 ingestion | `cic_ids_loader.py`: full 10-day CIC-IDS-2018, all 6 attack categories | ✅ |
| 5 | World model — P(Sₜ₊₁\|Sₜ) | `world_model.py` LSTM, seq_len=5, 30 features | ✅ |
| 6 | K-step forward simulation | `lstm_model.py --forecast` + World Model K-step | ✅ |
| 7 | MITRE ATT&CK stage mapping | 17 techniques detected in the reference run | ✅ |
| 8 | SHAP / attention explainability | `shap_explain.py`: attention + gradient saliency | ✅ |
| 9 | No black-box outputs | feature-importance / attention on every prediction | ✅ |
| 10 | Benchmark vs LR baseline | `world_model.py --benchmark` (validation-selected, 3-seed mean±std) | ✅ |
| 11 | F1, precision, recall, FPR + generalization | benchmark table + held-out per-category verdicts + lead-time | ✅ |
| 12 | Fully offline, no cloud API | Ollama + Mistral 7B (7.2B, Q4_K_M) at `10.0.2.2:11434` | ✅ |
| 13 | Streamlit demo interface | 6-page UI + PCAP-upload live inference at localhost:8501 | ✅ |
| 14 | Open-source tools only | Docker, PyTorch, Scapy, Streamlit, Cowrie, Elasticsearch, Ollama | ✅ |
| 15 | Training scripts + model weights | `world_model.py`, `lstm_model.py`, `.pt` weights | ✅ |

---

## License

MIT License — open source, free to use and modify.

## Acknowledgements

[Cowrie](https://github.com/cowrie/cowrie) · [MITRE ATT&CK](https://attack.mitre.org) · [CIC-IDS-2018](https://www.unb.ca/cic/datasets/ids-2018.html) · [Ollama](https://ollama.ai) + [Mistral](https://mistral.ai) · [PyTorch](https://pytorch.org) · [Elasticsearch + Kibana](https://elastic.co) · [Scapy](https://scapy.net)

---

*CyberSentinel AI — Built for Smart India Hackathon 2026 · Team Vertex · Utkarsh · Ayush · Umang · Uvais*
