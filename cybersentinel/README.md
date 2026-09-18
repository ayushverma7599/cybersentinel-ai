# CyberSentinel v3 — Attack Forecaster & Classifier

A defensive (blue-team) model that reads **behavioural telemetry** from a
sensor (EDR / sandbox / honeypot) and predicts:

- **technique** — the likely next MITRE ATT&CK technique (forecasting head)
- **attack class** — ransomware, wiper, RAT, infostealer, botnet, cryptominer, APT, fileless, benign
- **malware family** — e.g. LockBit, Emotet, AsyncRAT
- **severity** — a 0–1 damage estimate

This is a **detector**, not attack tooling. Every "signal" it consumes is an
*observation* a defensive sensor already produces (e.g. "shadow copies were
deleted", "CPU load spiked", "N files encrypted"). The synthetic generator
emits labelled **feature sequences** — numbers and MITRE labels — to train the
classifier; it contains no functional malware.

## What changed vs. the original 8-technique LSTM

| Area | Before | Now |
|---|---|---|
| Techniques | 8 | ~40 across all 12 tactics |
| Labels | technique only | technique + attack class + family + severity |
| Features | technique sequence | + network, host/process, temporal & behavioural vectors |
| Architecture | LSTM | BiLSTM + multi-head attention + multi-task heads |
| Imbalance | none | inverse-freq loss weights + WeightedRandomSampler + label smoothing |

## Files

- `config.py` — taxonomy: techniques, tactics, attack classes, families, kill-chain templates, feature schema, hyperparameters
- `features.py` — index maps + numeric normalisation (pure NumPy)
- `synthetic_data.py` — generates labelled behavioural sequences for training
- `dataset.py` — sessions → padded tensors, class weights, balanced sampler
- `model.py` — `CyberSentinelV3` + hierarchical multi-task loss
- `train.py` — training loop, checkpointing
- `evaluate.py` — top-k, per-technique bars, confusion matrix, severity calibration
- `predict.py` — score one session → defender **alert** (forecast + response playbook)

## Setup

```bash
pip install -r requirements.txt      # torch + numpy
```

CPU is fine for the default sizes. The data pipeline (config / features /
synthetic_data / dataset) runs without torch; only the model/train/evaluate/
predict steps need it.

## Run order

```bash
# 1. train (auto-generates class-balanced synthetic data if no --data)
python3 train.py --epochs 15 --sessions 6000

# 2. evaluate — prints the CYBERSENTINEL-style report
python3 evaluate.py --ckpt cybersentinel_v3.pt

# 3. inference — emit a defender alert for a session
python3 predict.py --ckpt cybersentinel_v3.pt
```

## Moving to real data (this is where accuracy actually comes from)

Synthetic data validates the pipeline; a production model needs real
telemetry. Keep the `Session` schema in `synthetic_data.py` and populate it
from:

- **Sandbox behavioural reports** — Cuckoo / CAPE / Hatching Triage (per-sample syscall, network, registry traces)
- **EDR / Sysmon logs** — process trees, command lines, file/registry ops
- **Honeypot capture** — Cowrie (SSH), Dionaea (droppers), Canary tokens (lateral movement)
- **Labelled PCAP datasets** — CTU-13 (botnet), CIC-IDS2018, UNSW-NB15 for network features
- **Threat-intel feeds** — MISP / OpenCTI to map observed IOCs → techniques & families

Then just point training at it:

```bash
python3 train.py --data sessions.json --epochs 30
```

## Notes / honest caveats

- Reported gains in earlier discussion are estimates; measure on held-out
  **real** data, not synthetic.
- Family-level labels are the hardest head; expect lower accuracy there until
  you have many real samples per family.
- Treat model output as decision support that a human analyst confirms, not an
  automatic block — false positives on production hosts are costly.
