# CyberSentinel AI — Command Reference Guide (v2, updated for this session's fixes)

This is an updated version of the `COMMANDS_updated.md` you uploaded, corrected to
match the current state of the code after this session's work on the World Model
pipeline (split-methodology fixes, the two-attack-type CIC merge, the held-out
generalization test, and offline CVE caching). It is **not** written into
`~/honeypot`** — it's a standalone reference file for you to review and merge in
yourself.

Sections unchanged from your uploaded version are carried over as-is. Sections
marked **🆕 v2** are new or materially changed since that version. A corrected
PS-compliance verdict, and one important correction to a claim in the technical
PDF, are at the bottom.

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
- `honeypot-payload-1` — the payload server used by Phase 3 of `attack1.sh`. Fixed earlier this project (was crash-looping on a wrong path) — should show `Up` in `docker ps`.

---

```bash
sleep 15
```
Wait for all containers to fully initialize before sending any traffic. Unchanged.

---

## Attack Simulation

Unchanged from your uploaded version — `attack1.sh`, `run_campaign.sh`, and their flags were not touched this session. See your existing doc for details.

---

## Log Extraction

Unchanged from your uploaded version.

---

## Core Pipeline

Unchanged from your uploaded version — `run_pipeline.sh`, `ttp_extract.py`, `parse_cowrie_logs.py` were not touched this session.

---

## LSTM Attack Progression Model

*(Operates on MITRE technique-ID sequences from `ttp_records.json` — separate from, and a different architecture than, the World Model below.)*

Unchanged from your uploaded version — `lstm_model.py` was not touched this session. The "three separate MITRE technique registries" caveat it describes is still accurate and still unresolved.

---

## SHAP Explainability

Unchanged from your uploaded version — `shap_explain.py` was not touched this session.

---

## Real Packet Capture (Scapy)

Unchanged mechanically from your uploaded version — `scapy_feature_extractor.py` itself was not touched this session. **But read the correction at the very bottom of this document** — the packet-level data actually used in this session's World Model training and benchmarks did **not** come from this real-capture-and-merge workflow, despite an earlier claim to the contrary in the PDF documentation.

---

## World Model Pipeline

*(Operates on 30-dimensional network feature vectors over 5-flow time windows — the architecture SIH26153 explicitly requires.)*

### 🆕 v2 — Corrected step order, now using two full CIC-IDS-2018 attack days

Your uploaded doc's sequence merges one CIC-IDS-2018 file into `features.json` in place. This session instead built a **two-attack-type** corpus — SSH/FTP Brute Force (Wednesday) *and* DoS (Thursday) — because a single attack type wasn't enough to catch a real split-methodology bug (see below) or to run a meaningful generalization test. The verified, reproducible sequence:

```bash
cd ~/honeypot

# 1. Wednesday (SSH/FTP Brute Force, T1110) + your existing honeypot flows
python3 cic_ids_loader.py --csv Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv \
    --max-rows 10000 --merge features_honeypot_only.json \
    --out features_v2.json --day Wednesday-14-02-2018

# 2. Thursday (DoS GoldenEye/Slowloris, T1499) on top of that
python3 cic_ids_loader.py --csv Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv \
    --max-rows 10000 --merge features_v2.json \
    --out features_v3.json --day Thursday-15-02-2018

# 3. Recompute normalisation params fresh from the FULL combined set, then
#    re-run both loader steps so every row's *_norm columns use the fresh params
#    (this matters more once you're mixing genuinely different attack types —
#    see the note on this below)
python3 -c "
import json
data = json.load(open('features_v3.json'))
NUMERIC_FEATURES = ['bytes_total','packets_total','bytes_fwd','bytes_bwd','packets_fwd',
    'packets_bwd','flow_duration_ms','bidir_ratio','syn_ratio','ack_ratio','fin_ratio',
    'rst_ratio','has_syn','has_ack','has_fin','has_rst','has_psh','has_urg','iat_mean',
    'iat_std','iat_max','ttl_mean','ttl_std','tcp_window_mean','tcp_window_std',
    'payload_size_mean','payload_size_std','retransmission_count','port_scan_score',
    'unique_dst_ports']
params = {c: {'min': min(float(f.get(c,0)) for f in data),
              'max': max(float(f.get(c,0)) for f in data)} for c in NUMERIC_FEATURES}
json.dump(params, open('features_norm_params.json','w'), indent=2)
print('norm params regenerated from', len(data), 'rows')
"
python3 cic_ids_loader.py --csv Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv \
    --max-rows 10000 --merge features_honeypot_only.json \
    --out features_v2.json --day Wednesday-14-02-2018
python3 cic_ids_loader.py --csv Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv \
    --max-rows 10000 --merge features_v2.json \
    --out features_v3.json --day Thursday-15-02-2018
cp features_v3.json features.json

# 4. Train + benchmark
python3 world_model.py --benchmark --features features.json --epochs 60

# 5. Held-out attack-type generalization test (new this session — see below)
python3 generalization_test.py --features features.json --epochs 60
```

Important behavior changes in `cic_ids_loader.py` you should know about:
- `--merge` now expects **`features_honeypot_only.json`** — a clean, honeypot-only
  baseline with no CIC rows in it — not your live, possibly-already-CIC-merged
  `features.json`. Merging onto an already-merged file double-counts rows and
  breaks the segment structure the split logic depends on. If you don't have
  `features_honeypot_only.json`, extract it once with:
  ```bash
  python3 -c "
  import json
  data = json.load(open('features.json'))
  honeypot_only = [r for r in data if r.get('source') == 'cowrie_proxy']
  json.dump(honeypot_only, open('features_honeypot_only.json','w'), indent=2)
  print(len(honeypot_only), 'honeypot-only rows saved')
  "
  ```
- `--day <name>` sets the `source` field to `cic_ids_2018:<name>` (e.g.
  `cic_ids_2018:Thursday-15-02-2018`) instead of the old flat `cic_ids_2018`.
  This matters: `world_model.py`'s segment-aware windowing (below) groups
  contiguous rows by exact `source` string, so each CIC day now forms its own
  clean segment instead of being lumped in with every other CIC day.
- `--max-rows` is a **total** cap (split evenly benign/attack), scanned across
  the **entire** CSV in chunks now, not just the first slice of it — the old
  behavior only ever looked at the first `max_rows*3` rows of a multi-million-
  row file, which for a chronologically-ordered CSV meant only ever sampling
  from early in the day.
- The full 10-day `CIC_FILES` mapping (each day's MITRE technique) is in
  `cic_ids_loader.py` if you want to pull further days — see the generalization
  section below for why you might want to.

### 🆕 v2 — `world_model.py` split methodology, fixed twice this session

Three real bugs were found and fixed in sequence, each one changing the reported benchmark materially — worth knowing if you retrain and see numbers move:

1. **Train/test leakage** — the original split was `random.shuffle(indices)` over overlapping 5-flow sliding windows. Since consecutive windows share 4 of their 5 timesteps, this let near-duplicate windows land on both sides of the split. Fixed with `_purged_segment_split()`, which splits within each contiguous same-`source` segment and drops a `purge` gap around the boundary.
2. **Mislabeled brute-force rows** — `is_compromise`/`infiltration_label` were scoped to only the 10-class `COMPROMISE_TECHNIQUES` set, which doesn't include T1110 (Brute Force). Every CIC brute-force row was silently labeled "not an attack." Fixed by changing the condition to `mitre != "BENIGN"`.
3. **Chronological-tail split hides class shift** — even after (1) and (2), taking the "last 20% of the day, per source" as test still failed badly (F1 collapsed to ~0.10–0.45) the moment a second attack type (DoS) was added, because real attacks cluster in a specific time window rather than spreading evenly across 24 hours — so a tail slice can land almost entirely on one side of that cluster. `_purged_segment_split()` now chops each segment into 10 interleaved chronological blocks and spreads the test blocks across the whole segment instead of only taking the tail. This fix alone took the benchmark from F1 0.10 (LR) / 0.45 (LSTM) to the real numbers below.

Also added: `weight_decay=1e-4` on the Adam optimizer (every run before this showed test F1 peaking in the first few epochs then degrading — a classic overfitting signature; this flattens it), and the `benchmark()` function's `--epochs` flag is no longer silently hardcoded to 50 regardless of what you pass.

### 🆕 v2 — Held-out attack-type generalization test (`generalization_test.py`, new)

A fair train/test split (above) still evaluates on attack types that also appear
in training. This new script excludes Thursday's DoS traffic from training
**entirely** — trains only on honeypot + brute-force, evaluates purely on DoS
traffic the model has never seen a single row of:

```bash
python3 generalization_test.py --features features.json --epochs 60
```

Real, verified result: the logistic-regression baseline essentially fails to
transfer (AUC 0.56, barely above chance). The LSTM World Model retains genuine
signal (AUC 0.73, 96% precision when it flags something) but limited recall
(49% — misses about half the unseen attack). Report this as real, partial
evidence of generalization, not as solved — see the PS Compliance table below.

### 🆕 v2 — Current real benchmark numbers (20,885 combined flows)

Your uploaded doc's numbers (434 flows, LR F1=1.0000 vs LSTM F1=0.9873, LSTM
*losing*) are from a much smaller, single-attack-type, leakage-affected dataset
and no longer reflect reality. The current, independently-reproduced-on-two-
machines numbers, on the corrected 20,885-flow, two-attack-type, leakage-safe
pipeline above:

```
Metric          Logistic Regression   LSTM World Model
F1 Score              0.8249               0.9680
Precision             0.7736               0.9571
Recall                0.8834               0.9792
FPR                   0.1847               0.0313
```

**The LSTM now beats the logistic-regression baseline by +0.1431 F1 (+14.3%)** —
a real, credible, non-inflated result (the baseline itself is a solid 0.82 F1,
not an artificially weak strawman). Per-source test accuracy: honeypot 97.1%,
brute-force 96.0%, DoS 98.6%.

```bash
python3 world_model.py --predict --k 3
```
Unchanged mechanically from your uploaded doc — `k_step_forecast()`'s genuine
rollout behavior, output format, and example were not touched this session.

---

## UI

```bash
streamlit run streamlit_app.py
```
Same six pages as your uploaded doc describes, plus one addition:

- **Agent Findings** — 🆕 v2 the CVE-lookup panel now checks a local
  `cve_cache.json` before ever calling the live NVD API (see
  `prefetch_cve_cache.py`, new this session, described below). Everything else
  about this page is unchanged.

### 🆕 v2 — Offline CVE caching (`prefetch_cve_cache.py`, new)

The one piece of the whole pipeline with a real internet dependency was the CVE-match agent's live NVD lookup. Run this once, while you have internet access:

```bash
python3 prefetch_cve_cache.py
```

It fetches real NVD results for all 41 MITRE-technique keywords the CVE-match
agent can ever query, and saves them to `cve_cache.json`. After that,
`nvd_cve_lookup()` reads from the cache first and never needs a live network
call — the Streamlit CVE panel keeps showing real CVE data even fully offline
or air-gapped. Safe to re-run any time; already-cached keywords are skipped, so
it only fills gaps. Takes about a minute (rate-limited to ~1.5s/keyword).

**Recommend committing `cve_cache.json` to git** (unlike `features.json` and the
other generated files in your `.gitignore`) — it's small (a few KB), and
checking it in is what makes the demo genuinely portable to a judge's machine
with no internet at all, not just yours.

---

## PS Compliance — honest status against the SIH26153 requirements

| Requirement | Status | Notes |
|---|---|---|
| Learn state transition dynamics P(S_t+1\|S_t) from flow + packet-level features | **Partial — see correction below** | `world_model.py` genuinely models this via `fc_next_state`, and flow-level features are solid across all 20,885 rows. Packet-level features are a real gap, larger than previously stated: see the correction at the bottom of this document. |
| Forecast future states | **Met** | `k_step_forecast()` does genuine forward simulation through the model's own predicted next-state vectors. Unchanged this session. |
| Map forecasts to MITRE ATT&CK stages | **Met** | `fc_technique` is trained and its predictions, plus full tactic-level mapping (`ttp_extract.py`'s `TACTIC_MAP`), are surfaced in the UI. |
| SHAP / attention-based explainability | **Met** | `shap_explain.py` plus `world_model.py`'s own attention-weight output, wired into the live PCAP/CSV upload path too, not just historical sessions. |
| Benchmark vs. logistic-regression baseline showing measurable improvement | **🆕 v2 — Met** | Was the one open gap in your uploaded doc (LR beating LSTM 1.0000 vs 0.9873). Now genuinely met: LSTM beats LR by +14.3% F1 (0.9680 vs 0.8249) on a verified, leakage-safe, two-attack-type split — see the World Model Pipeline section above for exactly what was fixed to get there honestly. |
| Generalizes to unseen attack patterns, not memorized signatures | **🆕 v2 — New evidence, partial** | Wasn't tested at all in your uploaded doc. Now has one real, disclosed data point (`generalization_test.py`): LSTM AUC 0.73 vs. LR AUC 0.56 on a completely held-out attack type. Real signal, not solved — 49% recall on the unseen attack. |
| Offline demo interface accepting PCAP/CSV input | **Met** | Streamlit upload panel, unchanged this session. Its one internet dependency (live CVE lookups) is now also closed via `prefetch_cve_cache.py` above. |

**Bottom line: the benchmark requirement — the one your uploaded doc correctly
flagged as the clearest gap — is now genuinely closed.** The honest remaining
open item is packet-level feature coverage (below), which is a real, disclosed
limitation, not a blocker: flow-level features alone already carry the
20,885-row benchmark above.

---

## 🔴 Correction to a claim in the PDF documentation

While writing this update, checking the actual `source` field and packet-level
column values on the 885 honeypot rows currently in `features.json` turned up
something the delivered PDF states incorrectly. Sections 6.1 and 8.1 of
`CyberSentinel_AI_Technical_Documentation.pdf` say the 885 honeypot flows
"carry real, measured packet-level values" via a genuine Scapy capture-and-merge
workflow. **Checking the actual data shows this is not true of the current
training set**: every one of those 885 rows has `source: "cowrie_proxy"`, and
`ttl_mean`, `ttl_std`, `port_scan_score`, and `unique_dst_ports` are hardcoded
constants (64.0 / 0.0 / 0.0 / 1) for all of them — exactly the "Cowrie-JSON-
proxy fallback" your own uploaded doc's "Real Packet Capture" section warns
about, not the output of `scapy_feature_extractor.py --merge`. A few other
columns (`tcp_window_mean`, `payload_size_mean`, `retransmission_count`) do
carry some real variance, but derived from Cowrie's own session behavior
(login-attempt counts, payload lengths), not from an actual packet capture.

I checked `features_with_real_packets.json` on your machine too, since its name
implies it should be the genuinely-merged file — it shows the same constants,
so whatever real-capture merge produced it originally either never matched a
meaningful number of flows or has since been overwritten by a Cowrie-only
rebuild.

**Net effect**: the packet-level gap disclosed in the PDF (Section 8.1) is
real, but understated — it currently applies to essentially the whole training
set, not just the CIC-derived 96% of it. I'd like to correct the PDF's Sections
6.1 and 8.1 to state this accurately rather than leave the overclaim standing —
let me know if you'd like me to do that now, or if you'd rather run a real
`scapy_feature_extractor.py --capture` + `--merge` round first (per the "Real
Packet Capture" section above) so the claim becomes true instead of just
corrected.
