# CyberSentinel AI — End-to-End Command Reference

The current, verified pipeline. Every command uses the correct files
(`features_all.json`, not the stale `features.json`) and the current scripts.

**Verified reference run:** 155 sessions → 17 MITRE techniques → 40
compromise-stage → 17 findings; real packet capture 154/155 (99.4%); combined
set 46,083 flows. Benchmark (3-seed mean): LR F1 0.784 / LSTM F1 0.779, LSTM
FPR 0.128 vs 0.214, and **lead-time ~24 flows earlier**. Generalization: 2
pass / 2 borderline / 2 fail. Numbers vary slightly with seed/dataset — the
scripts print mean ± std so you cite a range, not one figure.

Run everything from `~/honeypot` — every script uses relative paths.

---

## Part 1 — Infrastructure & Attack Capture

```bash
cd ~/honeypot
docker-compose up -d && sleep 15
docker-compose restart cowrie && sleep 10
chmod +x attack1.sh build_real_features.sh
```
Starts Cowrie + payload + Elasticsearch + Kibana, then restarts Cowrie so its
log holds exactly this run (its log is append-only — a fresh log is what makes
the real-packet match come out clean in Part 4).

```bash
./attack1.sh
```
Runs the primary 13-phase / 16-technique attack simulation AND self-captures a
matching packet trace, copying it to `honeypot_capture.pcap` on success. (The
simpler `attack.sh` — 4 phases, no built-in capture — still works if you prefer
it, but then you must capture manually; see Part 4 Step 2.)

The Cowrie log is pulled for you by `build_real_features.sh` (Part 4) and by
`run_pipeline.sh` (Part 2), so you don't normally `docker cp` by hand. To do it
manually: `docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ~/honeypot/cowrie-raw.json`.

---

## Part 2 — Core TTP Pipeline (MITRE classification + 3-agent scanner)

```bash
./run_pipeline.sh
```
Three steps in one command: re-pulls `cowrie-raw.json`, runs
`ttp_extract.py` to classify sessions against MITRE ATT&CK into
`ttp_records.json`, then runs `cybersentinel_skeleton.py`'s 3-agent scanner
(Recon / CVE-match / Config, all via the local Ollama Mistral 7B) to produce
`cybersentinel_report.json`.

```bash
python3 parse_cowrie_logs.py
```
Indexes every event into Elasticsearch. Browse at `http://10.0.2.15:5601`
(Discover → index `cowrie-*`) once this finishes.

```bash
python3 analyze.py
```
Independent IOC analysis — top attacking IPs, usernames, passwords, and
commands — separate from the MITRE classification above.

---

## Part 3 — LSTM Technique-Sequence Model, Forecasting, Explainability

This is the *separate* model from the flow-level World Model in Part 4 — it
operates on MITRE technique-ID sequences from `ttp_records.json`, not network
flow features.

```bash
python3 lstm_model.py --train
python3 lstm_model.py --eval
```
Trains the technique-sequence LSTM on your captured sessions plus synthetic
sequences, then evaluates it (accuracy vs. random baseline, confusion matrix,
infiltration-probability calibration). Re-run `--train` whenever
`ttp_records.json` changes.

```bash
python3 lstm_model.py --forecast T1082 T1087 --k 3
```
K-step forward simulation from an observed technique sequence. Example real
output from this session: starting at `T1082 → T1087`, the model forecast
`T1059 → T1548 → T1489` with a final infiltration probability of **72.8%
(HIGH)**. Swap in any starting sequence or `--k` value — the forecast is
stochastic on the trained weights, so exact numbers will vary run to run.

```bash
python3 shap_explain.py --all --save
```
Explains every session in `ttp_records.json` using LSTM attention weights +
gradient saliency, ranks them by risk, and saves `shap_all_sessions.json`
(155 sessions in the reference run, flagging the highest-risk distinct chains).

---

## Part 4 — World Model Pipeline (flow-level features, the PS-required part)

This is the section that changed the most. Every step below uses the fixed
code and produces `features_all.json` — the single dataset that training,
benchmarking, generalization testing, and the Streamlit demo all read from.

### Step 1 — Honeypot flow features (now circularity-free)

```bash
python3 packet_capture.py --cowrie cowrie-raw.json \
    --out-json features_honeypot_fresh.json --no-norm
```
Converts Cowrie sessions into 30-dimensional flow feature vectors.
Previously, several fields (`syn_ratio`, `ack_ratio`, TCP flags,
`retransmission_count`) were fabricated by bucketing on the same
login-attempt logic that also set the label — a circularity bug, now fixed.
Cowrie has zero real packet-layer visibility, so these fields are now
honestly imputed with fixed constants grounded in real observed data (see
the `COWRIE_PROXY_*` constants in `packet_capture.py`), tagged
`packet_features_source: "cowrie_proxy_imputed"` for full auditability.

### Step 2 — Real packet capture (optional, but recommended if you can)

**Use one script — it does the whole aligned chain for you and can't mix runs:**
```bash
docker-compose restart cowrie && sleep 10   # fresh log = exactly ONE run in it
./attack1.sh                                 # attacks AND self-captures the pcap
./build_real_features.sh                     # pull log → rebuild → extract → merge
```
`build_real_features.sh` pulls **this** run's Cowrie log, rebuilds
`features_honeypot_fresh.json` from it, extracts the packets from
`honeypot_capture.pcap` (which attack1.sh just wrote for the same run), merges
them, and prints the real-match count. It writes `features_with_real_packets.json`
with every row tagged `real_scapy_capture` or
`cowrie_proxy_imputed`/`unmatched_no_real_capture`, so it's always clear which is which.

**Why the three steps in that order matter — this is what caused every `0/155`.**
The merge matches a honeypot flow to a captured packet by source port. That only
works when the Cowrie log and the pcap are from the **same run** — different runs
use different ephemeral ports and match nothing (the extractor even prints "sample
ports look completely different"). `packet_capture.py` reads the *real* Cowrie
`src_port` and scapy reads the *real* wire port, so a same-run pair genuinely lines
up. The earlier `0/155` runs failed because `features_honeypot_fresh.json` was built
from an **old** `cowrie-raw.json` while the pcap was a **new** capture. The script
removes that trap by rebuilding the features from the same log it just pulled. The
`restart cowrie` matters because Cowrie's log is append-only: without it, an old
run's sessions linger in the log and dilute the match.

**Do NOT run a separate manual `scapy --capture`** — attack1.sh already captured the
matching pcap; a separate capture is a different run and matches 0 rows. (If you
must capture manually for the simpler `attack.sh`, capture → run that same attack →
then run `build_real_features.sh`, never a capture from one run against a log from
another.)

You no longer need the old `cp features_honeypot_fresh.json features_with_real_packets.json`
fallback at all — `merge_cic_data.sh` in Step 3 auto-selects whichever honeypot base
has the most real-capture rows and prints the count, so it can't be tricked into
using an all-imputed file. If a real capture genuinely isn't possible, just skip to
Step 3; the pipeline runs fine on honest imputed constants.

### Step 3 — Full 10-day CIC-IDS-2018 integration

```bash
bash merge_cic_data.sh
```
Downloads (if not already present — this is ~5GB total across all 10 days,
resumable if interrupted) and merges all 10 CIC-IDS-2018 days — all 6 attack
categories (Brute Force, DoS, DDoS, Web Attacks, Infiltration, Botnet), not
just one day — on top of `features_with_real_packets.json`, re-normalizes
the full combined set fresh, and trains the World Model. Produces the final
`features_all.json` (46,083 rows in the reference run). This script already
has the CIC-IDS-2018 "Thuesday" filename typo and the `Infilteration` label
mapping baked in as fixes — no manual patching needed on a fresh run.

### Step 4 — Benchmark (LR baseline vs. LSTM World Model)

```bash
python3 world_model.py --benchmark --features features_all.json --repeat 3
```
The direct SIH26153 requirement: trains a fresh Logistic Regression baseline
and a fresh LSTM World Model on identical features, reports F1 / precision /
recall / FPR / AUC-ROC for both, and saves `benchmark_results.json`.

Two things changed here and both matter for the report:

- **Checkpoint selection is now on a validation split, not the test set.** The
  LSTM's reported test metrics are taken at the epoch chosen by a held-out
  validation set carved from training — not the best-ever test epoch. That
  removes a test-set-peeking bias that used to both inflate the number and
  make it swing run-to-run.
- **`--repeat 3` reports the F1 improvement as mean ± std across 3 seeds**, plus
  the per-seed range. Cite the *range*, not one lucky run — a single LSTM run
  varies with initialisation at this data size. The benchmark also prints a
  **lead-time analysis**: how many flows earlier the LSTM raises a correct
  compromise alert than the static LR baseline (LR can't warn ahead of the
  attack flow by construction — this is the World Model's real differentiator).

Reference-run result: LR F1 0.784 vs LSTM F1 0.779 (a tie on raw F1), but LSTM
FPR 0.128 vs 0.214 and **lead-time 25.5 flows vs 1.5 — ~24 flows of early
warning**. Cite lead-time + FPR + K-step forecasting as the differentiator, not
the F1 number. Exact figures shift slightly by seed; the script prints the
range.

### Step 5 — Held-out category generalization test

```bash
python3 generalization_test.py --features features_all.json --repeat 3
```
Holds out each of the 6 CIC-IDS-2018 attack categories *entirely* from
training (zero rows trained on) and evaluates both models purely on the
excluded category, one at a time, then prints a consolidated summary table.
This is what demonstrates the model generalizes to genuinely unseen attack
types rather than memorizing per-category signatures — stronger evidence
than the standard chronological-split benchmark above.

Same two fixes as the benchmark apply here: checkpoint selection is on a
validation split (not the held-out category itself), and `--repeat 3` reports
each category's held-out AUC as **mean ± std across 3 seeds** with a
three-way verdict — **pass / borderline / FAIL** — instead of a brittle
single-run yes/no. "Borderline" is the honest label for a category sitting
right at the 0.6 chance line within its seed spread (that's why some
categories appeared to "flip" between earlier single-run tests); a stable
FAIL (Infiltration has been one) is a real weak spot to disclose, not hide.
Takes a while — a full LSTM training pass per category × 6 categories ×
`--repeat`, default 40 epochs each. Drop `--repeat` (or set it to 1) for a
faster single-seed smoke run.

### Step 6 — Live inference / prediction

```bash
python3 world_model.py --predict --features features_all.json
```
Runs inference on the 5 most recent **real honeypot** flows and prints
attention-weighted feature importance alongside the prediction — the
"no black-box outputs" requirement for the flow-level model. It now defaults
to `--predict-source honeypot`, which filters to genuine honeypot rows before
taking the last 5. This fixes a misleading demo: after a full CIC merge, the
last rows of `features_all.json` are the last-*merged* CIC day (e.g. an
Infiltration day), not live honeypot traffic — the old default scored a canned
CIC row at ~99% and called it "live inference." Pass `--predict-source any` if
you deliberately want the raw last rows of the file.

---

## Part 5 — Verification / audit tools (not part of the required pipeline)

These were built this session to root-cause specific bugs. Keep them —
they're cheap to re-run and immediately catch a regression if any of the
raw CIC-IDS-2018 files change or get re-downloaded.

```bash
python3 audit_cic_labels.py
```
Scans every downloaded CIC-IDS-2018 file's `Label` column and flags any
non-BENIGN label string that doesn't resolve to a MITRE technique under the
live `CIC_LABEL_TO_MITRE` mapping — this is exactly what caught the
`Infilteration` typo. Clean run = no silent label-mapping bugs.

```bash
curl -s http://10.0.2.2:11434/api/tags
```
One-line check that the offline Ollama/Mistral service (used by the 3-agent
scanner in Part 2) is actually reachable before a live demo.

---

## Part 6 — UI

```bash
streamlit run streamlit_app.py
# http://localhost:8501  (or http://10.0.2.15:8501 from the Windows host)
```
6-page dashboard. The **World Model** page's live-inference section now
correctly loads `features_all.json` (fixed this session — it used to
silently default to a stale `features.json`). Requires `world_model.pt`
(from Part 4, Step 4) and `features_all.json` (from Part 4, Step 3) to both
exist.

---

## Minimum path — the exact clean end-to-end run

```bash
cd ~/honeypot
docker-compose up -d && sleep 15
docker-compose restart cowrie && sleep 10       # fresh Cowrie log = one clean run
chmod +x attack1.sh build_real_features.sh
./attack1.sh                                     # attacks AND self-captures the pcap
./build_real_features.sh                         # aligned real-packet features (→ 154/155)
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json cowrie-raw.json
./run_pipeline.sh
bash merge_cic_data.sh                            # auto-picks the richest honeypot base
python3 world_model.py --benchmark --features features_all.json --repeat 3
python3 generalization_test.py --features features_all.json --repeat 3
python3 world_model.py --predict --features features_all.json
streamlit run streamlit_app.py
```

Fast first pass: drop `--repeat 3` on the benchmark and generalization steps
(single seed) — much quicker, then add it back for the report's mean ± std.
