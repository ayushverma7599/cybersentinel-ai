#!/bin/bash
# fix_infiltration_labels.sh — apply the CIC_LABEL_TO_MITRE "Infilteration"
# fix to the already-merged dataset, without re-running the full 10-day
# merge (which would re-touch the 4GB Tuesday file for no reason).
#
# What this does:
#   1. Drops every existing row in features_all.json whose source is one of
#      the two Infiltration days (those rows were generated BEFORE the fix,
#      so ~50% of them are real attack flows mislabeled infiltration_label=0).
#   2. Re-loads both raw CIC CSVs with the SAME sampling parameters used by
#      merge_cic_data.sh (max-rows=5000, seed=42) — now producing correctly
#      labeled rows, since load_cic_csv's row *selection* never depended on
#      the label mapping (only the label -> MITRE conversion did), the same
#      physical flows come back, just with the right infiltration_label this
#      time.
#   3. Appends the corrected rows back in as two contiguous per-day segments
#      (same `source` convention world_model.py's make_sequences() expects).
#   4. Re-normalises fresh and re-runs the benchmark.
#
# Run with: bash fix_infiltration_labels.sh
set -uo pipefail

python3 -c "
import json
from cic_ids_loader import load_cic_csv

with open('features_all.json') as f:
    combined = json.load(f)

before = len(combined)
DAYS = ['Wednesday-28-02-2018', 'Thursday-01-03-2018']
FILES = {
    'Wednesday-28-02-2018': 'Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv',
    'Thursday-01-03-2018':  'Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv',
}

kept = [r for r in combined if not any(str(r.get('source','')).startswith(f'cic_ids_2018:{d}') for d in DAYS)]
removed = before - len(kept)
print(f'[+] Removed {removed} stale (pre-fix) Infiltration-day rows')

new_rows = []
for day in DAYS:
    rows = load_cic_csv(FILES[day], max_rows=5000, seed=42, day_label=day)
    for r in rows:
        r['source'] = f'cic_ids_2018:{day}'
    print(f'[+] Re-generated {len(rows)} rows for {day} with corrected labels')
    new_rows.extend(rows)

n_attack = sum(1 for r in new_rows if r.get('infiltration_label') == 1)
print(f'[+] {n_attack}/{len(new_rows)} newly-generated rows now correctly carry infiltration_label=1')

combined = kept + new_rows
with open('features_all.json', 'w') as f:
    json.dump(combined, f, indent=2)
print(f'[+] features_all.json: {before} -> {len(combined)} rows')
"

# Re-normalise fresh — feature VALUES for these rows are unchanged (same
# underlying flows), but re-running keeps this consistent with every other
# fix this session and costs nothing.
rm -f features_norm_params.json
python3 -c "
import json
from cic_ids_loader import normalise
with open('features_all.json') as f:
    feats = json.load(f)
feats = normalise(feats)
with open('features_all.json', 'w') as f:
    json.dump(feats, f, indent=2)
print(f'[+] Re-normalised {len(feats)} combined rows')
"

# Re-run the PS-required LR-vs-LSTM benchmark against the corrected data.
python3 world_model.py --benchmark --features features_all.json
