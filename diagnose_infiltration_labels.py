#!/usr/bin/env python3
"""
diagnose_infiltration_labels.py — one-off diagnostic, not part of the pipeline.

generalization_test.py just reported AUC=0.0 / F1=0.0 / precision=0.0 /
recall=0.0 for BOTH the LR baseline and the LSTM on the held-out
"Infiltration (T1105)" category — identical zeros for both models is the
signature of "every row in the held-out test set has infiltration_label=0",
not "the models failed to learn." Confirmed already: 10,000/10,000 sampled
Infiltration-day rows in features_all.json have infiltration_label=0.

This script finds out WHY, straight from the two raw CIC-IDS-2018 CSVs
(Wednesday-28-02-2018 and Thursday-01-03-2018), by reading only the Label
column in chunks (cheap — no full-file load) and printing every distinct
label string found, with counts. Two possible root causes this will
distinguish between:

  (a) The raw files genuinely contain ~0 infiltration-attack flows (CIC-IDS-2018's
      Infiltration days are documented as extremely low-volume attacks, unlike
      the flood-style DoS/DDoS days) — in which case this is a data scarcity
      / representativeness gap, not a code bug.
  (b) The raw Label string doesn't match "Infiltration" the way
      cic_ids_loader.py's CIC_LABEL_TO_MITRE dict expects (e.g. a spelling
      variant, the same kind of upstream-typo issue already found once in
      this dataset with "Thuesday" vs "Tuesday") — in which case real
      attack rows exist but are being silently mapped to BENIGN and this is
      a fixable code bug.

Usage:
    python3 diagnose_infiltration_labels.py
"""
import pandas as pd
from collections import Counter

FILES = [
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
]

for fname in FILES:
    print(f"\n{'='*70}\n{fname}\n{'='*70}")
    counts = Counter()
    total = 0
    try:
        for chunk in pd.read_csv(fname, encoding="utf-8", on_bad_lines="skip",
                                  low_memory=False, usecols=lambda c: c.strip() == "Label",
                                  chunksize=200_000):
            chunk.columns = [c.strip() for c in chunk.columns]
            counts.update(chunk["Label"].astype(str).str.strip().value_counts().to_dict())
            total += len(chunk)
    except Exception as e:
        print(f"  FAILED to read {fname}: {e}")
        continue

    print(f"  Total rows scanned: {total}")
    for label, n in counts.most_common(20):
        pct = 100 * n / total if total else 0
        print(f"    {label!r:40s}  {n:>10d}  ({pct:.4f}%)")

print("\nCompare each non-BENIGN label string above against cic_ids_loader.py's")
print("CIC_LABEL_TO_MITRE dict (grep -n 'Infiltration' cic_ids_loader.py). If the")
print("exact string here isn't a key there, that's the bug — real attack rows")
print("are silently falling through to BENIGN.")
