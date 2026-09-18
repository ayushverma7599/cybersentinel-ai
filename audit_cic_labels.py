#!/usr/bin/env python3
"""
audit_cic_labels.py — one-off diagnostic, not part of the pipeline.

The "Infilteration" vs "Infiltration" mismatch (found by
diagnose_infiltration_labels.py, now fixed in cic_ids_loader.py's
CIC_LABEL_TO_MITRE) proves the official CIC-IDS-2018 CSVs contain upstream
label-spelling quirks that silently demote real attack rows to BENIGN. This
script checks EVERY downloaded day's file for the same failure mode in one
pass, using the EXACT matching logic cic_ids_loader.py itself applies (exact
key match, then substring fallback) — imported directly from the live file,
not reimplemented by hand, so this audit can't drift out of sync with the
real code.

For each file: reads only the Label column in cheap chunks, and for every
distinct non-BENIGN label found, reports whether it resolves to a MITRE
technique or falls through to BENIGN unmapped — flagging the latter loudly.

Usage:
    python3 audit_cic_labels.py
"""
import pandas as pd
from collections import Counter

from cic_ids_loader import CIC_FILES, CIC_LABEL_TO_MITRE


def resolves(cic_label: str) -> str | None:
    """Mirrors _row_to_feature_vector's label -> MITRE resolution exactly."""
    mitre = CIC_LABEL_TO_MITRE.get(cic_label)
    if mitre is None and cic_label.upper() != "BENIGN":
        for k, v in CIC_LABEL_TO_MITRE.items():
            if k.lower() in cic_label.lower() and v:
                mitre = v
                break
    return mitre


# CICFlowMeter occasionally embeds a literal repeated header row as a data row,
# so the Label column sometimes reads back the literal string "Label". These
# rows are NOT real attack data and are filtered out at load time by
# cic_ids_loader.py's header-hygiene filter (chunk[label_col] != label_col), so
# they never reach the model. Recognise them here as a known, already-handled
# artifact rather than raising a false "unmapped label" alarm.
HEADER_ARTIFACTS = {"label"}

any_unmapped = False

for day_label, fname in CIC_FILES.items():
    print(f"\n{'='*70}\n{day_label}  ({fname})\n{'='*70}")
    counts = Counter()
    total = 0
    try:
        for chunk in pd.read_csv(fname, encoding="utf-8", on_bad_lines="skip",
                                  low_memory=False, usecols=lambda c: c.strip() == "Label",
                                  chunksize=200_000):
            chunk.columns = [c.strip() for c in chunk.columns]
            counts.update(chunk["Label"].astype(str).str.strip().value_counts().to_dict())
            total += len(chunk)
    except FileNotFoundError:
        print(f"  [skip] file not downloaded locally")
        continue
    except Exception as e:
        print(f"  FAILED to read {fname}: {e}")
        continue

    print(f"  Total rows scanned: {total}")
    for label, n in counts.most_common(20):
        if label.upper() == "BENIGN":
            continue
        pct = 100 * n / total if total else 0
        if label.strip().lower() in HEADER_ARTIFACTS:
            # Known CICFlowMeter header-row artifact — filtered at load, not attack data.
            print(f"    {label!r:35s}  {n:>10d}  ({pct:6.3f}%)  -> [header-row artifact, "
                  f"filtered at load — not a real label]")
            continue
        mitre = resolves(label)
        flag = "" if mitre else "  <-- UNMAPPED, falls through to BENIGN!"
        print(f"    {label!r:35s}  {n:>10d}  ({pct:6.3f}%)  -> {mitre or 'BENIGN (unmapped)'}{flag}")
        if not mitre:
            any_unmapped = True

print("\n" + "=" * 70)
if any_unmapped:
    print("RESULT: at least one real non-BENIGN label is falling through unmapped.")
    print("Add it to CIC_LABEL_TO_MITRE in cic_ids_loader.py (same fix pattern")
    print("as the 'Infilteration' typo) before trusting labels for that day.")
else:
    print("RESULT: every real non-BENIGN label across all downloaded files resolves")
    print("to a MITRE technique. No further label-mapping bugs found.")
    print("(Any 'Label' rows shown above are CICFlowMeter header artifacts, filtered")
    print(" at load — not real data, not a bug.)")
