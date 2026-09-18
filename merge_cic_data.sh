#!/bin/bash
# merge_cic_data.sh — combine honeypot flows + all downloaded CIC-IDS-2018
# days into one training set for world_model.py.
#
# Run with: bash merge_cic_data.sh   (or: chmod +x merge_cic_data.sh && ./merge_cic_data.sh)
set -uo pipefail

rm -f features_norm_params.json

# ── Pick the honeypot base file (finding #3/#4 fix) ─────────────────────────
# The base is whichever candidate has the MOST rows tagged
# "real_scapy_capture". This defuses a footgun that silently discarded real
# packet-capture data before: the documented no-pcap fallback
# `cp features_honeypot_fresh.json features_with_real_packets.json` was, in at
# least one run, executed AFTER a successful capture+merge had already written
# real matches into features_with_real_packets.json — overwriting them with
# an all-imputed copy. Now the merge chooses the richer of the two files by
# actually counting real-capture rows, so a stray cp can't cost you your real
# data, and it prints the count loudly so an all-imputed base is obvious.
BASE_FILE=$(python3 - <<'PY'
import json, os
cands = ["features_with_real_packets.json", "features_honeypot_fresh.json"]
best, best_key = None, (-1, -1)
for c in cands:
    if not os.path.exists(c):
        continue
    try:
        rows = json.load(open(c))
    except Exception:
        continue
    real = sum(1 for r in rows
               if str(r.get("packet_features_source", "")).startswith("real_scapy"))
    print(f"[base-select] {c}: {len(rows)} rows, {real} real_scapy_capture")
    # Prefer more real-capture rows; break ties by total row count.
    key = (real, len(rows))
    if key > best_key:
        best, best_key = c, key
print("CHOSEN", best if best else "NONE")
PY
)
CHOSEN=$(echo "$BASE_FILE" | awk '/^CHOSEN /{print $2}')
echo "$BASE_FILE" | grep -v '^CHOSEN '
if [ -z "$CHOSEN" ] || [ "$CHOSEN" = "NONE" ]; then
  echo "[!] No honeypot base file found (need features_with_real_packets.json or features_honeypot_fresh.json)."
  echo "    Run Part 4 Step 1 of COMMANDS.md first (packet_capture.py --cowrie)."
  exit 1
fi
echo "[+] Using honeypot base: ${CHOSEN}"
cp "$CHOSEN" features_all.json

# day -> actual local CSV filename. Tuesday's real filename is misspelled
# upstream on S3 as "Thuesday" (confirmed by listing the bucket directly —
# a correctly-spelled request 404s) — see cic_ids_loader.py's CIC_FILES
# note for the same fix applied there.
declare -A CIC_CSV=(
  ["Wednesday-14-02-2018"]="Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Thursday-15-02-2018"]="Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Friday-16-02-2018"]="Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Tuesday-20-02-2018"]="Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Wednesday-21-02-2018"]="Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Thursday-22-02-2018"]="Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Friday-23-02-2018"]="Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Wednesday-28-02-2018"]="Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"
  ["Thursday-01-03-2018"]="Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
  ["Friday-02-03-2018"]="Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
)

for day in "${!CIC_CSV[@]}"; do
  csv="${CIC_CSV[$day]}"
  if [ -f "$csv" ]; then
    echo "=== merging $day ($csv) ==="
    python3 cic_ids_loader.py --csv "$csv" --merge features_all.json --out features_all.json --max-rows 5000 --no-norm
  else
    echo "=== skipping $day (file not found: $csv) ==="
  fi
done

# Recompute normalisation fresh, over the FULL combined honeypot+CIC dataset
# (not the stale params from the honeypot-only run) — otherwise CIC's real
# value ranges would be normalised against min/max computed before we ever
# saw them.
python3 -c "
import json
from cic_ids_loader import normalise
with open('features_all.json') as f:
    feats = json.load(f)
feats = normalise(feats)
with open('features_all.json', 'w') as f:
    json.dump(feats, f, indent=2)
print(f'[+] Normalised {len(feats)} combined rows')
"

python3 world_model.py --train --features features_all.json
