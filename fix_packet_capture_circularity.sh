#!/bin/bash
# fix_packet_capture_circularity.sh — propagate the packet_capture.py
# circularity fix (COWRIE_PROXY_* constants replacing label-bucketed
# syn_ratio/ack_ratio/has_*/retransmission_count) through to the live
# dataset and every downstream artifact that depends on it.
#
# What this does:
#   1. Regenerates all honeypot-derived flow features from the raw Cowrie
#      log with the now-fixed packet_capture.py.
#   2. Re-overlays the 170 rows that have REAL scapy packet-capture data
#      (packet_features_v4.json, already extracted — untouched by this fix,
#      no need to re-extract from the pcap) on top of the freshly-fixed
#      base, so real measurements still take precedence over imputed
#      constants wherever we actually have them.
#   3. Replaces all 1,983 existing source="cowrie_proxy" rows in
#      features_all.json with the corrected set (same row count expected —
#      same input log, only the fabricated fields changed).
#   4. Re-normalises fresh and re-runs the benchmark.
#
# Run with: bash fix_packet_capture_circularity.sh
set -uo pipefail

# Step 1: regenerate honeypot flow features with the fixed code.
python3 packet_capture.py --cowrie cowrie-raw.json \
    --out-json features_honeypot_fixed.json --no-norm

# Step 2: re-overlay the real scapy packet-capture rows (unchanged by this
# fix — reusing the existing extraction, no need to re-run --extract).
python3 scapy_feature_extractor.py --merge \
    --out packet_features_v4.json --features features_honeypot_fixed.json
# merge_packet_features() always writes to features_with_real_packets.json
# regardless of --out (see scapy_feature_extractor.py's main()) — that's
# expected, not a bug.

# Step 3: swap the corrected honeypot rows into features_all.json in place.
python3 -c "
import json

with open('features_with_real_packets.json') as f:
    fixed_honeypot = json.load(f)
with open('features_all.json') as f:
    combined = json.load(f)

before = len(combined)
kept = [r for r in combined if str(r.get('source','')) != 'cowrie_proxy']
removed = before - len(kept)
print(f'[+] Removed {removed} pre-fix cowrie_proxy rows')
print(f'[+] Replacing with {len(fixed_honeypot)} corrected rows')

real_capture = sum(1 for r in fixed_honeypot if r.get('packet_features_source') == 'real_scapy_capture')
imputed = sum(1 for r in fixed_honeypot if r.get('packet_features_source') == 'cowrie_proxy_imputed'
              or r.get('packet_features_source') == 'unmatched_no_real_capture')
print(f'[+] {real_capture} rows carry real scapy packet data, {imputed} carry honest imputed constants')

combined = kept + fixed_honeypot
with open('features_all.json', 'w') as f:
    json.dump(combined, f, indent=2)
print(f'[+] features_all.json: {before} -> {len(combined)} rows')
"

# Step 4: re-normalise fresh — these rows' feature VALUES genuinely changed
# this time (not just labels, like the Infiltration fix), so this isn't
# optional.
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

# Step 5: re-run the PS-required benchmark against the corrected data.
python3 world_model.py --benchmark --features features_all.json
