#!/bin/bash
# fix_and_rebenchmark.sh — regenerate real packet-level features with the
# now-fixed field names (ttl_std, payload_size_std, unique_dst_ports,
# port_scan_score), patch them into the existing combined honeypot+CIC
# dataset in place (no need to re-run the whole CIC merge), then re-run the
# LR-vs-LSTM benchmark against current, non-stale data.
#
# Run with: bash fix_and_rebenchmark.sh
set -uo pipefail

# Step 1: re-extract the SAME pcap with the fixed extract_features() —
# the capture itself hasn't changed, only what fields we compute from it.
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture_20260914_151746.pcap --out packet_features_v4.json --port 2222

# Step 2: re-merge into a fresh features_with_real_packets.json (this
# overwrites the one built earlier — that's expected, it's meant to be
# regenerated with the corrected fields).
python3 scapy_feature_extractor.py --merge --out packet_features_v4.json --features features_honeypot_v3.json

# Step 3: patch just the ~170 real-capture rows inside the existing
# features_all.json (honeypot + all 10 CIC days) with the corrected
# fields, instead of re-running the entire multi-GB CIC merge again.
python3 -c "
import json

with open('features_with_real_packets.json') as f:
    fresh = json.load(f)
with open('features_all.json') as f:
    combined = json.load(f)

fresh_by_port = {
    r['src_port']: r
    for r in fresh
    if r.get('packet_features_source') == 'real_scapy_capture'
}

FIELDS = ['ttl_mean', 'ttl_variance', 'ttl_std', 'tcp_window_mean',
          'payload_size_mean', 'payload_size_max', 'payload_size_std',
          'retransmission_count', 'distinct_dst_ports_from_src',
          'unique_dst_ports', 'port_scan_score']

patched = 0
for row in combined:
    if row.get('packet_features_source') == 'real_scapy_capture':
        src = fresh_by_port.get(row.get('src_port'))
        if src:
            for k in FIELDS:
                if k in src:
                    row[k] = src[k]
            patched += 1

with open('features_all.json', 'w') as f:
    json.dump(combined, f, indent=2)
print(f'[+] Patched {patched} real-capture rows in features_all.json with corrected fields')
"

# Step 4: re-normalise fresh, since these columns now carry real
# (non-default) values for the first time in the combined dataset.
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

# Step 5: the actual PS-required deliverable — LR baseline vs LSTM world
# model benchmark, run against today's fixed, non-circular, CIC-augmented
# dataset instead of the stale 16,708-row run from before today's fixes.
python3 world_model.py --benchmark --features features_all.json
