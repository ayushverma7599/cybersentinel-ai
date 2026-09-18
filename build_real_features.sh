#!/bin/bash
# build_real_features.sh — build features_with_real_packets.json from the MOST
# RECENT attack1.sh run, guaranteeing the Cowrie log and the pcap are from the
# SAME run.
#
# WHY THIS EXISTS: the #1 cause of "0/155 rows now have REAL packet-level
# features" is mixing runs — extracting a pcap from one attack run but merging
# it against a features_honeypot_fresh.json built from a DIFFERENT run's Cowrie
# log. The two runs have different ephemeral source ports, so nothing matches.
# packet_capture.py reads the REAL Cowrie src_port (cowrie.session.connect), and
# scapy reads the REAL wire src_port, so when both come from the same run they
# line up — this script just makes "same run" impossible to get wrong by doing
# the whole chain in one shot, in the right order.
#
# USAGE (cleanest match — do this for a demo / the report):
#   docker-compose restart cowrie && sleep 10   # fresh log = ONE run in it
#   ./attack1.sh                                 # attacks AND self-captures the
#                                                #   matching pcap
#   ./build_real_features.sh                     # <-- run immediately after
#
# The restart matters because Cowrie's log is append-only: if the container has
# been up across several attack runs the log holds ALL of them, but the pcap is
# only the latest run — so without a restart, only the latest run's sessions
# match and the rest stay (honestly) imputed. A restart makes it ~1:1.
#
# Do NOT run a separate manual `scapy --capture` — attack1.sh already captured
# the matching pcap. A separate capture is a different run and will match 0 rows.
set -uo pipefail
cd "$(dirname "$0")"

COWRIE_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i cowrie | head -1)
if [ -z "$COWRIE_CONTAINER" ]; then
  echo "[!] No running cowrie container found. Start it first: docker-compose up -d"
  exit 1
fi

if [ ! -f honeypot_capture.pcap ]; then
  echo "[!] honeypot_capture.pcap not found."
  echo "    Run ./attack1.sh first — it self-captures and copies its pcap to that name."
  exit 1
fi

# Sanity: the pcap should be recent (from the run you just did). Warn if it's old.
if [ -n "$(find honeypot_capture.pcap -mmin +30 2>/dev/null)" ]; then
  echo "[warn] honeypot_capture.pcap is more than 30 minutes old — if you ran"
  echo "       attack1.sh longer ago than that, its ports may not match the log"
  echo "       you're about to pull. Re-run ./attack1.sh for a clean match."
fi

echo "[1/4] Pulling THIS run's Cowrie log from ${COWRIE_CONTAINER}..."
docker cp "${COWRIE_CONTAINER}:/cowrie/cowrie-git/var/log/cowrie/cowrie.json" cowrie-raw.json
echo "      $(wc -l < cowrie-raw.json) log lines"

echo "[2/4] Rebuilding honeypot flow features from THIS run's log (real Cowrie src_ports)..."
python3 packet_capture.py --cowrie cowrie-raw.json --out-json features_honeypot_fresh.json --no-norm

echo "[3/4] Extracting real packet features from honeypot_capture.pcap..."
python3 scapy_feature_extractor.py --extract --pcap honeypot_capture.pcap --out packet_features.json --port 2222

echo "[4/4] Merging real packet features onto this run's flows (matched by src_port)..."
python3 scapy_feature_extractor.py --merge --out packet_features.json --features features_honeypot_fresh.json

# Report the real-capture count from the merged output, so success/failure is
# unambiguous without re-reading the merge's own stdout.
REAL=$(python3 -c "
import json
try:
    rows = json.load(open('features_with_real_packets.json'))
    real = sum(1 for r in rows if str(r.get('packet_features_source','')).startswith('real_scapy'))
    print(f'{real}/{len(rows)}')
except Exception as e:
    print('ERROR:', e)
")
echo ""
echo "================================================================"
echo "  features_with_real_packets.json written — ${REAL} rows have REAL packet features"
echo "================================================================"
case "$REAL" in
  0/*)
    echo "  Still 0 matched. The pcap and the Cowrie log are from different runs."
    echo "  Cowrie's log is append-only, so if the container has been up across"
    echo "  several attack runs the log holds them all, but the pcap is only the"
    echo "  latest run. For the cleanest match, restart Cowrie fresh, then run"
    echo "  exactly one attack:"
    echo "      docker-compose restart cowrie && sleep 10"
    echo "      ./attack1.sh"
    echo "      ./build_real_features.sh"
    ;;
  *)
    echo "  Next: bash merge_cic_data.sh   (it will use this file as the honeypot base)"
    ;;
esac
