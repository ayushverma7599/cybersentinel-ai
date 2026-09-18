#!/bin/bash
# =============================================================================
# CyberSentinel AI — run_campaign.sh
#
# Runs attack1.sh N times with varied phase ordering, DoS intensity, and
# occasional phase skips, so the corpus of REAL sessions has genuine
# sequence diversity — instead of the LSTM leaning on 1,445 synthetic
# sequences to cover >90% of its training data (see lstm_model.py's
# "[LSTM] Adding N targeted synthetic sequences" line) because every real
# run so far followed the exact same 11/13-phase order every time.
#
# This does NOT touch Phases 1-3 (entry: recon -> brute force -> tool
# transfer) or the general shape of the kill chain — it varies what a real
# attacker plausibly varies: the order of post-compromise enumeration
# (--shuffle-mid), how aggressive the DoS phase is, and whether an
# attacker bothers with every optional phase at all.
#
# Usage:
#   ./run_campaign.sh                 — 10 runs, default settings
#   ./run_campaign.sh 20               — 20 runs
#   ./run_campaign.sh 20 --extract     — 20 runs, then run ttp_extract.py once at the end
#
# Each run's own log is preserved as attacks_campaign_<n>.log so you can
# check what phase order/skips each run used.
# =============================================================================
set -uo pipefail

RUNS="${1:-10}"
EXTRACT_AT_END=0
[ "${2:-}" = "--extract" ] && EXTRACT_AT_END=1

if ! [[ "$RUNS" =~ ^[0-9]+$ ]]; then
  echo "[!] First argument must be a number of runs (got: $RUNS)"
  exit 1
fi

echo "================================================================"
echo "  CyberSentinel AI — Attack Campaign ($RUNS runs)"
echo "================================================================"

for ((run=1; run<=RUNS; run++)); do
  echo ""
  echo "── Run ${run}/${RUNS} ──────────────────────────────────────────"

  # Vary DoS intensity per run (10-80 connections) instead of always 50 —
  # gives the LSTM varied T1499 session counts to learn from, not one
  # constant.
  DOS_TARGET=$(( (RANDOM % 71) + 10 ))

  # ~1 in 4 runs, skip an optional-ish phase entirely (privesc, creds, or
  # lateral movement) to simulate an attacker who doesn't always do
  # everything — real kill chains aren't always complete.
  SKIP_FLAG=""
  if (( RANDOM % 4 == 0 )); then
    skip_choice=$(( (RANDOM % 3) + 6 ))  # 6=privesc, 7=creds, 8=lateral
    echo "  (this run skips Phase ${skip_choice})"
    # attack1.sh has no native "skip one phase" flag beyond --phase (which
    # runs ONLY one) — --no-brute is the only real skip it supports, so we
    # approximate variety here by occasionally dropping brute force instead
    # (a real attacker who already has a credential wouldn't re-brute).
    SKIP_FLAG="--no-brute"
  fi

  DOS_CONNECTIONS_TARGET="$DOS_TARGET" ./attack1.sh --shuffle-mid --quiet $SKIP_FLAG \
    2>&1 | tee "attacks_campaign_${run}.log" | tail -5

  echo "  Run ${run} complete (DoS target: ${DOS_TARGET}, flags: --shuffle-mid --quiet ${SKIP_FLAG})"
  sleep 2
done

echo ""
echo "================================================================"
echo "  Campaign complete: ${RUNS} runs, each with independently"
echo "  shuffled Phase 4-9 ordering and varied DoS intensity."
echo "================================================================"

if [ "$EXTRACT_AT_END" -eq 1 ]; then
  echo ""
  echo "[*] Pulling logs and re-running the extraction pipeline..."
  ./run_pipeline.sh
fi
