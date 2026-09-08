#!/bin/bash
# CyberSentinel AI — one-command launch
#
# Chains everything that currently has to be run by hand into a single
# pipeline, so a cold start looks like: "run one command, get a live
# autonomous dashboard" instead of six separate manual steps.
#
# Usage:
#   ./cybersentinel_launch.sh              # use existing trained model if present
#   ./cybersentinel_launch.sh --retrain    # force LSTM retrain even if .pt exists
#
set -e

echo "════════════════════════════════════════════════════════"
echo "  CyberSentinel AI — Autonomous Pipeline Launch"
echo "════════════════════════════════════════════════════════"

# ── Stage 1-3: honeypot logs → TTP extraction → 3-agent scan ──
# (Cowrie log pull, MITRE technique extraction, Recon/CVE/Config agents,
#  prioritized risk report — see run_pipeline.sh for details)
echo ""
echo "[Stage 1-3] Running honeypot log pull + TTP extraction + agent scan..."
./run_pipeline.sh

# ── Stage 4: LSTM attack-progression model ──
# Trained ONCE offline (like any ML model in a real security product) —
# not retrained on every dashboard view. --retrain forces a fresh train.
echo ""
if [ ! -f cybersentinel_lstm.pt ] || [ "$1" == "--retrain" ]; then
    echo "[Stage 4] Training LSTM attack-progression model..."
    python3 lstm_model.py --train
else
    echo "[Stage 4] Using existing trained model (cybersentinel_lstm.pt found)."
    echo "          Pass --retrain to force a fresh training run."
fi

# Quick post-train sanity check so a broken checkpoint never reaches the demo
python3 lstm_model.py --eval > /tmp/cybersentinel_eval_check.log 2>&1 \
    && echo "[Stage 4] Model verified loadable and evaluable." \
    || { echo "[Stage 4] ERROR: model failed eval check — see /tmp/cybersentinel_eval_check.log"; exit 1; }

# ── Stage 5: launch live dashboard ──
# From here on, everything is automatic in-browser: pick a session, the
# dashboard runs LSTM prediction + SHAP explanation + k-step forecast live,
# no further manual commands needed.
echo ""
echo "[Stage 5] Launching live dashboard at http://localhost:8501 ..."
echo "════════════════════════════════════════════════════════"
streamlit run streamlit_app.py
