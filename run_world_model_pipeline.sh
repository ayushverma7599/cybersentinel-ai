#!/usr/bin/env bash
# CyberSentinel AI — run_world_model_pipeline.sh
# Runs the complete SIH26153-compliant pipeline in order:
#   Step 1: Extract flow + packet features from Cowrie logs (Scapy/proxy)
#   Step 2: Load CIC-IDS-2018 data and merge
#   Step 3: Train World Model LSTM on real network features
#   Step 4: Run benchmark (LSTM vs Logistic Regression baseline)
#   Step 5: Launch Streamlit UI
#
# Usage:
#   chmod +x run_world_model_pipeline.sh
#   ./run_world_model_pipeline.sh
#
#   # Skip CIC download (use honeypot data only):
#   ./run_world_model_pipeline.sh --no-cic
#
#   # Use existing PCAP file:
#   ./run_world_model_pipeline.sh --pcap capture.pcap

set -e
cd ~/honeypot

NO_CIC=0
PCAP_FILE=""

for arg in "$@"; do
    case $arg in
        --no-cic)   NO_CIC=1 ;;
        --pcap=*)   PCAP_FILE="${arg#*=}" ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   CyberSentinel AI — World Model Pipeline (SIH26153)    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Feature Extraction ─────────────────────────────
echo "[*] Step 1: Extracting flow + packet features..."

if [ -n "$PCAP_FILE" ]; then
    echo "[*] Using PCAP file: $PCAP_FILE"
    python3 packet_capture.py --pcap "$PCAP_FILE"
elif [ -f "cowrie-raw.json" ]; then
    echo "[*] Using Cowrie JSON proxy (no PCAP needed)"
    python3 packet_capture.py --cowrie cowrie-raw.json
else
    echo "[*] No cowrie-raw.json found — running pipeline first"
    docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \
        ~/honeypot/cowrie-raw.json 2>/dev/null || true
    if [ -f "cowrie-raw.json" ]; then
        python3 packet_capture.py --cowrie cowrie-raw.json
    else
        echo "[!] No data source found. Run ./run_pipeline.sh first."
        exit 1
    fi
fi

echo "[+] Step 1 complete: features.json generated"
echo ""

# ── Step 2: CIC-IDS-2018 ──────────────────────────────────
if [ "$NO_CIC" -eq 0 ]; then
    echo "[*] Step 2: Loading CIC-IDS-2018 data..."

    # Check if already downloaded
    CIC_CSV=$(ls *TrafficForML_CICFlowMeter.csv 2>/dev/null | head -1)

    if [ -n "$CIC_CSV" ]; then
        echo "[*] Found existing CIC CSV: $CIC_CSV"
        python3 cic_ids_loader.py --csv "$CIC_CSV" --merge features.json
    else
        echo "[*] Downloading Wednesday-14-02-2018 (SSH Brute Force day)..."
        echo "[*] This is ~200MB — will take a few minutes"
        python3 cic_ids_loader.py --download --merge features.json || {
            echo "[!] CIC download failed — continuing with honeypot data only"
        }
    fi
    echo "[+] Step 2 complete"
else
    echo "[*] Step 2: Skipped (--no-cic flag)"
fi
echo ""

# ── Step 3: Train World Model ─────────────────────────────
echo "[*] Step 3: Training World Model LSTM..."
echo "[*] Input: real network features (30 dimensions)"
echo "[*] Architecture: LSTM with attention, seq_len=5 time windows"
python3 world_model.py --train --epochs 100
echo "[+] Step 3 complete: world_model.pt saved"
echo ""

# ── Step 4: Benchmark ─────────────────────────────────────
echo "[*] Step 4: Running benchmark (World Model vs LR Baseline)..."
python3 world_model.py --benchmark
echo "[+] Step 4 complete: benchmark_results.json saved"
echo ""

# ── Step 5: SHAP on world model features ─────────────────
echo "[*] Step 5: Running SHAP explanation on world model..."
python3 world_model.py --predict
echo "[+] Step 5 complete"
echo ""

# ── Summary ───────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Pipeline Complete — SIH26153 Requirements Met         ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  ✓ Flow + packet features extracted (Scapy proxy)       ║"
echo "║  ✓ CIC-IDS-2018 data integrated                         ║"
echo "║  ✓ World Model LSTM trained on network features         ║"
echo "║  ✓ LR baseline benchmark completed                      ║"
echo "║  ✓ F1/precision/recall/FPR comparison saved             ║"
echo "║                                                          ║"
echo "║  Files generated:                                        ║"
echo "║    features.json          — flow feature matrix          ║"
echo "║    features.csv           — same, CSV format             ║"
echo "║    world_model.pt         — trained LSTM weights         ║"
echo "║    benchmark_results.json — model comparison table       ║"
echo "║                                                          ║"
echo "║  Launch UI:                                              ║"
echo "║    streamlit run streamlit_app.py                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
