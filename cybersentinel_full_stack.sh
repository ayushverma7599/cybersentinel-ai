#!/bin/bash
# CyberSentinel AI — full stack launch
#
# One command, cold start to live dashboard:
#   docker-compose up (Cowrie honeypot + Elasticsearch/Kibana)
#   → wait for services healthy
#   → verify Ollama reachable
#   → pull logs + extract TTPs + run 3-agent scan (run_pipeline.sh)
#   → train/verify LSTM model
#   → launch Streamlit dashboard
#
# Usage:
#   ./cybersentinel_full_stack.sh              # normal run
#   ./cybersentinel_full_stack.sh --retrain    # force LSTM retrain
#
# Config (override via env if your setup differs from the defaults below):
#   OLLAMA_HOST   — e.g. OLLAMA_HOST=http://127.0.0.1:11434 ./cybersentinel_full_stack.sh
#   ES_PORT       — Elasticsearch port to health-check
#   COMPOSE_FILE  — path to docker-compose.yml if not in this directory
#
set -e

OLLAMA_HOST="${OLLAMA_HOST:-http://10.0.2.2:11434}"
ES_PORT="${ES_PORT:-9200}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
MAX_WAIT=90   # seconds to wait for each health check before giving up

banner() {
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════"
}

wait_for() {
    # wait_for "description" "check command" 
    local desc="$1"
    local check="$2"
    local waited=0
    printf "  Waiting for %s" "$desc"
    until eval "$check" > /dev/null 2>&1; do
        if [ "$waited" -ge "$MAX_WAIT" ]; then
            echo ""
            echo "  ERROR: $desc did not become ready within ${MAX_WAIT}s."
            echo "  Check 'docker-compose ps' and 'docker-compose logs' before retrying."
            exit 1
        fi
        printf "."
        sleep 3
        waited=$((waited + 3))
    done
    echo " ready ($waited s)"
}

banner "CyberSentinel AI — Full Stack Launch"

# ── Preflight ──
command -v docker-compose >/dev/null 2>&1 || { echo "docker-compose not found in PATH."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found in PATH."; exit 1; }
[ -f "$COMPOSE_FILE" ] || { echo "$COMPOSE_FILE not found. Set COMPOSE_FILE=/path/to/it if it's elsewhere."; exit 1; }

# ── Stage 0: bring up the Docker stack ──
banner "Stage 0: docker-compose up (Cowrie + Elasticsearch + Kibana)"
docker-compose -f "$COMPOSE_FILE" up -d

# Health-check: adjust container/service names below if yours differ
wait_for "Elasticsearch on :$ES_PORT" \
    "curl -sf http://localhost:$ES_PORT/_cluster/health"

wait_for "Cowrie container running" \
    "docker-compose -f '$COMPOSE_FILE' ps --status running | grep -qi cowrie"

# ── Stage 0.5: verify Ollama is reachable before anything depends on it ──
banner "Stage 0.5: Verifying Ollama connectivity ($OLLAMA_HOST)"
if curl -sf "$OLLAMA_HOST/api/tags" > /dev/null 2>&1; then
    echo "  Ollama reachable at $OLLAMA_HOST"
else
    echo "  ERROR: Ollama not reachable at $OLLAMA_HOST"
    echo "  If this box's networking differs from your dev VM, override with:"
    echo "    OLLAMA_HOST=http://127.0.0.1:11434 ./cybersentinel_full_stack.sh"
    exit 1
fi

# ── Stage 1-3: honeypot logs → TTP extraction → 3-agent scan ──
banner "Stage 1-3: Log pull + TTP extraction + Recon/CVE/Config agent scan"
./run_pipeline.sh

# ── Stage 4: LSTM attack-progression model ──
banner "Stage 4: LSTM model"
if [ ! -f cybersentinel_lstm.pt ] || [ "$1" == "--retrain" ]; then
    echo "  Training LSTM attack-progression model..."
    python3 lstm_model.py --train
else
    echo "  Using existing trained model (cybersentinel_lstm.pt found)."
    echo "  Pass --retrain to force a fresh training run."
fi

# Sanity check so a broken checkpoint never reaches the demo
python3 lstm_model.py --eval > /tmp/cybersentinel_eval_check.log 2>&1 \
    && echo "  Model verified loadable and evaluable." \
    || { echo "  ERROR: model failed eval check — see /tmp/cybersentinel_eval_check.log"; exit 1; }

# ── Stage 5: launch live dashboard ──
# From here everything is automatic in-browser: pick a session, the
# dashboard runs LSTM prediction + SHAP explanation + k-step forecast live.
banner "Stage 5: Launching live dashboard — http://localhost:8501"
echo "  (Docker stack stays up in the background. Run 'docker-compose down'"
echo "   manually when you're fully done, not automatically on exit.)"
echo ""
streamlit run streamlit_app.py
