#!/bin/bash
# =============================================================================
# CyberSentinel AI — zero_day_sim.sh
#
# Sends sessions against the Cowrie honeypot using command patterns that
# match NONE of ttp_extract.py's TECHNIQUE_RULES on purpose — standing in
# for "a real attacker doing something the registry was never taught to
# recognize." Point of this script: prove the UNCLASSIFIED fallback in
# ttp_extract.py actually catches them instead of silently dropping the
# session, the way the pipeline did before that fix.
#
# This is NOT a real exploit against anything — every payload here is
# inert (echoes text, or decodes+runs a harmless echo). It only exists to
# exercise the "unknown technique" code path in your own lab honeypot.
#
# Usage:
#   ./zero_day_sim.sh              — run all 4 unknown-pattern sessions
#   ./run_pipeline.sh              — then re-run extraction and look for
#                                     "[!] N session(s) flagged UNCLASSIFIED"
#                                     in the output
# =============================================================================
set -uo pipefail

HONEYPOT_IP="127.0.0.1"
HONEYPOT_PORT="2222"
SSH_OPTS="-p ${HONEYPOT_PORT} \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PasswordAuthentication=yes \
  -o PubkeyAuthentication=no \
  -o BatchMode=no \
  -o ConnectTimeout=5 \
  -o LogLevel=ERROR"

ssh_cmd() {
  local user="$1" pass="$2" cmds="$3"
  sshpass -p "$pass" ssh $SSH_OPTS "${user}@${HONEYPOT_IP}" bash -s <<< "$cmds" 2>/dev/null
}

if ! nc -z -w3 "$HONEYPOT_IP" "$HONEYPOT_PORT" 2>/dev/null; then
  echo "[!] Cowrie not reachable at ${HONEYPOT_IP}:${HONEYPOT_PORT} — run docker-compose up -d first"
  exit 1
fi

echo "================================================================"
echo "  CyberSentinel AI — Unknown/Unclassified Technique Simulation"
echo "  4 sessions, none of which match any TECHNIQUE_RULES entry"
echo "================================================================"

echo ""
echo "[1/4] Obfuscated (base64-encoded) command execution"
echo "      — no rule looks for base64-decode-then-run patterns"
ssh_cmd "root" "password123" '
echo "cGluZyAtYyAxIDEyNy4wLjAuMQ==" | base64 -d | bash
exit
' >/dev/null

echo "[2/4] Uncommon interpreter (perl one-liner)"
echo "      — T1059 only matches sh/bash starts, not perl/ruby/php"
ssh_cmd "root" "password123" '
perl -e "print \"zero_day_sim: perl execution\n\""
exit
' >/dev/null

echo "[3/4] Heavily chained/piped one-liner"
echo "      — a compound command no single keyword rule was written for"
ssh_cmd "root" "password123" '
echo start; echo step1 | tr a-z A-Z | rev && echo step2 ; echo done
exit
' >/dev/null

echo "[4/4] Novel tool combination (netcat listener probe)"
echo "      — nc is not covered by T1105/T1046/anything else here"
ssh_cmd "root" "password123" '
which nc >/dev/null 2>&1 && echo "nc available" || echo "nc not available"
timeout 1 nc -zv 127.0.0.1 9999 2>&1 || true
exit
' >/dev/null

echo ""
echo "================================================================"
echo "  Done. Now run:  ./run_pipeline.sh"
echo "  Look for '[!] N session(s) flagged UNCLASSIFIED' in the output"
echo "  — that's ttp_extract.py catching these instead of dropping them."
echo "================================================================"
