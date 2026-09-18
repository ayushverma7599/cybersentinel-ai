#!/usr/bin/env python3
"""
ttp_extract.py — Session-grouped TTP extraction with MITRE ATT&CK tagging.

Reads cowrie-attacks.json (one JSON object per line).
Groups events by session ID, classifies each session into
MITRE ATT&CK techniques, writes ttp_records.json.

Run from: ~/honeypot/
  python3 ttp_extract.py
"""
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta

# Fixed paths
log_file = os.path.expanduser("~/honeypot/cowrie-raw.json")
output_path = os.path.expanduser("~/honeypot/ttp_records.json")

if not os.path.exists(log_file):
    print(f"[!] File not found: {log_file}")
    print("    Run attack.sh and parse_cowrie_logs.py first")
    exit(1)

# -----------------------------------------------------------------------
# Step 1: Group raw events by session ID
# -----------------------------------------------------------------------
sessions = defaultdict(lambda: {
    "src_ip": None,
    "login_attempts": 0,
    "commands": [],
    "timestamps": [],
    "username": None,
})

total_lines = 0
with open(log_file, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
        except json.JSONDecodeError:
            continue

        total_lines += 1
        session_id = log.get("session")
        if not session_id:
            continue

        s = sessions[session_id]
        if log.get("src_ip"):
            s["src_ip"] = log["src_ip"]
        if log.get("timestamp"):
            s["timestamps"].append(log["timestamp"])

        eventid = log.get("eventid", "")
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            s["login_attempts"] += 1
            if log.get("username"):
                s["username"] = log["username"]
        # Cowrie uses 'input' for commands, NOT 'command'
        if eventid == "cowrie.command.input" and "input" in log:
            s["commands"].append(log["input"])

print(f"[+] Read {total_lines} log entries from cowrie-attacks.json")
print(f"[+] Found {len(sessions)} unique sessions")

# -----------------------------------------------------------------------
# Step 1.5: Cross-session brute-force detection (T1110)
# -----------------------------------------------------------------------
# Cowrie assigns a NEW session ID to every individual SSH connection, so a
# brute-force script making many separate login attempts (e.g. trying 5
# users x 6 passwords) produces that many separate one-event sessions —
# none of which individually has more than 1-2 login attempts. The
# per-session rule below (login_attempts > 3) only catches brute force
# *within* a single persistent connection and will never fire on the much
# more common "many short-lived connections from the same source" pattern.
#
# TWO EARLIER APPROACHES FAILED HERE, BOTH BECAUSE THEY RELIED ON TIMING:
#   - A sliding calendar-time window swept in unrelated nearby sessions.
#   - Gap-based clustering (only merge attempts <=2s apart) assumed
#     separate attack phases would be spaced far enough apart to split
#     into different clusters. On a real run, attack.sh's phases execute
#     tightly enough (sleep 0.1-0.2s throughout) that the ENTIRE run forms
#     one unbroken cluster with no gap ever exceeding 2s — so every
#     session got flagged, not just the real brute-force ones.
#
# FIX: use a signal grounded in session CONTENT, not timing at all.
# Recon/execution sessions (attack.sh Phases 1 and 3) always run several
# real commands (whoami, uname -a, wget, chmod, etc.). A brute-force probe
# (Phase 2's `ssh user@host -o ConnectTimeout=3 "exit"`) never runs
# anything beyond a bare "exit" — regardless of when it happened. This
# stays correct no matter how tightly the phases are packed together in
# time, because it doesn't look at time at all.
BRUTE_FORCE_THRESHOLD = 5               # attempts required from one source
BRUTE_FORCE_MIN_DISTINCT_USERNAMES = 3  # must try several different accounts, not repeat one
NON_PROBE_COMMANDS = {"exit"}           # a session limited to only these isn't "doing" anything

candidates_by_ip = defaultdict(list)  # src_ip -> [(session_id, username), ...]
for sid, s in sessions.items():
    if not s["src_ip"] or s["login_attempts"] == 0:
        continue
    commands_seen = {c.strip() for c in s["commands"]}
    is_probe = commands_seen <= NON_PROBE_COMMANDS  # empty set or subset of {"exit"}
    if is_probe:
        candidates_by_ip[s["src_ip"]].append((sid, s["username"]))

brute_force_sessions = set()
brute_force_ips = set()
for ip, candidates in candidates_by_ip.items():
    if len(candidates) < BRUTE_FORCE_THRESHOLD:
        continue
    distinct_users = {u for _, u in candidates if u}
    if len(distinct_users) >= BRUTE_FORCE_MIN_DISTINCT_USERNAMES:
        brute_force_ips.add(ip)
        for sid, _ in candidates:
            brute_force_sessions.add(sid)

print(f"[+] Brute-force correlation: {len(brute_force_ips)} source IP(s), "
      f"{len(brute_force_sessions)} session(s) flagged as T1110 "
      f"(>= {BRUTE_FORCE_THRESHOLD} no-command login attempts, "
      f">= {BRUTE_FORCE_MIN_DISTINCT_USERNAMES} distinct usernames, content-based)")

# -----------------------------------------------------------------------
# Step 1.6: Connection-flood detection (T1499 — Endpoint DoS)
# -----------------------------------------------------------------------
# attack1.sh Phase 10 never opens an authenticated SSH session at all — it's
# a raw `echo > /dev/tcp/host/port` connect/disconnect burst straight at
# Cowrie's listener. That means these sessions have ZERO login attempts and
# ZERO commands (they never get far enough for either), which is otherwise
# impossible for a session that matched any of the content-based rules
# below. A source IP that racks up a lot of these empty connect-only
# sessions is the T1499 signature — content-based again, no timing needed.
DOS_FLOOD_THRESHOLD = 15  # empty (no-login, no-command) sessions from one IP

empty_sessions_by_ip = defaultdict(list)
for sid, s in sessions.items():
    if s["src_ip"] and s["login_attempts"] == 0 and not s["commands"]:
        empty_sessions_by_ip[s["src_ip"]].append(sid)

dos_flood_sessions = set()
dos_flood_ips = set()
for ip, sids in empty_sessions_by_ip.items():
    if len(sids) >= DOS_FLOOD_THRESHOLD:
        dos_flood_ips.add(ip)
        dos_flood_sessions.update(sids)

if dos_flood_sessions:
    print(f"[+] Connection-flood correlation: {len(dos_flood_ips)} source IP(s), "
          f"{len(dos_flood_sessions)} session(s) flagged as T1499 "
          f"(>= {DOS_FLOOD_THRESHOLD} empty connect/disconnect sessions, content-based)")

# -----------------------------------------------------------------------
# Step 2: MITRE ATT&CK technique classification
#
# Extended to cover every phase attack1.sh actually runs (11 phases + the
# T1078/T1005/T1041 additions) — the previous version only recognized 5 of
# the ~14 techniques the attack script generates, so most of a run's real
# technique diversity was being silently dropped before it ever reached
# ttp_records.json (and therefore before it ever reached the LSTM).
# -----------------------------------------------------------------------
TECHNIQUE_RULES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Initial Access",
        "rule": lambda s: s["login_attempts"] > 3,
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        # wget is download-only, always counts. curl only counts here when
        # it's NOT an outbound POST/upload (that's T1041's signature, Phase
        # 13's exfil also uses curl and would otherwise double-tag as a
        # "tool transfer" when it's actually exfiltration going the other
        # direction).
        "rule": lambda s: any(
            c.strip().startswith("wget")
            or (c.strip().startswith("curl") and "-X POST" not in c and "-F " not in c and "--data" not in c)
            for c in s["commands"]
        ),
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "rule": lambda s: any(
            "chmod +x" in c or c.strip().startswith("./")
            for c in s["commands"]
        ),
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "rule": lambda s: any(
            c.strip() in ("uname -a", "whoami", "id", "uname")
            for c in s["commands"]
        ),
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "rule": lambda s: any(
            "cat /etc/passwd" in c for c in s["commands"]
        ),
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "rule": lambda s: any(
            c.strip().startswith(("/bin/sh", "/bin/bash", "sh ", "bash "))
            for c in s["commands"]
        ),
    },
    # ---- Newly recognized (attack1.sh already generates these) ----------
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "rule": lambda s: any(
            c.strip().startswith(("netstat", "ss -an", "ss -a")) for c in s["commands"]
        ),
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "rule": lambda s: any(
            c.strip().startswith("ps aux") or c.strip() == "ps" for c in s["commands"]
        ),
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        # "/dev/tcp/" alone isn't unique to port-sweeping — a reverse shell
        # (`bash -i >& /dev/tcp/host/port 0>&1`) uses the exact same bash
        # builtin for a different purpose and was colliding with this rule
        # until testing caught it. Exclude the reverse-shell fingerprint
        # (0>&1 stdin redirect, or "bash -i") explicitly.
        "rule": lambda s: any(
            (c.strip().startswith("nmap") or "/dev/tcp/" in c)
            and "0>&1" not in c and "bash -i" not in c
            for c in s["commands"]
        ),
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "rule": lambda s: any(
            c.strip().startswith("sudo -l") or "-perm -4000" in c
            or c.strip().startswith("cat /etc/sudoers")
            for c in s["commands"]
        ),
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "rule": lambda s: any(
            "id_rsa" in c or ".pem" in c or "credentials" in c.lower()
            or ("grep" in c and "password" in c.lower())
            for c in s["commands"]
        ),
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "rule": lambda s: any(
            c.strip().startswith("ssh ") and "ConnectTimeout" in c for c in s["commands"]
        ),
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "rule": lambda s: any(
            c.strip().startswith("history -c") or "bash_history" in c
            or c.strip().startswith("unset HISTFILE") or "rm -f /var/log" in c
            for c in s["commands"]
        ),
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "Impact",
        "rule": lambda s: any(
            (c.strip().startswith(("systemctl stop", "service ")) and ("auditd" in c or "rsyslog" in c))
            or c.strip().startswith("iptables -F") or "pkill -f auditd" in c
            for c in s["commands"]
        ),
    },
    # ---- New attack vectors (Phase 12/13 additions to attack1.sh) -------
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "rule": lambda s: any(c.strip().startswith("tar c") for c in s["commands"]),
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "rule": lambda s: any(
            c.strip().startswith("curl") and ("-X POST" in c or "-F " in c or "--data" in c)
            for c in s["commands"]
        ),
    },
    # ---- Realistic persistence/impact patterns (real-world attacker TTPs
    # that cybersentinel_skeleton.py's TECHNIQUE_REGISTRY already covers for
    # CVE/config lookups, but ttp_extract.py never matched) --------------
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "rule": lambda s: any(
            "crontab" in c or c.strip().startswith(("echo * * * * *", "(crontab"))
            for c in s["commands"]
        ),
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "rule": lambda s: any(
            "authorized_keys" in c for c in s["commands"]
        ),
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "rule": lambda s: any(
            any(tok in c.lower() for tok in ("xmrig", "minerd", "stratum+tcp", "cryptonight", "nicehash"))
            for c in s["commands"]
        ),
    },
}

# -----------------------------------------------------------------------
# Step 3: Build TTP records
# -----------------------------------------------------------------------
ttp_records = []
for session_id, s in sessions.items():
    techniques = [
        {"id": tid, "name": t["name"], "tactic": t["tactic"]}
        for tid, t in TECHNIQUE_RULES.items()
        if tid != "T1110" and t["rule"](s)
    ]
    # T1110: cross-session correlation (see Step 1.5) OR the original
    # within-session rule, in case a real attacker retries auth on one
    # persistent connection instead of opening many short ones.
    is_brute_force = session_id in brute_force_sessions or TECHNIQUE_RULES["T1110"]["rule"](s)
    if is_brute_force:
        techniques.append({
            "id": "T1110",
            "name": TECHNIQUE_RULES["T1110"]["name"],
            "tactic": TECHNIQUE_RULES["T1110"]["tactic"],
        })
    # T1499: connection-flood correlation (see Step 1.6) — content-based,
    # can't be expressed as a per-command rule since these sessions have no
    # commands at all.
    if session_id in dos_flood_sessions:
        techniques.append({
            "id": "T1499",
            "name": "Endpoint Denial of Service",
            "tactic": "Impact",
        })
    # T1078: Valid Accounts — attack1.sh Phase 12 re-authenticates with a
    # credential pair already confirmed to work in Phase 2, then runs a
    # check-in command tagged with a distinct marker string so this rule
    # can't collide with Phase 1's recon sessions (which also do a single
    # clean login + multiple commands, but never emit this marker).
    is_clean_reentry = any(
        "cs_valid_account_reentry" in c for c in s["commands"]
    )
    if is_clean_reentry:
        techniques.append({
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Persistence",
        })

    # -------------------------------------------------------------------
    # UNCLASSIFIED fallback — "zero-day" / unknown-technique handling.
    #
    # Every rule above is a signature match against a KNOWN, hand-written
    # command pattern. A session that does something genuinely new — a
    # different tool, an obfuscated/base64 command, a technique nobody
    # wrote a rule for — matches none of them. The old behaviour: such a
    # session was silently dropped (the `if techniques:` guard below never
    # ran), so it never reached ttp_records.json, the LSTM, or any report,
    # even though Cowrie recorded every command it ran.
    #
    # Fix: a session with real activity (more than a bare "exit" probe)
    # that matched NOTHING above is flagged UNCLASSIFIED instead of
    # discarded, with a lightweight, rule-independent suspicion score so
    # an analyst (or a future anomaly model) has something to go on even
    # without a signature. This is intentionally NOT another keyword rule
    # for a specific technique — it's a catch-all for "this doesn't look
    # like anything we know, but it isn't nothing either."
    # -------------------------------------------------------------------
    real_commands = [c for c in s["commands"] if c.strip() and c.strip() != "exit"]
    if not techniques and real_commands:
        reasons = []
        joined = " ".join(real_commands).lower()

        if "base64" in joined or " -d " in joined or "| bash" in joined or "|bash" in joined:
            reasons.append("possible obfuscated/encoded command execution")
        if any(tok in joined for tok in ("perl ", "ruby ", "php ", "nc ", "ncat ", "socat ", "python3 -c", "python -c")):
            reasons.append("uncommon interpreter/tool not in the known-technique list")
        if any(len(c) > 200 for c in real_commands):
            reasons.append("unusually long command (possible payload smuggling)")
        if any(c.count(";") + c.count("|") + c.count("&&") >= 4 for c in real_commands):
            reasons.append("heavily chained/piped command sequence")
        if not reasons:
            reasons.append("ran real commands but matched no known MITRE technique signature")

        techniques.append({
            "id": "UNCLASSIFIED",
            "name": "Unknown Technique (unmatched by any registry rule)",
            "tactic": "Unknown",
            "suspicion_reasons": reasons,
        })

    if techniques:
        ttp_records.append({
            "session_id": session_id,
            "source_ip": s["src_ip"],
            "login_attempts": s["login_attempts"],
            "techniques": techniques,
            "raw_commands": s["commands"],
            "first_seen": min(s["timestamps"]) if s["timestamps"] else None,
            "last_seen":  max(s["timestamps"]) if s["timestamps"] else None,
        })

# -----------------------------------------------------------------------
# Step 4: Write output
# -----------------------------------------------------------------------
with open(output_path, "w") as f:
    json.dump(ttp_records, f, indent=2)

# -----------------------------------------------------------------------
# Step 5: Print summary
# -----------------------------------------------------------------------
print("\n" + "=" * 60)
print("CYBERSENTINEL AI — TTP EXTRACTION SUMMARY")
print("=" * 60)
print(f"\nTotal sessions found:                      {len(sessions)}")
print(f"Sessions matching at least one technique:  {len(ttp_records)}")

technique_counts = defaultdict(int)
tactic_counts = defaultdict(int)
unclassified_records = []
for r in ttp_records:
    for t in r["techniques"]:
        technique_counts[f"{t['id']} -- {t['name']}"] += 1
        tactic_counts[t["tactic"]] += 1
        if t["id"] == "UNCLASSIFIED":
            unclassified_records.append(r)

print("\nTechnique frequency (MITRE ATT&CK):")
if technique_counts:
    for name, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count} sessions")
else:
    print("  None matched — see debug steps below")

if unclassified_records:
    print(f"\n[!] {len(unclassified_records)} session(s) flagged UNCLASSIFIED — "
          f"real activity that matched no known technique signature:")
    for r in unclassified_records[:10]:
        reasons = r["techniques"][-1].get("suspicion_reasons", [])
        cmds_preview = " | ".join(c.strip() for c in r["raw_commands"] if c.strip())[:80]
        print(f"    session {r['session_id']} from {r['source_ip']}: {reasons}")
        print(f"      commands: {cmds_preview}{'...' if len(cmds_preview) == 80 else ''}")
    if len(unclassified_records) > 10:
        print(f"    ... and {len(unclassified_records) - 10} more (see ttp_records.json, id=UNCLASSIFIED)")
    print("    Review these manually — they're the sessions ttp_extract.py")
    print("    couldn't explain, which is exactly what a rule-based system")
    print("    can't do anything about on its own.")

print("\nTactic distribution:")
for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
    print(f"  {tactic}: {count} sessions")

print(f"\nOutput written to: {output_path}")

# -----------------------------------------------------------------------
# Debug helper — shows a sample raw event so you can verify field names
# -----------------------------------------------------------------------
print("\n[debug] Sample raw event from cowrie-attacks.json:")
with open(log_file) as f:
    for line in f:
        line = line.strip()
        if line:
            sample = json.loads(line)
            print(f"  eventid: {sample.get('eventid')}")
            print(f"  session: {sample.get('session')}")
            print(f"  src_ip:  {sample.get('src_ip')}")
            print(f"  all keys: {list(sample.keys())}")
            break
