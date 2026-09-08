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
# Step 2: MITRE ATT&CK technique classification
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
        "rule": lambda s: any(
            c.strip().startswith(("wget", "curl")) for c in s["commands"]
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
for r in ttp_records:
    for t in r["techniques"]:
        technique_counts[f"{t['id']} -- {t['name']}"] += 1
        tactic_counts[t["tactic"]] += 1

print("\nTechnique frequency (MITRE ATT&CK):")
if technique_counts:
    for name, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count} sessions")
else:
    print("  None matched — see debug steps below")

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
