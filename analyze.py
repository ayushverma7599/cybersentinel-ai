#!/usr/bin/env python3
"""
analyze.py — Flat IOC extraction from Cowrie logs.

Reads cowrie-raw.json — the structured JSON log pulled directly from
Cowrie via docker cp (see run_pipeline.sh), the SAME source file
ttp_extract.py uses. This is a deliberate change from the previous
version, which read cowrie-attacks.json (built by parse_cowrie_logs.py
regex-parsing `docker-compose logs` text output).

That old path only ever extracted "New connection:" lines — it never
parsed login or command lines at all, so username/password/commands were
structurally always empty, not a bug in analyze.py itself. It also
inherited an unbounded, growing session count, since `docker-compose logs`
with no --since flag dumps the container's entire scrollback since it was
created, not just the latest run.

Reading cowrie-raw.json directly avoids both problems: real structured
fields for every event type, and counts that reflect whatever's in the
current log pull, not accumulated history across every past demo run.

Run from: ~/honeypot/
"""
import json
from collections import Counter
import os

log_file = os.path.expanduser("~/honeypot/cowrie-raw.json")

sessions = set()
ips = []
usernames = []
passwords = []
commands = []

if not os.path.exists(log_file):
    print(f"[!] File not found: {log_file}")
    print("    Run run_pipeline.sh first (it pulls cowrie-raw.json via docker cp)")
    exit(1)

total_lines = 0
with open(log_file, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        total_lines += 1
        try:
            log = json.loads(line)
        except json.JSONDecodeError:
            continue

        eventid = log.get("eventid", "")
        sid = log.get("session")
        if sid:
            sessions.add(sid)

        if log.get("src_ip"):
            ips.append(log["src_ip"])

        # username/password only ever appear on login events — restricting
        # to those (rather than checking "in log" on every line) avoids
        # accidentally picking up unrelated fields with the same name.
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            if "username" in log:
                usernames.append(log["username"])
            if "password" in log:
                passwords.append(log["password"])

        # Cowrie uses 'input' for commands, not 'command'
        if eventid == "cowrie.command.input" and "input" in log:
            commands.append(log["input"])

print("=" * 50)
print("CYBERSENTINEL AI — IOC ANALYSIS SUMMARY")
print("=" * 50)
print(f"\nTotal events processed: {total_lines}")
print(f"Unique sessions:        {len(sessions)}")

print("\nTop 10 attacking IPs:")
for ip, count in Counter(ips).most_common(10):
    print(f"  {ip}: {count} events")

print("\nTop 10 usernames tried:")
if usernames:
    for u, count in Counter(usernames).most_common(10):
        print(f"  {u}: {count}")
else:
    print("  None found — check cowrie-raw.json has login events")

print("\nTop 10 passwords tried:")
if passwords:
    for p, count in Counter(passwords).most_common(10):
        print(f"  {p}: {count}")
else:
    print("  None found — check cowrie-raw.json has login events")

print("\nTop 10 commands executed:")
if commands:
    for c, count in Counter(commands).most_common(10):
        print(f"  {c}: {count}")
else:
    print("  None yet — run attack.sh Phase 3 to generate commands")
