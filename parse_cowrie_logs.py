#!/usr/bin/env python3
"""
parse_cowrie_logs.py — Index real Cowrie events into Elasticsearch.

Reads cowrie-raw.json — the structured JSON log pulled via docker cp
(see run_pipeline.sh), the SAME source file ttp_extract.py and analyze.py
use — and indexes each event into Elasticsearch as-is.

This replaces the previous version, which regex-parsed plain-text
`docker-compose logs` output and only ever matched "New connection:"
lines. That meant every indexed document was missing session, username,
password, and command fields entirely (they were never parsed out of the
text), and re-running `docker-compose logs > cowrie-console.log` without
a --since flag captured the container's ENTIRE scrollback since it was
created — so the "session count" grew across every past demo run instead
of reflecting just the current one.

Two fixes here:
  1. Read the same structured cowrie-raw.json ttp_extract.py already uses
     correctly — real session/username/password/input fields for free,
     no regex guessing at log text format.
  2. Use a deterministic document _id (hash of the event's own content)
     instead of letting Elasticsearch auto-generate one on every POST.
     Re-running this script on the same log data now UPDATES existing
     documents instead of creating duplicates — so re-running the demo
     pipeline multiple times doesn't inflate your hit count each time.

Run from: ~/honeypot/
"""
import json
import os
import hashlib
from datetime import datetime, timezone

import requests

log_file = os.path.expanduser("~/honeypot/cowrie-raw.json")
es_url = "http://localhost:9200"
# Date-based index name, generated fresh each run (the old version had a
# hardcoded "cowrie-2026.08.13" — stale after the first day it was written).
index_name = f"cowrie-{datetime.now(timezone.utc):%Y.%m.%d}"

if not os.path.exists(log_file):
    print(f"[!] File not found: {log_file}")
    print("    Run run_pipeline.sh first (it pulls cowrie-raw.json via docker cp)")
    exit(1)

entries = []
with open(log_file, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(log)

print(f"[+] Read {len(entries)} events from {log_file}")
print(f"[*] Indexing into Elasticsearch index: {index_name}")

uploaded = 0
errors = 0
for entry in entries:
    # Deterministic ID: same event content always maps to the same
    # document, so re-running this script is idempotent instead of
    # duplicating data on every demo run.
    fingerprint = json.dumps(entry, sort_keys=True).encode("utf-8")
    doc_id = hashlib.sha256(fingerprint).hexdigest()

    try:
        response = requests.put(
            f"{es_url}/{index_name}/_doc/{doc_id}",
            json=entry,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code in (200, 201):
            uploaded += 1
        else:
            errors += 1
            print(f"  Error {response.status_code}: {response.text[:200]}")
    except Exception as e:
        errors += 1
        print(f"  Error uploading: {e}")

print(f"\n[+] Upload complete: {uploaded} indexed, {errors} errors")
print(f"[+] Index: {index_name}  (view in Kibana)")
