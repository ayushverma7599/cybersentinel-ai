"""
cowrie_adapter.py — convert REAL honeypot telemetry into v3 Session objects.

Joins ttp_records.json (ordered techniques per session, from parse_cowrie_logs)
with features.json (per-flow network/command features) on session_id, and emits
the Session schema used by the rest of the pipeline.

Honesty rules baked in:
  * Techniques, features, timing and the compromise signal are taken from the
    real data. Nothing is invented.
  * attack_class / malware_family are NOT fabricated. This SSH honeypot never
    observed ransomware/APT/etc., so every session is labelled "benign" and the
    real damage signal is carried in `severity` (from is_compromise /
    infiltration_label / login_success). Train the malware-class heads only
    when you have real malware telemetry (sandbox/EDR), not from this file.

Usage:
    python3 cowrie_adapter.py --ttp ttp_records.json --features features.json \
        --out sessions.json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime

import config as C
from features import TECH2IDX
from synthetic_data import Session

# real cowrie techniques -> keep only those the model knows (all 5 are in config)
KNOWN = set(C.TECHNIQUE_IDS)


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _agg_features(flows: list[dict]) -> dict:
    """Aggregate all flows belonging to a session into one feature summary."""
    if not flows:
        return {}
    def mean(k):
        vals = [f.get(k, 0) or 0 for f in flows]
        return sum(vals) / len(vals) if vals else 0.0
    def mx(k):
        return max((f.get(k, 0) or 0) for f in flows)
    proto = flows[0].get("protocol", "TCP")
    return {
        "dst_port": flows[0].get("dst_port", 0),
        "bytes_total": mean("bytes_total"),
        "bytes_fwd": mean("bytes_fwd"),
        "packets_total": mean("packets_total"),
        "connection_count": len(flows),
        "flow_duration_ms": mean("flow_duration_ms"),
        "login_attempts": mx("login_attempts"),
        "login_success": mx("login_success"),
        "command_count": mx("command_count"),
        "download_count": mx("download_count"),
        "is_compromise": mx("is_compromise"),
        "infiltration_label": mx("infiltration_label"),
        "port_scan_score": mean("port_scan_score"),
        "protocol": {"TCP": "tcp", "UDP": "udp"}.get(proto, "tcp"),
    }


def _event(technique: str, pos: float, agg: dict, rec: dict, cmd_len: float) -> dict:
    num = {f: 0.0 for f in C.NUMERIC_FEATURES}
    boo = {f: 0 for f in C.BOOLEAN_FEATURES}

    num["dst_port"] = float(agg.get("dst_port", 0))
    num["bytes_sent"] = float(agg.get("bytes_fwd", 0) or agg.get("bytes_total", 0))
    num["connection_count"] = float(agg.get("connection_count", 1))
    num["session_position"] = pos
    ts = _parse_ts(rec.get("first_seen"))
    num["hour_of_day"] = float(ts.hour) if ts else 0.0

    # technique-specific real signals
    if technique == "T1110":                       # brute force
        num["failed_auth_attempts"] = float(agg.get("login_attempts", 0))
    if technique == "T1059":                       # command execution
        num["command_length"] = float(cmd_len)
    if technique == "T1105":                       # ingress tool transfer
        num["data_exfil_mb"] = 0.0                 # inbound; kept 0
        num["bytes_sent"] = float(agg.get("bytes_total", 0))

    # real behavioural booleans we can actually attest to
    if agg.get("download_count", 0):
        boo["lolbin_used"] = 0                      # unknown; leave honest 0
    if agg.get("port_scan_score", 0) and agg["port_scan_score"] > 0.5:
        pass                                        # no matching flag; skip

    return {"technique": technique, "protocol": agg.get("protocol", "tcp"),
            "numeric": num, "boolean": boo}


def build_sessions(ttp_path: str, feat_path: str) -> list[Session]:
    ttp = json.load(open(ttp_path))
    feats = json.load(open(feat_path))

    by_sid = defaultdict(list)
    for f in feats:
        if f.get("session_id"):
            by_sid[f["session_id"]].append(f)

    sessions, skipped = [], 0
    for rec in ttp:
        sid = rec.get("session_id")
        techs = [t["id"] for t in rec.get("techniques", []) if t["id"] in KNOWN]
        if len(techs) < 2:                          # need >=2 for next-step
            skipped += 1
            continue
        agg = _agg_features(by_sid.get(sid, []))

        cmds = rec.get("raw_commands", [])
        cmd_len = sum(len(c) for c in cmds) / len(cmds) if cmds else 0.0

        n = len(techs)
        events = [_event(t, i / max(1, n - 1), agg, rec, cmd_len)
                  for i, t in enumerate(techs)]

        # severity from REAL compromise signals (not invented)
        sev = min(1.0,
                  0.35 * agg.get("is_compromise", 0) +
                  0.30 * agg.get("infiltration_label", 0) +
                  0.20 * (1 if agg.get("login_success", 0) else 0) +
                  0.15 * min(agg.get("command_count", 0) / 10.0, 1.0))

        sessions.append(Session(attack_class="benign", family="n/a",
                                severity=float(sev), events=events))
    return sessions, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ttp", default="ttp_records.json")
    ap.add_argument("--features", default="features.json")
    ap.add_argument("--out", default="sessions.json")
    args = ap.parse_args()

    sessions, skipped = build_sessions(args.ttp, args.features)

    from collections import Counter
    seqs = Counter(tuple(e["technique"] for e in s.events) for s in sessions)
    last = Counter(s.events[-1]["technique"] for s in sessions)

    print(f"[adapter] usable sessions (>=2 techniques): {len(sessions)}")
    print(f"[adapter] skipped (single-technique, unusable for forecasting): {skipped}")
    print(f"[adapter] distinct input sequences: {len(seqs)}")
    for seq, c in seqs.most_common():
        print(f"          x{c:<4d} {' -> '.join(seq)}")
    print(f"[adapter] distinct forecast targets (last technique): "
          f"{dict(last)}")

    from synthetic_data import save_sessions
    save_sessions(sessions, args.out)
    print(f"[adapter] wrote {args.out}")


if __name__ == "__main__":
    main()
