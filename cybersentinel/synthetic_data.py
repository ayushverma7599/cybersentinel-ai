"""
Synthetic training-data generator for CyberSentinel v3.

Produces labelled *behavioural sequences* — ordered technique observations
with correlated sensor features — for each attack class. This is training
data for a DETECTOR: every row is a description of what a sensor would see,
expressed as numbers and MITRE labels. It contains no functional attack code
and provides no operational uplift to an attacker.

Until you have real telemetry (EDR traces, sandbox reports, honeypot logs),
this lets the whole pipeline train and evaluate end-to-end.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field, asdict

import numpy as np

import config as C


@dataclass
class Session:
    attack_class: str
    family: str
    severity: float
    events: list = field(default_factory=list)  # list of raw event dicts


def _blank_numeric() -> dict:
    return {f: 0.0 for f in C.NUMERIC_FEATURES}


def _blank_boolean() -> dict:
    return {f: 0 for f in C.BOOLEAN_FEATURES}


def _sample_features(attack_class: str, technique: str, rng: random.Random) -> tuple[dict, dict, str]:
    """Draw correlated numeric/boolean features + a protocol for one event.

    Correlations encode domain knowledge so the classifier has real signal,
    e.g. ransomware impact events show shadow-copy deletion + high encryption
    counts; cryptominers show sustained CPU load; infostealers show exfil MB.
    """
    num = _blank_numeric()
    boo = _blank_boolean()

    # generic baseline
    num["dst_port"] = rng.choice([22, 80, 443, 445, 3389, 8080, 4444, 3333])
    num["bytes_sent"] = rng.uniform(0, 5000)
    num["connection_count"] = rng.uniform(1, 20)
    num["time_delta_secs"] = rng.uniform(0.1, 120)
    num["hour_of_day"] = rng.randint(0, 23)
    num["command_length"] = rng.uniform(0, 120)
    protocol = rng.choice(["tcp", "http", "https", "dns"])

    tactic = C.TECHNIQUES[technique][1]

    # tactic-level signals
    if tactic == "credential-access":
        num["failed_auth_attempts"] = rng.uniform(5, 80)
        if technique == "T1003":
            boo["lsass_access"] = 1
    if tactic == "defense-evasion":
        boo["security_tool_disabled"] = int(rng.random() < 0.7)
        boo["event_logs_cleared"] = int(rng.random() < 0.5)
    if tactic == "execution":
        num["command_length"] = rng.uniform(80, 600)
        boo["lolbin_used"] = int(rng.random() < 0.6)
        boo["parent_child_anomaly"] = int(rng.random() < 0.5)
    if tactic == "lateral-movement":
        num["remote_hosts_targeted"] = rng.uniform(1, 30)
        boo["smb_spread"] = int(rng.random() < 0.6)
        protocol = "smb"
    if tactic == "command-and-control":
        num["beacon_interval_secs"] = rng.uniform(15, 300)
        boo["tor_or_proxy"] = int(rng.random() < 0.4)

    # class-level signals (the strongest discriminators)
    if attack_class == "ransomware" and technique in ("T1486", "T1490", "T1489"):
        num["files_encrypted_count"] = rng.uniform(2000, 45000)
        num["files_touched_rate"] = rng.uniform(200, 1800)
        boo["shadow_copies_deleted"] = 1
    if attack_class == "wiper" and technique in ("T1561", "T1489"):
        num["files_touched_rate"] = rng.uniform(500, 2000)
        boo["shadow_copies_deleted"] = 1
    if attack_class == "cryptominer":
        num["cpu_load_pct"] = rng.uniform(70, 100)
        if technique == "T1496":
            num["dst_port"] = rng.choice([3333, 4444, 5555])
    if attack_class == "infostealer" and technique in ("T1041", "T1567", "T1555"):
        num["data_exfil_mb"] = rng.uniform(5, 800)
        boo["lsass_access"] = int(rng.random() < 0.4)
    if attack_class in ("rat", "botnet", "fileless") and tactic == "command-and-control":
        num["beacon_interval_secs"] = rng.uniform(10, 120)
    if attack_class == "fileless":
        boo["memory_only"] = 1
        boo["process_injection"] = int(rng.random() < 0.7)
    if attack_class == "apt":
        boo["lolbin_used"] = int(rng.random() < 0.5)
        num["time_delta_secs"] = rng.uniform(60, 3600)  # slow & stealthy
    if attack_class == "benign":
        # keep everything quiet; occasional benign admin noise
        num["command_length"] = rng.uniform(0, 60)

    if technique == "T1055":
        boo["process_injection"] = 1
    if technique == "T1110":
        num["failed_auth_attempts"] = rng.uniform(10, 100)

    return num, boo, protocol


def generate_session(attack_class: str, rng: random.Random) -> Session:
    template = C.KILL_CHAIN_TEMPLATES[attack_class]
    family = rng.choice(C.MALWARE_FAMILIES[attack_class])
    base_sev = C.CLASS_SEVERITY[attack_class]

    techniques: list[str] = []
    for stage in template:
        # draw 1-2 techniques per stage, preserving order
        k = 1 if rng.random() < 0.6 else 2
        for t in rng.sample(stage, min(k, len(stage))):
            techniques.append(t)

    # ensure a usable length for next-step forecasting
    if len(techniques) < 2:
        techniques.append(rng.choice(C.TECHNIQUE_IDS))
    techniques = techniques[: C.HP.max_seq_len]

    n = len(techniques)
    events = []
    for i, tech in enumerate(techniques):
        num, boo, proto = _sample_features(attack_class, tech, rng)
        num["session_position"] = i / max(1, n - 1)
        events.append({
            "technique": tech,
            "protocol": proto,
            "numeric": num,
            "boolean": boo,
        })

    # severity rises as the chain approaches impact
    severity = float(np.clip(base_sev * (0.6 + 0.4 * (n / C.HP.max_seq_len))
                             + rng.uniform(-0.05, 0.05), 0.0, 1.0))
    return Session(attack_class=attack_class, family=family,
                   severity=severity, events=events)


def build_dataset(n_sessions: int = 6000, seed: int = 1337,
                  class_weights: dict | None = None) -> list[Session]:
    """Generate a class-balanced set of sessions.

    class_weights lets you oversample under-represented attack classes; by
    default classes are sampled roughly uniformly (a deliberate rebalance vs
    real-world data, which is dominated by a few noisy techniques).
    """
    rng = random.Random(seed)
    classes = C.ATTACK_CLASSES
    if class_weights is None:
        class_weights = {c: 1.0 for c in classes}
    total_w = sum(class_weights[c] for c in classes)
    probs = [class_weights[c] / total_w for c in classes]

    sessions = []
    for _ in range(n_sessions):
        cls = rng.choices(classes, weights=probs, k=1)[0]
        sessions.append(generate_session(cls, rng))
    return sessions


def save_sessions(sessions: list[Session], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(s) for s in sessions], fh)


def load_sessions(path: str) -> list[Session]:
    with open(path) as fh:
        raw = json.load(fh)
    return [Session(**s) for s in raw]


if __name__ == "__main__":
    ds = build_dataset(n_sessions=20)
    from collections import Counter
    print("generated", len(ds), "sessions")
    print("class distribution:", Counter(s.attack_class for s in ds))
    ex = ds[0]
    print("example class:", ex.attack_class, "family:", ex.family,
          "severity:", round(ex.severity, 3), "len:", len(ex.events))
    print("first event technique:", ex.events[0]["technique"])
