"""
Encoding & normalisation helpers.

Maps categorical taxonomy entries to integer indices and provides simple,
deterministic normalisation for the numeric feature block. Pure NumPy so the
data pipeline runs without any deep-learning dependency.
"""

from __future__ import annotations

import numpy as np

import config as C

# ---- categorical -> index maps -------------------------------------------
TECH2IDX = {t: i for i, t in enumerate(C.TECHNIQUE_IDS)}
IDX2TECH = {i: t for t, i in TECH2IDX.items()}

TACTIC2IDX = {t: i for i, t in enumerate(C.TACTICS)}
PROTO2IDX = {p: i for i, p in enumerate(C.PROTOCOLS)}
CLASS2IDX = {c: i for i, c in enumerate(C.ATTACK_CLASSES)}
IDX2CLASS = {i: c for c, i in CLASS2IDX.items()}
FAMILY2IDX = {f: i for i, f in enumerate(C.FAMILY_IDS)}
IDX2FAMILY = {i: f for f, i in FAMILY2IDX.items()}


def tactic_of(technique_id: str) -> str:
    return C.TECHNIQUES[technique_id][1]


# Rough per-feature scales used for min-max style normalisation to ~[0,1].
# Values are clipped, so out-of-range sensor readings degrade gracefully.
_NUMERIC_SCALE = {
    "dst_port": 65535.0,
    "bytes_sent": 5_000_000.0,
    "connection_count": 500.0,
    "time_delta_secs": 3600.0,
    "hour_of_day": 23.0,
    "session_position": 1.0,
    "failed_auth_attempts": 100.0,
    "command_length": 2000.0,
    "files_touched_rate": 2000.0,
    "files_encrypted_count": 50000.0,
    "data_exfil_mb": 2000.0,
    "cpu_load_pct": 100.0,
    "beacon_interval_secs": 600.0,
    "remote_hosts_targeted": 100.0,
}


def normalize_numeric(vec: np.ndarray) -> np.ndarray:
    """vec shape (..., NUM_NUMERIC) -> normalised copy in [0,1]."""
    scale = np.array([_NUMERIC_SCALE[f] for f in C.NUMERIC_FEATURES],
                     dtype=np.float32)
    out = vec.astype(np.float32) / scale
    return np.clip(out, 0.0, 1.0)


def encode_event(event: dict) -> dict:
    """Turn one raw event dict into integer/float arrays for the model."""
    numeric = np.array([event["numeric"][f] for f in C.NUMERIC_FEATURES],
                       dtype=np.float32)
    boolean = np.array([event["boolean"][f] for f in C.BOOLEAN_FEATURES],
                       dtype=np.float32)
    return {
        "technique": TECH2IDX[event["technique"]],
        "tactic": TACTIC2IDX[tactic_of(event["technique"])],
        "protocol": PROTO2IDX[event["protocol"]],
        "numeric": normalize_numeric(numeric),
        "boolean": boolean,
    }
