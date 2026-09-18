"""
CyberSentinel AI — cic_ids_loader.py
Step 2 of 4: CIC-IDS-2018 dataset loader

SIH26153 requirement:
  "A feature extraction pipeline that ingests CIC-IDS-2018 CSV flow records
   and outputs a timestamped, normalised feature matrix."

CIC-IDS-2018 dataset:
  - Published by Canadian Institute for Cybersecurity
  - Contains labelled network flows from a simulated enterprise environment
  - 7 attack days: Brute Force, DoS, Web Attacks, Infiltration, Botnet, DDoS
  - Download from: https://www.unb.ca/cic/datasets/ids-2018.html
  - Or: https://registry.opendata.aws/cse-cic-ids2018/

What this does:
  1. Downloads a CIC-IDS-2018 day CSV (or loads from disk)
  2. Maps CIC features → CyberSentinel feature vector format
  3. Maps CIC attack labels → MITRE ATT&CK technique IDs
  4. Merges with honeypot features from packet_capture.py
  5. Outputs combined features.json for world_model.py training

Usage:
  # Auto-download Wednesday-14-02-2018 (Brute Force + DoS day)
  python3 cic_ids_loader.py --download

  # Load from existing CSV
  python3 cic_ids_loader.py --csv Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv

  # Merge with honeypot features
  python3 cic_ids_loader.py --csv <file> --merge features.json

Install:
  pip install pandas requests --break-system-packages
"""

import argparse
import json
import math
import os
import sys
from pathlib import Path
from collections import Counter

# ── Pandas import ────────────────────────────────────────
try:
    import pandas as pd
    PANDAS_OK = True
except ImportError:
    PANDAS_OK = False
    print("[CIC] pandas not found. Install: pip install pandas --break-system-packages")

# ── Requests for download ────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ─────────────────────────────────────────────────────────
# CIC-IDS-2018 CONFIGURATION
# ─────────────────────────────────────────────────────────

# AWS Open Data Registry URL for CIC-IDS-2018
# Wednesday file chosen: contains SSH Brute Force (maps to T1110)
# which is the technique missing from your honeypot data
CIC_S3_BASE = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/"

# All 10 days of the published dataset. Each day = its own attack category,
# which matters for CyberSentinel specifically: the technique-classification
# head only predicts the 10-class COMPROMISE_TECHNIQUES set (T1105, T1204,
# T1059, T1548, T1136, T1070, T1499, T1498, T1071, T1190) — Wednesday's
# brute-force traffic maps to T1110, which is OUTSIDE that set, so it helps
# the binary infiltration benchmark but adds zero technique-classification
# training signal. The days commented "-> Txxxx" below are the ones that
# actually feed the technique head; pull those first if technique top-k
# accuracy (not just binary F1) is what you're trying to move.
CIC_FILES = {
    "Wednesday-14-02-2018": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",   # FTP/SSH Brute Force -> T1110 (binary only)
    "Thursday-15-02-2018":  "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",    # DoS GoldenEye/Slowloris -> T1499
    "Friday-16-02-2018":    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",      # DoS Hulk/SlowHTTPTest -> T1499
    # NOTE: the real object on S3 is misspelled "Thuesday" (not "Tuesday") —
    # this is a genuine typo in the original CIC-IDS-2018 publication itself,
    # confirmed by listing the bucket directly (a plain "Tuesday-..." request
    # 404s). The dict KEY stays correctly spelled since that's the --day
    # value users type; only the filename VALUE needs to match upstream's
    # actual (misspelled) key so downloads/local filenames resolve.
    "Tuesday-20-02-2018":   "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",    # DDoS LOIC-UDP -> T1498 (~4.05GB, much larger than every other day)
    "Wednesday-21-02-2018": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",   # DDoS LOIC-HTTP/HOIC -> T1498
    "Thursday-22-02-2018":  "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",    # Web Brute Force/XSS -> T1110/T1059
    "Friday-23-02-2018":    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",      # Web XSS/SQL Injection -> T1059/T1190
    "Wednesday-28-02-2018": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",   # Infiltration -> T1105
    "Thursday-01-03-2018":  "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",    # Infiltration -> T1105
    "Friday-02-03-2018":    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",      # Botnet (Ares) -> T1071
}

# Default: Wednesday (SSH Brute Force day) — already on disk in most setups
DEFAULT_FILE = "Wednesday-14-02-2018"

# ─────────────────────────────────────────────────────────
# LABEL → MITRE ATT&CK MAPPING
# Maps CIC-IDS-2018 attack labels to MITRE technique IDs
# ─────────────────────────────────────────────────────────

CIC_LABEL_TO_MITRE = {
    # Benign
    "Benign":                       None,
    "BENIGN":                       None,

    # Brute Force
    "SSH-Bruteforce":               "T1110",
    "FTP-BruteForce":               "T1110",
    "Brute Force -Web":             "T1110",
    "Brute Force -XSS":             "T1110",
    "SQL Injection":                "T1190",

    # DoS / DDoS
    "DoS attacks-Hulk":             "T1499",
    "DoS attacks-SlowHTTPTest":     "T1499",
    "DoS attacks-GoldenEye":        "T1499",
    "DoS attacks-Slowloris":        "T1499",
    "DDOS attack-LOIC-UDP":         "T1498",
    "DDOS attack-HOIC":             "T1498",
    "DDoS attacks-LOIC-HTTP":       "T1498",

    # Infiltration
    # NOTE: the real Label string in the official CIC-IDS-2018 CSVs is
    # "Infilteration" (misspelled, extra "e") — NOT "Infiltration". Confirmed
    # by scanning the raw Wednesday-28-02-2018 / Thursday-01-03-2018 files
    # directly: 68,871 + 93,063 rows carry this exact misspelled label, and
    # none of them matched the correctly-spelled key below (nor the
    # substring fallback in _row_to_feature_vector, since "infiltration" is
    # not a contiguous substring of "infilteration" — the letters are
    # transposed). Every one of those ~162k real attack rows was silently
    # falling through to mitre=None -> "BENIGN" before this fix. This is the
    # same kind of upstream-typo quirk as the "Thuesday" S3 filename (see
    # CIC_FILES above) — keeping both spellings mapped here for robustness.
    "Infiltration":                 "T1105",
    "Infilteration":                "T1105",

    # Botnet
    "Bot":                          "T1071",

    # Web attacks
    "Web Attack - Brute Force":     "T1110",
    "Web Attack - XSS":             "T1059",
    "Web Attack - Sql Injection":   "T1190",
}

COMPROMISE_TECHNIQUES = {
    "T1105", "T1204", "T1059", "T1548", "T1136", "T1070",
    "T1499", "T1498", "T1071", "T1190"
}

# ─────────────────────────────────────────────────────────
# CIC COLUMN → CYBERSENTINEL FEATURE MAPPING
# ─────────────────────────────────────────────────────────

# Maps CIC-IDS-2018 column names → our feature vector keys
# CIC uses spaces in column names and different naming conventions
CIC_COLUMN_MAP = {
    # Flow identifiers
    "Src IP":                   "src_ip",
    "Src Port":                 "src_port",
    "Dst IP":                   "dst_ip",
    "Dst Port":                 "dst_port",
    "Protocol":                 "protocol_num",
    "Timestamp":                "timestamp",

    # Flow-level
    "Tot Fwd Pkts":             "packets_fwd",
    "Tot Bwd Pkts":             "packets_bwd",
    "TotLen Fwd Pkts":          "bytes_fwd",
    "TotLen Bwd Pkts":          "bytes_bwd",
    "Flow Duration":            "flow_duration_us",    # microseconds in CIC
    "Flow Byts/s":              "bytes_per_sec",
    "Flow Pkts/s":              "pkts_per_sec",

    # IAT statistics
    "Flow IAT Mean":            "iat_mean",
    "Flow IAT Std":             "iat_std",
    "Flow IAT Max":             "iat_max",
    "Fwd IAT Mean":             "fwd_iat_mean",
    "Bwd IAT Mean":             "bwd_iat_mean",

    # TCP flags
    "FIN Flag Cnt":             "fin_count",
    "SYN Flag Cnt":             "syn_count",
    "RST Flag Cnt":             "rst_count",
    "PSH Flag Cnt":             "psh_count",
    "ACK Flag Cnt":             "ack_count",
    "URG Flag Cnt":             "urg_count",

    # Packet-level
    "Pkt Len Mean":             "payload_size_mean",
    "Pkt Len Std":              "payload_size_std",
    "Pkt Len Max":              "payload_size_max",
    "Fwd Header Len":           "fwd_header_len",
    "Bwd Header Len":           "bwd_header_len",
    "Init Fwd Win Byts":        "tcp_window_fwd",
    "Init Bwd Win Byts":        "tcp_window_bwd",

    # Label
    "Label":                    "cic_label",
}

# ─────────────────────────────────────────────────────────
# DOWNLOAD
# ─────────────────────────────────────────────────────────

def download_cic(day: str = DEFAULT_FILE,
                 output_dir: str = ".") -> str | None:
    """
    Download a CIC-IDS-2018 day CSV from AWS S3.
    Returns path to downloaded file, or None on failure.
    """
    if not REQUESTS_OK:
        print("[CIC] requests not installed. Run: pip install requests --break-system-packages")
        print("[CIC] Manual download:")
        print(f"  wget '{CIC_S3_BASE}{CIC_FILES[day]}'")
        return None

    filename = CIC_FILES.get(day, CIC_FILES[DEFAULT_FILE])
    url      = CIC_S3_BASE + filename
    out_path = os.path.join(output_dir, filename)

    # Resume support: a previous attempt can be cut short by a read timeout
    # partway through — confirmed happening on this exact ~4GB file (a
    # single 30s stall mid-transfer killed an otherwise-progressing
    # download at 9%/384MB). An existing file here is NOT necessarily
    # "already downloaded" — the old code assumed that unconditionally,
    # which would have silently handed a truncated, corrupt CSV to every
    # downstream step with zero warning. Treat it as a resume point via an
    # HTTP Range request instead.
    resume_from = 0
    mode = "wb"
    headers = {}
    if os.path.exists(out_path):
        resume_from = os.path.getsize(out_path)
        headers["Range"] = f"bytes={resume_from}-"
        mode = "ab"
        print(f"[CIC] Found existing file ({resume_from // 1024 // 1024}MB) — checking whether to resume")

    print(f"[CIC] Downloading {filename}...")
    print(f"[CIC] URL: {url}")

    try:
        # (connect_timeout, read_timeout): 30s to establish the connection,
        # 120s per chunk read. The old single timeout=30 applied AS the
        # per-read timeout too — fine for a ~200MB file, much too tight for
        # a multi-GB transfer where any brief stall kills the whole thing.
        resp = requests.get(url, stream=True, timeout=(30, 120), headers=headers)

        if resume_from and resp.status_code == 416:
            # Range start == the file's true total size: nothing left to
            # fetch, this file was already complete.
            print(f"[CIC] Already fully downloaded: {out_path}")
            resp.close()
            return out_path

        if resume_from and resp.status_code == 200:
            # Server ignored the Range request and is sending the whole
            # file again — restart clean rather than appending a full
            # second copy onto our partial one.
            print("[CIC] Server did not honor resume — restarting from scratch")
            resume_from = 0
            mode = "wb"

        resp.raise_for_status()

        total = int(resp.headers.get("content-length", 0)) + resume_from
        downloaded = resume_from
        with open(out_path, mode) as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = 100 * downloaded // total
                    print(f"\r[CIC] {pct}% ({downloaded // 1024 // 1024}MB / {total // 1024 // 1024}MB)", end="")
        print()
        print(f"[CIC] Downloaded to {out_path}")
        return out_path

    except Exception as e:
        print(f"[CIC] Download failed: {e}")
        print(f"[CIC] Progress is saved on disk — just re-run the same command to resume from here.")
        print(f"[CIC] Manual download (resumable):")
        print(f"  wget -c '{url}' -O '{out_path}'")
        return None


# ─────────────────────────────────────────────────────────
# LOAD AND MAP
# ─────────────────────────────────────────────────────────

def load_cic_csv(csv_path: str,
                 max_rows: int = 20000,
                 balance: bool = True,
                 seed: int = 42,
                 day_label: str | None = None,
                 chunksize: int = 200_000) -> list[dict]:
    """
    Load a CIC-IDS-2018 CSV and convert to CyberSentinel feature vectors.

    Scans the WHOLE file in chunks and builds a stratified sample across it.
    The previous version read only the first `max_rows * 3` rows via
    `nrows=` — CIC-IDS-2018 days are laid out as long contiguous runs (often
    benign-only for a stretch, then an attack window), so a head-only read
    can badly over- or under-represent the attack traffic depending on
    where in the ~1M-row file it happens to fall, without any warning that
    that's what happened.

    max_rows: target OUTPUT sample size (not an input row cap — the file is
              scanned in full regardless of its size).
    balance:  aim for ~50/50 benign vs attack in the output sample.
    seed:     deterministic sampling — same seed, same sample, every run.
    day_label: tags every row's `source` field (e.g. "Wednesday-14-02-2018")
              so world_model.py treats each day as its own segment instead
              of silently blending it with anything else. Auto-derived from
              the filename when not given.
    """
    if not PANDAS_OK:
        print("[CIC] pandas required. Install: pip install pandas --break-system-packages")
        return []

    if not os.path.exists(csv_path):
        print(f"[CIC] File not found: {csv_path}")
        return []

    if day_label is None:
        day_label = Path(csv_path).stem.split("_TrafficForML")[0]

    rng = __import__("random").Random(seed)
    target_per_class = max(1, max_rows // 2) if balance else max_rows
    keep_cap = target_per_class * 3  # trim running lists back to this before they balloon

    print(f"[CIC] Scanning {csv_path} in chunks of {chunksize} rows "
          f"(day_label={day_label!r})...")

    benign_rows: list = []
    attack_rows: list = []
    total_seen = 0
    label_col = None

    try:
        reader = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip",
                              low_memory=False, chunksize=chunksize)
        for chunk in reader:
            chunk.columns = [c.strip() for c in chunk.columns]
            if label_col is None:
                for possible in ["Label", "label"]:
                    if possible in chunk.columns:
                        label_col = possible
                        break
                if label_col is None:
                    print(f"[CIC] Warning: No Label column found. Columns: {list(chunk.columns[:10])}")
                    chunk["Label"] = "BENIGN"
                    label_col = "Label"

            chunk = chunk.replace([float("inf"), float("-inf")], 0).fillna(0)
            # CICFlowMeter files are concatenations of multiple capture
            # sessions, each with its own header line — a handful of rows
            # per file are that literal header ("Label,Dst Port,...") parsed
            # as a normal data row, i.e. the Label column reads back the
            # string "Label" itself. Confirmed via audit_cic_labels.py: 1-33
            # such rows per file, out of 300k-1M+ real rows. Drop them here
            # rather than letting them silently count as BENIGN.
            chunk = chunk[chunk[label_col].astype(str).str.strip() != label_col]
            is_benign = chunk[label_col].astype(str).str.upper() == "BENIGN"
            benign_chunk = chunk[is_benign]
            attack_chunk = chunk[~is_benign]
            total_seen += len(chunk)

            if len(benign_chunk):
                benign_rows.extend(benign_chunk.to_dict("records"))
                if len(benign_rows) > keep_cap:
                    benign_rows = list(pd.DataFrame(benign_rows)
                                        .sample(n=keep_cap, random_state=rng.randint(0, 2**31 - 1))
                                        .to_dict("records"))
            if len(attack_chunk):
                attack_rows.extend(attack_chunk.to_dict("records"))
                if len(attack_rows) > keep_cap:
                    attack_rows = list(pd.DataFrame(attack_rows)
                                        .sample(n=keep_cap, random_state=rng.randint(0, 2**31 - 1))
                                        .to_dict("records"))
    except Exception as e:
        print(f"[CIC] Failed to read CSV: {e}")
        return []

    print(f"[CIC] Scanned {total_seen} total rows across the file — "
          f"{len(benign_rows)} benign / {len(attack_rows)} attack retained "
          f"pre-final-sample")

    # Final downsample to the actual target size
    n_benign = min(len(benign_rows), target_per_class) if balance else len(benign_rows)
    n_attack = min(len(attack_rows), target_per_class) if balance else len(attack_rows)

    if len(benign_rows) > n_benign:
        benign_rows = list(pd.DataFrame(benign_rows).sample(n=n_benign, random_state=seed).to_dict("records"))
    if len(attack_rows) > n_attack:
        attack_rows = list(pd.DataFrame(attack_rows).sample(n=n_attack, random_state=seed).to_dict("records"))

    all_rows = benign_rows + attack_rows
    # Sort back into chronological order (do NOT shuffle here). These rows
    # become a contiguous "segment" in features.json that world_model.py
    # builds sliding 5-flow windows from — if the rows are in random order,
    # each window is 5 unrelated flows glued together, not a real
    # progression, which gives the LSTM nothing genuine to learn from.
    # world_model.py's own DataLoader(shuffle=True) already randomises
    # BATCH order during training — that's the right place for randomness,
    # not here.
    try:
        all_rows.sort(key=lambda r: pd.to_datetime(r.get("Timestamp", ""), dayfirst=True, errors="coerce"))
    except Exception:
        pass  # if Timestamp parsing fails entirely, fall back to scan order (still not random)
    if not balance and len(all_rows) > max_rows:
        all_rows = all_rows[:max_rows]

    print(f"[CIC] Final sample: {len(all_rows)} rows "
          f"({len(benign_rows)} benign + {len(attack_rows)} attack)")

    # Convert to feature vectors
    features = []
    label_counts = Counter()

    for row in all_rows:
        try:
            fv = _row_to_feature_vector(row, label_col, day_label=day_label, rng=rng)
            if fv:
                features.append(fv)
                label_counts[fv["mitre_technique"]] += 1
        except Exception:
            continue

    print(f"[CIC] Converted {len(features)} flows to feature vectors")
    print(f"[CIC] MITRE distribution: {dict(label_counts.most_common(8))}")
    return features


def _row_to_feature_vector(row, label_col: str, day_label: str = "unknown", rng=None) -> dict | None:
    """Convert one CIC-IDS-2018 CSV row to a CyberSentinel feature vector."""

    def safe(col, default=0.0):
        try:
            val = row.get(col, default)
            return float(val) if val is not None else default
        except (ValueError, TypeError):
            return default

    def safe_int(col, default=0):
        try:
            return int(safe(col, default))
        except Exception:
            return default

    # Label → MITRE
    cic_label = str(row.get(label_col, "BENIGN")).strip()
    mitre = CIC_LABEL_TO_MITRE.get(cic_label)
    if mitre is None and cic_label.upper() != "BENIGN":
        # Try partial match
        for k, v in CIC_LABEL_TO_MITRE.items():
            if k.lower() in cic_label.lower() and v:
                mitre = v
                break
    if mitre is None:
        mitre = "BENIGN"

    # NOTE: benign/attack balancing now happens upstream in load_cic_csv
    # (a proper stratified sample across the whole file), so this function
    # no longer does its own probabilistic benign-dropping — doing both
    # would double-filter and skew the balance load_cic_csv already set up.

    # Flow counters
    pkts_fwd  = safe_int("Tot Fwd Pkts")
    pkts_bwd  = safe_int("Tot Bwd Pkts")
    bytes_fwd = safe("TotLen Fwd Pkts")
    bytes_bwd = safe("TotLen Bwd Pkts")
    total_pkts  = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd
    duration_us = safe("Flow Duration")
    duration_ms = duration_us / 1000.0

    # Flag counts
    syn_cnt = safe("SYN Flag Cnt")
    ack_cnt = safe("ACK Flag Cnt")
    fin_cnt = safe("FIN Flag Cnt")
    rst_cnt = safe("RST Flag Cnt")
    psh_cnt = safe("PSH Flag Cnt")
    urg_cnt = safe("URG Flag Cnt")

    syn_ratio = syn_cnt / max(total_pkts, 1)
    ack_ratio = ack_cnt / max(total_pkts, 1)
    fin_ratio = fin_cnt / max(total_pkts, 1)
    rst_ratio = rst_cnt / max(total_pkts, 1)

    # TCP window
    win_fwd = safe("Init Fwd Win Byts")
    win_bwd = safe("Init Bwd Win Byts")
    win_mean = (win_fwd + win_bwd) / 2 if win_fwd + win_bwd > 0 else 65535
    win_std  = abs(win_fwd - win_bwd) / 2

    # Protocol
    proto_num = safe_int("Protocol")
    proto = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else "OTHER"

    # Dst port
    dst_port = safe_int("Dst Port")

    # Bidir ratio
    bidir = bytes_fwd / max(bytes_bwd, 1)

    # Flags bitmask
    flags = 0
    if syn_cnt > 0: flags |= 0x02
    if ack_cnt > 0: flags |= 0x10
    if fin_cnt > 0: flags |= 0x01
    if rst_cnt > 0: flags |= 0x04
    if psh_cnt > 0: flags |= 0x08
    if urg_cnt > 0: flags |= 0x20

    return {
        # Identifiers
        "src_ip":               str(row.get("Src IP", "0.0.0.0")),
        "dst_ip":               str(row.get("Dst IP", "0.0.0.0")),
        "src_port":             safe_int("Src Port"),
        "dst_port":             dst_port,
        "protocol":             proto,
        "timestamp":            str(row.get("Timestamp", "")),

        # Flow-level
        "bytes_total":          total_bytes,
        "packets_total":        total_pkts,
        "bytes_fwd":            bytes_fwd,
        "bytes_bwd":            bytes_bwd,
        "packets_fwd":          pkts_fwd,
        "packets_bwd":          pkts_bwd,
        "flow_duration_ms":     round(duration_ms, 2),
        "bidir_ratio":          round(bidir, 4),

        # TCP flags
        "tcp_flags_bitmask":    flags,
        "syn_ratio":            round(syn_ratio, 4),
        "ack_ratio":            round(ack_ratio, 4),
        "fin_ratio":            round(fin_ratio, 4),
        "rst_ratio":            round(rst_ratio, 4),
        "has_syn":              int(syn_cnt > 0),
        "has_ack":              int(ack_cnt > 0),
        "has_fin":              int(fin_cnt > 0),
        "has_rst":              int(rst_cnt > 0),
        "has_psh":              int(psh_cnt > 0),
        "has_urg":              int(urg_cnt > 0),

        # IAT
        "iat_mean":             round(safe("Flow IAT Mean"), 4),
        "iat_std":              round(safe("Flow IAT Std"), 4),
        "iat_max":              round(safe("Flow IAT Max"), 4),

        # Packet-level (CIC doesn't have TTL — use defaults)
        "ttl_mean":             64.0,
        "ttl_std":              0.0,
        "tcp_window_mean":      round(win_mean, 2),
        "tcp_window_std":       round(win_std, 2),
        "payload_size_mean":    round(safe("Pkt Len Mean"), 4),
        "payload_size_std":     round(safe("Pkt Len Std"), 4),
        "retransmission_count": 0,
        "port_scan_score":      0.0,
        "unique_dst_ports":     1,

        # Labels.
        # is_compromise / infiltration_label answer "is this attack traffic
        # at all" — TRUE for every recognised attack label (brute force,
        # DoS, SQLi, ...), not just the 10-class COMPROMISE_TECHNIQUES set.
        # That set is a SEPARATE, narrower thing: which of the 10 late-stage
        # techniques the technique-classification head predicts (world_model
        # .py's make_sequences() already excludes anything outside it from
        # that head's loss via ignore_index — it does not need is_compromise
        # to also be restricted to it). Reusing COMPROMISE_TECHNIQUES for
        # both used to mislabel every CIC brute-force row (T1110, not in the
        # 10-class set) as infiltration_label=0 — i.e. "not an attack" —
        # which is wrong and was quietly corrupting the binary-detection
        # ground truth for every merged CIC-IDS-2018 attack row.
        "mitre_technique":      mitre,
        "cic_label":            cic_label,
        "is_compromise":        int(mitre != "BENIGN"),
        "infiltration_label":   int(mitre != "BENIGN"),
        # Day-qualified source so world_model.py's segment-aware sequence
        # building and train/test split (see _purged_segment_split) treat
        # each CIC day as its own contiguous block, same as it already does
        # for the honeypot's own flows — never silently blending two
        # unrelated traffic sources into one sliding window.
        "source":               f"cic_ids_2018:{day_label}",
    }


# ─────────────────────────────────────────────────────────
# MERGE WITH HONEYPOT FEATURES
# ─────────────────────────────────────────────────────────

def merge_with_honeypot(cic_features: list[dict],
                         honeypot_path: str = "features.json") -> list[dict]:
    """
    Merge CIC-IDS-2018 features with honeypot features from packet_capture.py.
    Result is a combined training dataset with both real attack data sources.
    """
    try:
        with open(honeypot_path) as f:
            honeypot = json.load(f)
        print(f"[CIC] Loaded {len(honeypot)} honeypot flows from {honeypot_path}")
    except FileNotFoundError:
        print(f"[CIC] {honeypot_path} not found — using CIC data only")
        honeypot = []

    combined = honeypot + cic_features

    # Technique distribution
    from collections import Counter
    dist = Counter(f["mitre_technique"] for f in combined)
    print(f"[CIC] Combined dataset: {len(combined)} flows")
    print(f"[CIC] Technique distribution: {dict(dist.most_common(10))}")

    return combined


# ─────────────────────────────────────────────────────────
# NORMALISE (same as packet_capture.py for consistency)
# ─────────────────────────────────────────────────────────

NUMERIC_FEATURES = [
    "bytes_total", "packets_total", "bytes_fwd", "bytes_bwd",
    "packets_fwd", "packets_bwd", "flow_duration_ms", "bidir_ratio",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
    "has_syn", "has_ack", "has_fin", "has_rst", "has_psh", "has_urg",
    "iat_mean", "iat_std", "iat_max",
    "ttl_mean", "ttl_std",
    "tcp_window_mean", "tcp_window_std",
    "payload_size_mean", "payload_size_std",
    "retransmission_count", "port_scan_score", "unique_dst_ports",
]


def normalise(features: list[dict]) -> list[dict]:
    """Min-max normalise numeric features. Load existing params if available."""
    params_path = "features_norm_params.json"
    params = {}

    if os.path.exists(params_path):
        with open(params_path) as f:
            params = json.load(f)
        print(f"[CIC] Loaded normalisation params from {params_path}")
    else:
        for col in NUMERIC_FEATURES:
            vals = [float(f.get(col, 0)) for f in features]
            params[col] = {"min": min(vals), "max": max(vals)}
        with open(params_path, "w") as f:
            json.dump(params, f, indent=2)

    for feat in features:
        for col in NUMERIC_FEATURES:
            mn  = params.get(col, {}).get("min", 0.0)
            mx  = params.get(col, {}).get("max", 1.0)
            raw = float(feat.get(col, 0.0))
            feat[f"{col}_norm"] = round((raw - mn) / (mx - mn), 6) if mx > mn else 0.0

    return features


# ─────────────────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────────────────

def save(features: list[dict], path: str = "features.json"):
    with open(path, "w") as f:
        json.dump(features, f, indent=2)
    print(f"[CIC] Saved {len(features)} flows to {path}")

    # Also CSV
    csv_path = path.replace(".json", ".csv")
    if features:
        cols = list(features[0].keys())
        with open(csv_path, "w") as f:
            f.write(",".join(cols) + "\n")
            for feat in features:
                f.write(",".join(str(feat.get(c, "")) for c in cols) + "\n")
        print(f"[CIC] Saved CSV to {csv_path}")


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel — CIC-IDS-2018 loader"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--download", action="store_true",
                       help="Download Wednesday CIC-IDS-2018 CSV")
    group.add_argument("--csv", metavar="FILE",
                       help="Load existing CIC CSV file")

    parser.add_argument("--day",      default=DEFAULT_FILE,
                        choices=list(CIC_FILES.keys()),
                        help="Which day to download")
    parser.add_argument("--max-rows", type=int, default=20000,
                        help="Target OUTPUT sample size, scanned across the "
                             "WHOLE file not just its head (default: 20000)")
    parser.add_argument("--seed",     type=int, default=42,
                        help="Sampling seed — same seed always gives the same sample")
    parser.add_argument("--merge",    metavar="HONEYPOT_JSON",
                        help="Merge with honeypot features.json")
    parser.add_argument("--out",      default="features.json",
                        help="Output path (default: features.json)")
    parser.add_argument("--no-norm",  action="store_true")
    args = parser.parse_args()

    # Load CIC data
    if args.download:
        csv_path = download_cic(args.day)
        if not csv_path:
            sys.exit(1)
        day_label = args.day
    else:
        csv_path = args.csv
        # If the given --csv path happens to match a known day's filename,
        # use that day's pretty label; otherwise load_cic_csv derives one
        # from the filename itself.
        day_label = next((k for k, v in CIC_FILES.items() if v == os.path.basename(csv_path)), None)

    features = load_cic_csv(csv_path, max_rows=args.max_rows, seed=args.seed, day_label=day_label)
    if not features:
        print("[CIC] No features loaded")
        sys.exit(1)

    # Merge with honeypot data
    if args.merge:
        features = merge_with_honeypot(features, args.merge)
    elif os.path.exists("features.json"):
        print("[CIC] Found existing features.json — merging automatically")
        features = merge_with_honeypot(features, "features.json")

    # Normalise
    if not args.no_norm:
        features = normalise(features)

    # Save
    save(features, args.out)

    print(f"\n[CIC] Next step:")
    print(f"  python3 world_model.py --train --features {args.out}")


if __name__ == "__main__":
    main()
