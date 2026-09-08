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
CIC_FILES = {
    "Wednesday-14-02-2018": "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-15-02-2018":  "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018":    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
}

# Default: Wednesday (SSH Brute Force day)
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
    "Infiltration":                 "T1105",

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

    if os.path.exists(out_path):
        print(f"[CIC] Already exists: {out_path}")
        return out_path

    print(f"[CIC] Downloading {filename}...")
    print(f"[CIC] URL: {url}")
    print(f"[CIC] This file is ~200MB — may take a few minutes")

    try:
        resp = requests.get(url, stream=True, timeout=30)
        resp.raise_for_status()

        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        with open(out_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = 100 * downloaded // total
                    print(f"\r[CIC] {pct}% ({downloaded // 1024 // 1024}MB)", end="")
        print()
        print(f"[CIC] Downloaded to {out_path}")
        return out_path

    except Exception as e:
        print(f"[CIC] Download failed: {e}")
        print(f"[CIC] Manual download:")
        print(f"  wget '{url}'")
        return None


# ─────────────────────────────────────────────────────────
# LOAD AND MAP
# ─────────────────────────────────────────────────────────

def load_cic_csv(csv_path: str,
                 max_rows: int = 10000,
                 balance: bool = True) -> list[dict]:
    """
    Load a CIC-IDS-2018 CSV and convert to CyberSentinel feature vectors.

    max_rows: limit rows for memory — CIC files have millions of flows
    balance:  balance benign vs attack samples (prevent class imbalance)
    """
    if not PANDAS_OK:
        print("[CIC] pandas required. Install: pip install pandas --break-system-packages")
        return []

    if not os.path.exists(csv_path):
        print(f"[CIC] File not found: {csv_path}")
        return []

    print(f"[CIC] Loading {csv_path}...")

    try:
        # Read with error handling for CIC's mixed encoding
        df = pd.read_csv(
            csv_path,
            encoding="utf-8",
            on_bad_lines="skip",
            nrows=max_rows * 3,    # read extra to allow balancing
            low_memory=False,
        )
    except Exception as e:
        print(f"[CIC] Failed to read CSV: {e}")
        return []

    print(f"[CIC] Loaded {len(df)} rows, {len(df.columns)} columns")

    # Normalise column names (strip whitespace)
    df.columns = [c.strip() for c in df.columns]

    # Check required columns exist
    label_col = None
    for possible in ["Label", "label", " Label"]:
        if possible.strip() in df.columns:
            label_col = possible.strip()
            break

    if label_col is None:
        print(f"[CIC] Warning: No Label column found. Columns: {list(df.columns[:10])}")
        df["Label"] = "BENIGN"
        label_col = "Label"

    # Balance: equal attack and benign samples
    if balance:
        benign  = df[df[label_col].str.upper() == "BENIGN"]
        attacks = df[df[label_col].str.upper() != "BENIGN"]
        n = min(len(benign), len(attacks), max_rows // 2)
        if n > 0:
            df = pd.concat([
                benign.sample(n=n, random_state=42),
                attacks.sample(n=min(n, len(attacks)), random_state=42)
            ]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"[CIC] Balanced: {len(df)} rows ({n} benign + {min(n,len(attacks))} attack)")

    df = df.head(max_rows)

    # Replace inf values
    df = df.replace([float("inf"), float("-inf")], 0)
    df = df.fillna(0)

    # Convert to feature vectors
    features = []
    label_counts = Counter()

    for _, row in df.iterrows():
        try:
            fv = _row_to_feature_vector(row, label_col)
            if fv:
                features.append(fv)
                label_counts[fv["mitre_technique"]] += 1
        except Exception:
            continue

    print(f"[CIC] Converted {len(features)} flows to feature vectors")
    print(f"[CIC] MITRE distribution: {dict(label_counts.most_common(8))}")
    return features


def _row_to_feature_vector(row, label_col: str) -> dict | None:
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

    # Skip if not useful for our techniques
    # Focus on T1110 (brute force) which honeypot data lacks
    # Keep all attacks + 30% of benign for balance
    import random
    if mitre == "BENIGN" and random.random() > 0.3:
        return None

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

        # Labels
        "mitre_technique":      mitre,
        "cic_label":            cic_label,
        "is_compromise":        int(mitre in COMPROMISE_TECHNIQUES),
        "infiltration_label":   int(mitre in COMPROMISE_TECHNIQUES),
        "source":               "cic_ids_2018",
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
    parser.add_argument("--max-rows", type=int, default=10000,
                        help="Max rows to load (default: 10000)")
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
    else:
        csv_path = args.csv

    features = load_cic_csv(csv_path, max_rows=args.max_rows)
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
