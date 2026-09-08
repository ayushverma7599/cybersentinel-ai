"""
CyberSentinel AI — packet_capture.py
Step 1 of 4: Scapy PCAP feature extractor

SIH26153 requirement:
  "A feature extraction pipeline that ingests raw PCAP files parsed using Scapy
   and outputs a timestamped, normalised feature matrix covering both flow-level
   and packet-level attributes."

What this produces:
  Flow-level features (NetFlow/IPFIX format):
    - src_ip, dst_ip, src_port, dst_port, protocol
    - tcp_flags (SYN, ACK, FIN, RST, PSH, URG bitmask)
    - bytes_total, packets_total, flow_duration_ms
    - iat_mean, iat_std, iat_max (inter-arrival time statistics)
    - bidir_ratio (bytes sent / bytes received)

  Packet-level features (PCAP-derived):
    - ttl_mean, ttl_std (TTL variance across session)
    - tcp_window_mean, tcp_window_std
    - payload_size_mean, payload_size_std
    - retransmission_count
    - port_scan_score (sequential/random port access pattern)
    - syn_ratio, ack_ratio, fin_ratio (flag distributions)

Output:
  features.json  — one record per flow, used by world_model.py for training
  features.csv   — same data, for logistic regression baseline

Usage:
  # Capture live during attack simulation
  sudo python3 packet_capture.py --live --iface docker0 --duration 60

  # Parse existing PCAP file
  python3 packet_capture.py --pcap cowrie_capture.pcap

  # Use Cowrie JSON logs as proxy (if no PCAP available)
  python3 packet_capture.py --cowrie cowrie-raw.json

Install:
  pip install scapy --break-system-packages
"""

import argparse
import json
import math
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Scapy import ─────────────────────────────────────────
try:
    from scapy.all import (
        sniff, rdpcap, IP, TCP, UDP, Raw,
        PcapWriter, conf
    )
    conf.verb = 0          # suppress Scapy output
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[Capture] Scapy not found. Install: pip install scapy --break-system-packages")

# ── Output paths ─────────────────────────────────────────
FEATURES_JSON = "features.json"
FEATURES_CSV  = "features.csv"

# ── TCP flag bitmasks ────────────────────────────────────
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

# ── MITRE technique heuristics ───────────────────────────
# Map observed network patterns → likely MITRE technique
# Used to label flows for LSTM training
TECHNIQUE_HEURISTICS = {
    "T1110": lambda f: f["syn_ratio"] > 0.8 and f["dst_port"] in (22, 23, 3389, 445),
    "T1082": lambda f: f["payload_size_mean"] < 100 and f["dst_port"] == 22,
    "T1087": lambda f: f["payload_size_mean"] < 150 and f["dst_port"] == 22,
    "T1105": lambda f: f["dst_port"] in (80, 443, 21, 8080) and f["bytes_total"] > 1000,
    "T1204": lambda f: f["dst_port"] in (80, 443) and f["syn_ratio"] < 0.3 and f["bytes_total"] > 500,
    "T1059": lambda f: f["dst_port"] == 22 and f["flow_duration_ms"] > 5000,
    "T1071": lambda f: f["dst_port"] in (80, 443, 53) and f["iat_mean"] > 100,
    "T1046": lambda f: f["port_scan_score"] > 0.6,
}

COMPROMISE_TECHNIQUES = {
    "T1105", "T1204", "T1059", "T1548", "T1136", "T1070"
}


# ─────────────────────────────────────────────────────────
# FLOW TRACKER
# Groups packets into bidirectional flows
# ─────────────────────────────────────────────────────────

class FlowKey:
    """Bidirectional flow key: (min_ip, max_ip, min_port, max_port, proto)"""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        if (src_ip, src_port) < (dst_ip, dst_port):
            self.key = (src_ip, dst_ip, src_port, dst_port, proto)
            self.fwd = (src_ip, src_port)
        else:
            self.key = (dst_ip, src_ip, dst_port, src_port, proto)
            self.fwd = (dst_ip, dst_port)

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return self.key == other.key


class FlowRecord:
    """Accumulates per-packet stats into a flow feature vector."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, first_ts):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto

        self.first_ts = first_ts
        self.last_ts  = first_ts
        self.prev_ts  = first_ts

        # Counters
        self.packets_fwd = 0
        self.packets_bwd = 0
        self.bytes_fwd   = 0
        self.bytes_bwd   = 0

        # TCP flags (union across all packets)
        self.flags_seen  = 0
        self.syn_count   = 0
        self.ack_count   = 0
        self.fin_count   = 0
        self.rst_count   = 0

        # Packet-level lists
        self.ttl_values      = []
        self.window_sizes    = []
        self.payload_sizes   = []
        self.iat_values      = []       # inter-arrival times (ms)
        self.dst_ports_seen  = set()    # for port scan detection
        self.retransmissions = 0
        self.seq_numbers     = []

    def add_packet(self, pkt, is_fwd: bool, ts: float):
        """Ingest one packet into this flow."""
        size = len(pkt)

        # IAT
        iat_ms = (ts - self.prev_ts) * 1000.0
        if iat_ms > 0:
            self.iat_values.append(iat_ms)
        self.prev_ts = ts
        self.last_ts = ts

        # Direction
        if is_fwd:
            self.packets_fwd += 1
            self.bytes_fwd   += size
        else:
            self.packets_bwd += 1
            self.bytes_bwd   += size

        # IP layer
        if pkt.haslayer(IP):
            self.ttl_values.append(pkt[IP].ttl)

        # TCP layer
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            self.flags_seen |= flags
            if flags & FLAG_SYN: self.syn_count += 1
            if flags & FLAG_ACK: self.ack_count += 1
            if flags & FLAG_FIN: self.fin_count += 1
            if flags & FLAG_RST: self.rst_count += 1
            self.window_sizes.append(tcp.window)
            self.dst_ports_seen.add(tcp.dport)

            # Retransmission heuristic: duplicate seq number
            seq = tcp.seq
            if seq in self.seq_numbers and seq != 0:
                self.retransmissions += 1
            self.seq_numbers.append(seq)

        # Payload size
        if pkt.haslayer(Raw):
            self.payload_sizes.append(len(pkt[Raw].load))
        else:
            self.payload_sizes.append(0)

    def _stats(self, lst):
        """Return (mean, std, max) of a list, safe for empty lists."""
        if not lst:
            return 0.0, 0.0, 0.0
        n    = len(lst)
        mean = sum(lst) / n
        var  = sum((x - mean) ** 2 for x in lst) / n if n > 1 else 0.0
        return round(mean, 4), round(math.sqrt(var), 4), round(max(lst), 4)

    def _port_scan_score(self) -> float:
        """
        Score 0-1 indicating likelihood of port scanning behaviour.
        High score = many different destination ports accessed = port scan.
        Sequential ports score higher than random (classic nmap pattern).
        """
        ports = sorted(self.dst_ports_seen)
        if len(ports) < 3:
            return 0.0
        # Sequential score: how many consecutive port numbers
        consecutive = sum(
            1 for i in range(len(ports) - 1)
            if ports[i+1] - ports[i] == 1
        )
        diversity = len(ports) / max(self.packets_fwd + self.packets_bwd, 1)
        seq_ratio = consecutive / max(len(ports) - 1, 1)
        return round(min(1.0, diversity * 0.5 + seq_ratio * 0.5), 4)

    def to_feature_vector(self) -> dict:
        """Convert accumulated stats to a flat feature dict."""
        total_pkts = self.packets_fwd + self.packets_bwd
        total_bytes = self.bytes_fwd + self.bytes_bwd
        duration_ms = (self.last_ts - self.first_ts) * 1000.0

        iat_mean, iat_std, iat_max       = self._stats(self.iat_values)
        ttl_mean, ttl_std, _             = self._stats(self.ttl_values)
        win_mean, win_std, _             = self._stats(self.window_sizes)
        pay_mean, pay_std, _             = self._stats(self.payload_sizes)

        syn_ratio = self.syn_count / max(total_pkts, 1)
        ack_ratio = self.ack_count / max(total_pkts, 1)
        fin_ratio = self.fin_count / max(total_pkts, 1)
        rst_ratio = self.rst_count / max(total_pkts, 1)
        bidir     = self.bytes_fwd / max(self.bytes_bwd, 1)

        fv = {
            # ── Identifiers ──────────────────────────────
            "src_ip":               self.src_ip,
            "dst_ip":               self.dst_ip,
            "src_port":             self.src_port,
            "dst_port":             self.dst_port,
            "protocol":             self.proto,
            "timestamp":            datetime.fromtimestamp(self.first_ts).isoformat(),

            # ── Flow-level (NetFlow/IPFIX) ────────────────
            "bytes_total":          total_bytes,
            "packets_total":        total_pkts,
            "bytes_fwd":            self.bytes_fwd,
            "bytes_bwd":            self.bytes_bwd,
            "packets_fwd":          self.packets_fwd,
            "packets_bwd":          self.packets_bwd,
            "flow_duration_ms":     round(duration_ms, 2),
            "bidir_ratio":          round(bidir, 4),

            # TCP flag bitmask + ratios
            "tcp_flags_bitmask":    self.flags_seen,
            "syn_ratio":            round(syn_ratio, 4),
            "ack_ratio":            round(ack_ratio, 4),
            "fin_ratio":            round(fin_ratio, 4),
            "rst_ratio":            round(rst_ratio, 4),
            "has_syn":              int(bool(self.flags_seen & FLAG_SYN)),
            "has_ack":              int(bool(self.flags_seen & FLAG_ACK)),
            "has_fin":              int(bool(self.flags_seen & FLAG_FIN)),
            "has_rst":              int(bool(self.flags_seen & FLAG_RST)),
            "has_psh":              int(bool(self.flags_seen & FLAG_PSH)),
            "has_urg":              int(bool(self.flags_seen & FLAG_URG)),

            # IAT statistics
            "iat_mean":             iat_mean,
            "iat_std":              iat_std,
            "iat_max":              iat_max,

            # ── Packet-level (PCAP-derived) ───────────────
            "ttl_mean":             ttl_mean,
            "ttl_std":              ttl_std,
            "tcp_window_mean":      win_mean,
            "tcp_window_std":       win_std,
            "payload_size_mean":    pay_mean,
            "payload_size_std":     pay_std,
            "retransmission_count": self.retransmissions,
            "port_scan_score":      self._port_scan_score(),
            "unique_dst_ports":     len(self.dst_ports_seen),
        }

        # ── MITRE technique label (for LSTM training) ─────
        technique = "UNKNOWN"
        for tid, heuristic in TECHNIQUE_HEURISTICS.items():
            try:
                if heuristic(fv):
                    technique = tid
                    break
            except Exception:
                pass
        fv["mitre_technique"]    = technique
        fv["is_compromise"]      = int(technique in COMPROMISE_TECHNIQUES)
        fv["infiltration_label"] = fv["is_compromise"]

        return fv


# ─────────────────────────────────────────────────────────
# PCAP PARSER
# ─────────────────────────────────────────────────────────

def parse_pcap(pcap_path: str, max_packets: int = 50000) -> list[dict]:
    """
    Parse a PCAP file using Scapy.
    Returns list of flow feature vectors.
    """
    if not SCAPY_OK:
        print("[Capture] Scapy not available — cannot parse PCAP")
        return []

    print(f"[Capture] Reading {pcap_path}...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[Capture] Failed to read PCAP: {e}")
        return []

    print(f"[Capture] {len(packets)} packets loaded")
    return _process_packets(packets[:max_packets])


def _process_packets(packets) -> list[dict]:
    """Group packets into flows and extract feature vectors."""
    flows: dict = {}
    processed = 0

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        # Only TCP and UDP
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = "TCP"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = "UDP"
        else:
            continue

        ts  = float(pkt.time)
        fk  = FlowKey(ip.src, ip.dst, sport, dport, proto)
        is_fwd = fk.fwd == (ip.src, sport)

        if fk not in flows:
            flows[fk] = FlowRecord(
                src_ip=ip.src, dst_ip=ip.dst,
                src_port=sport, dst_port=dport,
                proto=proto, first_ts=ts
            )

        flows[fk].add_packet(pkt, is_fwd, ts)
        processed += 1

    print(f"[Capture] Processed {processed} packets → {len(flows)} flows")
    features = [fr.to_feature_vector() for fr in flows.values()]
    return features


# ─────────────────────────────────────────────────────────
# LIVE CAPTURE
# ─────────────────────────────────────────────────────────

def live_capture(iface: str = "docker0",
                 duration: int = 60,
                 output_path: str = "live_capture.pcap") -> list[dict]:
    """
    Capture live traffic on an interface for `duration` seconds.
    Saves to PCAP then processes into feature vectors.
    Requires root / sudo.
    """
    if not SCAPY_OK:
        print("[Capture] Scapy not available")
        return []

    print(f"[Capture] Live capture on {iface} for {duration}s...")
    print(f"[Capture] Run ./attack.sh in another terminal now")
    print(f"[Capture] Saving to {output_path}")

    writer = PcapWriter(output_path, append=False, sync=True)
    captured = []

    def handle(pkt):
        writer.write(pkt)
        captured.append(pkt)

    try:
        sniff(iface=iface, prn=handle, timeout=duration,
              filter="tcp or udp", store=False)
    except PermissionError:
        print("[Capture] Permission denied — run with sudo")
        return []
    except Exception as e:
        print(f"[Capture] Capture error: {e}")
        return []

    writer.close()
    print(f"[Capture] Captured {len(captured)} packets → processing...")
    return _process_packets(captured)


# ─────────────────────────────────────────────────────────
# COWRIE JSON PROXY
# When no PCAP is available, derive approximate flow features
# from Cowrie session logs (application-layer proxy)
# ─────────────────────────────────────────────────────────

def parse_cowrie_as_flows(cowrie_json_path: str) -> list[dict]:
    """
    Parse Cowrie JSON logs and synthesize approximate flow feature vectors.

    This is a proxy mode: Cowrie gives us session-level data, not raw packets.
    We derive approximate flow-level features from session metadata.
    Packet-level features (TTL, window size) are estimated from SSH defaults.

    Use this when:
      - No PCAP capture is available
      - Scapy is not installed
      - You want to cross-reference with Cowrie session data
    """
    print(f"[Capture] Parsing Cowrie JSON as flow proxy: {cowrie_json_path}")

    try:
        with open(cowrie_json_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[Capture] {cowrie_json_path} not found")
        return []

    # Group events by session
    sessions = defaultdict(list)
    for line in lines:
        try:
            event = json.loads(line.strip())
            sid = event.get("session", "")
            if sid:
                sessions[sid].append(event)
        except json.JSONDecodeError:
            continue

    print(f"[Capture] Found {len(sessions)} sessions in Cowrie log")
    features = []

    for sid, events in sessions.items():
        if not events:
            continue

        # Extract session metadata
        connect_event = next(
            (e for e in events if e.get("eventid") == "cowrie.session.connect"), None
        )
        if not connect_event:
            continue

        src_ip   = connect_event.get("src_ip", "0.0.0.0")
        src_port = connect_event.get("src_port", 0)
        dst_port = 2222   # Cowrie default

        # Timestamps
        timestamps = []
        for e in events:
            ts_str = e.get("timestamp", "")
            if ts_str:
                try:
                    from datetime import datetime
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(ts.timestamp())
                except Exception:
                    pass

        if len(timestamps) < 2:
            timestamps = [time.time(), time.time() + 1.0]

        duration_ms = (max(timestamps) - min(timestamps)) * 1000.0

        # Count event types
        login_attempts = sum(
            1 for e in events
            if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
        )
        commands = [
            e.get("input", "")
            for e in events
            if e.get("eventid") == "cowrie.command.input"
        ]
        downloads = [
            e for e in events
            if e.get("eventid") in ("cowrie.session.file_download",
                                    "cowrie.session.file_download.failed")
        ]
        login_success = any(
            e.get("eventid") == "cowrie.login.success" for e in events
        )

        # Synthesize IAT from event timestamps
        iats = []
        for i in range(1, len(timestamps)):
            iat = (timestamps[i] - timestamps[i-1]) * 1000.0
            if iat > 0:
                iats.append(iat)

        iat_mean = sum(iats) / len(iats) if iats else 0.0
        iat_std  = math.sqrt(
            sum((x - iat_mean)**2 for x in iats) / len(iats)
        ) if len(iats) > 1 else 0.0
        iat_max  = max(iats) if iats else 0.0

        # Estimate bytes from command lengths
        cmd_bytes = sum(len(c) for c in commands) * 10   # rough estimate
        total_bytes = max(cmd_bytes, 500)  # SSH handshake minimum

        # SSH default packet-level estimates
        ttl_mean    = 64.0   # Linux SSH default TTL
        ttl_std     = 0.0
        win_mean    = 65535.0
        win_std     = 0.0
        pay_mean    = float(total_bytes) / max(len(events), 1)
        pay_std     = pay_mean * 0.3

        # Flags: brute force = high SYN ratio; established session = ACK dominant
        if login_attempts > 3 and not login_success:
            syn_ratio = 0.85
            ack_ratio = 0.10
            flags     = FLAG_SYN | FLAG_RST
        elif login_success:
            syn_ratio = 0.10
            ack_ratio = 0.75
            flags     = FLAG_SYN | FLAG_ACK | FLAG_PSH | FLAG_FIN
        else:
            syn_ratio = 0.50
            ack_ratio = 0.40
            flags     = FLAG_SYN | FLAG_ACK

        # MITRE technique labelling from Cowrie events
        if login_attempts > 5 and not login_success:
            technique = "T1110"
        elif downloads:
            technique = "T1105"
        elif commands and any(
            kw in " ".join(commands).lower()
            for kw in ["wget", "curl", "chmod", "payload", "./"]
        ):
            technique = "T1204"
        elif commands and any(
            kw in " ".join(commands).lower()
            for kw in ["uname", "id", "whoami", "cat /etc"]
        ):
            technique = "T1082" if "uname" in " ".join(commands).lower() else "T1087"
        elif login_success and commands:
            technique = "T1059"
        else:
            technique = "T1082"

        fv = {
            # Identifiers
            "src_ip":               src_ip,
            "dst_ip":               "172.18.0.2",
            "src_port":             src_port,
            "dst_port":             dst_port,
            "protocol":             "TCP",
            "timestamp":            datetime.fromtimestamp(min(timestamps)).isoformat(),
            "session_id":           sid,

            # Flow-level
            "bytes_total":          total_bytes,
            "packets_total":        len(events),
            "bytes_fwd":            total_bytes,
            "bytes_bwd":            total_bytes // 4,
            "packets_fwd":          len(events),
            "packets_bwd":          len(events) // 4,
            "flow_duration_ms":     round(duration_ms, 2),
            "bidir_ratio":          4.0,

            # TCP flags
            "tcp_flags_bitmask":    flags,
            "syn_ratio":            round(syn_ratio, 4),
            "ack_ratio":            round(ack_ratio, 4),
            "fin_ratio":            0.05,
            "rst_ratio":            round(1.0 - syn_ratio - ack_ratio - 0.05, 4),
            "has_syn":              int(bool(flags & FLAG_SYN)),
            "has_ack":              int(bool(flags & FLAG_ACK)),
            "has_fin":              int(bool(flags & FLAG_FIN)),
            "has_rst":              int(bool(flags & FLAG_RST)),
            "has_psh":              int(bool(flags & FLAG_PSH)),
            "has_urg":              0,

            # IAT
            "iat_mean":             round(iat_mean, 4),
            "iat_std":              round(iat_std, 4),
            "iat_max":              round(iat_max, 4),

            # Packet-level
            "ttl_mean":             ttl_mean,
            "ttl_std":              ttl_std,
            "tcp_window_mean":      win_mean,
            "tcp_window_std":       win_std,
            "payload_size_mean":    round(pay_mean, 4),
            "payload_size_std":     round(pay_std, 4),
            "retransmission_count": max(0, login_attempts - 1),
            "port_scan_score":      0.0,
            "unique_dst_ports":     1,

            # Labels
            "mitre_technique":      technique,
            "is_compromise":        int(technique in COMPROMISE_TECHNIQUES),
            "infiltration_label":   int(technique in COMPROMISE_TECHNIQUES),

            # Cowrie extras
            "login_attempts":       login_attempts,
            "login_success":        int(login_success),
            "command_count":        len(commands),
            "download_count":       len(downloads),
            "source":               "cowrie_proxy",
        }
        features.append(fv)

    print(f"[Capture] Generated {len(features)} flow feature vectors from Cowrie logs")
    return features


# ─────────────────────────────────────────────────────────
# FEATURE NORMALISATION
# ─────────────────────────────────────────────────────────

# Numeric feature columns used by LSTM and logistic regression
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
    """
    Min-max normalise all numeric features to [0, 1].
    Saves normalisation params to features_norm_params.json
    for use during inference.
    """
    if not features:
        return features

    params = {}
    for col in NUMERIC_FEATURES:
        vals = [f.get(col, 0.0) for f in features]
        mn, mx = min(vals), max(vals)
        params[col] = {"min": mn, "max": mx}

    for f in features:
        for col in NUMERIC_FEATURES:
            mn = params[col]["min"]
            mx = params[col]["max"]
            raw = f.get(col, 0.0)
            f[f"{col}_norm"] = round((raw - mn) / (mx - mn), 6) if mx > mn else 0.0

    with open("features_norm_params.json", "w") as fp:
        json.dump(params, fp, indent=2)
    print(f"[Capture] Normalisation params saved to features_norm_params.json")

    return features


# ─────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────

def save_features(features: list[dict],
                  json_path: str = FEATURES_JSON,
                  csv_path:  str = FEATURES_CSV):
    """Save feature vectors to JSON and CSV."""
    if not features:
        print("[Capture] No features to save")
        return

    # JSON
    with open(json_path, "w") as f:
        json.dump(features, f, indent=2)
    print(f"[Capture] Saved {len(features)} flows to {json_path}")

    # CSV
    cols = list(features[0].keys())
    with open(csv_path, "w") as f:
        f.write(",".join(cols) + "\n")
        for feat in features:
            row = ",".join(str(feat.get(c, "")) for c in cols)
            f.write(row + "\n")
    print(f"[Capture] Saved {len(features)} flows to {csv_path}")


def print_summary(features: list[dict]):
    """Print a summary of extracted features."""
    if not features:
        return

    from collections import Counter
    tech_counts = Counter(f["mitre_technique"] for f in features)
    compromise  = sum(f["infiltration_label"] for f in features)

    print()
    print("═" * 55)
    print("  PACKET CAPTURE — FEATURE EXTRACTION SUMMARY")
    print("═" * 55)
    print(f"  Total flows extracted:    {len(features)}")
    print(f"  Compromise-stage flows:   {compromise}  "
          f"({100*compromise//max(len(features),1)}%)")
    print(f"  Feature dimensions:       {len(NUMERIC_FEATURES)} numeric features")
    print()
    print("  MITRE technique distribution:")
    for tech, count in tech_counts.most_common():
        bar = "█" * min(count * 2, 30)
        print(f"    {tech:8s}  {bar}  {count}")
    print()
    print("  Sample feature vector (first flow):")
    fv = features[0]
    for key in ["src_ip", "dst_ip", "dst_port", "protocol",
                "bytes_total", "flow_duration_ms",
                "syn_ratio", "iat_mean", "ttl_mean",
                "port_scan_score", "mitre_technique", "infiltration_label"]:
        print(f"    {key:25s}: {fv.get(key, 'N/A')}")
    print("═" * 55)


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel — PCAP/Scapy feature extractor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live",   action="store_true",
                       help="Live capture on interface")
    group.add_argument("--pcap",   metavar="FILE",
                       help="Parse existing PCAP file")
    group.add_argument("--cowrie", metavar="FILE",
                       help="Parse Cowrie JSON log as flow proxy")

    parser.add_argument("--iface",    default="docker0",
                        help="Network interface for live capture (default: docker0)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Live capture duration in seconds (default: 60)")
    parser.add_argument("--out-json", default=FEATURES_JSON)
    parser.add_argument("--out-csv",  default=FEATURES_CSV)
    parser.add_argument("--no-norm",  action="store_true",
                        help="Skip normalisation")
    args = parser.parse_args()

    # Extract features
    if args.live:
        features = live_capture(args.iface, args.duration)
    elif args.pcap:
        features = parse_pcap(args.pcap)
    else:
        features = parse_cowrie_as_flows(args.cowrie)

    if not features:
        print("[Capture] No features extracted. Check input and try again.")
        sys.exit(1)

    # Normalise
    if not args.no_norm:
        features = normalise(features)

    # Save
    save_features(features, args.out_json, args.out_csv)
    print_summary(features)

    print(f"\n[Capture] Next step:")
    print(f"  python3 world_model.py --train --features {args.out_json}")


if __name__ == "__main__":
    main()
