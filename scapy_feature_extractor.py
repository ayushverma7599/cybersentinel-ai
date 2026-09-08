#!/usr/bin/env python3
"""
scapy_feature_extractor.py — REAL packet-level feature extraction from a
genuine PCAP capture, using Scapy.

WHY THIS EXISTS:
SIH26153 explicitly requires TWO levels of traffic features, and says the
combination is required, not optional:
  - Flow-level (NetFlow/IPFIX): src/dst IP/port, TCP flags, bytes, duration,
    IAT stats — already covered by the Cowrie-JSON-proxy + CIC-IDS-2018
    pipeline (world_model_pipeline.sh Step 1-2).
  - Packet-level (PCAP-derived): TTL values + variance, TCP window size,
    IP fragment flags, payload size distribution, port scan signatures,
    retransmission counts — this requires an ACTUAL packet capture. Cowrie's
    JSON session logs are application-layer only (commands typed); they
    contain no packet headers at all, so no amount of clever parsing can
    honestly produce real TTL/window/fragmentation/retransmission values
    from them. The previous pipeline's "Scapy proxy" step filled these with
    constants (ttl_mean=64.0 every time) rather than measured values.

This script fixes that by processing a REAL .pcap file captured with Scapy
(or tcpdump/Wireshark — any standard pcap works) during an actual attack.sh
run, and computing genuine per-flow packet-level statistics.

WORKFLOW (two steps, because sniffing needs root and a live capture window):

  Step 1 — capture real traffic while attack.sh runs (separate terminal,
  needs sudo since packet capture requires elevated privileges):

    sudo python3 scapy_feature_extractor.py --capture \\
        --iface docker0 --port 2222 --out honeypot_capture.pcap
    # (in another terminal) ./attack.sh
    # Ctrl+C the capture once attack.sh finishes

  Step 2 — extract real packet-level features from the capture:

    python3 scapy_feature_extractor.py --extract \\
        --pcap honeypot_capture.pcap --out packet_features.json

  packet_features.json can then be merged into features.json (see
  merge_packet_features() below) so downstream world_model.py training
  uses REAL packet-level values instead of the old proxy constants.

NOTE ON --iface: this must be whichever interface actually carries traffic
to your Cowrie container — commonly the Docker bridge (`docker0` or a
`br-xxxxxxxx` interface; check `ip addr` or `docker network inspect
honeypot_default` to find the exact name), NOT `lo` or your host's main
NIC, since Cowrie's container has its own bridge-routed address.
"""
import argparse
import json
import sys
from collections import defaultdict


def _require_scapy():
    try:
        from scapy.all import sniff, wrpcap, rdpcap, IP, TCP  # noqa: F401
    except ImportError:
        print("[!] scapy required: pip install scapy --break-system-packages")
        sys.exit(1)


def capture_traffic(iface: str, port: int, out_path: str):
    """Live-sniff real packets to/from the given port and save to a pcap.
    Requires root. Run this WHILE attack.sh is running in another terminal.
    """
    _require_scapy()
    from scapy.all import sniff, wrpcap

    print(f"[*] Sniffing on {iface}, filter: tcp port {port}")
    print(f"[*] Run ./attack.sh in another terminal now. Ctrl+C here when it finishes.")
    packets = sniff(iface=iface, filter=f"tcp port {port}")
    wrpcap(out_path, packets)
    print(f"[+] Captured {len(packets)} real packets to {out_path}")


def _mean(vals):
    return sum(vals) / len(vals) if vals else 0.0


def _variance(vals):
    if len(vals) < 2:
        return 0.0
    m = _mean(vals)
    return sum((v - m) ** 2 for v in vals) / len(vals)


def extract_features(pcap_path: str) -> dict:
    """
    Parse a real pcap and compute genuine per-flow packet-level features,
    matching SIH26153's explicit list:
      - TTL values and their variance across a session
      - TCP window size
      - IP fragment flags
      - payload size distribution
      - port scan signatures (distinct dst ports touched by one src)
      - retransmission counts
    """
    _require_scapy()
    from scapy.all import rdpcap, IP, TCP

    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} real packets from {pcap_path}")

    # Group by 5-tuple flow: (src_ip, dst_ip, src_port, dst_port, proto)
    flows = defaultdict(lambda: {
        "ttl_values": [],
        "window_sizes": [],
        "fragment_count": 0,
        "payload_sizes": [],
        "dst_ports_by_src": None,  # filled in below, shared across flow's src_ip
        "seq_seen": set(),
        "retransmissions": 0,
        "packet_count": 0,
    })
    dst_ports_by_src_ip = defaultdict(set)  # for port-scan signature, across ALL flows from an IP

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        flow_key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport, "TCP")
        f = flows[flow_key]

        f["packet_count"] += 1
        f["ttl_values"].append(ip_layer.ttl)
        f["window_sizes"].append(tcp_layer.window)

        # IP fragmentation: MF (more fragments) flag set, or non-zero frag offset
        if int(ip_layer.flags) & 0x1 or ip_layer.frag > 0:
            f["fragment_count"] += 1

        payload_len = len(tcp_layer.payload) if tcp_layer.payload else 0
        f["payload_sizes"].append(payload_len)

        # Retransmission: same (src,sport,dport,seq) seen more than once
        seq_key = (ip_layer.src, tcp_layer.sport, tcp_layer.dport, tcp_layer.seq)
        if seq_key in f["seq_seen"]:
            f["retransmissions"] += 1
        else:
            f["seq_seen"].add(seq_key)

        dst_ports_by_src_ip[ip_layer.src].add(tcp_layer.dport)

    results = {}
    for flow_key, f in flows.items():
        src_ip, dst_ip, sport, dport, proto = flow_key
        key_str = f"{src_ip}:{sport}->{dst_ip}:{dport}"
        results[key_str] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "packet_count": f["packet_count"],
            # Real measured values, not constants:
            "ttl_mean": round(_mean(f["ttl_values"]), 2),
            "ttl_variance": round(_variance(f["ttl_values"]), 4),
            "tcp_window_mean": round(_mean(f["window_sizes"]), 2),
            "ip_fragment_count": f["fragment_count"],
            "payload_size_mean": round(_mean(f["payload_sizes"]), 2),
            "payload_size_max": max(f["payload_sizes"]) if f["payload_sizes"] else 0,
            "retransmission_count": f["retransmissions"],
            # Port scan signature: how many distinct dst ports this src IP touched
            # across the WHOLE capture, not just this one flow.
            "distinct_dst_ports_from_src": len(dst_ports_by_src_ip[src_ip]),
        }

    return results


def merge_packet_features(packet_features_path: str, features_json_path: str, out_path: str):
    """
    Merge real packet-level features into the existing flow-level
    features.json, matched by src_port (Cowrie's src_port field, which is
    the same value the client's real TCP source port takes on the wire —
    so a genuine packet capture and a Cowrie session log from the SAME
    attack.sh run should share these values exactly).

    IMPORTANT: this only works if the pcap capture and features.json's
    underlying cowrie-raw.json come from the SAME attack.sh invocation.
    Ephemeral source ports are assigned fresh by the OS every run, so a
    capture from one run will never match a features.json built from a
    different run — that's not a bug to fix in this function, it's a
    sequencing requirement: capture packets, THEN pull fresh Cowrie logs
    from that same run, THEN rebuild features.json, THEN merge.

    Ports are normalized to int on both sides before matching, since a
    str/int mismatch (e.g. one side stores "49368", the other 49368) would
    otherwise cause a silent 0-match that looks identical to the
    different-run problem above.
    """
    with open(packet_features_path) as f:
        packet_features = json.load(f)
    with open(features_json_path) as f:
        flow_features = json.load(f)

    def _norm_port(p):
        try:
            return int(p)
        except (TypeError, ValueError):
            return None

    by_srcport = {}
    for v in packet_features.values():
        p = _norm_port(v.get("src_port"))
        if p is not None:
            by_srcport[p] = v

    merged = []
    matched = 0
    for row in flow_features:
        row = dict(row)  # copy
        src_port = _norm_port(row.get("src_port"))
        pkt = by_srcport.get(src_port)
        if pkt:
            row.update({
                "ttl_mean": pkt["ttl_mean"],
                "ttl_variance": pkt["ttl_variance"],
                "tcp_window_mean": pkt["tcp_window_mean"],
                "ip_fragment_count": pkt["ip_fragment_count"],
                "payload_size_mean": pkt["payload_size_mean"],
                "payload_size_max": pkt["payload_size_max"],
                "retransmission_count": pkt["retransmission_count"],
                "distinct_dst_ports_from_src": pkt["distinct_dst_ports_from_src"],
                "packet_features_source": "real_scapy_capture",
            })
            matched += 1
        else:
            row["packet_features_source"] = "unmatched_no_real_capture"
        merged.append(row)

    with open(out_path, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"[+] Merged: {matched}/{len(flow_features)} rows now have REAL packet-level features")
    print(f"[+] {len(flow_features) - matched} rows unmatched (no capture for that src_port) "
          f"— flagged as 'unmatched_no_real_capture', not silently faked")

    if matched == 0 and flow_features and packet_features:
        # Diagnostic: show both sides' ports so a mismatch is visible immediately,
        # instead of leaving "0 matched" as an unexplained dead end.
        flow_ports = sorted({_norm_port(r.get("src_port")) for r in flow_features})[:5]
        pcap_ports = sorted(by_srcport.keys())[:5]
        print(f"\n[!] Zero matches — sample ports from features.json: {flow_ports}")
        print(f"[!] Sample ports from this capture:                  {pcap_ports}")
        print(f"[!] If these look completely different, features.json and the pcap are from")
        print(f"[!] DIFFERENT attack.sh runs. Capture and log-pull must be the same run:")
        print(f"[!]   1. Start capture  2. Run attack.sh  3. Stop capture")
        print(f"[!]   4. Pull fresh cowrie-raw.json from THAT run  5. Rebuild features.json")
        print(f"[!]   6. Then re-run --extract and --merge")

    print(f"[+] Written to {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--capture", action="store_true", help="Live-sniff real packets (requires root)")
    parser.add_argument("--extract", action="store_true", help="Extract features from a saved pcap")
    parser.add_argument("--merge", action="store_true", help="Merge packet features into features.json")
    parser.add_argument("--iface", default="docker0", help="Network interface to sniff on")
    parser.add_argument("--port", type=int, default=2222, help="Port to filter on (Cowrie's SSH port)")
    parser.add_argument("--pcap", default="honeypot_capture.pcap", help="Path to pcap file")
    parser.add_argument("--features", default="features.json", help="Existing flow-level features.json")
    parser.add_argument("--out", default="packet_features.json", help="Output path")
    args = parser.parse_args()

    if args.capture:
        capture_traffic(args.iface, args.port, args.out if args.out != "packet_features.json" else "honeypot_capture.pcap")
    elif args.extract:
        results = extract_features(args.pcap)
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] {len(results)} real flows extracted, written to {args.out}")
    elif args.merge:
        merge_packet_features(args.out, args.features, "features_with_real_packets.json")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
