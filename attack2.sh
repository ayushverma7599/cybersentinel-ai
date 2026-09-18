#!/usr/bin/env python3
"""
honeypot_http_traffic.py — controlled HTTP traffic generator for testing your
OWN HTTP honeypot on localhost and producing varied capture data for the
detection model.

This is a defensive test harness: it points at a honeypot you control and
generates benign, throttled, varied requests so your pipeline (packet capture
-> feature extraction -> classifier) has diverse data to learn from. It is not
a stress/DoS tool — volume is low and every worker sleeps between requests.

IMPORTANT — the target:
  Cowrie listens on port 2222 speaking SSH, NOT HTTP. Sending HTTP GETs to
  127.0.0.1:2222 will just hang or error, which is almost certainly why the
  original script "did nothing". Point --target at an actual HTTP honeypot,
  e.g. Glastopf (:80), SNARE/Tanner, or a simple web honeypot on :8080.

Usage:
  python3 honeypot_http_traffic.py --target http://127.0.0.1:8080/ --total 500
  python3 honeypot_http_traffic.py            # uses the defaults below
"""

from __future__ import annotations

import argparse
import random
import threading
import time
from collections import Counter

import requests

# --- benign, varied request shapes so the honeypot logs aren't monotonous ---
# (variety here directly fixes the "duplicate-heavy / low-variance" data problem
#  the evaluation harness flagged — more diverse flows = more useful features)
USER_AGENTS = [
    "Honeypot-Simulator/1.0",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "SecurityLab-Test/1.0",
    "curl/8.5.0",
    "python-requests/2.x",
]
PATHS = ["/", "/index.html", "/login", "/admin", "/robots.txt",
         "/status", "/api/health", "/favicon.ico"]
METHODS = ["GET", "GET", "GET", "HEAD", "POST"]   # weighted toward GET
SIM_IPS = ["10.10.0.11", "10.10.0.12", "10.10.0.13", "10.10.0.14", "10.10.0.15"]

stats = Counter()
lock = threading.Lock()


def send_request(session: requests.Session, base: str, timeout: float) -> None:
    sim_ip = random.choice(SIM_IPS)
    method = random.choice(METHODS)
    path = random.choice(PATHS)
    url = base.rstrip("/") + path
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        # App-layer hint so the honeypot can log a simulated source; this is
        # NOT network spoofing — the real socket is still loopback.
        "X-Simulated-IP": sim_ip,
    }

    # count the attempt regardless of outcome (fixes the original accounting)
    with lock:
        stats["attempts"] += 1

    try:
        start = time.time()
        resp = session.request(method, url, headers=headers, timeout=timeout)
        elapsed = time.time() - start
        with lock:
            stats["ok"] += 1
            stats[f"status_{resp.status_code}"] += 1
        print(f"[{sim_ip}] {method:4s} {path:15s} {resp.status_code} {elapsed:.3f}s")
    except requests.RequestException as e:
        with lock:
            stats["errors"] += 1
        print(f"[{sim_ip}] {method:4s} {path:15s} ERROR: {e}")


def worker(worker_id: int, count: int, base: str, timeout: float,
           delay: tuple[float, float]) -> None:
    print(f"[worker {worker_id}] sending {count} requests")
    with requests.Session() as session:          # reuse the connection
        for _ in range(count):
            send_request(session, base, timeout)
            time.sleep(random.uniform(*delay))
    print(f"[worker {worker_id}] done")


def run_burst(size: int, base: str, timeout: float) -> None:
    print("\n--- controlled burst ---")
    with requests.Session() as session:
        for _ in range(size):
            send_request(session, base, timeout)
    print("--- burst finished ---\n")


def split_counts(total: int, workers: int) -> list[int]:
    """Distribute `total` across workers, spreading any remainder."""
    base, rem = divmod(total, workers)
    return [base + (1 if i < rem else 0) for i in range(workers)]


def main() -> None:
    ap = argparse.ArgumentParser(description="Controlled HTTP traffic for your own honeypot")
    ap.add_argument("--target", default="http://127.0.0.1:8080/",
                    help="HTTP honeypot base URL (NOT Cowrie's SSH port 2222)")
    ap.add_argument("--total", type=int, default=500, help="total worker requests")
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--burst", type=int, default=20, help="extra burst requests at the end")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--min-delay", type=float, default=0.05)
    ap.add_argument("--max-delay", type=float, default=0.25)
    args = ap.parse_args()

    if ":2222" in args.target:
        print("WARNING: port 2222 is Cowrie's SSH port — HTTP requests will fail there.")
        print("         Point --target at a real HTTP honeypot (e.g. :80 or :8080).\n")

    print("=" * 52)
    print("  HONEYPOT HTTP TRAFFIC SIMULATOR (defensive test tool)")
    print("=" * 52)
    print(f"  target : {args.target}")
    print(f"  total  : {args.total}  | workers: {args.workers}  | burst: {args.burst}")
    print(f"  delay  : {args.min_delay}-{args.max_delay}s between requests\n")

    counts = split_counts(args.total, args.workers)
    threads = []
    for i, c in enumerate(counts):
        t = threading.Thread(target=worker,
                             args=(i + 1, c, args.target, args.timeout,
                                   (args.min_delay, args.max_delay)))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    if args.burst > 0:
        run_burst(args.burst, args.target, args.timeout)

    print("=" * 52)
    print("  SIMULATION COMPLETE")
    print("=" * 52)
    print(f"  attempts : {stats['attempts']}")
    print(f"  ok       : {stats['ok']}")
    print(f"  errors   : {stats['errors']}")
    for key in sorted(stats):
        if key.startswith("status_"):
            print(f"  {key} : {stats[key]}")


if __name__ == "__main__":
    main()
