#!/usr/bin/env python3
import json
from collections import Counter

# Read logs
log_file = "/home/kali/honeypot/all-attacks.log"

ips = []
usernames = []
commands = []

with open(log_file, 'r') as f:
    for line in f:
        if "New connection:" in line:
            # Extract IP
            parts = line.split("New connection:")[1].strip().split(':')
            if parts:
                ips.append(parts[0])

# Count
print("=" * 60)
print("INDICATORS OF COMPROMISE (IOC) SUMMARY")
print("=" * 60)
print(f"\nTotal Unique Attacking IPs: {len(set(ips))}")
print("\nTop 10 Attacking IPs:")
for ip, count in Counter(ips).most_common(10):
    print(f"  {ip}: {count} attacks")

# Save to file
with open("/home/kali/honeypot/ioc-summary.txt", "w") as f:
    f.write("INDICATORS OF COMPROMISE\n")
    f.write("=" * 60 + "\n")
    f.write(f"Total Attacks: {len(ips)}\n")
    f.write(f"Unique IPs: {len(set(ips))}\n\n")
    f.write("Top 10 IPs:\n")
    for ip, count in Counter(ips).most_common(10):
        f.write(f"  {ip}: {count}\n")

print("\n[+] Summary saved to ioc-summary.txt")
