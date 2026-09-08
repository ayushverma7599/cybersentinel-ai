#!/bin/bash
echo "[*] CyberSentinel AI — Full Pipeline Run"
echo "[*] Step 1: Pulling fresh Cowrie logs..."
docker cp honeypot-cowrie-1:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ~/honeypot/cowrie-raw.json

echo "[*] Step 2: Extracting TTPs..."
python3 ~/honeypot/ttp_extract.py

echo "[*] Step 3: Running multi-agent scanner..."
python3 ~/honeypot/cybersentinel_skeleton.py
