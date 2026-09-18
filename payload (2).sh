#!/bin/bash
# CyberSentinel AI — harmless test payload
# This file proves T1105 (Ingress Tool Transfer) and T1204 (User Execution)
# It performs no harmful action — it only identifies itself
echo "[payload] CyberSentinel test payload executed"
echo "[payload] hostname: $(hostname 2>/dev/null || echo 'cowrie-honeypot')"
echo "[payload] whoami:   $(whoami 2>/dev/null || echo 'root')"
echo "[payload] T1204 User Execution — confirmed"
