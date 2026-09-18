"""
Run inference on a single session and emit a defender alert.

This is the operational output: given the events seen so far, forecast the
likely next techniques, classify the campaign, estimate severity, and map to
recommended defensive actions. Purely a detection/response aid.

Usage:
    python3 predict.py --ckpt cybersentinel_v3.pt            # demo session
    python3 predict.py --ckpt cybersentinel_v3.pt --session my_session.json
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone

import numpy as np

import config as C
import features as F

# Defensive playbook keyed by predicted attack class (response guidance only).
RESPONSE_PLAYBOOK = {
    "ransomware": [
        "Isolate the affected host from the network immediately",
        "Snapshot/preserve VMs before encryption spreads",
        "Block SMB (445) laterally at the segment boundary",
        "Revoke active sessions/tokens for impacted accounts",
    ],
    "wiper": [
        "Isolate host; assume destructive intent (no decryption path)",
        "Protect backups and out-of-band recovery media now",
        "Alert IR on-call \u2014 treat as critical",
    ],
    "rat": [
        "Hunt for the C2 beacon and block the destination",
        "Reset credentials that may have been captured",
        "Inspect persistence (autoruns, scheduled tasks, services)",
    ],
    "infostealer": [
        "Force password resets; invalidate browser/session cookies",
        "Rotate any secrets/API keys accessible from the host",
        "Review outbound data volume for exfiltration",
    ],
    "botnet": [
        "Block C2 domains/IPs; sinkhole if possible",
        "Check for spam/DDoS participation from the host",
    ],
    "cryptominer": [
        "Kill mining process; block mining-pool ports/domains",
        "Right-size affected cloud resources / quotas",
    ],
    "apt": [
        "Do NOT tip off the actor \u2014 coordinate a scoped IR",
        "Preserve forensic evidence; expand hunt for LOLBins",
        "Assume long dwell; audit persistence and cred access",
    ],
    "fileless": [
        "Capture volatile memory before reboot",
        "Constrain PowerShell/WMI; enable script-block logging",
    ],
    "benign": [
        "No action required \u2014 monitor",
    ],
}


def demo_session():
    import synthetic_data as S
    import random
    return S.generate_session("ransomware", random.Random(3))


def load_session(path):
    import synthetic_data as S
    with open(path) as fh:
        raw = json.load(fh)
    return S.Session(**raw)


def predict(ckpt: str, session):
    import torch
    from model import CyberSentinelV3
    from dataset import build_arrays

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = CyberSentinelV3().to(device)
    model.load_state_dict(torch.load(ckpt, map_location=device)["model"])
    model.eval()

    arr = build_arrays([session])
    to_t = lambda k: torch.tensor(arr[k]).to(device)
    with torch.no_grad():
        out = model(to_t("tech"), to_t("tactic"), to_t("protocol"),
                    to_t("numeric"), to_t("boolean"), to_t("mask"))

    tech = torch.softmax(out["technique"][0], -1).cpu().numpy()
    cls = torch.softmax(out["class"][0], -1).cpu().numpy()
    fam = torch.softmax(out["family"][0], -1).cpu().numpy()
    sev = float(out["severity"][0].cpu())

    top3 = np.argsort(-tech)[:3]
    cls_idx = int(np.argmax(cls))
    fam_idx = int(np.argmax(fam))
    attack_class = F.IDX2CLASS[cls_idx]

    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "predicted_next": [
            {"technique": F.IDX2TECH[int(t)],
             "name": C.TECHNIQUES[F.IDX2TECH[int(t)]][0],
             "prob": round(float(tech[t]), 3)} for t in top3
        ],
        "attack_class": attack_class,
        "class_confidence": round(float(cls[cls_idx]), 3),
        "malware_family": F.IDX2FAMILY[fam_idx],
        "family_confidence": round(float(fam[fam_idx]), 3),
        "severity": round(sev, 3),
        "recommended_actions": RESPONSE_PLAYBOOK.get(attack_class, []),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", type=str, default="cybersentinel_v3.pt")
    ap.add_argument("--session", type=str, default=None)
    args = ap.parse_args()
    session = load_session(args.session) if args.session else demo_session()
    alert = predict(args.ckpt, session)
    print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
