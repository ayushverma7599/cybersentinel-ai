"""
Evaluate a trained CyberSentinel v3 checkpoint and print a report in the same
style as the original CyberSentinel LSTM eval (top-k, per-class accuracy bars,
confusion matrix, severity/impact calibration).

Usage:
    python3 evaluate.py --ckpt cybersentinel_v3.pt
    python3 evaluate.py --ckpt cybersentinel_v3.pt --data sessions.json
"""

from __future__ import annotations

import argparse

import numpy as np

import config as C
import features as F


def _bar(frac: float, width: int = 24) -> str:
    filled = int(round(frac * width))
    return "#" * filled + " " * (width - filled)


def evaluate(ckpt: str, data: str | None, sessions_n: int, seed: int):
    import torch
    from model import CyberSentinelV3
    from dataset import build_arrays
    import synthetic_data as S

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = CyberSentinelV3().to(device)
    state = torch.load(ckpt, map_location=device)
    model.load_state_dict(state["model"])
    model.eval()

    if data:
        sessions = S.load_sessions(data)
    else:
        # held-out split via a different seed
        sessions = S.build_dataset(n_sessions=sessions_n, seed=seed + 999)

    arr = build_arrays(sessions)
    to_t = lambda k: torch.tensor(arr[k]).to(device)

    with torch.no_grad():
        preds = model(to_t("tech"), to_t("tactic"), to_t("protocol"),
                      to_t("numeric"), to_t("boolean"), to_t("mask"))
        tech_logits = preds["technique"].cpu().numpy()
        class_logits = preds["class"].cpu().numpy()
        sev = preds["severity"].cpu().numpy()

    y = arr["y_tech"]
    yc = arr["y_class"]
    order = np.argsort(-tech_logits, axis=1)          # ranked predictions
    top1 = order[:, 0]

    n = len(y)
    K = C.NUM_TECHNIQUES

    def topk_acc(k):
        return np.mean([y[i] in order[i, :k] for i in range(n)])

    print()
    print("  CYBERSENTINEL v3 \u2014 EVALUATION REPORT")
    print("  " + "-" * 58)
    acc1, acc2, acc3 = topk_acc(1), topk_acc(2), topk_acc(3)
    print(f"  Top-1 accuracy:  {acc1*100:5.1f}%  ({int(acc1*n)}/{n} correct)")
    print(f"  Top-2 accuracy:  {acc2*100:5.1f}%")
    print(f"  Top-3 accuracy:  {acc3*100:5.1f}%")
    base = 1.0 / K
    print(f"  Random baseline: {base*100:5.1f}%  (1 / {K} classes)")
    print(f"  Lift over random:{acc1/base:5.1f}x  (top-1)")
    print()

    # ---- attack-class accuracy (the high-level label) --------------------
    class_pred = np.argmax(class_logits, axis=1)
    cls_acc = np.mean(class_pred == yc)
    print(f"  Attack-class accuracy: {cls_acc*100:5.1f}%  "
          f"({int(cls_acc*n)}/{n})")
    print()

    # ---- per-technique accuracy bars ------------------------------------
    print("  Per-technique accuracy:")
    present = sorted(set(int(v) for v in y))
    for t in present:
        idx = np.where(y == t)[0]
        acc = np.mean(top1[idx] == t) if len(idx) else 0.0
        name = F.IDX2TECH[t]
        print(f"    {name:7s} {_bar(acc)} {acc*100:3.0f}%  "
              f"({int(acc*len(idx))}/{len(idx)})")
    print()

    # ---- confusion matrix (top classes by support) ----------------------
    supports = {t: int(np.sum(y == t)) for t in present}
    top_classes = sorted(present, key=lambda t: -supports[t])[:8]
    print("  Confusion matrix (row=actual, col=predicted) \u2014 top 8 by support:")
    header = "         " + "".join(f"{F.IDX2TECH[t]:>8s}" for t in top_classes)
    print(header)
    for a in top_classes:
        row = [int(np.sum((y == a) & (top1 == b))) for b in top_classes]
        cells = "".join(
            (f"[{v:5d}]" if a == b else f"{v:7d} ")
            for v, b in zip(row, top_classes)
        )
        print(f"  {F.IDX2TECH[a]:7s}{cells}")
    print("  [bracketed] = correct predictions")
    print()

    # ---- severity / impact calibration ----------------------------------
    # Treat high-impact classes as the "compromise" positive set.
    high_impact = {F.CLASS2IDX[c] for c in
                   ("ransomware", "wiper", "apt", "rat", "infostealer")}
    is_hi = np.array([1 if c in high_impact else 0 for c in yc])
    if is_hi.sum() and (1 - is_hi).sum():
        avg_hi = sev[is_hi == 1].mean()
        avg_lo = sev[is_hi == 0].mean()
        print("  Severity calibration:")
        print(f"    Avg predicted severity on high-impact sessions: "
              f"{avg_hi*100:4.1f}%  (n={int(is_hi.sum())})")
        print(f"    Avg predicted severity on low-impact sessions:  "
              f"{avg_lo*100:4.1f}%  (n={int((1-is_hi).sum())})")
        delta = (avg_hi - avg_lo) * 100
        ok = "\u2713" if delta > 0 else "\u2717"
        print(f"    {ok} High-impact sessions score {delta:+.1f}% higher.")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ckpt", type=str, default="cybersentinel_v3.pt")
    ap.add_argument("--data", type=str, default=None)
    ap.add_argument("--sessions", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    evaluate(args.ckpt, args.data, args.sessions, args.seed)


if __name__ == "__main__":
    main()
