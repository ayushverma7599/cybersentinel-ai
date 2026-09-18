"""
Train CyberSentinel v3.

Usage:
    python3 train.py --epochs 15 --sessions 6000
    python3 train.py --data sessions.json          # train on saved telemetry

If no --data is given, a class-balanced synthetic set is generated so the
pipeline runs end-to-end. Swap in real EDR/sandbox/honeypot telemetry (same
Session schema) for a production model.
"""

from __future__ import annotations

import argparse
import os

import numpy as np

import config as C


def move_batch(batch, device):
    keys = ["tech", "tactic", "protocol", "numeric", "boolean", "mask",
            "y_tech", "y_class", "y_family", "y_sev"]
    return {k: t.to(device) for k, t in zip(keys, batch)}


def run_epoch(model, loader, loss_fn, class_w, device, optim=None):
    import torch
    train = optim is not None
    model.train(train)
    tot, n = 0.0, 0
    correct = 0
    with torch.set_grad_enabled(train):
        for batch in loader:
            b = move_batch(batch, device)
            preds = model(b["tech"], b["tactic"], b["protocol"],
                          b["numeric"], b["boolean"], b["mask"])
            targets = {"y_tech": b["y_tech"], "y_class": b["y_class"],
                       "y_family": b["y_family"], "y_sev": b["y_sev"]}
            loss, _ = loss_fn(preds, targets, class_w)
            if train:
                optim.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optim.step()
            bs = b["y_tech"].size(0)
            tot += loss.item() * bs
            n += bs
            correct += (preds["technique"].argmax(-1) == b["y_tech"]).sum().item()
    return tot / max(1, n), correct / max(1, n)


def main():
    import torch
    from model import CyberSentinelV3, hierarchical_loss
    from dataset import make_loaders
    import synthetic_data as S

    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=C.HP.epochs)
    ap.add_argument("--sessions", type=int, default=6000)
    ap.add_argument("--data", type=str, default=None)
    ap.add_argument("--out", type=str, default="cybersentinel_v3.pt")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[train] device={device}")

    if args.data and os.path.exists(args.data):
        sessions = S.load_sessions(args.data)
        print(f"[train] loaded {len(sessions)} real sessions from {args.data}")
    else:
        sessions = S.build_dataset(n_sessions=args.sessions, seed=args.seed)
        print(f"[train] generated {len(sessions)} synthetic sessions")

    train_loader, val_loader, class_w = make_loaders(sessions, seed=args.seed)
    class_w = class_w.to(device)

    model = CyberSentinelV3().to(device)
    optim = torch.optim.AdamW(model.parameters(), lr=C.HP.lr,
                              weight_decay=C.HP.weight_decay)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(optim, T_max=args.epochs)

    best_val = 0.0
    for ep in range(1, args.epochs + 1):
        tr_loss, tr_acc = run_epoch(model, train_loader, hierarchical_loss,
                                    class_w, device, optim)
        va_loss, va_acc = run_epoch(model, val_loader, hierarchical_loss,
                                    class_w, device, None)
        sched.step()
        print(f"[epoch {ep:02d}] train_loss={tr_loss:.3f} train_top1={tr_acc:.3f} "
              f"| val_loss={va_loss:.3f} val_top1={va_acc:.3f}")
        if va_acc >= best_val:
            best_val = va_acc
            torch.save({"model": model.state_dict(),
                        "config": {k: getattr(C.HP, k) for k in dir(C.HP)
                                   if not k.startswith("_")}},
                       args.out)
    print(f"[train] best val top-1 = {best_val:.3f} -> saved {args.out}")


if __name__ == "__main__":
    main()
