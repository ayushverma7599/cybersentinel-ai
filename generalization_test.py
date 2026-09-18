#!/usr/bin/env python3
"""
generalization_test.py — CyberSentinel AI / SIH26153

Tests whether the LSTM World Model genuinely GENERALIZES to unseen attack
types, rather than memorizing per-attack signatures.

The main benchmark (world_model.py --benchmark) holds out a chronological
slice of EVERY attack type it trains on — a fair, standard train/test split,
but it can't answer "does this model work on an attack it has never seen
at all?", because every category appears in both its train and test sets.

This script instead excludes one ENTIRE attack category from training at a
time — zero rows of that category anywhere in the training data — and
tests on nothing but that category. It repeats this once per category
(not just once, as the original version of this script did) now that all
10 CIC-IDS-2018 days are available, covering brute force, DoS, DDoS, web
attacks, infiltration, and botnet traffic, each fully held out in turn.

Categories are grouped by attack TYPE, not by individual day, wherever more
than one day shares a category (e.g. both DoS days held out together) —
holding out only one of two same-category days would let the model see
that category's general signature from the other day still in training,
which would defeat the point of testing generalization to something
genuinely unseen.

Usage:
    python3 generalization_test.py --features features_all.json --epochs 40
    python3 generalization_test.py --features features_all.json --groups "DoS,Botnet"
"""
import argparse
import json
import random

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                              precision_score, recall_score, roc_auc_score)
from sklearn.preprocessing import StandardScaler

from world_model import (FEATURES_PATH, INPUT_DIM, SEQ_LEN, TORCH_OK,
                          WorldModelLSTM, _purged_segment_split, flow_to_vector,
                          load_features, make_sequences)

if TORCH_OK:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset


# Each held-out group excludes ALL listed source prefixes from training and
# tests on ONLY those rows. Grouped by attack category (matching the
# category comments in cic_ids_loader.py's CIC_FILES), not by individual
# day, so a same-category day never leaks the pattern into training on the
# other side of a "held out" test.
HELD_OUT_GROUPS = [
    {
        "name": "Brute Force (T1110)",
        "prefixes": ["cic_ids_2018:Wednesday-14-02-2018"],
    },
    {
        "name": "DoS (T1499)",
        "prefixes": ["cic_ids_2018:Thursday-15-02-2018", "cic_ids_2018:Friday-16-02-2018"],
    },
    {
        "name": "DDoS (T1498)",
        "prefixes": ["cic_ids_2018:Tuesday-20-02-2018", "cic_ids_2018:Wednesday-21-02-2018"],
    },
    {
        "name": "Web Attacks (T1059/T1110/T1190)",
        "prefixes": ["cic_ids_2018:Thursday-22-02-2018", "cic_ids_2018:Friday-23-02-2018"],
    },
    {
        "name": "Infiltration (T1105)",
        "prefixes": ["cic_ids_2018:Wednesday-28-02-2018", "cic_ids_2018:Thursday-01-03-2018"],
    },
    {
        "name": "Botnet (T1071)",
        "prefixes": ["cic_ids_2018:Friday-02-03-2018"],
    },
]


def split_by_holdout_prefixes(features: list[dict], prefixes: list[str]) -> tuple:
    """
    Splits the flat feature list into (train_features, test_features) by
    excluding every row whose `source` starts with ANY of `prefixes` from
    train, and keeping ONLY those rows for test. Order is preserved (both
    outputs stay chronologically sorted within their own sources), and
    contiguous same-source runs stay contiguous, so make_sequences() still
    builds clean, non-overlapping segments on each side.
    """
    def _held_out(f):
        src = str(f.get("source", ""))
        return any(src.startswith(p) for p in prefixes)

    train_features = [f for f in features if not _held_out(f)]
    test_features  = [f for f in features if _held_out(f)]
    return train_features, test_features


def run_lstm_generalization(train_features: list[dict], test_features: list[dict],
                             group_name: str,
                             epochs: int = 60, lr: float = 0.001,
                             batch_size: int = 32, seed: int = 42) -> dict:
    if not TORCH_OK:
        print("[Generalization] PyTorch required")
        return {}

    random.seed(seed)
    torch.manual_seed(seed)

    X_all, y_all, y_state_all, y_tech_all, seg_ids_all = make_sequences(train_features, SEQ_LEN)
    X_test,  y_test,  y_state_test,  y_tech_test,  _ = make_sequences(test_features,  SEQ_LEN)
    if X_all is None or X_test is None:
        print(f"[Generalization] [{group_name}] Not enough data to build sequences on one side of the split")
        return {}

    # Carve a VALIDATION set out of the training data (everything-except-this-
    # category) for checkpoint selection. Selecting the best epoch on the
    # held-out category itself — the earlier behaviour — is peeking at the very
    # thing we claim is unseen, which inflates and destabilises the number.
    rel_train, rel_val = _purged_segment_split(seg_ids_all, test_split=0.2, purge=SEQ_LEN - 1)
    if not rel_val:
        rel_train, rel_val = list(range(len(X_all))), []
    X_train, y_train = X_all[rel_train], y_all[rel_train]
    y_state_train, y_tech_train = y_state_all[rel_train], y_tech_all[rel_train]
    has_val = len(rel_val) > 0
    if has_val:
        X_val, y_val = X_all[rel_val], y_all[rel_val]

    train_ds = TensorDataset(X_train, y_train, y_state_train, y_tech_train)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    model = WorldModelLSTM(input_dim=INPUT_DIM)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    criterion       = nn.BCELoss()
    state_criterion = nn.MSELoss()
    tech_criterion  = nn.CrossEntropyLoss(ignore_index=-100)
    STATE_LOSS_WEIGHT, TECH_LOSS_WEIGHT = 0.3, 0.3

    print(f"\n[Generalization] [{group_name}] Training LSTM on {len(X_train)} sequences "
          f"(everything EXCEPT this category)")
    print(f"[Generalization] [{group_name}] held out entirely: {len(X_test)} test sequences, "
          f"zero of which were trained on\n")

    best_sel, best_state = -1.0, None
    for epoch in range(1, epochs + 1):
        model.train()
        for Xb, yb, y_state_b, y_tech_b in train_loader:
            optimizer.zero_grad()
            inf_prob, tech_logits, next_state_pred = model(Xb)
            loss_bce = criterion(inf_prob.squeeze(-1), yb)
            loss_mse = state_criterion(next_state_pred, y_state_b)
            has_tech_labels = bool((y_tech_b != -100).any())
            loss_ce = tech_criterion(tech_logits, y_tech_b) if has_tech_labels else torch.tensor(0.0)
            loss = loss_bce + STATE_LOSS_WEIGHT * loss_mse + TECH_LOSS_WEIGHT * loss_ce
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        scheduler.step()

        # Checkpoint selection on the VALIDATION split (in-distribution held-out
        # rows from the training categories) — never on the unseen test
        # category. Falls back to the held-out set only when the data was too
        # small to carve a validation split at all.
        model.eval()
        with torch.no_grad():
            if has_val:
                vprob = model(X_val)[0].squeeze(-1).tolist()
                vpred = [1 if p >= 0.5 else 0 for p in vprob]
                sel = f1_score(y_val.tolist(), vpred, zero_division=0)
            else:
                tprob = model(X_test)[0].squeeze(-1).tolist()
                tpred = [1 if p >= 0.5 else 0 for p in tprob]
                sel = f1_score(y_test.tolist(), tpred, zero_division=0)
        if sel > best_sel:
            best_sel = sel
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if epoch % 10 == 0 or epoch == 1:
            print(f"  [{group_name}] Epoch {epoch:3d}/{epochs}  "
                  f"{'val' if has_val else 'heldout'}_f1={sel:.3f}")

    if best_state:
        model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        inf_prob, _, _ = model(X_test)
        probs = inf_prob.squeeze(-1).tolist()
    preds = [1 if p >= 0.5 else 0 for p in probs]
    trues = y_test.tolist()

    f1   = f1_score(trues, preds, zero_division=0)
    prec = precision_score(trues, preds, zero_division=0)
    rec  = recall_score(trues, preds, zero_division=0)
    acc  = accuracy_score(trues, preds)
    cm   = confusion_matrix(trues, preds)
    fpr  = cm[0, 1] / (cm[0, 1] + cm[0, 0]) if cm.shape == (2, 2) and (cm[0, 1] + cm[0, 0]) > 0 else 0.0
    try:
        auc = roc_auc_score(trues, probs) if len(set(trues)) > 1 else 0.0
    except Exception:
        auc = 0.0

    return {"model": f"LSTM World Model (never trained on {group_name})", "f1": round(f1, 4),
            "precision": round(prec, 4), "recall": round(rec, 4), "accuracy": round(acc, 4),
            "fpr": round(fpr, 4), "auc_roc": round(auc, 4),
            "n_train_sequences": len(X_train), "n_test_sequences": len(X_test)}


def run_lr_generalization(train_features: list[dict], test_features: list[dict],
                           group_name: str, seed: int = 42) -> dict:
    X_train = [flow_to_vector(f) for f in train_features]
    y_train = [int(f.get("infiltration_label", f.get("is_compromise", 0))) for f in train_features]
    X_test  = [flow_to_vector(f) for f in test_features]
    y_test  = [int(f.get("infiltration_label", f.get("is_compromise", 0))) for f in test_features]

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    clf = LogisticRegression(max_iter=1000, random_state=seed, C=1.0)
    clf.fit(X_train_s, y_train)
    y_pred = clf.predict(X_test_s)
    y_prob = clf.predict_proba(X_test_s)[:, 1]

    f1   = f1_score(y_test, y_pred, zero_division=0)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    acc  = accuracy_score(y_test, y_pred)
    cm   = confusion_matrix(y_test, y_pred)
    fpr  = cm[0, 1] / (cm[0, 1] + cm[0, 0]) if cm.shape == (2, 2) and (cm[0, 1] + cm[0, 0]) > 0 else 0.0
    try:
        auc = roc_auc_score(y_test, y_prob) if len(set(y_test)) > 1 else 0.0
    except Exception:
        auc = 0.0

    return {"model": f"Logistic Regression (never trained on {group_name})", "f1": round(f1, 4),
            "precision": round(prec, 4), "recall": round(rec, 4), "accuracy": round(acc, 4),
            "fpr": round(fpr, 4), "auc_roc": round(auc, 4),
            "n_train": len(X_train), "n_test": len(X_test)}


def main():
    parser = argparse.ArgumentParser(description="Held-out attack-category generalization test")
    parser.add_argument("--features", default=FEATURES_PATH)
    parser.add_argument("--epochs", type=int, default=40,
                        help="Epochs PER held-out group (default 40 — lower than the single-pair "
                             "test's old default of 60, since this now runs multiple full training "
                             "passes back to back)")
    parser.add_argument("--groups", default="all",
                        help="Comma-separated group names to run, or 'all' (default) for every "
                             "category. Names match HELD_OUT_GROUPS, e.g. 'DoS,Botnet'")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Retrain the LSTM under this many seeds per category and report "
                             "held-out AUC as mean ± std (recommended: 3). A single run is noisy "
                             "near the 0.6 chance threshold — averaging is what makes the "
                             "pass/borderline/fail verdict trustworthy.")
    args = parser.parse_args()

    features = load_features(args.features)
    if not features:
        return

    if args.groups.strip().lower() == "all":
        groups = HELD_OUT_GROUPS
    else:
        wanted = {g.strip().lower() for g in args.groups.split(",")}
        groups = [g for g in HELD_OUT_GROUPS if g["name"].split(" (")[0].strip().lower() in wanted]
        if not groups:
            print(f"[Generalization] No groups matched --groups {args.groups!r}. "
                  f"Available: {[g['name'] for g in HELD_OUT_GROUPS]}")
            return

    all_results = {}
    for group in groups:
        name = group["name"]
        train_features, test_features = split_by_holdout_prefixes(features, group["prefixes"])

        print("\n" + "=" * 65)
        print(f"  HELD-OUT ATTACK-CATEGORY GENERALIZATION TEST — {name}")
        print(f"  Train: everything EXCEPT {name}")
        print(f"  Test:  {name} only — never seen in training")
        print("=" * 65)
        print(f"[Generalization] {len(train_features)} train rows")
        print(f"[Generalization] {len(test_features)} held-out test rows (0 used in training)")

        if len(test_features) < SEQ_LEN * 2:
            print(f"[Generalization] [{name}] Skipping — too few held-out rows "
                  f"({len(test_features)}) to build a meaningful test set")
            continue

        # LR is deterministic given the split — run it once. The LSTM is
        # retrained under `--repeat` seeds and its held-out AUC reported as
        # mean ± std, because a single run is noisy right at the 0.6 threshold
        # (which is exactly why some categories looked like they "flipped"
        # pass/fail between earlier single-run tests).
        lr_results = run_lr_generalization(train_features, test_features, name)
        seeds = [42 + i for i in range(max(1, args.repeat))]
        lstm_runs = []
        for seed in seeds:
            r = run_lstm_generalization(train_features, test_features, name,
                                        epochs=args.epochs, seed=seed)
            if r:
                lstm_runs.append(r)
        if not lstm_runs:
            print(f"[Generalization] [{name}] No successful LSTM run — skipping")
            continue

        def _mean(xs): return sum(xs) / len(xs)
        def _std(xs):
            if len(xs) < 2: return 0.0
            m = _mean(xs); return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5

        lstm_aucs = [r.get("auc_roc", 0) for r in lstm_runs]
        lstm_auc_mean, lstm_auc_std = _mean(lstm_aucs), _std(lstm_aucs)
        # Representative LSTM row = the run whose AUC is closest to the mean.
        lstm_results = min(lstm_runs, key=lambda r: abs(r.get("auc_roc", 0) - lstm_auc_mean))

        lr_auc = lr_results.get("auc_roc", 0)

        # Three-way verdict instead of a brittle binary. A category only counts
        # as a clean pass when BOTH models sit comfortably above chance; if
        # either straddles the 0.6 line (within its own seed spread, or just
        # in the grey 0.55–0.65 band) it's BORDERLINE, not a pass or a fail —
        # this is the honest way to describe the categories that looked like
        # they flipped between earlier runs.
        def _verdict(a_mean, a_std):
            lo, hi = a_mean - a_std, a_mean + a_std
            if a_mean >= 0.65 and lo >= 0.6:
                return "pass"
            if a_mean < 0.55 and hi < 0.6:
                return "FAIL"
            return "borderline"

        lstm_v = _verdict(lstm_auc_mean, lstm_auc_std)
        lr_v   = _verdict(lr_auc, 0.0)
        if lstm_v == "FAIL" or lr_v == "FAIL":
            verdict = "FAIL"
        elif lstm_v == "pass" and lr_v == "pass":
            verdict = "pass"
        else:
            verdict = "borderline"

        print(f"\n  RESULTS — {name}")
        print(f"  {'Metric':20s}  {'Logistic Reg':16s}  {'LSTM World Model':16s}")
        print("  " + "-" * 55)
        for metric, label in zip(["f1", "precision", "recall", "accuracy", "fpr", "auc_roc"],
                                  ["F1 Score", "Precision", "Recall", "Accuracy", "FPR", "AUC-ROC"]):
            print(f"  {label:20s}  {lr_results.get(metric, 0):16.4f}  {lstm_results.get(metric, 0):16.4f}")
        if len(seeds) > 1:
            print(f"  {'AUC-ROC (mean±std)':20s}  {lr_auc:16.4f}  "
                  f"{lstm_auc_mean:.4f}±{lstm_auc_std:.4f}   over {len(seeds)} seeds "
                  f"{[round(a,3) for a in lstm_aucs]}")
        print(f"  → verdict: {verdict.upper()}")

        all_results[name] = {
            "train_composition": f"everything except {name}",
            "held_out_test": f"{name} — zero rows trained on",
            "logistic_regression": lr_results,
            "lstm_world_model": lstm_results,
            "lstm_auc_mean": round(lstm_auc_mean, 4),
            "lstm_auc_std": round(lstm_auc_std, 4),
            "lstm_auc_per_seed": [round(a, 4) for a in lstm_aucs],
            "n_seeds": len(seeds),
            "verdict": verdict,
            # kept for backward-compat with anything reading the old key:
            "generalizes_above_chance": (verdict == "pass"),
        }

    # Consolidated summary across every category actually run
    print("\n" + "=" * 88)
    print("  GENERALIZATION SUMMARY — held-out AUC-ROC (pass / borderline / FAIL vs 0.6 chance)")
    print("=" * 88)
    print(f"  {'Category':32s}  {'LR AUC':>10s}  {'LSTM AUC (mean±std)':>22s}  {'Verdict':>12s}")
    print("  " + "-" * 84)
    n_pass = n_border = n_fail = 0
    for name, res in all_results.items():
        lr_auc = res["logistic_regression"].get("auc_roc", 0)
        lm, ls = res.get("lstm_auc_mean", 0), res.get("lstm_auc_std", 0)
        v = res.get("verdict", "?")
        n_pass   += int(v == "pass")
        n_border += int(v == "borderline")
        n_fail   += int(v == "FAIL")
        print(f"  {name:32s}  {lr_auc:10.4f}  {lm:>13.4f}±{ls:.4f}  {v.upper():>12s}")
    print("=" * 88)
    print(f"\n  {n_pass} pass / {n_border} borderline / {n_fail} fail, out of {len(all_results)} "
          f"held-out categories (AUC > 0.6 = better than chance, for BOTH models).")
    print("  Report this per-category. 'Borderline' means the category sits near the chance")
    print("  threshold within its seed-to-seed spread — neither a clean pass nor a clear fail,")
    print("  which is the accurate description for the categories that appeared to flip between")
    print("  earlier single-run tests. A stable FAIL (e.g. Infiltration) is a real weak spot to")
    print("  disclose, not hide.")

    with open("generalization_test_results.json", "w") as fp:
        json.dump(all_results, fp, indent=2)
    print("\n  Full per-category results saved to generalization_test_results.json")


if __name__ == "__main__":
    main()
