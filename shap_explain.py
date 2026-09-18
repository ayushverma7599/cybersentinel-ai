"""
CyberSentinel AI — shap_explain.py
Week 4: Explainability for LSTM attack progression predictions

Works with YOUR lstm_model.py (the uploaded version with attention weights).
No extra libraries needed — uses attention weights + gradient saliency built
into the AttackLSTM model.

Usage:
  python3 shap_explain.py --sequence T1082 T1087
  python3 shap_explain.py --sequence T1082 T1087 T1105
  python3 shap_explain.py --all
  python3 shap_explain.py --sequence T1082 T1087 --method gradient
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# ── PyTorch ───────────────────────────────────────────────
try:
    import torch
    TORCH_OK = True
except ImportError:
    TORCH_OK = False
    print("[SHAP] PyTorch not found. Install: pip install torch --break-system-packages")

# ── Import from your lstm_model.py ───────────────────────
try:
    from lstm_model import (
        load_model,
        encode_sequence,
        get_attention_explanation,
        predict_next_technique,
        PAD_TOKEN, UNK_TOKEN, START_TOKEN,
        COMPROMISE_TECHNIQUES,
        MODEL_PATH, TTP_PATH,
    )
    LSTM_OK = True
except ImportError as e:
    LSTM_OK = False
    print(f"[SHAP] Cannot import lstm_model: {e}")
    print("       Make sure lstm_model.py is in the same folder.")

# ── Technique labels for display ─────────────────────────
TECHNIQUE_LABELS = {
    "T1082": "System Info Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1204": "User Execution",
    "T1059": "Command Interpreter",
    "T1110": "Brute Force",
    "T1548": "Privilege Escalation",
    "T1136": "Create Account",
    "T1070": "Indicator Removal",
    "T1496": "Resource Hijacking",
    "T1016": "Network Config Discovery",
    "T1057": "Process Discovery",
    "T1021": "Remote Services",
}

def label(tid: str) -> str:
    return TECHNIQUE_LABELS.get(tid, tid)


# ─────────────────────────────────────────────────────────
# METHOD 1: ATTENTION WEIGHTS (from lstm_model.py built-in)
# Your AttackLSTM already computes attention over every
# timestep — we just surface it as importance scores.
# ─────────────────────────────────────────────────────────

def attention_importance(sequence: list[str],
                          model=None, vocab=None) -> list[tuple[str, float]]:
    """
    Use the LSTM's built-in additive attention weights as feature importance.
    Returns list of (technique_id, importance_score) in input order.
    Score = attention weight the model assigned to that position.
    """
    if not TORCH_OK or model is None:
        # Uniform fallback
        n = len(sequence)
        return [(t, 1.0 / n) for t in sequence]

    ids = encode_sequence(sequence, vocab)
    model.eval()
    with torch.no_grad():
        x = torch.tensor([ids], dtype=torch.long)
        _, _, attn_weights = model(x, return_attention=True)
        weights = attn_weights[0].tolist()   # length = max_seq_len (8)

    # Align weights back to actual input techniques
    # ids = [PAD...PAD, START, t1, t2, ...] — last len(sequence) positions
    max_seq_len = 8
    n_pad = max_seq_len - len(sequence) - 1   # -1 for START
    start_offset = n_pad + 1                   # index of first real technique

    result = []
    for i, tid in enumerate(sequence):
        pos = start_offset + i
        w = weights[pos] if pos < len(weights) else 0.0
        result.append((tid, round(w, 6)))

    return result


# ─────────────────────────────────────────────────────────
# METHOD 2: GRADIENT SALIENCY
# Backprop gradient of predicted class score w.r.t.
# input embeddings. L2 norm at each position = saliency.
# Independent from attention — gives a second view.
# ─────────────────────────────────────────────────────────

def gradient_saliency(sequence: list[str],
                       predicted_class_idx: int,
                       model=None, vocab=None) -> list[tuple[str, float]]:
    """
    Gradient-based saliency: how much does changing each input position
    affect the predicted class score?
    Returns list of (technique_id, saliency_score) in input order.
    """
    if not TORCH_OK or model is None:
        n = len(sequence)
        return [(t, 1.0 / n) for t in sequence]

    ids = encode_sequence(sequence, vocab)
    model.eval()

    x = torch.tensor([ids], dtype=torch.long)
    embeds = model.embedding(x).detach().requires_grad_(True)

    # Forward through LSTM using embeddings directly
    dropped = model.dropout(embeds)
    lstm_out, _ = model.lstm(dropped)

    # Attention
    mask = (x != 0).float()
    raw_scores = model.attn_score(lstm_out).squeeze(-1)
    raw_scores = raw_scores.masked_fill(mask == 0, float("-inf"))
    attn_w = torch.softmax(raw_scores, dim=1)
    attn_w = torch.nan_to_num(attn_w, nan=0.0)
    context = torch.bmm(attn_w.unsqueeze(1), lstm_out).squeeze(1)
    context = model.dropout(context)
    logits = model.fc_next(context)

    # Backprop w.r.t. predicted class
    model.zero_grad()
    logits[0, predicted_class_idx].backward()

    grads = embeds.grad[0]                     # (seq_len, embed_dim)
    saliency = grads.norm(dim=1).tolist()      # (seq_len,)

    # Align to actual input techniques
    max_seq_len = 8
    n_pad = max_seq_len - len(sequence) - 1
    start_offset = n_pad + 1

    result = []
    for i, tid in enumerate(sequence):
        pos = start_offset + i
        s = saliency[pos] if pos < len(saliency) else 0.0
        result.append((tid, round(float(s), 6)))

    return result


# ─────────────────────────────────────────────────────────
# MAIN EXPLAIN FUNCTION
# ─────────────────────────────────────────────────────────

def explain_prediction(sequence: list[str],
                        method: str = "attention",
                        top_k: int = 3) -> dict:
    """
    Full SHAP-style explanation for a sequence prediction.

    method: "attention"  — use LSTM attention weights (fast, always works)
            "gradient"   — use gradient saliency (more precise, needs grad)
            "both"       — run both and average (most robust for demo)

    Returns a dict with everything needed for Streamlit UI + terminal display.
    """
    if not TORCH_OK or not LSTM_OK:
        return _fallback(sequence)

    model, vocab = load_model()
    if model is None:
        return _fallback(sequence)

    # ── Get prediction ────────────────────────────────────
    ids = encode_sequence(sequence, vocab)
    model.eval()
    with torch.no_grad():
        x = torch.tensor([ids], dtype=torch.long)
        logits, inf_prob = model(x)
        probs = torch.softmax(logits[0], dim=0)
        top_probs, top_ids = torch.topk(probs, k=min(top_k, len(probs)))

    top_preds = [(vocab.decode(top_ids[i].item()), round(top_probs[i].item(), 4))
                 for i in range(len(top_ids))
                 if vocab.decode(top_ids[i].item()) not in (PAD_TOKEN, UNK_TOKEN, START_TOKEN)]

    predicted = top_preds[0][0] if top_preds else "UNKNOWN"
    confidence = top_preds[0][1] if top_preds else 0.0
    inf_prob_val = round(inf_prob.item(), 4)
    predicted_idx = top_ids[0].item() if top_preds else 0

    # ── Compute importance scores ─────────────────────────
    if method == "attention":
        scores = attention_importance(sequence, model, vocab)
        method_used = "attention_weights"

    elif method == "gradient":
        try:
            scores = gradient_saliency(sequence, predicted_idx, model, vocab)
            method_used = "gradient_saliency"
        except Exception as e:
            scores = attention_importance(sequence, model, vocab)
            method_used = f"attention_weights (gradient failed: {e})"

    else:  # both — average attention and gradient
        attn = attention_importance(sequence, model, vocab)
        try:
            grad = gradient_saliency(sequence, predicted_idx, model, vocab)
            method_used = "attention+gradient (averaged)"
            # Normalise each to [0,1] then average
            def norm(scores_list):
                mx = max(s for _, s in scores_list) or 1.0
                return [(t, s / mx) for t, s in scores_list]
            attn_n = norm(attn)
            grad_n = norm(grad)
            scores = [(attn_n[i][0], round((attn_n[i][1] + grad_n[i][1]) / 2, 6))
                      for i in range(len(sequence))]
        except Exception:
            scores = attn
            method_used = "attention_weights"

    # ── Normalise importance to [0, 1] ───────────────────
    max_score = max(s for _, s in scores) if scores else 1.0
    if max_score == 0:
        max_score = 1.0
    scores_norm = [(t, round(s / max_score, 4)) for t, s in scores]

    # ── Build feature_importance list ────────────────────
    ranked = sorted(enumerate(scores_norm), key=lambda x: -x[1][1])
    feature_importance = []
    for rank, (pos, (tid, imp)) in enumerate(ranked, 1):
        feature_importance.append({
            "position":       pos,
            "technique":      tid,
            "label":          label(tid),
            "importance":     imp,
            "rank":           rank,
            "is_compromise":  tid in COMPROMISE_TECHNIQUES,
        })
    # Re-sort by position for display
    feature_importance_by_pos = sorted(feature_importance, key=lambda x: x["position"])

    # ── Risk label ───────────────────────────────────────
    risk_label = (
        "CRITICAL" if inf_prob_val >= 0.85 else
        "HIGH"     if inf_prob_val >= 0.65 else
        "MEDIUM"   if inf_prob_val >= 0.40 else
        "LOW"
    )

    # ── Explanation text ─────────────────────────────────
    top_driver = min(feature_importance, key=lambda x: x["rank"]) if feature_importance else None
    seq_str = " → ".join(f"{t} ({label(t)})" for t in sequence)
    compromise_note = (
        " Session already contains compromise-stage techniques — active exploitation likely."
        if any(t in COMPROMISE_TECHNIQUES for t in sequence) else ""
    )
    driver_note = (
        f" Strongest driver: {top_driver['technique']} ({top_driver['label']}, "
        f"importance {top_driver['importance']:.0%})."
        if top_driver else ""
    )

    explanation_text = (
        f"Observed: {seq_str}. "
        f"Predicted next: {predicted} ({label(predicted)}) "
        f"with {confidence:.0%} confidence. "
        f"Infiltration probability: {inf_prob_val:.1%} [{risk_label}]."
        f"{driver_note}"
        f"{compromise_note}"
    )

    return {
        "sequence":              sequence,
        "predicted_next":        predicted,
        "predicted_label":       label(predicted),
        "confidence":            confidence,
        "infiltration_prob":     inf_prob_val,
        "risk_label":            risk_label,
        "method":                method_used,
        "feature_importance":    feature_importance_by_pos,
        "top_predictions":       top_preds,
        "explanation_text":      explanation_text,
    }


def _fallback(sequence: list[str]) -> dict:
    return {
        "sequence":          sequence,
        "predicted_next":    "UNKNOWN",
        "predicted_label":   "Unknown",
        "confidence":        0.0,
        "infiltration_prob": 0.5,
        "risk_label":        "UNKNOWN",
        "method":            "fallback",
        "feature_importance": [],
        "top_predictions":   [],
        "explanation_text":  "Model not available. Run: python3 lstm_model.py --train",
    }


# ─────────────────────────────────────────────────────────
# TERMINAL DISPLAY
# ─────────────────────────────────────────────────────────

def print_explanation(result: dict):
    print()
    print("═" * 62)
    print("  CYBERSENTINEL AI — PREDICTION EXPLANATION (SHAP)")
    print("═" * 62)
    print(f"  Input sequence:    {' → '.join(result['sequence'])}")
    print(f"  Predicted next:    {result['predicted_next']}  ({result['predicted_label']})")
    print(f"  Confidence:        {result['confidence']:.0%}")
    print(f"  Infiltration prob: {result['infiltration_prob']:.1%}  [{result['risk_label']}]")
    print(f"  Method:            {result['method']}")
    print()

    # Top predictions
    if result["top_predictions"]:
        print("  Top predicted next techniques:")
        for i, (tech, conf) in enumerate(result["top_predictions"][:3], 1):
            bar = "█" * int(conf * 25)
            print(f"    #{i}  {tech:8s}  {label(tech):28s}  {bar}  {conf:.0%}")
        print()

    # Feature importance bar chart
    if result["feature_importance"]:
        print("  Feature importance — what drove this prediction:")
        print("  (100% = most influential input in the sequence)")
        print()
        for fi in result["feature_importance"]:
            imp = fi["importance"]
            filled = int(imp * 30)
            bar    = "█" * filled + "░" * (30 - filled)
            marker = "  ← TOP DRIVER" if fi["rank"] == 1 else ""
            comp   = "  [COMPROMISE STAGE]" if fi["is_compromise"] else ""
            print(f"  [{fi['position']+1}] {fi['technique']:8s}  "
                  f"({fi['label']:28s})  {bar}  {imp:.0%}"
                  f"{marker}{comp}")
        print()

    # Explanation paragraph
    print("  Explanation:")
    words = result["explanation_text"].split()
    line = "    "
    for word in words:
        if len(line) + len(word) + 1 > 62:
            print(line)
            line = "    " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)
    print()
    print("═" * 62)


# ─────────────────────────────────────────────────────────
# BATCH: explain all sessions in ttp_records.json
# ─────────────────────────────────────────────────────────

def explain_all_sessions(ttp_path: str = TTP_PATH,
                          method: str = "attention") -> list[dict]:
    try:
        with open(ttp_path) as f:
            records = json.load(f)
    except FileNotFoundError:
        print(f"[SHAP] {ttp_path} not found")
        return []

    results = []
    for record in records:
        techniques = []
        for t in record.get("techniques", []):
            tid = (t.get("id") or t.get("technique_id", "")) if isinstance(t, dict) else str(t)
            if tid:
                techniques.append(tid)
        if not techniques:
            continue

        explanation = explain_prediction(techniques, method=method)
        explanation["session_id"] = record.get("session_id", "unknown")
        explanation["src_ip"]     = record.get("src_ip", "unknown")
        results.append(explanation)

    # Highest infiltration probability first
    results.sort(key=lambda x: -x["infiltration_prob"])
    return results


def top_distinct_risk_sessions(results: list[dict], n: int = 5) -> list[dict]:
    """
    Pick the top-n highest-risk DISTINCT technique sequences, for display.

    Many real sessions share the exact same technique sequence -- e.g.
    every connection-only probe that trips the T1499 DoS-flood detector
    encodes to the identical single-token sequence ["T1499"]. The LSTM is
    deterministic, so it returns the identical prediction/probability for
    every one of them. Sorting all results by risk and slicing [:n]
    (the old behaviour) can surface n different session_ids that are
    really just one finding repeated n times -- correct output, but it
    reads as a duplication bug in a "Top N riskiest sessions" table and
    tells the viewer nothing new after the first row.

    This groups by sequence first, keeps the single highest-probability
    session per distinct sequence, and tags it with how many real sessions
    shared that pattern -- so "Top 5" means 5 distinct risk findings, each
    honestly labeled with its true prevalence, instead of 5 rows that
    happen to look identical.
    """
    best_by_seq: dict[tuple, dict] = {}
    for r in results:
        key = tuple(r["sequence"])
        if key not in best_by_seq or r["infiltration_prob"] > best_by_seq[key]["infiltration_prob"]:
            best_by_seq[key] = r

    counts = Counter(tuple(r["sequence"]) for r in results)

    ranked = sorted(best_by_seq.values(), key=lambda x: -x["infiltration_prob"])
    top = []
    for r in ranked[:n]:
        r = dict(r)
        r["session_count"] = counts[tuple(r["sequence"])]
        top.append(r)
    return top


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel SHAP — explainability for LSTM predictions"
    )
    parser.add_argument("--sequence", nargs="+", metavar="T",
                        help="Techniques to explain  e.g. T1082 T1087")
    parser.add_argument("--all", action="store_true",
                        help="Explain every session in ttp_records.json")
    parser.add_argument("--method",
                        choices=["attention", "gradient", "both"],
                        default="attention",
                        help="Attribution method (default: attention)")
    parser.add_argument("--top", type=int, default=3,
                        help="Number of top predictions to show")
    parser.add_argument("--ttp", default="ttp_records.json")
    parser.add_argument("--save", action="store_true",
                        help="Save explanation to shap_explanation.json")
    args = parser.parse_args()

    if args.sequence:
        print(f"\n[SHAP] Method: {args.method}")
        result = explain_prediction(args.sequence, method=args.method, top_k=args.top)
        print_explanation(result)
        if args.save:
            out = "shap_explanation.json"
            with open(out, "w") as f:
                json.dump(result, f, indent=2)
            print(f"  Saved to {out}\n")

    elif args.all:
        print(f"\n[SHAP] Explaining all sessions in {args.ttp} (method={args.method})...")
        results = explain_all_sessions(args.ttp, method=args.method)
        print(f"[SHAP] Explained {len(results)} sessions\n")
        top5 = top_distinct_risk_sessions(results, n=5)
        n_distinct = len({tuple(r["sequence"]) for r in results})
        print(f"  Top {len(top5)} highest-risk DISTINCT sequences "
              f"({n_distinct} distinct sequence(s) across {len(results)} sessions):")
        print(f"  {'Session':14s}  {'Sequence':30s}  {'Pred':8s}  {'P(comp)':8s}  {'Count':6s}  Risk")
        print("  " + "-" * 80)
        for r in top5:
            sid   = r["session_id"][:12]
            seq   = " → ".join(r["sequence"])[:28]
            pred  = r["predicted_next"]
            prob  = f"{r['infiltration_prob']:.0%}"
            risk  = r["risk_label"]
            count = f"x{r['session_count']}"
            print(f"  {sid:14s}  {seq:30s}  {pred:8s}  {prob:8s}  {count:6s}  {risk}")
        if n_distinct == 1 and len(results) > 1:
            print(f"\n  Note: all {len(results)} sessions collapse to the same technique "
                  f"sequence, so the model's single deterministic prediction is repeated "
                  f"{len(results)}x -- that's expected, not a diversity bug. Run "
                  f"realistic_attack_sim.sh / run_campaign.sh for more varied sequences.")

        if args.save:
            out = "shap_all_sessions.json"
            with open(out, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n  Full results saved to {out}")

    else:
        parser.print_help()
        print("\nExamples:")
        print("  python3 shap_explain.py --sequence T1082 T1087")
        print("  python3 shap_explain.py --sequence T1082 T1087 T1105 --method gradient")
        print("  python3 shap_explain.py --sequence T1082 T1087 --method both --save")
        print("  python3 shap_explain.py --all --save")


if __name__ == "__main__":
    main()
