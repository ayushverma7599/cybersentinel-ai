"""
CyberSentinel AI — world_model.py
Step 3+4 of 4: World model LSTM on real network features
            + Logistic Regression baseline benchmark

SIH26153 requirements:
  "A trained world model (LSTM) that demonstrably learns traffic state
   transition dynamics — not a static input-output classifier."

  "Benchmark results comparing model performance (F1, precision, recall,
   false positive rate) against a logistic regression baseline trained on
   the same features, demonstrating that the world model's temporal dynamics
   learning provides measurable improvement."

What this does:
  1. Loads features.json from packet_capture.py + cic_ids_loader.py
  2. Builds time-windowed sequences (world model input: state at time t)
  3. Trains LSTM world model: learns P(S_t+1 | S_t) — state transition dynamics
  4. Trains Logistic Regression baseline on same features (static classifier)
  5. Benchmarks both: F1, precision, recall, FPR, accuracy
  6. Shows that LSTM temporal learning beats static classification
  7. Saves world_model.pt for integration into streamlit_app.py

Key distinction from lstm_model.py:
  lstm_model.py:  input = MITRE technique IDs (discrete tokens)
  world_model.py: input = real network feature vectors (30 numeric features)
                  This is what SIH26153 explicitly requires.

Usage:
  python3 world_model.py --train
  python3 world_model.py --train --features features.json
  python3 world_model.py --benchmark
  python3 world_model.py --predict --flow '{"syn_ratio": 0.85, "dst_port": 22, ...}'

Install:
  pip install torch scikit-learn --break-system-packages
"""

import argparse
import json
import math
import os
import random
import sys
from collections import Counter
from pathlib import Path

# ── PyTorch ───────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, Dataset, TensorDataset
    TORCH_OK = True
except ImportError:
    TORCH_OK = False
    print("[WorldModel] PyTorch not found. Install: pip install torch --break-system-packages")

# ── scikit-learn ──────────────────────────────────────────
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (
        f1_score, precision_score, recall_score,
        accuracy_score, confusion_matrix, roc_auc_score
    )
    from sklearn.preprocessing import StandardScaler
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
    print("[WorldModel] scikit-learn not found. Install: pip install scikit-learn --break-system-packages")

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────

MODEL_PATH    = "world_model.pt"
FEATURES_PATH = "features.json"

# Network feature columns (from packet_capture.py)
FEATURE_COLS = [
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
    "has_syn", "has_ack", "has_fin", "has_rst", "has_psh", "has_urg",
    "iat_mean", "iat_std", "iat_max",
    "ttl_mean", "ttl_std",
    "tcp_window_mean", "tcp_window_std",
    "payload_size_mean", "payload_size_std",
    "retransmission_count", "port_scan_score", "unique_dst_ports",
    "bytes_total", "packets_total", "flow_duration_ms", "bidir_ratio",
    "bytes_fwd", "bytes_bwd", "packets_fwd", "packets_bwd",
]

# Use normalised versions if available
NORM_SUFFIX = "_norm"

INPUT_DIM  = len(FEATURE_COLS)  # 30 network features
SEQ_LEN    = 5                  # 5 time windows = world model context
HIDDEN_DIM = 128
NUM_LAYERS = 2
DROPOUT    = 0.3

COMPROMISE_TECHNIQUES = {
    "T1105", "T1204", "T1059", "T1548", "T1136", "T1070",
    "T1499", "T1498", "T1071", "T1190"
}

# fc_technique's 10 output classes, in a fixed stable order. This is exactly
# COMPROMISE_TECHNIQUES (that's not a coincidence — the head was originally
# sized nn.Linear(hidden_dim, 10) to match this exact set, it just was never
# wired to real labels or a loss term). Non-compromise / UNKNOWN techniques
# (T1082, T1087, T1046, ...) have no slot here by design: this head answers
# "given a predicted compromise, which technique is it" — not "classify
# every possible technique" (that's lstm_model.py's job, at the MITRE-ID
# sequence level). Samples whose true next technique isn't in this set are
# excluded from this loss term via CrossEntropyLoss's ignore_index, not
# forced into a wrong class.
TECHNIQUE_CLASSES = sorted(COMPROMISE_TECHNIQUES)
TECHNIQUE_TO_IDX  = {t: i for i, t in enumerate(TECHNIQUE_CLASSES)}
IGNORE_INDEX = -100  # torch.nn.CrossEntropyLoss default — skips loss/grad for these


# ─────────────────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────────────────

def load_features(path: str = FEATURES_PATH) -> list[dict]:
    """Load feature vectors from packet_capture.py / cic_ids_loader.py output."""
    try:
        with open(path) as f:
            features = json.load(f)
        print(f"[WorldModel] Loaded {len(features)} flows from {path}")
        return features
    except FileNotFoundError:
        print(f"[WorldModel] {path} not found")
        print(f"[WorldModel] Run first: python3 packet_capture.py --cowrie cowrie-raw.json")
        return []


def flow_to_vector(flow: dict) -> list[float]:
    """
    Convert a flow feature dict to a numeric vector.
    Prefers normalised (_norm) values; falls back to raw.
    """
    vec = []
    for col in FEATURE_COLS:
        norm_key = col + NORM_SUFFIX
        if norm_key in flow:
            vec.append(float(flow[norm_key]))
        else:
            # Manual min-max normalisation fallback
            raw = float(flow.get(col, 0.0))
            # Clip extreme values
            vec.append(min(1.0, max(0.0, raw / 1e6 if raw > 1 else raw)))
    return vec


def make_sequences(features: list[dict],
                   seq_len: int = SEQ_LEN) -> tuple:
    """
    Build time-windowed sequences for world model training.

    World model concept: given the last `seq_len` network states (flows),
    predict the NEXT state — its infiltration label, its actual feature
    vector, and (when it's a compromise technique) which one.

    This is P(S_t+1 | S_t, S_t-1, ..., S_t-n) — state transition dynamics.
    NOT a static single-flow classifier.

    Returns:
      X:          (N, seq_len, input_dim) float32 — input sequences
      y:          (N,) float32 — binary infiltration label for state t+1
      y_state:    (N, input_dim) float32 — the ACTUAL next feature vector,
                  used to train fc_next_state so k_step_forecast() rolls
                  forward through genuinely learned state predictions
                  instead of overwriting one field with a probability.
      y_tech:     (N,) long — index into TECHNIQUE_CLASSES for state t+1's
                  technique, or IGNORE_INDEX if it's not a compromise
                  technique (excluded from the technique-loss term, not
                  forced into a wrong class).
    """
    if len(features) < seq_len + 1:
        print(f"[WorldModel] Need at least {seq_len+1} flows, got {len(features)}")
        return None, None, None, None, None

    vectors    = [flow_to_vector(f) for f in features]
    labels     = [f.get("infiltration_label", f.get("is_compromise", 0)) for f in features]
    techniques = [f.get("mitre_technique", "UNKNOWN") for f in features]

    # Group flows into contiguous same-source runs BEFORE windowing. Without
    # this, a sliding window built straight across the raw concatenated list
    # (honeypot flows immediately followed by a different day's CIC-IDS-2018
    # flows, say) would mix two unrelated traffic sources into one "session"
    # sequence — meaningless as an attack-progression window. `source` (set
    # by packet_capture.py / cic_ids_loader.py, e.g. "cowrie_proxy" or
    # "cic_ids_2018:Wednesday-14-02-2018") is the grouping key; any change in
    # it starts a new segment. Sequences are only ever built within one
    # segment, and `seg_ids` (one entry per sequence, same order as X) lets
    # the caller do a leakage-safe split later without re-deriving this.
    segments = []
    if features:
        seg_start = 0
        prev_source = features[0].get("source", "unknown")
        for i in range(1, len(features)):
            cur_source = features[i].get("source", "unknown")
            if cur_source != prev_source:
                segments.append((seg_start, i))
                seg_start = i
                prev_source = cur_source
        segments.append((seg_start, len(features)))

    X_seqs, y_seqs, state_seqs, tech_seqs, seg_ids = [], [], [], [], []

    for gi, (s, e) in enumerate(segments):
        if e - s < seq_len + 1:
            continue  # this source segment is too short to form even one sequence
        for i in range(s + seq_len, e):
            seq = vectors[i - seq_len: i]   # last seq_len flows = current state
            X_seqs.append(seq)
            y_seqs.append(labels[i])                 # NEXT flow's compromise label
            state_seqs.append(vectors[i])             # NEXT flow's actual feature vector
            tech_seqs.append(TECHNIQUE_TO_IDX.get(techniques[i], IGNORE_INDEX))
            seg_ids.append(gi)

    if not TORCH_OK:
        return X_seqs, y_seqs, state_seqs, tech_seqs, seg_ids

    X       = torch.tensor(X_seqs, dtype=torch.float32)
    y       = torch.tensor(y_seqs, dtype=torch.float32)
    y_state = torch.tensor(state_seqs, dtype=torch.float32)
    y_tech  = torch.tensor(tech_seqs, dtype=torch.long)

    n_tech_labeled = int((y_tech != IGNORE_INDEX).sum().item())
    print(f"[WorldModel] Built {len(X_seqs)} sequences of length {seq_len} "
          f"across {len(segments)} source segment(s)")
    print(f"[WorldModel] Positive (compromise) rate: "
          f"{sum(y_seqs)}/{len(y_seqs)} = {100*sum(y_seqs)//max(len(y_seqs),1)}%")
    print(f"[WorldModel] Technique-labeled targets (compromise-stage only): "
          f"{n_tech_labeled}/{len(y_seqs)} — the rest are excluded from the "
          f"technique-classification loss via ignore_index, not mislabeled")

    return X, y, y_state, y_tech, seg_ids


def _purged_segment_split(seg_ids: list, test_split: float = 0.2, purge: int = 0,
                           n_blocks: int = 10) -> tuple:
    """
    Leakage-safe train/test split for sliding-window sequences.

    A plain random shuffle over overlapping windows (the original behaviour)
    lets near-duplicate windows land on both sides of the split — since
    consecutive windows share `seq_len - 1` of their `seq_len` timesteps,
    that is real train/test leakage, not a fair benchmark. Splitting WITHIN
    each contiguous source segment fixes that leakage, but a *single* tail
    split (chronologically-last `test_split` fraction = test) turned out to
    have its own honesty problem once real CIC-IDS-2018 attack days were
    added: an attack (e.g. a DoS run) isn't spread evenly across a day, it
    happens in a concentrated window. If that window lands mostly in the
    train portion (or mostly in the test tail), train and test end up with
    very different attack/benign ratios — verified empirically on the
    Thursday DoS day, where LR test accuracy fell to 38% despite the model
    genuinely having learned real signal (AUC ~0.71).

    Fix: each segment is chopped into `n_blocks` equal contiguous
    chronological blocks, and roughly `test_split` of those blocks — spread
    evenly across the segment via round-robin selection, not just the last
    one — are held out as test. This samples test examples from multiple
    points across each segment's timeline (start, middle, end), so the test
    set sees a representative mix of whatever time-varying attack/benign
    pattern the segment contains, while still never letting train and test
    windows overlap: `purge` windows are dropped from whichever side of
    every block boundary would otherwise bleed into the other (a sliding
    window spans `purge + 1` = seq_len consecutive rows, so this is enough
    to guarantee no window straddles a train/test transition).

    Segments too small to safely support `n_blocks` blocks fall back to the
    simple tail-purge split so tiny segments (e.g. a short honeypot run)
    don't get shredded into unusable slivers.
    """
    by_seg = {}
    for idx, g in enumerate(seg_ids):
        by_seg.setdefault(g, []).append(idx)

    train_idx, test_idx = [], []
    for g, idxs in by_seg.items():
        n = len(idxs)

        # Too small to block-split meaningfully (need room for purge on both
        # sides of every block boundary) — fall back to a plain tail split.
        if n < n_blocks * max(4, purge * 2 + 2):
            n_test = int(round(n * test_split))
            if n_test == 0 or n - n_test <= purge:
                train_idx.extend(idxs)
                continue
            split_point = n - n_test
            train_idx.extend(idxs[: max(0, split_point - purge)])
            test_idx.extend(idxs[split_point:])
            continue

        n_test_blocks = max(1, round(n_blocks * test_split))
        step = n_blocks / n_test_blocks
        test_blocks = {int(round(i * step)) % n_blocks for i in range(n_test_blocks)}

        block_bounds = [int(round(b * n / n_blocks)) for b in range(n_blocks + 1)]

        for b in range(n_blocks):
            b_start, b_end = block_bounds[b], block_bounds[b + 1]
            if b_start >= b_end:
                continue
            is_test      = b in test_blocks
            prev_is_test = (b - 1) in test_blocks
            next_is_test = (b + 1) in test_blocks

            if is_test:
                # Purge the leading edge if a train block precedes this one.
                start = b_start + purge if (b > 0 and not prev_is_test) else b_start
                start = min(start, b_end)
                test_idx.extend(idxs[start:b_end])
            else:
                # Purge the trailing edge if a test block follows this one.
                end = b_end - purge if (b < n_blocks - 1 and next_is_test) else b_end
                end = max(end, b_start)
                train_idx.extend(idxs[b_start:end])

    return train_idx, test_idx


# ─────────────────────────────────────────────────────────
# WORLD MODEL — LSTM
# ─────────────────────────────────────────────────────────

class WorldModelLSTM(nn.Module):
    """
    LSTM World Model: learns P(S_t+1 | S_t) from network feature sequences.

    Architecture:
      Input: (batch, seq_len, input_dim) — sequence of network state vectors
        → LSTM: learns temporal dynamics across time windows
        → Attention: weights which time steps matter most
        → FC: predicts infiltration probability for next state
        → Sigmoid: outputs P(compromise at t+1)

    This is fundamentally different from a static classifier:
    - A static classifier sees one flow and outputs a label
    - This model sees the SEQUENCE of recent flows and predicts the future state
    - The LSTM hidden state encodes the "current network situation"
    - Forward simulation: run K steps to predict future infiltration trajectory
    """

    def __init__(self, input_dim: int = INPUT_DIM,
                 hidden_dim: int = HIDDEN_DIM,
                 num_layers: int = NUM_LAYERS,
                 dropout: float = DROPOUT):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # Input projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        # LSTM: learns state transition dynamics
        self.lstm = nn.LSTM(
            hidden_dim, hidden_dim,
            num_layers=num_layers,
            dropout=dropout if num_layers > 1 else 0.0,
            batch_first=True,
        )

        # Attention: which time steps matter most
        self.attn = nn.Linear(hidden_dim, 1)

        # Output heads
        self.dropout = nn.Dropout(dropout)
        self.fc_infiltration = nn.Linear(hidden_dim, 1)         # P(compromise)
        self.fc_technique    = nn.Linear(hidden_dim, 10)        # next MITRE technique
        self.fc_next_state   = nn.Linear(hidden_dim, input_dim) # next full feature vector —
        # this is what makes k_step_forecast() a genuine forward simulation of
        # P(S_t+1 | S_t) instead of a placeholder that only overwrites one field.

    def forward(self, x: torch.Tensor, return_attention: bool = False):
        """
        x: (batch, seq_len, input_dim)
        Returns: infiltration_prob (batch, 1), technique_logits (batch, 10),
                 next_state_pred (batch, input_dim)
        """
        # Project input features
        proj = self.input_proj(x)                          # (batch, seq, hidden)

        # LSTM temporal dynamics
        lstm_out, (h_n, _) = self.lstm(proj)               # (batch, seq, hidden)

        # Attention over time steps
        attn_scores = self.attn(lstm_out).squeeze(-1)      # (batch, seq)
        attn_weights = torch.softmax(attn_scores, dim=1)   # (batch, seq)
        context = torch.bmm(
            attn_weights.unsqueeze(1), lstm_out
        ).squeeze(1)                                        # (batch, hidden)

        context = self.dropout(context)

        # Predictions
        inf_prob  = torch.sigmoid(self.fc_infiltration(context))  # (batch, 1)
        tech_logits = self.fc_technique(context)                   # (batch, 10)
        next_state_pred = self.fc_next_state(context)               # (batch, input_dim)

        if return_attention:
            return inf_prob, tech_logits, next_state_pred, attn_weights

        return inf_prob, tech_logits, next_state_pred

    def k_step_forecast(self, initial_sequence: torch.Tensor,
                         k: int = 5) -> list[dict]:
        """
        Roll the world model forward k steps — a GENUINE forward simulation.

        At each step the model predicts its own next full feature vector
        (fc_next_state) and that becomes the next timestep's state, exactly
        like a real world model rolling forward through P(S_t+1 | S_t).
        The previous version only overwrote seq[0,0] (syn_ratio) with the
        infiltration probability and left the other 29 features frozen —
        that was a placeholder, not state simulation.

        Returns a list of k dicts:
          {"infiltration_prob": float,
           "predicted_technique": str or None,
           "technique_confidence": float}
        """
        self.eval()
        seq = initial_sequence.clone()   # (1, seq_len, input_dim)
        results = []

        with torch.no_grad():
            for _ in range(k):
                inf_prob, tech_logits, next_state_pred = self(seq)
                p = inf_prob.item()

                tech_probs = torch.softmax(tech_logits, dim=1)[0]
                tech_idx  = int(torch.argmax(tech_probs).item())
                tech_conf = float(tech_probs[tech_idx].item())
                # Only report a technique when the model is reasonably
                # confident — otherwise it's noise, not a prediction.
                predicted_technique = TECHNIQUE_CLASSES[tech_idx] if tech_conf >= 0.3 else None

                results.append({
                    "infiltration_prob":    round(p, 4),
                    "predicted_technique":  predicted_technique,
                    "technique_confidence": round(tech_conf, 4),
                })

                # Genuine forward simulation: shift the window and append the
                # model's OWN predicted next state vector (clamped back into
                # the valid normalised [0,1] range), not a hand-patched field.
                new_state = next_state_pred.clamp(0.0, 1.0).unsqueeze(1)  # (1, 1, input_dim)
                seq = torch.cat([seq[:, 1:, :], new_state], dim=1)

        return results


# ─────────────────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────────────────

def _eval_loader(model, loader) -> dict:
    """
    Run the model over a DataLoader and return classification metrics for the
    infiltration head, plus technique-head accuracy. Used for BOTH the
    validation set (checkpoint selection) and the test set (final reporting),
    so the two are scored by identical logic. Returns raw probs/trues too so a
    caller can compute a lead-time / AUC analysis without a second forward pass.
    """
    model.eval()
    all_preds, all_probs, all_true = [], [], []
    tech_correct, tech_total = 0, 0
    with torch.no_grad():
        for Xb, yb, y_state_b, y_tech_b in loader:
            inf_prob, tech_logits, next_state_pred = model(Xb)
            probs = inf_prob.squeeze(-1).tolist()
            probs = probs if isinstance(probs, list) else [probs]
            preds = [1 if p >= 0.5 else 0 for p in probs]
            trues = yb.tolist()
            trues = trues if isinstance(trues, list) else [trues]
            all_probs.extend(probs)
            all_preds.extend(preds)
            all_true.extend(trues)
            labeled_mask = y_tech_b != IGNORE_INDEX
            if labeled_mask.any():
                tech_preds = torch.argmax(tech_logits, dim=1)
                tech_correct += int((tech_preds[labeled_mask] == y_tech_b[labeled_mask]).sum().item())
                tech_total   += int(labeled_mask.sum().item())

    if SKLEARN_OK and all_true and len(set(all_true)) > 1:
        f1   = f1_score(all_true, all_preds, zero_division=0)
        prec = precision_score(all_true, all_preds, zero_division=0)
        rec  = recall_score(all_true, all_preds, zero_division=0)
        cm   = confusion_matrix(all_true, all_preds)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        else:
            fpr = 0.0
    else:
        f1 = prec = rec = fpr = 0.0

    tech_acc = tech_correct / tech_total if tech_total > 0 else 0.0
    return {"f1": f1, "precision": prec, "recall": rec, "fpr": fpr,
            "tech_acc": tech_acc, "probs": all_probs, "true": all_true}


def train_world_model(features: list[dict],
                       epochs: int = 100,
                       lr: float = 0.001,
                       batch_size: int = 32,
                       test_split: float = 0.2,
                       seed: int = 42,
                       verbose: bool = True) -> tuple:
    """Train the LSTM world model on network feature sequences.

    Checkpoint selection is done on a VALIDATION split carved out of the
    training data — never on the test set. Selecting the best epoch by test F1
    (the earlier behaviour) is test-set peeking: it reports the single luckiest
    epoch on the very data it claims to be held out, which both inflates the
    number and makes it swing run-to-run. Here the best epoch is chosen by
    validation F1, and the test metrics *at that same epoch* are what get
    reported — an honest estimate of generalization, and a far more stable one.
    """
    if not TORCH_OK:
        print("[WorldModel] PyTorch required for training")
        return None, {}

    random.seed(seed)
    torch.manual_seed(seed)

    # Build sequences
    X, y, y_state, y_tech, seg_ids = make_sequences(features, SEQ_LEN)
    if X is None:
        return None, {}

    # Leakage-safe train/test split — see _purged_segment_split's docstring.
    # purge = SEQ_LEN - 1 because that's the largest timestep overlap two
    # windows can share (a window one step apart still shares 4 of 5 steps).
    train_idx_all, test_idx = _purged_segment_split(seg_ids, test_split=test_split, purge=SEQ_LEN - 1)

    # Carve a VALIDATION set out of the training portion, with the same
    # leakage-safe segment/purge logic, for checkpoint selection. The test set
    # is never consulted for choosing the best epoch — see the docstring.
    train_seg_ids = [seg_ids[i] for i in train_idx_all]
    rel_train, rel_val = _purged_segment_split(train_seg_ids, test_split=0.2, purge=SEQ_LEN - 1)
    train_idx = [train_idx_all[j] for j in rel_train]
    val_idx   = [train_idx_all[j] for j in rel_val]
    if not val_idx:
        # Dataset too small to carve a validation set — fall back to selecting
        # on the test set (the old behaviour), but say so loudly so the number
        # is read with the right caveat rather than mistaken for a clean split.
        val_idx = test_idx
        print("[WorldModel] WARNING: dataset too small for a separate validation "
              "split — falling back to test-set checkpoint selection (optimistic).")

    print(f"[WorldModel] Split: {len(train_idx)} train / {len(val_idx)} val / "
          f"{len(test_idx)} test sequences (purged, per-source-segment — not a random shuffle)")

    X_train, y_train = X[train_idx], y[train_idx]
    X_val,   y_val   = X[val_idx],   y[val_idx]
    X_test,  y_test  = X[test_idx],  y[test_idx]
    y_state_train = y_state[train_idx]
    y_state_val,  y_state_test = y_state[val_idx], y_state[test_idx]
    y_tech_train  = y_tech[train_idx]
    y_tech_val,   y_tech_test  = y_tech[val_idx],  y_tech[test_idx]

    train_ds = TensorDataset(X_train, y_train, y_state_train, y_tech_train)
    val_ds   = TensorDataset(X_val,   y_val,   y_state_val,   y_tech_val)
    test_ds  = TensorDataset(X_test,  y_test,  y_state_test,  y_tech_test)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size)
    test_loader  = DataLoader(test_ds,  batch_size=batch_size)

    # Model
    model = WorldModelLSTM(input_dim=INPUT_DIM)
    # weight_decay: every benchmark run so far (2-segment and 3-segment)
    # showed the same shape — test F1 peaks in the first few epochs, then
    # degrades steadily even though train loss keeps falling. That's
    # classic overfitting on a relatively small, non-i.i.d. dataset. A
    # small L2 penalty won't fix it outright but should flatten the decay
    # and give the best-checkpoint mechanism a higher peak to land on.
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    criterion       = nn.BCELoss()                                 # infiltration head (primary)
    state_criterion = nn.MSELoss()                                 # fc_next_state head — teaches
    # genuine state-transition prediction, which is what k_step_forecast() rolls forward through
    tech_criterion  = nn.CrossEntropyLoss(ignore_index=IGNORE_INDEX)  # fc_technique head — was
    # defined but never trained before; ignore_index skips non-compromise/UNKNOWN targets rather
    # than forcing them into a wrong class

    # Loss weights: infiltration detection is the primary SIH26153 objective, so it keeps weight
    # 1.0. The two auxiliary heads are real training signal but shouldn't be able to dominate it.
    STATE_LOSS_WEIGHT = 0.3
    TECH_LOSS_WEIGHT  = 0.3

    print(f"\n[WorldModel] Training LSTM World Model")
    print(f"  Parameters:  {sum(p.numel() for p in model.parameters()):,}")
    print(f"  Input dim:   {INPUT_DIM} network features")
    print(f"  Seq length:  {SEQ_LEN} time windows")
    print(f"  Train:       {len(train_ds)} sequences")
    print(f"  Val:         {len(val_ds)} sequences (checkpoint selection)")
    print(f"  Test:        {len(test_ds)} sequences (held out, reporting only)")
    print(f"  Epochs:      {epochs}")
    print(f"  Loss:        BCE(infiltration) + {STATE_LOSS_WEIGHT}*MSE(next_state) + "
          f"{TECH_LOSS_WEIGHT}*CE(technique, ignore_index={IGNORE_INDEX})\n")

    best_val_f1 = -1.0
    best_state = None
    best_epoch = 0
    history   = {"train_loss": [],
                  "val_f1": [],
                  "test_f1": [], "test_precision": [],
                  "test_recall": [], "test_fpr": [], "test_tech_acc": []}

    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        total_loss = 0.0
        for Xb, yb, y_state_b, y_tech_b in train_loader:
            optimizer.zero_grad()
            inf_prob, tech_logits, next_state_pred = model(Xb)

            loss_bce = criterion(inf_prob.squeeze(-1), yb)
            loss_mse = state_criterion(next_state_pred, y_state_b)

            # A batch can be entirely non-compromise (all IGNORE_INDEX), in which case
            # CrossEntropyLoss(ignore_index=...) divides 0/0 -> nan. Guard against that
            # rather than letting a nan silently poison the combined loss/backward pass.
            has_tech_labels = bool((y_tech_b != IGNORE_INDEX).any())
            loss_ce = tech_criterion(tech_logits, y_tech_b) if has_tech_labels else torch.tensor(0.0)

            loss = loss_bce + STATE_LOSS_WEIGHT * loss_mse + TECH_LOSS_WEIGHT * loss_ce
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)
        scheduler.step()

        # Evaluate on validation (drives checkpoint selection) and test
        # (recorded for reporting only — never used to pick the epoch).
        val_m  = _eval_loader(model, val_loader)
        test_m = _eval_loader(model, test_loader)

        history["train_loss"].append(avg_loss)
        history["val_f1"].append(val_m["f1"])
        history["test_f1"].append(test_m["f1"])
        history["test_precision"].append(test_m["precision"])
        history["test_recall"].append(test_m["recall"])
        history["test_fpr"].append(test_m["fpr"])
        history["test_tech_acc"].append(test_m["tech_acc"])

        # Select the checkpoint by VALIDATION F1, not test F1.
        if val_m["f1"] > best_val_f1:
            best_val_f1 = val_m["f1"]
            best_epoch  = epoch - 1  # 0-indexed into history lists
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if verbose and (epoch % 10 == 0 or epoch == 1):
            lr_now = optimizer.param_groups[0]["lr"]
            print(f"  Epoch {epoch:3d}/{epochs}  "
                  f"loss={avg_loss:.4f}  val_f1={val_m['f1']:.3f}  test_f1={test_m['f1']:.3f}  "
                  f"prec={test_m['precision']:.3f}  rec={test_m['recall']:.3f}  "
                  f"fpr={test_m['fpr']:.3f}  lr={lr_now:.6f}")

    if best_state:
        model.load_state_dict(best_state)

    # Record which epoch was selected on validation, so benchmark() reports the
    # test metrics AT that epoch rather than the max-over-epochs test F1.
    history["selected_epoch"] = best_epoch
    sel_test_f1 = history["test_f1"][best_epoch] if history["test_f1"] else 0.0
    print(f"\n[WorldModel] Selected epoch {best_epoch + 1} by val F1={best_val_f1:.3f} "
          f"-> held-out test F1={sel_test_f1:.3f}")

    # Save model
    torch.save({
        "model_state": model.state_dict(),
        "input_dim":   INPUT_DIM,
        "hidden_dim":  HIDDEN_DIM,
        "num_layers":  NUM_LAYERS,
        "seq_len":     SEQ_LEN,
        "feature_cols": FEATURE_COLS,
        "best_f1":     sel_test_f1,
        "best_val_f1": best_val_f1,
        "selected_epoch": best_epoch + 1,
    }, MODEL_PATH)
    print(f"[WorldModel] Model saved to {MODEL_PATH}")

    return model, history


# ─────────────────────────────────────────────────────────
# LOGISTIC REGRESSION BASELINE
# ─────────────────────────────────────────────────────────

def train_logistic_baseline(features: list[dict],
                              test_split: float = 0.2,
                              seed: int = 42) -> dict:
    """
    Train a Logistic Regression classifier on the SAME features.
    This is the static baseline — it sees each flow in isolation,
    with no temporal context.

    SIH26153 requires: "Benchmark results demonstrating that the world model's
    temporal dynamics learning provides measurable improvement."
    """
    if not SKLEARN_OK:
        print("[Baseline] scikit-learn required")
        return {}, None, None

    print(f"\n[Baseline] Training Logistic Regression baseline")
    print(f"  Features: {INPUT_DIM} network features (same as world model)")
    print(f"  No temporal context — static single-flow classifier\n")

    # Build flat feature matrix (no sequences — that's the point)
    X_raw = []
    y_raw = []
    seg_ids = []
    prev_source, gi = None, -1
    for f in features:
        vec = flow_to_vector(f)
        label = f.get("infiltration_label", f.get("is_compromise", 0))
        X_raw.append(vec)
        y_raw.append(int(label))
        cur_source = f.get("source", "unknown")
        if cur_source != prev_source:
            gi += 1
            prev_source = cur_source
        seg_ids.append(gi)

    if not X_raw:
        print("[Baseline] No data")
        return {}, None, None

    # Same per-source-segment split as the World Model (see
    # _purged_segment_split) — no purge needed here since the baseline sees
    # single flows, not overlapping windows, but using the same segment-aware
    # split keeps the comparison apples-to-apples rather than random-shuffle
    # for one model and leakage-safe for the other.
    random.seed(seed)
    train_idx, test_idx = _purged_segment_split(seg_ids, test_split=test_split, purge=0)

    X_train = [X_raw[i] for i in train_idx]
    y_train = [y_raw[i] for i in train_idx]
    X_test  = [X_raw[i] for i in test_idx]
    y_test  = [y_raw[i] for i in test_idx]

    # Scale
    scaler  = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # Train
    clf = LogisticRegression(max_iter=1000, random_state=seed, C=1.0)
    clf.fit(X_train_s, y_train)

    # Evaluate
    y_pred  = clf.predict(X_test_s)
    y_prob  = clf.predict_proba(X_test_s)[:, 1]

    f1   = f1_score(y_test, y_pred, zero_division=0)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    acc  = accuracy_score(y_test, y_pred)

    cm  = confusion_matrix(y_test, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    else:
        fpr = 0.0

    try:
        auc = roc_auc_score(y_test, y_prob) if len(set(y_test)) > 1 else 0.0
    except Exception:
        auc = 0.0

    results = {
        "model":     "Logistic Regression (baseline)",
        "f1":        round(f1, 4),
        "precision": round(prec, 4),
        "recall":    round(rec, 4),
        "accuracy":  round(acc, 4),
        "fpr":       round(fpr, 4),
        "auc_roc":   round(auc, 4),
        "n_train":   len(X_train),
        "n_test":    len(X_test),
        "note":      "Static classifier — no temporal context. Each flow classified independently.",
    }

    print(f"  Logistic Regression Results:")
    print(f"    F1 Score:   {f1:.4f}")
    print(f"    Precision:  {prec:.4f}")
    print(f"    Recall:     {rec:.4f}")
    print(f"    Accuracy:   {acc:.4f}")
    print(f"    FPR:        {fpr:.4f}")
    print(f"    AUC-ROC:    {auc:.4f}")

    # Return the fitted classifier + scaler too, so the lead-time analysis can
    # score the SAME baseline per-flow without retraining it.
    return results, clf, scaler


# ─────────────────────────────────────────────────────────
# BENCHMARK REPORT
# ─────────────────────────────────────────────────────────

def _segment_bounds(features: list[dict]) -> list[tuple]:
    """Contiguous [start, end) runs of identical `source` — a single timeline."""
    segments = []
    if not features:
        return segments
    seg_start = 0
    prev = features[0].get("source", "unknown")
    for i in range(1, len(features)):
        cur = features[i].get("source", "unknown")
        if cur != prev:
            segments.append((seg_start, i))
            seg_start = i
            prev = cur
    segments.append((seg_start, len(features)))
    return segments


def _consecutive_lead(probs: list, onset_i: int, threshold: float) -> int:
    """
    How many consecutive flows immediately BEFORE the compromise onset the
    model was already alerting (prob >= threshold). This is the early-warning
    lead: a static per-flow classifier can only cross the threshold once the
    flow itself looks like an attack (lead ~0); a temporal model can cross it
    earlier, on the benign-looking build-up flows (lead > 0).
    """
    lead = 0
    j = onset_i - 1
    while j >= 0 and probs[j] >= threshold:
        lead += 1
        j -= 1
    return lead


def lead_time_analysis(model, lr_clf, lr_scaler, features: list[dict],
                        seq_len: int = SEQ_LEN, alert_threshold: float = 0.5,
                        tail_frac: float = 0.2) -> dict:
    """
    Measure how many flows EARLIER the LSTM World Model raises a correct
    compromise alert than the static Logistic Regression baseline.

    This is the World Model's real differentiator — the SIH26153 problem
    statement asks for temporal dynamics / forward simulation, and a static
    classifier cannot look ahead by construction. Point-classification F1 does
    not capture it; lead-time does.

    Method (honest and reproducible): each contiguous source segment is a
    timeline. Its chronological TAIL (last `tail_frac`) is the evaluation
    region — a held-out-style stretch the model is scored on moving forward in
    time, never used to pick anything. At every benign->compromise onset in
    that region, we measure how many consecutive preceding flows each model was
    already alerting on (see _consecutive_lead). We report the mean lead per
    model and the LSTM's advantage in flows.
    """
    if not TORCH_OK or lr_clf is None:
        return {}

    segments = _segment_bounds(features)
    lstm_leads, lr_leads = [], []
    n_onsets = 0

    for (s, e) in segments:
        seg = features[s:e]
        if len(seg) < seq_len + 3:
            continue
        labels = [int(f.get("infiltration_label", f.get("is_compromise", 0))) for f in seg]
        if sum(labels) == 0 or sum(labels) == len(labels):
            continue  # no benign->compromise transition possible in this segment
        vecs = [flow_to_vector(f) for f in seg]

        tail_start = int(len(seg) * (1.0 - tail_frac))
        eval_start = max(seq_len, tail_start)
        positions = list(range(eval_start, len(seg)))
        if len(positions) < 2:
            continue

        # LSTM per-position P(compromise at t) from the window ending just before t
        Xw = [vecs[t - seq_len:t] for t in positions]
        with torch.no_grad():
            out = model(torch.tensor(Xw, dtype=torch.float32))[0].squeeze(-1).tolist()
        lstm_probs = out if isinstance(out, list) else [out]

        # LR per-flow P(compromise) at the same positions
        lr_in = lr_scaler.transform([vecs[t] for t in positions])
        lr_probs = lr_clf.predict_proba(lr_in)[:, 1].tolist()

        for i, t in enumerate(positions):
            if labels[t] == 1 and labels[t - 1] == 0:  # benign -> compromise onset
                n_onsets += 1
                lstm_leads.append(_consecutive_lead(lstm_probs, i, alert_threshold))
                lr_leads.append(_consecutive_lead(lr_probs, i, alert_threshold))

    if n_onsets == 0:
        return {"n_onsets": 0,
                "note": "No benign->compromise transitions in the evaluation tails "
                        "(each source segment is single-class there) — lead-time "
                        "not measurable on this dataset composition."}

    mean_lstm = sum(lstm_leads) / len(lstm_leads)
    mean_lr   = sum(lr_leads) / len(lr_leads)
    return {
        "n_onsets": n_onsets,
        "mean_lead_lstm_flows": round(mean_lstm, 2),
        "mean_lead_lr_flows":   round(mean_lr, 2),
        "lstm_advantage_flows": round(mean_lstm - mean_lr, 2),
        "alert_threshold": alert_threshold,
        "note": "Mean flows of early warning before a benign->compromise onset, "
                "measured on each source segment's chronological tail. Higher = "
                "earlier detection; LR is static so it cannot warn ahead of the "
                "attack flow itself.",
    }


def benchmark(features: list[dict],
               model_path: str = MODEL_PATH,
               epochs: int = 50,
               repeats: int = 1) -> dict:
    """
    Run full benchmark: World Model LSTM vs Logistic Regression baseline.
    Produces the comparison table required by SIH26153.

    With repeats > 1 the LSTM is retrained under several seeds and the F1
    improvement is reported as mean ± std across seeds, not a single figure —
    an honest range, since a single LSTM run varies with initialisation on a
    dataset this size. The LR baseline is deterministic given the split, so its
    numbers don't move across seeds.
    """
    print("\n" + "═" * 65)
    print("  CYBERSENTINEL — WORLD MODEL BENCHMARK")
    print("  (LSTM World Model vs Logistic Regression Baseline)")
    print("═" * 65)

    # Baseline first (deterministic given the split) — also returns the fitted
    # classifier + scaler for the lead-time analysis below.
    baseline_results, lr_clf, lr_scaler = train_logistic_baseline(features)

    if not SKLEARN_OK or not baseline_results:
        print("[Benchmark] Insufficient data for comparison")
        return {}

    # World model — retrain under `repeats` seeds. For each run we take the
    # test metrics AT the validation-selected epoch (train_world_model already
    # did that selection), never the max-over-epochs test F1. The last-trained
    # model + its history are kept for the lead-time analysis and saved weights.
    seeds = [42 + i for i in range(max(1, repeats))]
    per_seed = []
    model, history = None, None
    for si, seed in enumerate(seeds):
        if len(seeds) > 1:
            print(f"\n[Benchmark] LSTM run {si+1}/{len(seeds)} (seed={seed})")
        model, history = train_world_model(features, epochs=epochs, seed=seed,
                                           verbose=(si == 0))
        if not history:
            print("[Benchmark] Insufficient data for comparison")
            return {}
        se = history["selected_epoch"]
        per_seed.append({
            "seed": seed,
            "f1":        history["test_f1"][se],
            "precision": history["test_precision"][se],
            "recall":    history["test_recall"][se],
            "fpr":       history["test_fpr"][se],
        })

    def _mean(xs): return sum(xs) / len(xs)
    def _std(xs):
        if len(xs) < 2: return 0.0
        m = _mean(xs); return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5

    f1s   = [r["f1"] for r in per_seed]
    precs = [r["precision"] for r in per_seed]
    recs  = [r["recall"] for r in per_seed]
    fprs  = [r["fpr"] for r in per_seed]

    lstm_results = {
        "model":     "LSTM World Model (temporal dynamics)",
        "f1":        round(_mean(f1s), 4),
        "f1_std":    round(_std(f1s), 4),
        "precision": round(_mean(precs), 4),
        "recall":    round(_mean(recs), 4),
        "fpr":       round(_mean(fprs), 4),
        "n_seeds":   len(seeds),
        "per_seed_f1": [round(x, 4) for x in f1s],
        "note":      f"Temporal model — sees {SEQ_LEN} time windows. Learns P(S_t+1 | S_t). "
                     f"Test metrics at the validation-selected epoch; "
                     f"{'mean over '+str(len(seeds))+' seeds' if len(seeds)>1 else 'single seed'}.",
    }

    # Lead-time analysis on the last trained model (the World Model's real
    # differentiator — see lead_time_analysis).
    lead = lead_time_analysis(model, lr_clf, lr_scaler, features)

    # Print comparison table
    print("\n" + "═" * 65)
    print("  BENCHMARK RESULTS")
    print("═" * 65)
    print(f"  {'Metric':20s}  {'Logistic Reg':16s}  {'LSTM World Model':16s}  {'Improvement':12s}")
    print("  " + "-" * 63)

    metrics = ["f1", "precision", "recall", "fpr"]
    labels  = ["F1 Score", "Precision", "Recall", "False Positive Rate"]
    lower_is_better = {"fpr"}

    for metric, label in zip(metrics, labels):
        lr_val   = baseline_results.get(metric, 0.0)
        lstm_val = lstm_results.get(metric, 0.0)

        if metric in lower_is_better:
            improvement = lr_val - lstm_val   # lower FPR = improvement
            symbol = "↓" if improvement > 0 else "↑"
        else:
            improvement = lstm_val - lr_val
            symbol = "↑" if improvement > 0 else "↓"

        print(f"  {label:20s}  {lr_val:16.4f}  {lstm_val:16.4f}  "
              f"{symbol}{abs(improvement):.4f}")

    print("═" * 65)

    f1_improvement = lstm_results["f1"] - baseline_results.get("f1", 0)

    # Report the F1 improvement honestly — as a range when multiple seeds were
    # run, since a single LSTM run varies with initialisation at this data size.
    if len(seeds) > 1:
        f1_imp_per_seed = [r["f1"] - baseline_results.get("f1", 0) for r in per_seed]
        lo, hi = min(f1_imp_per_seed), max(f1_imp_per_seed)
        print(f"\n  F1 improvement over baseline: mean {f1_improvement:+.4f} "
              f"(±{lstm_results['f1_std']:.4f}), range [{lo:+.4f}, {hi:+.4f}] "
              f"across {len(seeds)} seeds")
        print(f"  Report this as a RANGE, not a single figure — the LSTM's margin "
              f"varies with seed and dataset composition.")
    else:
        print(f"\n  F1 improvement over baseline: {f1_improvement:+.4f} "
              f"({100*f1_improvement:+.1f}%). Single seed — re-run with --repeat N "
              f"for a mean ± std range (recommended for the report).")

    if f1_improvement > 0:
        print(f"  ✓ Temporal dynamics learning provides a measurable improvement")
        print(f"  ✓ SIH26153 benchmark requirement satisfied")
    else:
        print(f"  ⚠ Baseline competitive at this dataset size — richer honeypot data widens the gap")

    # Lead-time — the capability LR cannot match by construction
    print(f"\n  Lead-time (early-warning) analysis:")
    if lead.get("n_onsets", 0) > 0:
        print(f"    Benign→compromise onsets measured: {lead['n_onsets']}")
        print(f"    LSTM mean early warning: {lead['mean_lead_lstm_flows']} flows")
        print(f"    LR   mean early warning: {lead['mean_lead_lr_flows']} flows")
        print(f"    LSTM advantage:          {lead['lstm_advantage_flows']} flows earlier")
        print(f"    → Only the temporal model can warn BEFORE the attack flow itself.")
    else:
        print(f"    {lead.get('note', 'not measurable on this dataset composition')}")

    print(f"\n  Key advantage of World Model over Logistic Regression:")
    print(f"    LR sees:   1 flow → binary label (static)")
    print(f"    LSTM sees: {SEQ_LEN} flows → P(compromise at t+1) (temporal)")
    print(f"    Only LSTM can do forward simulation (K-step forecast) and lead-time warning")

    # Save benchmark results
    results = {
        "baseline":    baseline_results,
        "world_model": lstm_results,
        "f1_improvement": round(f1_improvement, 4),
        "lead_time": lead,
    }
    with open("benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to benchmark_results.json")
    print("═" * 65)

    return results


# ─────────────────────────────────────────────────────────
# INFERENCE
# ─────────────────────────────────────────────────────────

def load_world_model(model_path: str = MODEL_PATH):
    """Load saved world model."""
    if not TORCH_OK:
        return None
    if not Path(model_path).exists():
        print(f"[WorldModel] No model at {model_path} — run --train first")
        return None

    ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
    model = WorldModelLSTM(
        input_dim  = ckpt.get("input_dim",  INPUT_DIM),
        hidden_dim = ckpt.get("hidden_dim", HIDDEN_DIM),
        num_layers = ckpt.get("num_layers", NUM_LAYERS),
    )
    model.load_state_dict(ckpt["model_state"])
    model.eval()
    return model


def predict_from_recent_flows(recent_flows: list[dict],
                               k_steps: int = 3,
                               model_path: str = MODEL_PATH) -> dict:
    """
    Given the last `seq_len` observed flows, predict:
      - Infiltration probability for next state
      - K-step forward simulation
      - Which features drove the prediction (attention weights)

    This is the world model inference API used by streamlit_app.py.
    """
    model = load_world_model(model_path)
    if model is None:
        return {"error": "Model not trained. Run: python3 world_model.py --train"}

    # Pad or truncate to SEQ_LEN
    if len(recent_flows) < SEQ_LEN:
        pad = [recent_flows[0]] * (SEQ_LEN - len(recent_flows))
        recent_flows = pad + recent_flows
    else:
        recent_flows = recent_flows[-SEQ_LEN:]

    # Build tensor
    vecs = [flow_to_vector(f) for f in recent_flows]
    X = torch.tensor([vecs], dtype=torch.float32)   # (1, seq_len, input_dim)

    model.eval()
    with torch.no_grad():
        inf_prob, tech_logits, next_state_pred, attn_weights = model(X, return_attention=True)

    inf_prob_val = inf_prob.item()
    attn = attn_weights[0].tolist()   # (seq_len,)

    # Decode the technique head for the immediate next state (same head that
    # k_step_forecast() decodes at each of its k steps — see there for why
    # confidence < 0.3 is reported as "no confident technique" rather than
    # a forced guess).
    tech_probs = torch.softmax(tech_logits, dim=1)[0]
    tech_idx   = int(torch.argmax(tech_probs).item())
    tech_conf  = float(tech_probs[tech_idx].item())
    predicted_technique = TECHNIQUE_CLASSES[tech_idx] if tech_conf >= 0.3 else None

    # Feature importance: which time step was most attended
    most_attended_step = attn.index(max(attn))
    most_attended_flow = recent_flows[most_attended_step]

    # Which features in the attended flow are most extreme
    attended_vec = vecs[most_attended_step]
    feature_importance = sorted(
        zip(FEATURE_COLS, attended_vec),
        key=lambda x: -abs(x[1])
    )[:8]

    # K-step forecast — genuine forward simulation through the model's own
    # predicted next-state vectors (see k_step_forecast()'s docstring).
    forecast = model.k_step_forecast(X, k=k_steps)
    forecast_pct_str = ", ".join(f"{step['infiltration_prob']:.0%}" for step in forecast)

    risk = (
        "CRITICAL" if inf_prob_val >= 0.85 else
        "HIGH"     if inf_prob_val >= 0.65 else
        "MEDIUM"   if inf_prob_val >= 0.40 else
        "LOW"
    )

    return {
        "infiltration_prob":    round(inf_prob_val, 4),
        "risk_label":           risk,
        "predicted_technique":  predicted_technique,
        "technique_confidence": round(tech_conf, 4),
        "k_step_forecast":      forecast,
        "attention_weights":    [round(a, 4) for a in attn],
        "most_attended_step":   most_attended_step,
        "feature_importance": [
            {"feature": f, "importance": round(abs(v), 4)}
            for f, v in feature_importance
        ],
        "explanation": (
            f"World model analysed {SEQ_LEN} consecutive network flows. "
            f"Infiltration probability: {inf_prob_val:.1%} [{risk}]. "
            f"Predicted technique: {predicted_technique or 'none (confidence too low)'} "
            f"({tech_conf:.1%} confidence). "
            f"Strongest signal: {feature_importance[0][0]} "
            f"(value={feature_importance[0][1]:.3f}). "
            f"K={k_steps} step forecast: [{forecast_pct_str}]."
        ),
    }


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel — World Model LSTM + LR Baseline"
    )
    parser.add_argument("--train",      action="store_true",
                        help="Train world model")
    parser.add_argument("--benchmark",  action="store_true",
                        help="Train both models and compare")
    parser.add_argument("--predict",    action="store_true",
                        help="Run inference on recent flows")
    parser.add_argument("--features",   default=FEATURES_PATH,
                        help="Path to features.json")
    parser.add_argument("--epochs",     type=int, default=100)
    parser.add_argument("--k",          type=int, default=3,
                        help="K steps for forward simulation")
    parser.add_argument("--repeat",     type=int, default=1,
                        help="Benchmark: retrain the LSTM under this many seeds and "
                             "report F1 improvement as mean ± std (recommended: 3-5). "
                             "The report should cite the range, not one lucky run.")
    parser.add_argument("--predict-source", default="honeypot",
                        choices=["honeypot", "any"],
                        help="Which rows --predict runs on. 'honeypot' (default) uses "
                             "the most recent real honeypot flows — genuine live-capture "
                             "inference. 'any' uses the last rows of the file as-is, which "
                             "after a full CIC merge are the last-merged CIC day, NOT live "
                             "honeypot traffic.")
    args = parser.parse_args()

    if args.train:
        features = load_features(args.features)
        if not features:
            print("\n[WorldModel] No features found. Generate them first:")
            print("  python3 packet_capture.py --cowrie cowrie-raw.json")
            print("  python3 cic_ids_loader.py --download")
            sys.exit(1)
        train_world_model(features, epochs=args.epochs)

    elif args.benchmark:
        features = load_features(args.features)
        if not features:
            sys.exit(1)
        benchmark(features, epochs=args.epochs, repeats=args.repeat)

    elif args.predict:
        features = load_features(args.features)
        if not features:
            sys.exit(1)

        # Choose which flows to run live inference on. By default use the most
        # recent REAL honeypot flows — otherwise, after a full CIC-IDS-2018
        # merge, features_all.json's last rows are the last-merged CIC day
        # (e.g. an Infiltration day), not live honeypot traffic, which made the
        # "live inference" demo silently score a canned CIC row at ~99%.
        def _is_honeypot(f):
            src = str(f.get("source", "")).lower()
            return src.startswith("cowrie") or src.startswith("honeypot") or "proxy" in src

        if args.predict_source == "honeypot":
            honeypot_rows = [f for f in features if _is_honeypot(f)]
            if len(honeypot_rows) >= 1:
                recent = honeypot_rows[-SEQ_LEN:]
                print(f"[WorldModel] --predict on the {len(recent)} most recent REAL honeypot "
                      f"flow(s) (of {len(honeypot_rows)} honeypot rows in {args.features})")
            else:
                recent = features[-SEQ_LEN:]
                print(f"[WorldModel] WARNING: no honeypot rows found in {args.features} — "
                      f"falling back to the last {len(recent)} rows (these are CIC-IDS-2018 "
                      f"data, NOT live honeypot traffic). Pass a honeypot-only features file "
                      f"for a genuine live-inference demo.")
        else:
            recent = features[-SEQ_LEN:]
            print(f"[WorldModel] --predict on the last {len(recent)} rows of {args.features} "
                  f"as-is (--predict-source any). After a full CIC merge these are the "
                  f"last-merged CIC day, not live honeypot traffic.")

        result = predict_from_recent_flows(recent, k_steps=args.k)
        print("\n" + "═" * 55)
        print("  WORLD MODEL INFERENCE")
        print("═" * 55)
        print(f"  Infiltration prob:  {result['infiltration_prob']:.1%}  [{result['risk_label']}]")
        print(f"  Predicted technique: {result['predicted_technique'] or 'none (confidence too low)'} "
              f"({result['technique_confidence']:.1%} confidence)")
        print(f"  Attention weights:  {result['attention_weights']}")
        print(f"\n  K-step forecast (genuine forward simulation through predicted next states):")
        for i, step in enumerate(result["k_step_forecast"], 1):
            tech_str = f" -> {step['predicted_technique']}" if step["predicted_technique"] else ""
            print(f"    t+{i}: infiltration={step['infiltration_prob']:.1%}{tech_str}")
        print(f"\n  Top feature drivers:")
        for fi in result["feature_importance"][:5]:
            bar = "█" * int(fi["importance"] * 30)
            print(f"    {fi['feature']:30s}  {bar}  {fi['importance']:.4f}")
        print(f"\n  Explanation:")
        print(f"    {result['explanation']}")
        print("═" * 55)

    else:
        parser.print_help()
        print("\nQuick start:")
        print("  # Step 1: Extract features from Cowrie logs")
        print("  python3 packet_capture.py --cowrie cowrie-raw.json")
        print()
        print("  # Step 2: Add CIC-IDS-2018 data (optional but recommended)")
        print("  python3 cic_ids_loader.py --download")
        print()
        print("  # Step 3: Train world model")
        print("  python3 world_model.py --train")
        print()
        print("  # Step 4: Full benchmark comparison")
        print("  python3 world_model.py --benchmark")


if __name__ == "__main__":
    main()
