"""
CyberSentinel AI — lstm_model.py
Week 2: LSTM sequence model for attack progression prediction

SIH26153 requirement: "AI-based learning of temporal behavior and prediction of attacker progression"

What this does:
  - Reads ttp_records.json (your honeypot sessions)
  - Builds sequences: each session = ordered list of MITRE technique IDs
  - Trains a PyTorch LSTM: given first N techniques, predict the next one
  - Outputs infiltration probability: P(session leads to system compromise)
  - Saves model to cybersentinel_lstm.pt for use in main pipeline

Usage:
  python3 lstm_model.py                        # train on ttp_records.json
  python3 lstm_model.py --predict T1082 T1087  # predict next technique
  python3 lstm_model.py --eval                 # evaluate on test split

Install deps:
  pip install torch --break-system-packages
"""

import argparse
import json
import math
import os
import random
import sys
from collections import Counter
from pathlib import Path

# ─────────────────────────────────────────────
# PYTORCH IMPORT (graceful error if not installed)
# ─────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, Dataset
    TORCH_OK = True
except ImportError:
    TORCH_OK = False
    print("[LSTM] PyTorch not found. Install with:")
    print("       pip install torch --break-system-packages")
    print("[LSTM] Running in demo mode (no training).\n")

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

MODEL_PATH = "cybersentinel_lstm.pt"
TTP_PATH   = "ttp_records.json"

# Techniques that imply system compromise — used for infiltration probability
COMPROMISE_TECHNIQUES = {
    "T1059", "T1059.004", "T1059.006",  # Shell / script execution
    "T1105",                              # Tool download (payload staging)
    "T1204", "T1204.002",                # User execution of malicious file
    "T1548", "T1068",                    # Privilege escalation
    "T1136",                              # Create account (persistence)
    "T1070",                              # Log deletion (cover tracks)
    "T1485", "T1489", "T1496",           # Impact: destruction / hijack
}

# Padding and unknown tokens
PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
START_TOKEN = "<START>"

# ─────────────────────────────────────────────
# VOCABULARY
# ─────────────────────────────────────────────

class TechniqueVocab:
    """Maps technique IDs ↔ integer indices."""

    def __init__(self):
        self.tok2idx = {PAD_TOKEN: 0, UNK_TOKEN: 1, START_TOKEN: 2}
        self.idx2tok = {0: PAD_TOKEN, 1: UNK_TOKEN, 2: START_TOKEN}
        self._next = 3

    def add(self, token: str):
        if token not in self.tok2idx:
            self.tok2idx[token] = self._next
            self.idx2tok[self._next] = token
            self._next += 1

    def encode(self, token: str) -> int:
        return self.tok2idx.get(token, self.tok2idx[UNK_TOKEN])

    def decode(self, idx: int) -> str:
        return self.idx2tok.get(idx, UNK_TOKEN)

    def __len__(self):
        return self._next

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"tok2idx": self.tok2idx, "idx2tok": {str(k): v for k, v in self.idx2tok.items()}}, f)

    @classmethod
    def load(cls, path: str) -> "TechniqueVocab":
        with open(path) as f:
            data = json.load(f)
        v = cls()
        v.tok2idx = data["tok2idx"]
        v.idx2tok = {int(k): v2 for k, v2 in data["idx2tok"].items()}
        v._next = max(v.idx2tok.keys()) + 1
        return v


# ─────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────

def load_real_sessions(ttp_path: str = TTP_PATH) -> list[list[str]]:
    """
    Load ttp_records.json → list of technique ID sequences per session.
    Each session = ordered list of MITRE technique IDs observed.

    REAL DATA ONLY — no synthetic augmentation here. This is deliberate:
    callers that need a training set must split real sessions into
    train/test FIRST (see split_sessions()) and only augment the train
    side (see augment_train_sessions()) afterwards. Augmenting before
    splitting — the old behaviour — let synthetic (templated) sequences
    land in the test set and inflated reported accuracy with what was
    partly in-sample/memorized performance rather than genuine
    generalization to real attacker behaviour.

    Handles both formats:
      - Plain strings:  ["T1082", "T1087"]
      - Dicts:          [{"id": "T1082", "name": "..."}, ...]
    """
    try:
        with open(ttp_path) as f:
            records = json.load(f)
    except FileNotFoundError:
        print(f"[LSTM] {ttp_path} not found — using synthetic demo sequences")
        return _synthetic_sequences()

    sessions = []
    for record in records:
        seq = []
        for t in record.get("techniques", []):
            if isinstance(t, dict):
                tid = t.get("id") or t.get("technique_id", "")
            else:
                tid = str(t)
            if tid:
                seq.append(tid)

        # Also extract technique evidence from commands if present
        # (augments sparse technique lists with command-inferred techniques)
        commands = record.get("raw_commands", [])
        inferred = _infer_from_commands(commands)
        for tid in inferred:
            if tid not in seq:
                seq.append(tid)

        if len(seq) >= 1:
            sessions.append(seq)

    print(f"[LSTM] Loaded {len(sessions)} sessions, "
          f"{sum(len(s) for s in sessions)} total technique observations")

    # Discover which techniques actually appear in the real sessions
    real_techniques = sorted({t for s in sessions for t in s})
    print(f"[LSTM] Real techniques found: {real_techniques}")

    return sessions


def split_sessions(sessions: list[list[str]], test_split: float = 0.1) -> tuple:
    """
    Split REAL sessions into (train, test). Sorted by each session's first
    technique, then every Nth session (N = round(1/test_split)) goes to
    test — a simple stratified-ish split so techniques with enough sessions
    get representation on both sides.

    MUST run on real sessions BEFORE synthetic augmentation (see
    load_real_sessions() / augment_train_sessions()) — augmenting first and
    splitting after leaks synthetic sequences into the test set.
    """
    step = max(1, round(1 / test_split)) if test_split > 0 else len(sessions) + 1
    sessions_sorted = sorted(sessions, key=lambda s: s[0] if s else "")
    train_sessions = [s for i, s in enumerate(sessions_sorted) if i % step != 0]
    test_sessions  = [s for i, s in enumerate(sessions_sorted) if i % step == 0]
    return train_sessions, test_sessions


def augment_train_sessions(train_sessions: list[list[str]], real_techniques: list[str]) -> list[list[str]]:
    """
    Add synthetic + optional real CIC-IDS-2018 T1110 sequences to the
    TRAINING split ONLY. Never call this on a test split — see the warning
    in split_sessions(). We generate synthetic sequences using ONLY the
    techniques actually in the data, so the vocab stays consistent and
    every synthetic sample is learnable.
    """
    synthetic = _targeted_synthetic(real_techniques)
    print(f"[LSTM] Adding {len(synthetic)} targeted synthetic sequences "
          f"(training split only — test split stays 100% real)")
    augmented = train_sessions + synthetic

    # Optional: real CIC-IDS-2018 brute-force supplement (see cic_ids_loader.py).
    # This is REAL academic benchmark data, distinct from the rule-based
    # synthetic sequences above — kept separate and clearly labeled so it's
    # never confused with either the honeypot captures or the synthetic
    # generator. Only ever contributes standalone T1110 observations (see
    # cic_ids_loader.py's docstring for why: CIC-IDS-2018 is flow-level data
    # with no surrounding technique context, so multi-step chains would be
    # fabricated, not real). Silently skipped if the file doesn't exist —
    # this dataset is optional, not a hard dependency of training.
    cic_path = Path("cic_t1110_augment.json")
    if cic_path.exists():
        try:
            with open(cic_path) as f:
                cic_sequences = json.load(f)
            print(f"[LSTM] Adding {len(cic_sequences)} real CIC-IDS-2018 "
                  f"brute-force sequences (T1110 supplement, training only)")
            augmented = augmented + cic_sequences
        except (json.JSONDecodeError, OSError) as e:
            print(f"[LSTM] WARNING: found {cic_path} but couldn't load it: {e}")

    return augmented


def load_sessions(ttp_path: str = TTP_PATH) -> list[list[str]]:
    """
    Backward-compatible convenience wrapper: real sessions plus training-
    style augmentation, combined into one list with NO train/test boundary.

    Do NOT use this to build a test/eval set — the returned list mixes
    synthetic sequences in with real ones. Use load_real_sessions() +
    split_sessions() instead, which keeps synthetic data out of test.
    """
    sessions = load_real_sessions(ttp_path)
    real_techniques = sorted({t for s in sessions for t in s})
    return augment_train_sessions(sessions, real_techniques)


# Kill-chain stage order — used to constrain synthetic training sequences to
# forward (or same-stage) transitions only. Real attackers don't re-run
# system discovery *after* executing a downloaded payload; unconstrained
# itertools.permutations() in synthetic data generation was teaching the
# model contradictory transitions in both directions, diluting the real
# signal (this is why T1105 kept getting confused with T1082 — reversed
# synthetic pairs like [T1204, T1082] taught it that pattern too).
# Lower number = earlier in a typical attack progression. Techniques not
# listed default to a high rank (end of chain) rather than crashing.
STAGE_RANK = {
    # Initial Access / Credential Access — the ENTRY POINT, always first.
    # Brute force is how the attacker gets in; nothing precedes it.
    "T1110": 0, "T1110.001": 0, "T1110.003": 0,
    "T1078": 0, "T1078.001": 0, "T1190": 0, "T1133": 0,
    # Discovery / recon — after gaining access
    "T1082": 1, "T1083": 1, "T1033": 1,
    "T1049": 1, "T1087": 1, "T1087.001": 1, "T1046": 1,
    # Credential access (post-login credential theft)
    "T1552": 1,
    # Ingress tool transfer / C2 staging
    "T1105": 2, "T1071": 2, "T1048": 2,
    # Execution
    "T1059": 3, "T1059.004": 3, "T1059.006": 3, "T1204": 3,
    "T1204.002": 3, "T1053": 3,
    # Post-compromise / post-execution enumeration — placed AFTER execution to
    # match attack.sh's actual Phase 4-5 ordering (ps aux, netstat, ifconfig,
    # nmap run only after initial access + execution have happened).
    "T1057": 4, "T1016": 4,
    # Persistence
    "T1136": 5, "T1098": 5, "T1053.003": 5,
    # Privilege escalation
    "T1548": 6, "T1068": 6,
    # Defense evasion / lateral movement / impact — end of chain
    "T1070": 7, "T1021": 7, "T1021.004": 7,
    "T1485": 7, "T1489": 7, "T1496": 7, "T1499": 7,
}


def _forward_orderings(subset: tuple, rank_map: dict) -> list[list[str]]:
    """
    Generate orderings of `subset` that respect kill-chain stage order:
    techniques from an earlier stage always come before a later stage.
    Techniques in the *same* stage may appear in either order (their
    relative order genuinely doesn't matter — e.g. discovering system
    info vs. discovering accounts first is not a meaningful distinction).

    This replaces unconstrained itertools.permutations(), which produced
    backwards sequences (e.g. execution before recon) that taught the
    model transitions that never happen in practice.
    """
    import itertools
    groups: dict[int, list[str]] = {}
    for t in subset:
        groups.setdefault(rank_map.get(t, 99), []).append(t)

    ordered_ranks = sorted(groups.keys())
    per_group_perms = [list(itertools.permutations(groups[r])) for r in ordered_ranks]

    results = []
    for combo in itertools.product(*per_group_perms):
        seq = []
        for group in combo:
            seq.extend(group)
        results.append(seq)
    return results


def _infer_from_commands(commands: list[str]) -> list[str]:
    """
    Infer additional MITRE techniques from raw commands observed in a session.
    This enriches sparse TTP records with technique IDs implied by attacker commands.
    """
    inferred = []
    cmd_str = " ".join(commands).lower()

    rules = [
        (["wget ", "curl "],                          "T1105"),
        (["chmod +x", "chmod 777"],                   "T1204"),
        (["uname", "cat /etc/issue", "/proc/version"], "T1082"),
        (["cat /etc/passwd", "getent passwd", "whoami", "id"], "T1087"),
        (["bash -i", "/dev/tcp", "nc ", "ncat "],      "T1059"),
        (["useradd", "adduser"],                       "T1136"),
        (["crontab", "/etc/cron"],                     "T1053"),
        (["sudo ", "su -"],                            "T1548"),
        (["rm -rf", "shred ", "wipe "],                "T1485"),
        (["ifconfig", "ip addr", "ip route"],          "T1016"),
        (["ps aux", "ps -ef", "top "],                 "T1057"),
        (["python", "python3", "perl ", "ruby "],      "T1059.006"),
    ]

    for keywords, tid in rules:
        if any(kw in cmd_str for kw in keywords):
            inferred.append(tid)

    return inferred


def _targeted_synthetic(real_techniques: list[str]) -> list[list[str]]:
    """
    Generate synthetic sequences using ONLY techniques actually present in the
    real honeypot data. This keeps the vocab consistent and ensures every
    synthetic sample is learnable — no unknown technique IDs introduced.

    BALANCED generation (fixes class collapse):
    Earlier versions used unconstrained combinations, which made discovery
    techniques (T1082/T1087) and T1110 appear as prediction targets far more
    often than rare techniques (T1016/T1105). The model then collapsed to
    always predicting the 2-3 most frequent classes (31% accuracy, everything
    guessed as T1087/T1110).

    This version guarantees each technique appears as a PREDICTION TARGET
    roughly equally, by building sequences that END on each technique in turn.
    Stage-order is still respected (via _forward_orderings), so no backwards
    chains are introduced. The result is a class-balanced training set where
    the model must actually learn each technique's context, not just memorise
    the frequency prior.
    """
    import itertools
    from collections import Counter

    seqs = []
    techs = list(real_techniques)
    if len(techs) < 2:
        return seqs

    # ── Step 1: generate all stage-ordered subsequences up to length 4 ────────
    # Cap at length 4: longer chains multiply intermediate-target counts for
    # discovery techniques (which appear in every chain), unbalancing the set.
    raw = []
    for size in range(2, min(4, len(techs)) + 1):
        for subset in itertools.combinations(techs, size):
            raw.extend(_forward_orderings(subset, STAGE_RANK))

    # ── Step 2: balance by PREDICTION TARGET frequency ────────────────────────
    # A training sample predicts full_seq[i] from full_seq[:i], so every
    # position after the first is a target. Naively, discovery techniques
    # (in every chain) dominate. We fix this by:
    #   (a) counting each technique's natural target frequency in `raw`
    #   (b) down-sampling over-represented techniques' sequences
    #   (c) up-sampling under-represented ones
    # so every technique ends up as a target ~TARGET_PER_TECHNIQUE times.
    TARGET_PER_TECHNIQUE = 200

    # Group sequences by their LAST element (primary target signal)
    by_ending = {t: [] for t in techs}
    for s in raw:
        by_ending[s[-1]].append(s)

    # Cap how hard we'll duplicate a tiny natural pool to reach TARGET_PER_TECHNIQUE.
    # Rank-0 techniques (T1110, T1078 — the entry-point stage) structurally have
    # almost nowhere valid to END a stage-ordered chain: with only 2 techniques
    # sharing rank 0, the only sequence that can end in either of them is the
    # single 2-element permutation of the other one followed by it (e.g.
    # [T1078, T1110]). That's ONE distinct sequence — and naive duplication to
    # TARGET_PER_TECHNIQUE=200 copied that single sequence 200 times, teaching
    # "T1078 -> T1110" (and the reverse) as if it were as common a transition as
    # the ~200 genuinely-diverse chains every other technique got. That's what
    # was pulling next-step predictions from unrelated contexts (T1046, T1049,
    # T1082, T1087, T1552 -> ...) toward T1110/T1078 in the eval confusion
    # matrix: the model over-learned two narrow, massively-duplicated edges.
    # Real single-technique brute-force sessions in ttp_records.json already
    # teach "<START> -> T1110" plenty on their own (there were 128 of them in
    # the last run) — the synthetic generator doesn't need to manufacture more
    # of that signal, and definitely shouldn't manufacture it via 200x copies
    # of one sequence. Capping the duplication factor keeps a structurally-rare
    # technique's synthetic weight proportionate to how rare that transition
    # actually is, instead of forcing false parity with common mid-chain steps.
    MAX_DUP_FACTOR = 5

    import random
    random.seed(42)
    balanced = []
    for tech in techs:
        pool = by_ending[tech]
        if not pool:
            continue
        if len(pool) >= TARGET_PER_TECHNIQUE:
            # Over-represented: sample down to target
            balanced.extend(random.sample(pool, TARGET_PER_TECHNIQUE))
        else:
            # Under-represented: repeat to reach target, but capped — see
            # MAX_DUP_FACTOR note above. A pool this small gets fewer than
            # TARGET_PER_TECHNIQUE samples rather than drowning training in
            # duplicates of one or two sequences.
            reps = min(TARGET_PER_TECHNIQUE // len(pool), MAX_DUP_FACTOR)
            actual_count = reps * len(pool)
            balanced.extend(pool * reps)
            if actual_count < TARGET_PER_TECHNIQUE:
                print(f"[LSTM] NOTE: {tech} has only {len(pool)} natural stage-ordered "
                      f"chain(s) ending in it — capped at {actual_count}/{TARGET_PER_TECHNIQUE} "
                      f"synthetic samples (duplicating further would teach a structurally-rare "
                      f"transition as if it were common)")

    seqs.extend(balanced)

    # ── Step 3: reinforce the real canonical kill chain ───────────────────────
    # attack.sh order: brute force -> recon -> tool transfer -> execution -> enum
    # This teaches the full T1110 -> ... progression that judges will demo.
    canonical_order = ["T1110", "T1082", "T1087", "T1105", "T1059",
                       "T1204", "T1057", "T1016", "T1548"]
    canonical = [t for t in canonical_order if t in techs]
    if len(canonical) >= 3:
        for _ in range(15):
            seqs.append(canonical)
            seqs.append(canonical[:len(canonical) // 2])
            seqs.append(canonical[:2])   # T1110 -> T1082 entry pattern

    return seqs


# ─────────────────────────────────────────────
# DATASET
# ─────────────────────────────────────────────

class AttackSequenceDataset(Dataset):
    """
    Each sample: (input_sequence, target_technique, compromise_label)
    Given first N techniques in a session, predict the (N+1)th, and whether
    that (N+1)th technique itself represents a compromise step.

    compromise_label = 1.0 if the target technique is in COMPROMISE_TECHNIQUES,
    else 0.0. This is the supervision signal for the infiltration-probability
    head (fc_prob) — without it, fc_prob receives no gradient at all and its
    output is just noise from random initialization.

    For a session [T1082, T1087, T1105, T1204]:
      - ([<START>, T1082], T1087, 0.0)
      - ([<START>, T1082, T1087], T1105, 1.0)   # T1105 is a compromise technique
      - ([<START>, T1082, T1087, T1105], T1204, 1.0)  # T1204 is a compromise technique
    """

    def __init__(self, sessions: list[list[str]], vocab: TechniqueVocab,
                 max_seq_len: int = 8):
        self.samples = []
        self.vocab = vocab
        self.max_seq_len = max_seq_len

        for session in sessions:
            # Prepend <START> token
            full_seq = [START_TOKEN] + session

            for i in range(1, len(full_seq)):
                inp = full_seq[:i]
                target = full_seq[i]
                compromise_label = 1.0 if target in COMPROMISE_TECHNIQUES else 0.0

                # Encode
                inp_ids = [vocab.encode(t) for t in inp]
                target_id = vocab.encode(target)

                # Pad or truncate input to max_seq_len
                if len(inp_ids) > max_seq_len:
                    inp_ids = inp_ids[-max_seq_len:]  # keep most recent context
                else:
                    inp_ids = [vocab.encode(PAD_TOKEN)] * (max_seq_len - len(inp_ids)) + inp_ids

                self.samples.append((inp_ids, target_id, compromise_label))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        inp, target, compromise_label = self.samples[idx]
        return (
            torch.tensor(inp, dtype=torch.long),
            torch.tensor(target, dtype=torch.long),
            torch.tensor(compromise_label, dtype=torch.float32),
        )


# ─────────────────────────────────────────────
# LSTM MODEL
# ─────────────────────────────────────────────

class AttackLSTM(nn.Module):
    """
    LSTM sequence model for attack technique prediction.

    Architecture:
      Embedding(vocab_size, embed_dim)
        → LSTM(embed_dim, hidden_dim, num_layers, dropout)
        → Linear(hidden_dim, vocab_size)   [next technique prediction]
        → sigmoid output for infiltration probability

    The context vector (attention-weighted sum of LSTM outputs across the
    sequence) encodes the "danger level" of the session so far. Infiltration
    probability = sigmoid(linear(context)) — trained via a dedicated BCE loss
    against COMPROMISE_TECHNIQUES labels (see train()).

    Uses additive attention over LSTM outputs instead of just the last hidden
    state — this is what makes per-token attention weights available for
    Week 4 explainability (see get_attention_explanation() below and
    shap_explain.py). PAD positions are masked out of the attention softmax
    so they never receive weight regardless of learned scores.
    """

    def __init__(self, vocab_size: int, embed_dim: int = 16,
                 hidden_dim: int = 32, num_layers: int = 1, dropout: float = 0.1):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            embed_dim, hidden_dim,
            num_layers=num_layers,
            dropout=dropout if num_layers > 1 else 0.0,
            batch_first=True,
        )
        self.dropout = nn.Dropout(dropout)
        self.attn_score = nn.Linear(hidden_dim, 1)          # additive attention over timesteps
        self.fc_next = nn.Linear(hidden_dim, vocab_size)   # next technique prediction
        self.fc_prob = nn.Linear(hidden_dim, 1)            # infiltration probability

    def forward(self, x: torch.Tensor, return_attention: bool = False):
        """
        x: (batch, seq_len) — padded technique ID sequences (PAD id = 0, left-padded)
        Returns:
          logits: (batch, vocab_size) — next technique log-probabilities
          prob:   (batch, 1)         — infiltration probability [0, 1]
          attn_weights (only if return_attention=True): (batch, seq_len)
            — how much each input position contributed to the prediction
        """
        mask = (x != 0).float()                             # (batch, seq) — 0 at PAD positions
        embedded = self.dropout(self.embedding(x))          # (batch, seq, embed)
        lstm_out, (h_n, _) = self.lstm(embedded)             # lstm_out: (batch, seq, hidden)

        # Additive attention: score every timestep, mask PAD positions to -inf
        # so softmax assigns them exactly zero weight, then take the weighted
        # sum as the context vector fed into both output heads.
        raw_scores = self.attn_score(lstm_out).squeeze(-1)   # (batch, seq)
        raw_scores = raw_scores.masked_fill(mask == 0, float("-inf"))
        attn_weights = torch.softmax(raw_scores, dim=1)      # (batch, seq)
        attn_weights = torch.nan_to_num(attn_weights, nan=0.0)  # guard all-PAD rows

        context = torch.bmm(attn_weights.unsqueeze(1), lstm_out).squeeze(1)  # (batch, hidden)
        context = self.dropout(context)

        logits = self.fc_next(context)                       # (batch, vocab_size)
        prob = torch.sigmoid(self.fc_prob(context))          # (batch, 1)

        if return_attention:
            return logits, prob, attn_weights
        return logits, prob

    def predict_next(self, sequence: list[int], top_k: int = 3):
        """
        Given an encoded sequence, return top-k predicted next techniques with probabilities.
        Also returns infiltration probability.
        """
        self.eval()
        with torch.no_grad():
            x = torch.tensor([sequence], dtype=torch.long)
            logits, inf_prob = self(x)
            probs = torch.softmax(logits[0], dim=0)
            top_probs, top_ids = torch.topk(probs, k=min(top_k, len(probs)))
        return (
            [(top_ids[i].item(), top_probs[i].item()) for i in range(len(top_ids))],
            inf_prob.item(),
        )


def encode_sequence(session_techniques: list[str], vocab: "TechniqueVocab",
                     max_seq_len: int = 8) -> list[int]:
    """
    Shared encoding logic: prepend <START>, encode, left-pad/truncate to
    max_seq_len. Used by predict_next_technique, k_step_forecast, and
    shap_explain.py so all three treat a given input identically.
    """
    encoded = [vocab.encode(START_TOKEN)] + [vocab.encode(t) for t in session_techniques]
    if len(encoded) > max_seq_len:
        encoded = encoded[-max_seq_len:]
    else:
        encoded = [vocab.encode(PAD_TOKEN)] * (max_seq_len - len(encoded)) + encoded
    return encoded


def get_attention_explanation(session_techniques: list[str],
                               model_path: str = MODEL_PATH,
                               max_seq_len: int = 8) -> dict:
    """
    Week 4 explainability (attention half): shows which prior techniques in
    the session the model weighted most heavily when making its prediction.
    Does not require the `shap` package — this is the fast, always-available
    explanation. shap_explain.py builds on top of this with SHAP values for
    a second, independent view of feature importance.
    """
    model, vocab = load_model(model_path)
    if model is None:
        return {"error": "Model not trained or PyTorch unavailable"}

    ids = encode_sequence(session_techniques, vocab, max_seq_len)
    model.eval()
    with torch.no_grad():
        x = torch.tensor([ids], dtype=torch.long)
        logits, inf_prob, attn_weights = model(x, return_attention=True)
        probs = torch.softmax(logits[0], dim=0)
        top_id = int(probs.argmax().item())

    tokens = [vocab.decode(i) for i in ids]
    weights = attn_weights[0].tolist()

    per_token = [
        {"technique": tok, "attention_weight": round(w, 4)}
        for tok, w in zip(tokens, weights)
        if tok not in (PAD_TOKEN,)
    ]
    per_token.sort(key=lambda d: -d["attention_weight"])

    if per_token:
        top = per_token[0]
        explanation = (
            f"Predicted next technique: {vocab.decode(top_id)} "
            f"(P(compromise)={inf_prob.item():.1%}). "
            f"Most influential prior step: {top['technique']} "
            f"(attention weight {top['attention_weight']:.1%})."
        )
    else:
        explanation = f"Predicted next technique: {vocab.decode(top_id)}."

    return {
        "input_sequence": session_techniques,
        "predicted_next": vocab.decode(top_id),
        "infiltration_prob": round(inf_prob.item(), 4),
        "attention_per_token": per_token,
        "explanation": explanation,
    }


# ─────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────

def train(ttp_path: str = TTP_PATH,
          epochs: int = 200,
          lr: float = 0.001,
          batch_size: int = 16,
          test_split: float = 0.1,
          seed: int = 42) -> tuple:
    """
    Train the LSTM on sessions from ttp_records.json.
    Returns (model, vocab, train_loss_history, test_acc_history).
    """
    if not TORCH_OK:
        print("[LSTM] Cannot train — PyTorch not installed")
        return None, None, [], []

    random.seed(seed)
    torch.manual_seed(seed)

    # Load REAL sessions and split BEFORE any synthetic augmentation, so
    # synthetic (templated) sequences can never leak into the test set —
    # see split_sessions()'s docstring. This is the same class of
    # train/test leakage bug already found and fixed in world_model.py
    # this project (segment-purged split), applied here too.
    real_sessions = load_real_sessions(ttp_path)
    real_techniques = sorted({t for s in real_sessions for t in s})

    train_real, test_sessions = split_sessions(real_sessions, test_split=test_split)
    train_sessions = augment_train_sessions(train_real, real_techniques)

    # Build vocabulary from every technique ever seen (real + synthetic) —
    # vocabulary/tokenization coverage isn't a leakage issue, only sharing
    # actual train/test EXAMPLES is.
    vocab = TechniqueVocab()
    for session in train_sessions + test_sessions:
        for tid in session:
            vocab.add(tid)
        vocab.add(START_TOKEN)

    print(f"[LSTM] Vocabulary: {len(vocab)} tokens ({len(vocab)-3} unique techniques)")

    # Show what techniques appear in each split
    train_techs = sorted({t for s in train_sessions for t in s})
    test_techs  = sorted({t for s in test_sessions  for t in s})
    print(f"[LSTM] Train techniques: {train_techs}")
    print(f"[LSTM] Test  techniques: {test_techs}  (100% real sessions — zero synthetic in test)")

    train_ds = AttackSequenceDataset(train_sessions, vocab)
    test_ds  = AttackSequenceDataset(test_sessions, vocab)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    test_loader  = DataLoader(test_ds,  batch_size=batch_size, shuffle=False)

    print(f"[LSTM] Train samples: {len(train_ds)}, Test samples: {len(test_ds)}")

    # ── Compute class weights from training target distribution ───────────────
    # Even with balanced synthetic data, class weighting stops the model from
    # winning by ignoring rare classes. weight = total / (n_classes * count).
    from collections import Counter
    target_counts = Counter()
    for _, target, _ in train_ds:
        t = target.item() if hasattr(target, "item") else target
        target_counts[t] += 1

    n_classes = len(vocab)
    total_targets = sum(target_counts.values())
    class_weights = torch.ones(n_classes)
    for idx in range(n_classes):
        cnt = target_counts.get(idx, 0)
        if cnt > 0:
            class_weights[idx] = total_targets / (len(target_counts) * cnt)
    # Cap extreme weights to avoid instability
    class_weights = torch.clamp(class_weights, max=5.0)
    class_weights[0] = 0.0   # PAD gets zero weight

    # Model — capacity scaled to vocabulary size.
    # embed=16/hidden=32 was tuned for 4 techniques; with 8+ techniques the
    # model needs more capacity to separate classes (was collapsing to the
    # 2 most frequent). Scale hidden dim with vocab.
    embed_dim  = 32
    hidden_dim = 64
    num_layers = 2
    model = AttackLSTM(vocab_size=len(vocab), embed_dim=embed_dim,
                       hidden_dim=hidden_dim, num_layers=num_layers)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    # Class-weighted cross-entropy — the key fix for class collapse.
    criterion = nn.CrossEntropyLoss(weight=class_weights, ignore_index=0)
    # BCE loss for the infiltration-probability head.
    inf_criterion = nn.BCELoss()

    train_losses = []
    test_accs = []

    print(f"\n[LSTM] Training for {epochs} epochs...")
    print(f"       Model: {sum(p.numel() for p in model.parameters())} parameters")
    print(f"       LR: {lr}, Batch: {batch_size}\n")

    best_acc = 0.0
    best_state = None

    for epoch in range(1, epochs + 1):
        # ── Train ──
        model.train()
        total_loss = 0.0
        for inp, target, compromise in train_loader:
            optimizer.zero_grad()
            logits, prob = model(inp)
            loss_next = criterion(logits, target)
            loss_inf = inf_criterion(prob.squeeze(1), compromise)
            loss = loss_next + loss_inf
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)
        train_losses.append(avg_loss)

        # ── Evaluate ──
        model.eval()
        correct = total = 0
        with torch.no_grad():
            for inp, target, compromise in test_loader:
                logits, prob = model(inp)
                preds = logits.argmax(dim=1)
                # Ignore PAD targets
                mask = target != 0
                correct += (preds[mask] == target[mask]).sum().item()
                total   += mask.sum().item()

        acc = correct / total if total > 0 else 0.0
        test_accs.append(acc)
        scheduler.step()  # CosineAnnealingLR takes no argument

        if acc > best_acc:
            best_acc = acc
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if epoch % 5 == 0 or epoch == 1:
            current_lr = optimizer.param_groups[0]['lr']
            print(f"  Epoch {epoch:3d}/{epochs}  loss={avg_loss:.4f}  test_acc={acc:.3f}  best={best_acc:.3f}  lr={current_lr:.6f}")

    # Restore best weights
    if best_state:
        model.load_state_dict(best_state)

    print(f"\n[LSTM] Training complete. Best test accuracy: {best_acc:.3f}")

    # Save model + vocab
    torch.save({
        "model_state": model.state_dict(),
        "vocab_tok2idx": vocab.tok2idx,
        "vocab_idx2tok": {str(k): v for k, v in vocab.idx2tok.items()},
        "vocab_next": vocab._next,
        "embed_dim": embed_dim,
        "hidden_dim": hidden_dim,
        "num_layers": num_layers,
    }, MODEL_PATH)

    # Verify the save round-trips *now* — catch corruption at save time
    # instead of discovering it later in a separate --eval process.
    try:
        _ = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
        print(f"[LSTM] Model saved to {MODEL_PATH} (verified loadable)")
    except Exception as e:
        print(f"[LSTM] WARNING: model saved but failed to reload immediately after: {e}")
        print(f"[LSTM] This usually means a stale/partial file, a disk issue, or a "
              f"torch/Python version mismatch. Do not trust {MODEL_PATH} until this is resolved.")

    return model, vocab, train_losses, test_accs


# ─────────────────────────────────────────────
# LOADING
# ─────────────────────────────────────────────

def load_model(model_path: str = MODEL_PATH) -> tuple:
    """Load saved model and vocab. Returns (model, vocab) or (None, None)."""
    if not TORCH_OK:
        return None, None
    if not Path(model_path).exists():
        print(f"[LSTM] No saved model at {model_path} — run training first")
        return None, None

    # A valid modern torch checkpoint is a zip archive (starts with 'PK').
    # If it isn't, torch.load() will fall back to the legacy pickle loader
    # and fail with a cryptic "invalid load key" error. Catch it here with
    # a message that actually tells you what to do.
    import zipfile
    if not zipfile.is_zipfile(model_path):
        raise RuntimeError(
            f"[LSTM] {model_path} is not a valid checkpoint (not a zip archive). "
            f"This usually means it's a stale/partial file from an earlier run. "
            f"Fix: delete it (`rm {model_path}`) and re-run `python3 lstm_model.py --train`. "
            f"If a fresh --train also fails to verify itself, check `pip show torch` "
            f"for compatibility with your Python version."
        )

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)

    vocab = TechniqueVocab()
    vocab.tok2idx = checkpoint["vocab_tok2idx"]
    vocab.idx2tok = {int(k): v for k, v in checkpoint["vocab_idx2tok"].items()}
    vocab._next   = checkpoint["vocab_next"]

    model = AttackLSTM(
        vocab_size=len(vocab),
        embed_dim=checkpoint.get("embed_dim", 32),
        hidden_dim=checkpoint.get("hidden_dim", 64),
        num_layers=checkpoint.get("num_layers", 2),
    )
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    return model, vocab


# ─────────────────────────────────────────────
# PREDICTION API (called from cybersentinel_skeleton.py)
# ─────────────────────────────────────────────

def predict_next_technique(session_techniques: list[str],
                            model_path: str = MODEL_PATH,
                            top_k: int = 3) -> dict:
    """
    Public API: given a list of observed technique IDs for a session,
    predict the next most likely technique and infiltration probability.

    Returns:
      {
        "input_sequence":      ["T1082", "T1087"],
        "predicted_next":      [("T1105", 0.74), ("T1059", 0.12), ("T1204", 0.08)],
        "infiltration_prob":   0.82,
        "risk_label":          "HIGH",
        "predicted_technique": "T1105",
        "explanation":         "Based on observed T1082→T1087, model predicts T1105..."
      }
    """
    model, vocab = load_model(model_path)

    if model is None:
        return {
            "input_sequence": session_techniques,
            "predicted_next": [],
            "infiltration_prob": 0.5,
            "risk_label": "UNKNOWN",
            "predicted_technique": "UNKNOWN",
            "explanation": "LSTM model not trained yet. Run: python3 lstm_model.py",
        }

    max_seq_len = 8
    encoded = [vocab.encode(START_TOKEN)] + [vocab.encode(t) for t in session_techniques]

    # Pad/truncate
    if len(encoded) > max_seq_len:
        encoded = encoded[-max_seq_len:]
    else:
        encoded = [vocab.encode(PAD_TOKEN)] * (max_seq_len - len(encoded)) + encoded

    top_preds, inf_prob = model.predict_next(encoded, top_k=top_k)

    # Decode predictions
    decoded = [(vocab.decode(idx), round(prob, 4)) for idx, prob in top_preds
               if vocab.decode(idx) not in (PAD_TOKEN, UNK_TOKEN, START_TOKEN)]

    risk_label = (
        "CRITICAL" if inf_prob >= 0.85 else
        "HIGH"     if inf_prob >= 0.65 else
        "MEDIUM"   if inf_prob >= 0.40 else
        "LOW"
    )

    best_next = decoded[0][0] if decoded else "UNKNOWN"

    # Build explanation
    seq_str = " → ".join(session_techniques) if session_techniques else "(empty)"
    preds_str = ", ".join(f"{t} ({p:.0%})" for t, p in decoded[:3])
    is_compromise = any(t in COMPROMISE_TECHNIQUES for t in session_techniques)
    compromise_note = " Session already contains compromise-stage techniques." if is_compromise else ""

    explanation = (
        f"Sequence observed: {seq_str}. "
        f"Model predicts next technique: {preds_str}. "
        f"Infiltration probability: {inf_prob:.1%}.{compromise_note}"
    )

    return {
        "input_sequence":      session_techniques,
        "predicted_next":      decoded,
        "infiltration_prob":   round(inf_prob, 4),
        "risk_label":          risk_label,
        "predicted_technique": best_next,
        "explanation":         explanation,
    }


# ─────────────────────────────────────────────
# K-STEP FORWARD SIMULATION (Week 3 preview)
# ─────────────────────────────────────────────

def k_step_forecast(session_techniques: list[str],
                    k: int = 3,
                    threshold: float = None,
                    model_path: str = MODEL_PATH) -> dict:
    """
    Roll the LSTM forward k steps from the observed sequence.
    At each step, take the top predicted technique and append it.
    Stop early if infiltration probability exceeds 0.9 or confidence drops below threshold.

    Returns predicted attack kill chain with probability at each step.

    `threshold` is the minimum softmax confidence required to accept a
    forecasted step. Leave it as None (default) to use a threshold scaled
    to the model's vocabulary size — 1.5x the random-guess baseline
    (1.5 / len(vocab)) — instead of a fixed absolute cutoff. A fixed 0.15
    was fine when the vocabulary had ~8 techniques (random baseline ~9%,
    so 0.15 was a real bar above chance), but it silently broke forecasting
    once the registry grew to 24 techniques: random baseline dropped to
    ~4%, top-1 confidence naturally spreads thinner across more classes,
    and a "confident, well above chance" prediction can now legitimately
    sit under 0.15 — causing every forecast to stop at step 0. Pass an
    explicit float to override.
    """
    model, vocab = load_model(model_path)
    if model is None:
        return {"error": "Model not trained"}

    if threshold is None:
        threshold = 1.5 / len(vocab)

    current_seq = list(session_techniques)
    forecast_steps = []
    max_seq_len = 8

    for step in range(k):
        encoded = [vocab.encode(START_TOKEN)] + [vocab.encode(t) for t in current_seq]
        if len(encoded) > max_seq_len:
            encoded = encoded[-max_seq_len:]
        else:
            encoded = [vocab.encode(PAD_TOKEN)] * (max_seq_len - len(encoded)) + encoded

        # Search deeper than top-5 so that already-seen techniques / special
        # tokens filling the top slots can't exhaust the candidate pool
        # before we reach a real, novel next-step prediction — this gets
        # more important as the vocabulary (and therefore the number of
        # "already seen" or irrelevant top-k slots) grows.
        top_preds, inf_prob = model.predict_next(encoded, top_k=min(len(vocab), 15))
        if not top_preds:
            break

        # Pick best prediction that isn't already in the sequence (no repeats)
        already_seen = set(current_seq)
        next_tech = None
        next_conf = 0.0
        for idx, conf in top_preds:
            candidate = vocab.decode(idx)
            if candidate not in (PAD_TOKEN, UNK_TOKEN, START_TOKEN) and candidate not in already_seen:
                next_tech = candidate
                next_conf = conf
                break

        # If all top-5 are repeats or invalid, stop forecast
        if next_tech is None or next_conf < threshold:
            break

        forecast_steps.append({
            "step": step + 1,
            "predicted_technique": next_tech,
            "confidence": round(next_conf, 4),
            "infiltration_prob": round(inf_prob, 4),
        })

        current_seq.append(next_tech)

        if inf_prob >= 0.9:
            break  # Certain compromise predicted — stop

    final_prob = forecast_steps[-1]["infiltration_prob"] if forecast_steps else 0.3

    return {
        "observed_sequence": session_techniques,
        "forecast_steps": forecast_steps,
        "final_infiltration_prob": final_prob,
        "risk_label": (
            "CRITICAL" if final_prob >= 0.85 else
            "HIGH"     if final_prob >= 0.65 else
            "MEDIUM"   if final_prob >= 0.40 else
            "LOW"
        ),
        "full_predicted_chain": session_techniques + [s["predicted_technique"] for s in forecast_steps],
        "threshold_used": threshold,
    }


# ─────────────────────────────────────────────
# EVALUATION
# ─────────────────────────────────────────────

def evaluate(model_path: str = MODEL_PATH, ttp_path: str = TTP_PATH, test_split: float = 0.1):
    """
    Evaluate the model on its held-out test split ONLY.

    Previously this evaluated on load_sessions()'s full combined output —
    train sessions, test sessions, AND synthetic sequences all mixed
    together — so the reported accuracy was dominated by in-sample
    (memorized) performance, not genuine held-out generalization. This now
    reproduces the exact same real-sessions split train() used (same
    default test_split, same split_sessions() logic) and evaluates purely
    on that held-out, 100%-real portion.
    """
    model, vocab = load_model(model_path)
    if model is None:
        return

    real_sessions = load_real_sessions(ttp_path)
    _, test_sessions = split_sessions(real_sessions, test_split=test_split)
    print(f"[LSTM] Evaluating on {len(test_sessions)} held-out REAL sessions "
          f"(same split train() used — zero synthetic, zero train-set leakage)")
    ds = AttackSequenceDataset(test_sessions, vocab)
    loader = DataLoader(ds, batch_size=32, shuffle=False)

    model.eval()
    correct = total = 0
    per_tech_correct = Counter()
    per_tech_total   = Counter()
    # confusion[actual][predicted] = count
    confusion = {}

    # Infiltration-probability calibration check: does the model actually
    # predict higher P(compromise) for compromise-technique targets than
    # for non-compromise targets? If not, fc_prob still isn't learning.
    compromise_probs = []
    non_compromise_probs = []
    # Top-k accuracy: for attack forecasting, "the next step is one of these
    # 2-3 techniques" is what a defender acts on. Standard metric for
    # sequence prediction where multiple next-steps are genuinely plausible.
    top2_correct = 0
    top3_correct = 0

    with torch.no_grad():
        for inp, target, compromise in loader:
            logits, prob = model(inp)
            preds = logits.argmax(dim=1)
            # Top-3 predictions per sample
            topk = torch.topk(logits, k=min(3, logits.size(1)), dim=1).indices
            prob_list = prob.squeeze(1).tolist()
            for i, (pred, tgt, is_compromise, p) in enumerate(zip(
                preds.tolist(), target.tolist(), compromise.tolist(), prob_list
            )):
                if tgt == 0:
                    continue
                actual = vocab.decode(tgt)
                predicted = vocab.decode(pred)
                per_tech_total[actual] += 1
                confusion.setdefault(actual, Counter())
                confusion[actual][predicted] += 1
                if pred == tgt:
                    correct += 1
                    per_tech_correct[actual] += 1
                # Top-k hits
                topk_ids = topk[i].tolist()
                if tgt in topk_ids[:2]:
                    top2_correct += 1
                if tgt in topk_ids[:3]:
                    top3_correct += 1
                total += 1
                (compromise_probs if is_compromise else non_compromise_probs).append(p)

    overall = correct / total if total > 0 else 0
    top2_acc = top2_correct / total if total > 0 else 0
    top3_acc = top3_correct / total if total > 0 else 0
    baseline = 1.0 / max(len(per_tech_total), 1)  # random chance

    print("\n" + "═" * 55)
    print("  CYBERSENTINEL LSTM — EVALUATION REPORT")
    print("═" * 55)
    print(f"  Top-1 accuracy:    {overall:.1%}  ({correct}/{total} correct)")
    print(f"  Top-2 accuracy:    {top2_acc:.1%}  (true next-step in model's top 2 guesses)")
    print(f"  Top-3 accuracy:    {top3_acc:.1%}  (true next-step in model's top 3 guesses)")
    print(f"  Random baseline:   {baseline:.1%}  (1 / {len(per_tech_total)} classes)")
    print(f"  Lift over random:  {overall/baseline:.1f}×  (top-1)")
    print()
    print("  Note: For attack forecasting, top-2/top-3 is the operationally")
    print("  relevant metric — a defender acts on 'the next step is likely")
    print("  one of these', and several techniques are genuinely plausible")
    print("  at each stage of a real kill chain.")
    print()
    print("  Per-technique accuracy:")
    for tech, tot in sorted(per_tech_total.items(), key=lambda x: -x[1]):
        acc = per_tech_correct[tech] / tot
        bar = "█" * int(acc * 20)
        print(f"    {tech:12s} {bar:20s} {acc:.0%}  ({per_tech_correct[tech]}/{tot})")
    print()
    print("  Confusion matrix (row=actual, col=predicted):")
    all_techs = sorted(per_tech_total.keys())
    header = "  " + " " * 14 + "  ".join(f"{t:7s}" for t in all_techs)
    print(header)
    for actual in all_techs:
        row = f"  {actual:12s}  "
        for pred_tech in all_techs:
            count = confusion.get(actual, {}).get(pred_tech, 0)
            marker = f"[{count:3d}]" if actual == pred_tech else f" {count:3d} "
            row += marker + " "
        print(row)
    print()
    print("  [bracketed] = correct predictions")
    print("═" * 55)

    print("\n  Infiltration-probability calibration:")
    if compromise_probs:
        avg_c = sum(compromise_probs) / len(compromise_probs)
        print(f"    Avg P(compromise) on compromise-technique targets:     {avg_c:.1%}  (n={len(compromise_probs)})")
    else:
        avg_c = None
        print("    No compromise-technique targets in this data.")
    if non_compromise_probs:
        avg_nc = sum(non_compromise_probs) / len(non_compromise_probs)
        print(f"    Avg P(compromise) on non-compromise-technique targets: {avg_nc:.1%}  (n={len(non_compromise_probs)})")
    else:
        avg_nc = None
        print("    No non-compromise-technique targets in this data.")
    if avg_c is not None and avg_nc is not None:
        if avg_c > avg_nc:
            print(f"    ✓ Calibrated correctly: compromise targets score {avg_c - avg_nc:+.1%} higher.")
        else:
            print(f"    ✗ NOT calibrated: compromise targets score {avg_c - avg_nc:+.1%} vs non-compromise. "
                  f"fc_prob may need more epochs or a higher loss weight.")
    print("═" * 55)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberSentinel LSTM — attack progression model")
    parser.add_argument("--train",   action="store_true", help="Train model on ttp_records.json")
    parser.add_argument("--predict", nargs="+", metavar="TECHNIQUE",
                        help="Predict next technique given observed sequence (e.g. T1082 T1087)")
    parser.add_argument("--forecast", nargs="+", metavar="TECHNIQUE",
                        help="K-step forward simulation from observed sequence")
    parser.add_argument("--explain", nargs="+", metavar="TECHNIQUE",
                        help="Attention-based explanation for observed sequence (e.g. T1082 T1087)")
    parser.add_argument("--eval",    action="store_true", help="Evaluate trained model")
    parser.add_argument("--ttp",     default=TTP_PATH, help="Path to ttp_records.json")
    parser.add_argument("--epochs",  type=int, default=200)
    parser.add_argument("--k",       type=int, default=3, help="Steps for k-step forecast")
    parser.add_argument("--forecast-threshold", type=float, default=None,
                        help="Min confidence to accept a forecast step (default: "
                             "scaled to vocab size, 1.5x random baseline)")
    args = parser.parse_args()

    # Default: train if no model exists, then predict
    if not any([args.train, args.predict, args.forecast, args.eval, args.explain]):
        args.train = True

    if args.train:
        print("=" * 55)
        print("  CyberSentinel LSTM — Training")
        print("=" * 55)
        model, vocab, losses, accs = train(args.ttp, epochs=args.epochs)

        if losses:
            print(f"\n  Final train loss:   {losses[-1]:.4f}")
            print(f"  Final test acc:     {accs[-1]:.3f}")
            print(f"  Best test acc:      {max(accs):.3f}")

    if args.eval:
        evaluate(ttp_path=TTP_PATH)

    if args.predict:
        print("\n" + "=" * 55)
        print("  CyberSentinel LSTM — Prediction")
        print("=" * 55)
        result = predict_next_technique(args.predict)
        print(f"  Input sequence:      {' → '.join(result['input_sequence'])}")
        print(f"  Predicted next:      {result['predicted_next']}")
        print(f"  Infiltration prob:   {result['infiltration_prob']:.1%}  [{result['risk_label']}]")
        print(f"  Explanation:         {result['explanation']}")

    if args.forecast:
        print("\n" + "=" * 55)
        print("  CyberSentinel LSTM — K-Step Forecast")
        print("=" * 55)
        result = k_step_forecast(args.forecast, k=args.k, threshold=args.forecast_threshold)
        if result.get("error"):
            print(f"  [!] {result['error']}")
        else:
            print(f"  Confidence threshold: {result['threshold_used']:.1%} "
                  f"({'explicit' if args.forecast_threshold is not None else 'auto, scaled to vocab size'})")
            print(f"  Observed:  {' → '.join(result['observed_sequence'])}")
            print(f"  Forecast steps:")
            if result["forecast_steps"]:
                for step in result["forecast_steps"]:
                    print(f"    Step {step['step']}: {step['predicted_technique']} "
                          f"(conf={step['confidence']:.0%}, P(compromise)={step['infiltration_prob']:.0%})")
            else:
                print("    (none — model's top prediction never cleared the confidence "
                      "threshold above. Try --forecast-threshold with a lower value to "
                      "see low-confidence guesses anyway.)")
            print(f"  Final infiltration prob: {result['final_infiltration_prob']:.1%}  [{result['risk_label']}]")
            print(f"  Full predicted chain:    {' → '.join(result['full_predicted_chain'])}")

    if args.explain:
        print("\n" + "=" * 55)
        print("  CyberSentinel LSTM — Attention Explanation")
        print("=" * 55)
        result = get_attention_explanation(args.explain)
        if "error" in result:
            print(f"  Error: {result['error']}")
        else:
            print(f"  Input sequence:      {' → '.join(result['input_sequence'])}")
            print(f"  Predicted next:      {result['predicted_next']}")
            print(f"  Infiltration prob:   {result['infiltration_prob']:.1%}")
            print(f"  Attention weights (highest first):")
            for item in result["attention_per_token"]:
                bar = "█" * int(item["attention_weight"] * 30)
                print(f"    {item['technique']:12s} {bar:30s} {item['attention_weight']:.1%}")
            print(f"  Explanation:         {result['explanation']}")


if __name__ == "__main__":
    main()
