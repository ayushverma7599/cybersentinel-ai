"""
Turn Session objects into padded, batched tensors.

Task framing (matches the original tool's evaluation semantics):
  * input   = all events in a session except the last
  * target  = the technique of the LAST event  (next-step forecasting)
  * plus session-level targets: attack class, malware family, severity

build_arrays() is pure NumPy so it can be validated without torch.
CyberDataset / make_loaders() add the thin torch layer.
"""

from __future__ import annotations

from collections import Counter

import numpy as np

import config as C
import features as F

# Reserved padding indices (one past the real vocabulary).
TECH_PAD = C.NUM_TECHNIQUES
TACTIC_PAD = C.NUM_TACTICS
PROTO_PAD = C.NUM_PROTOCOLS


def build_arrays(sessions) -> dict:
    L = C.HP.max_seq_len
    N = len(sessions)

    tech = np.full((N, L), TECH_PAD, dtype=np.int64)
    tac = np.full((N, L), TACTIC_PAD, dtype=np.int64)
    proto = np.full((N, L), PROTO_PAD, dtype=np.int64)
    numeric = np.zeros((N, L, C.NUM_NUMERIC), dtype=np.float32)
    boolean = np.zeros((N, L, C.NUM_BOOLEAN), dtype=np.float32)
    mask = np.zeros((N, L), dtype=np.float32)

    y_tech = np.zeros((N,), dtype=np.int64)
    y_class = np.zeros((N,), dtype=np.int64)
    y_family = np.zeros((N,), dtype=np.int64)
    y_sev = np.zeros((N,), dtype=np.float32)

    for i, s in enumerate(sessions):
        if len(s.events) < 2:
            continue
        inp, last = s.events[:-1], s.events[-1]
        inp = inp[:L]
        for j, ev in enumerate(inp):
            enc = F.encode_event(ev)
            tech[i, j] = enc["technique"]
            tac[i, j] = enc["tactic"]
            proto[i, j] = enc["protocol"]
            numeric[i, j] = enc["numeric"]
            boolean[i, j] = enc["boolean"]
            mask[i, j] = 1.0

        y_tech[i] = F.TECH2IDX[last["technique"]]
        y_class[i] = F.CLASS2IDX[s.attack_class]
        y_family[i] = F.FAMILY2IDX[s.family]
        y_sev[i] = s.severity

    return {
        "tech": tech, "tactic": tac, "protocol": proto,
        "numeric": numeric, "boolean": boolean, "mask": mask,
        "y_tech": y_tech, "y_class": y_class,
        "y_family": y_family, "y_sev": y_sev,
    }


def technique_class_weights(y_tech: np.ndarray) -> np.ndarray:
    """Inverse-frequency weights over the technique target, for the loss."""
    counts = Counter(int(v) for v in y_tech)
    w = np.ones(C.NUM_TECHNIQUES, dtype=np.float32)
    for k in range(C.NUM_TECHNIQUES):
        c = counts.get(k, 0)
        w[k] = 1.0 / c if c > 0 else 0.0
    # normalise so mean weight ~= 1 (keeps loss scale stable)
    nz = w[w > 0]
    if len(nz):
        w = w / nz.mean()
    return w


def sample_weights_for_balancing(y_tech: np.ndarray) -> np.ndarray:
    """Per-sample weights for a WeightedRandomSampler (balances techniques)."""
    counts = Counter(int(v) for v in y_tech)
    return np.array([1.0 / counts[int(v)] for v in y_tech], dtype=np.float64)


# --------------------------------------------------------------------------
# torch layer (imported lazily so build_arrays works without torch installed)
# --------------------------------------------------------------------------
def make_loaders(sessions, val_frac: float = 0.2, seed: int = 0):
    import torch
    from torch.utils.data import TensorDataset, DataLoader, WeightedRandomSampler

    arr = build_arrays(sessions)
    N = len(sessions)
    rng = np.random.default_rng(seed)
    idx = rng.permutation(N)
    n_val = int(N * val_frac)
    val_idx, tr_idx = idx[:n_val], idx[n_val:]

    def subset(keys_idx):
        return TensorDataset(
            torch.tensor(arr["tech"][keys_idx]),
            torch.tensor(arr["tactic"][keys_idx]),
            torch.tensor(arr["protocol"][keys_idx]),
            torch.tensor(arr["numeric"][keys_idx]),
            torch.tensor(arr["boolean"][keys_idx]),
            torch.tensor(arr["mask"][keys_idx]),
            torch.tensor(arr["y_tech"][keys_idx]),
            torch.tensor(arr["y_class"][keys_idx]),
            torch.tensor(arr["y_family"][keys_idx]),
            torch.tensor(arr["y_sev"][keys_idx]),
        )

    train_ds, val_ds = subset(tr_idx), subset(val_idx)

    sw = sample_weights_for_balancing(arr["y_tech"][tr_idx])
    sampler = WeightedRandomSampler(torch.tensor(sw), num_samples=len(sw),
                                    replacement=True)

    train_loader = DataLoader(train_ds, batch_size=C.HP.batch_size,
                              sampler=sampler)
    val_loader = DataLoader(val_ds, batch_size=C.HP.batch_size, shuffle=False)

    class_w = torch.tensor(technique_class_weights(arr["y_tech"][tr_idx]))
    return train_loader, val_loader, class_w


if __name__ == "__main__":
    import synthetic_data as S
    ds = S.build_dataset(n_sessions=200)
    a = build_arrays(ds)
    for k, v in a.items():
        print(f"{k:10s} shape={v.shape} dtype={v.dtype}")
    print("technique weight vector shape:", technique_class_weights(a["y_tech"]).shape)
    print("sample weights (first 5):", sample_weights_for_balancing(a["y_tech"])[:5])
