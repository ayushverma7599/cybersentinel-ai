"""
CyberSentinel v3 — multi-head attack forecaster / classifier.

Given a sequence of behavioural events it predicts:
  * technique   — the likely next MITRE ATT&CK technique (forecasting head)
  * class       — high-level attack class (ransomware / apt / botnet / ...)
  * family      — malware family
  * severity    — 0..1 damage estimate (regression)

Architecture: heterogeneous feature encoder -> bidirectional LSTM ->
multi-head self-attention -> masked mean pool -> task heads.
"""

from __future__ import annotations

import torch
import torch.nn as nn

import config as C
from dataset import TECH_PAD, TACTIC_PAD, PROTO_PAD


class FeatureEncoder(nn.Module):
    """Encode one event (categoricals + numeric + boolean) into a vector."""

    def __init__(self):
        super().__init__()
        self.tech_emb = nn.Embedding(C.NUM_TECHNIQUES + 1, C.HP.technique_emb,
                                     padding_idx=TECH_PAD)
        self.tac_emb = nn.Embedding(C.NUM_TACTICS + 1, C.HP.tactic_emb,
                                    padding_idx=TACTIC_PAD)
        self.proto_emb = nn.Embedding(C.NUM_PROTOCOLS + 1, C.HP.protocol_emb,
                                      padding_idx=PROTO_PAD)
        self.numeric_proj = nn.Sequential(
            nn.Linear(C.NUM_NUMERIC, C.HP.numeric_proj),
            nn.ReLU(),
            nn.LayerNorm(C.HP.numeric_proj),
        )
        self.boolean_proj = nn.Linear(C.NUM_BOOLEAN, C.HP.boolean_proj)

        self.out_dim = (C.HP.technique_emb + C.HP.tactic_emb +
                        C.HP.protocol_emb + C.HP.numeric_proj +
                        C.HP.boolean_proj)

    def forward(self, tech, tac, proto, numeric, boolean):
        parts = [
            self.tech_emb(tech),
            self.tac_emb(tac),
            self.proto_emb(proto),
            self.numeric_proj(numeric),
            self.boolean_proj(boolean),
        ]
        return torch.cat(parts, dim=-1)          # [B, L, out_dim]


class CyberSentinelV3(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = FeatureEncoder()
        lstm_out = C.HP.lstm_hidden * (2 if C.HP.bidirectional else 1)

        self.lstm = nn.LSTM(
            input_size=self.encoder.out_dim,
            hidden_size=C.HP.lstm_hidden,
            num_layers=C.HP.lstm_layers,
            batch_first=True,
            dropout=C.HP.dropout if C.HP.lstm_layers > 1 else 0.0,
            bidirectional=C.HP.bidirectional,
        )
        self.attention = nn.MultiheadAttention(
            embed_dim=lstm_out, num_heads=C.HP.attn_heads,
            dropout=0.1, batch_first=True,
        )
        self.norm = nn.LayerNorm(lstm_out)

        def head(out):
            return nn.Sequential(
                nn.Linear(lstm_out, lstm_out // 2),
                nn.GELU(),
                nn.Dropout(C.HP.dropout),
                nn.Linear(lstm_out // 2, out),
            )

        self.technique_head = head(C.NUM_TECHNIQUES)
        self.class_head = head(C.NUM_ATTACK_CLASSES)
        self.family_head = head(C.NUM_FAMILIES)
        self.severity_head = nn.Sequential(
            nn.Linear(lstm_out, 64), nn.GELU(),
            nn.Linear(64, 1), nn.Sigmoid(),
        )

    def forward(self, tech, tac, proto, numeric, boolean, mask):
        x = self.encoder(tech, tac, proto, numeric, boolean)   # [B,L,D]
        lstm_out, _ = self.lstm(x)                             # [B,L,H]

        pad = mask < 0.5                                       # True where pad
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out,
                                     key_padding_mask=pad)
        attn_out = self.norm(attn_out + lstm_out)

        # masked mean pool over valid timesteps
        m = mask.unsqueeze(-1)                                 # [B,L,1]
        summed = (attn_out * m).sum(dim=1)
        denom = m.sum(dim=1).clamp(min=1.0)
        context = summed / denom                               # [B,H]

        return {
            "technique": self.technique_head(context),
            "class": self.class_head(context),
            "family": self.family_head(context),
            "severity": self.severity_head(context).squeeze(-1),
        }


def hierarchical_loss(preds, targets, technique_weight=None):
    ce_tech = nn.CrossEntropyLoss(weight=technique_weight,
                                  label_smoothing=C.HP.label_smoothing)
    ce = nn.CrossEntropyLoss()
    mse = nn.MSELoss()

    l_tech = ce_tech(preds["technique"], targets["y_tech"])
    l_class = ce(preds["class"], targets["y_class"])
    l_family = ce(preds["family"], targets["y_family"])
    l_sev = mse(preds["severity"], targets["y_sev"])

    total = (C.HP.w_technique * l_tech +
             C.HP.w_class * l_class +
             C.HP.w_family * l_family +
             C.HP.w_severity * l_sev)
    parts = {"technique": l_tech.item(), "class": l_class.item(),
             "family": l_family.item(), "severity": l_sev.item()}
    return total, parts


if __name__ == "__main__":
    B, L = 4, C.HP.max_seq_len
    m = CyberSentinelV3()
    dummy = {
        "tech": torch.randint(0, C.NUM_TECHNIQUES, (B, L)),
        "tac": torch.randint(0, C.NUM_TACTICS, (B, L)),
        "proto": torch.randint(0, C.NUM_PROTOCOLS, (B, L)),
        "numeric": torch.rand(B, L, C.NUM_NUMERIC),
        "boolean": torch.randint(0, 2, (B, L, C.NUM_BOOLEAN)).float(),
        "mask": torch.ones(B, L),
    }
    out = m(dummy["tech"], dummy["tac"], dummy["proto"],
            dummy["numeric"], dummy["boolean"], dummy["mask"])
    for k, v in out.items():
        print(k, tuple(v.shape))
    total = sum(p.numel() for p in m.parameters())
    print("params:", f"{total:,}")
