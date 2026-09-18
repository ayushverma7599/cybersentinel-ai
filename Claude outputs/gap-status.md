# Cyber Sentinel AI (SIH26153) — Gap Status

_Last updated: 2026-09-15_

This tracks what's been validated and fixed in the Cowrie honeypot + MITRE ATT&CK TTP extraction + multi-agent CVE/config scanner + LSTM "World Model" forecasting pipeline, against the SIH26153 problem statement's requirements. It reflects the current state of the code on the Kali machine (`~/honeypot`) and the most recent training/benchmark/generalization runs.

## Resolved this session

**Real packet-level features are now actually used by the model.** `scapy_feature_extractor.py`'s output field names (`ttl_variance`, `payload_size_max`, `distinct_dst_ports_from_src`) didn't match what `world_model.py`'s `FEATURE_COLS` expected (`ttl_std`, `payload_size_std`, `unique_dst_ports`), so real captured values for those columns were silently discarded even for genuinely-captured packet data. Fixed by adding correctly-named fields alongside the originals and propagating them through the merge step. `port_scan_score` was completely unpopulated across the entire dataset — it was redefined as a genuinely-measurable connection-frequency signal (distinct flows per client IP, saturating at 20) rather than a per-port signal the single-port capture filter architecturally cannot observe.

**A feature-circularity validity problem was found and addressed.** The honeypot-only dataset had several input features (`syn_ratio`, `ack_ratio`, TCP-flag values) hardcoded by the same login-attempt logic that also set the label, making the pre-fix benchmark's near-perfect scores (F1=0.996, FPR=0.000) largely circular rather than learned. Addressed by integrating the full CIC-IDS-2018 10-day public dataset (47,911 combined rows: 1 honeypot segment + 10 CIC-IDS-2018 days) as independent, externally-labeled training/test data, diluting the circular signal. Legitimate F1 dropped to 0.80–0.84 as a direct, expected consequence — confirmed as validating evidence, not a regression.

**A genuine upstream data-label bug was found and fixed.** The official CIC-IDS-2018 Infiltration-day CSVs use the label string `"Infilteration"` (transposed letters — an upstream typo, not a code bug on our side), which didn't match `cic_ids_loader.py`'s `CIC_LABEL_TO_MITRE` key `"Infiltration"` (exact match failed, and the substring fallback also failed since the letter order differs). This silently mapped ~162,000 real Infiltration attack rows (68,871 + 93,063 across the two Infiltration days) to `BENIGN`. Root-caused by scanning the raw CSVs' `Label` column directly rather than guessing, fixed by adding the correctly-spelled key, and verified clean via a full audit of all 10 downloaded days' label strings against the live mapping code. A separate, much smaller hygiene issue (CICFlowMeter's duplicate embedded header rows, ~40 rows total across 3 files, `Label` literally appearing as its own value) was filtered defensively in the same pass.

**The benchmark requirement is satisfied on corrected, non-stale, non-circular data.** `world_model.py --benchmark` now runs against the current, bug-fixed 47,911-row dataset:

| Metric | Logistic Regression (baseline) | LSTM World Model | Delta |
|---|---|---|---|
| F1 | 0.7955 | 0.8022 | +0.0067 |
| Precision | 0.7569 | 0.8488 | +0.0919 |
| Recall | 0.8382 | 0.7605 | −0.0777 |
| FPR | 0.2082 | 0.1051 | −0.1031 |

The F1 margin is thinner than an earlier (pre-label-fix) run showed (0.048 → 0.007), because that earlier margin was partly the LSTM getting free credit for confidently agreeing with ~10,000 mislabeled-benign rows — a temporal model is especially good at exploiting that kind of spurious consistency. The corrected number is smaller but honest: the LSTM still wins on F1, precision, and FPR (10pp lower false-positive rate is the strongest practical win), just not by a dramatic margin. **This should be the number cited in the report, not the earlier 4.8% figure.**

**Generalization to entirely unseen attack categories is now demonstrated, cleanly, across all 6 CIC-IDS-2018 categories** (not just one hardcoded pair as before). `generalization_test.py` was rewritten to hold out each category's day(s) entirely from training — zero rows trained on — and evaluate both models purely on the excluded category:

| Category | LR AUC | LSTM AUC | Generalizes? |
|---|---|---|---|
| Brute Force (T1110) | 0.620 | 0.881 | yes |
| DoS (T1499) | 0.857 | 0.864 | yes |
| DDoS (T1498) | 0.845 | 0.886 | yes |
| Web Attacks (T1059/T1110/T1190) | 0.687 | 0.610 | yes |
| Infiltration (T1105) | 0.622 | 0.642 | yes |
| Botnet (T1071) | 0.857 | 0.733 | yes |

6/6 categories generalize above chance (AUC > 0.6) for both models — real evidence of learned, transferable attack-vs-benign structure rather than memorized per-category signatures. Before the label fix, this table showed only 4/6 with two false failures: Brute Force was marked "NO" only because a weak LR baseline (0.395) dragged down an otherwise-strong LSTM (0.835), and Infiltration scored an exact 0.0/0.0 for both models — the signature of a test set with zero true-positive labels, not a real model failure. Both are now resolved with real numbers.

## Known remaining gaps

**The benchmark only measures point classification, not the World Model's actual differentiator.** The architecture's real value proposition is forward simulation — `P(compromise at t+k)` several steps ahead — which a static LR classifier cannot do by construction, no matter how well-tuned. Right now nothing in the pipeline measures or reports lead-time (how many flows/seconds before compromise the LSTM raises a correct alert). Adding this would replace a thin F1-margin argument with a capability gap LR literally cannot close, and would more directly demonstrate the "temporal dynamics" claim the problem statement is likely asking for.

**Infiltration and Web Attacks remain the weakest categories.** Infiltration AUC (0.62–0.64) is real but modest — consistent with it being a genuinely hard category (CIC-IDS-2018's Infiltration attacks are designed to mimic benign traffic). Web Attacks LSTM AUC (0.610) is barely above the chance threshold and is now the single weakest cell in the table. Candidate improvements, not yet attempted: widening the LSTM's sequence window for slow/stealthy categories (current `SEQ_LEN=5` may be too short for Infiltration's low-and-slow pattern), recalibrating the classification threshold away from a fixed 0.5 (the LSTM's precision/FPR are strong but recall dropped — suggests a ranking that's fine but a cutoff that's too conservative), and per-category loss weighting so high-volume categories (DoS/DDoS/Botnet) don't dominate training at the expense of smaller ones (Infiltration/Web Attacks).

**Point 4 (PDF/report correction) remains explicitly deferred** per earlier instruction — not touched, do not revisit without it being re-raised.

## Operational notes for future sessions

This session has no `device_bash` — all Kali-side file edits go through stage → edit locally → verify (`py_compile`/`bash -n`) → push (`device_commit_files`) → re-stage and checksum-verify (`md5sum`), retrying the commit once if checksums mismatch (a known, recurring silent-failure mode of the commit bridge, roughly half the time historically). The user's shell is zsh, not bash — multi-command sequences go out as `.sh` files with a `#!/bin/bash` shebang and are run explicitly with `bash script.sh`, never pasted inline.
