# CyberSentinel AI — 3-Minute Prototype Video Voiceover Script

**Total runtime: 3:00 · Pace: ~150 words/min · ~450 words**
Time markers show when to switch to each screenshot. Read at a steady, confident pace; pause ~0.5s at each screen change.

---

## [0:00 – 0:05] — Title slide (`1.jpeg`)

> "CyberSentinel AI, by Team Vertex — our solution for Smart India Hackathon problem S-I-H two-six-one-five-three: forecasting network attacks *before* they succeed."

---

## [0:05 – 0:45] — Proposed Solution slide (`2.jpeg`)

> "Today, security teams react *after* a breach. We flip that — we forecast the attack before it completes.
>
> CyberSentinel captures real attacker behavior in a honeypot, decodes it into MITRE ATT&CK techniques, and learns an AI *World Model* that predicts the attacker's next move.
>
> It runs as a seven-stage pipeline — Catch, Decode, Learn, Predict, Explain, Check, and Act — from capturing sessions, to forecasting the next step, to a ranked report with fixes.
>
> Three things set it apart: it's predictive, not reactive; it runs fully offline on a local Mistral model; and every prediction is explainable and auditable — never a black box."

---

## [0:45 – 1:03] — Dashboard (`13_34_57`, `13_35_07`)

> "This is the live dashboard, built entirely on real honeypot attack data. This run captured 155 attacker sessions, mapped to 17 MITRE ATT&CK techniques — 40 of them at the compromise stage. The charts break down technique frequency and attacker tactics, and the model reconstructs the full kill chain — System Discovery, Account Discovery, Tool Transfer, then User Execution — flagged at 90 percent critical probability."

---

## [1:03 – 1:17] — Session Explorer (`13_35_16`, `13_37_33`)

> "Session Explorer drills into any single attack. For this denial-of-service session, the LSTM predicts the likely next technique — Remote Services — with its infiltration probability, and the SHAP panel shows exactly which signals drove that call."

---

## [1:17 – 1:32] — Live Attack Predictor (`13_37_53`, `13_37_59`)

> "The Attack Predictor is fully interactive. Type any sequence of techniques — here, System and Account Discovery — and the model instantly predicts what comes next: Command Interpreter, with its confidence and the exact prior step that drove the prediction."

---

## [1:32 – 1:47] — K-Step Attack Forecast (`13_38_12`, `13_38_19`)

> "This is the heart of the World Model — K-step forecasting. From two observed steps, it simulates the attacker's next three moves and plots how infiltration probability evolves against the critical threshold. A static classifier simply cannot do this."

---

## [1:47 – 2:07] — World Model Benchmark (`13_38_27`, `13_38_38`)

> "Here's the benchmark the problem statement requires — our World Model against a Logistic Regression baseline on identical data. On raw F1 they're close, but the World Model delivers higher precision and a much lower false-positive rate. And the key distinction says it all: only the temporal model can forecast future states and run K-step simulation — the baseline is blind to what comes next, and in our lead-time test the World Model warns far earlier."

---

## [2:07 – 2:24] — Upload PCAP for Live Inference (`13_39_28`, `13_39_33`)

> "To prove it generalizes beyond training, we upload a raw packet capture. The model extracts 154 real flows, runs inference across 150 sliding windows, and flags 101 as critical — you can watch infiltration probability collapse when the attack pauses, then spike again as it resumes."

---

## [2:24 – 2:38] — Live World Model Inference (`13_40_01`, `13_40_05`)

> "Running the World Model on the five most recent real honeypot flows, it reports 99.9 percent critical infiltration, predicts Command Interpreter next, and shows the attention weights behind it — port-scan score and retransmission count as the top real signals."

---

## [2:38 – 2:54] — Agent Security Findings (`13_40_12` → `13_40_29`)

> "Finally, three autonomous AI agents — Recon, CVE, and Config — analyze every technique fully offline with Mistral, producing 17 ranked findings. The top one links Command Interpreter to a real CVE at severity 9.8, with concrete verification steps and a remediation fix."

---

## [2:54 – 3:00] — Close (hold on Agent Findings or return to title)

> "CyberSentinel AI — from raw attack traffic to a forecasted, explained, and actionable defense. Thank you."

---

### Recording notes
- If you run short, stretch the pauses at the K-Step Forecast and Benchmark screens — those are your strongest "wow" moments.
- If you run long, cut the Session Explorer line to one sentence: *"Session Explorer drills into any single attack, showing the predicted next technique and the SHAP signals behind it."*
- Numbers to say as words for clarity: "155", "17", "40", "90 percent", "99.9 percent", "severity 9.8".
