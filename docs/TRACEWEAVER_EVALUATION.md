# TraceWeaver — Evaluation

Reproducible: `python3 -m scripts.traceweaver.evaluate` writes
`results/engine/evaluation.json` + `evaluation.md` (auto-generated, carries git
revision, engine/schema versions, config hash, timestamp).

## Methodology

- **Task.** Surface-as-suspicious: does a method *flag* a malicious-scenario stream while
  staying quiet on the benign control? (A verified `DETECTED` still requires P>0; this task
  measures the broader suspicious-flag signal.)
- **Methods (same eligible set, same labels):**
  - `rules_only` — flag iff P>0 (the sensor's own alerts/signatures).
  - `anomaly_only` — flag iff A ≥ 0.2.
  - `combined` (TraceWeaver) — flag iff P>0 **or** a strong pattern (severity ≥ 0.6) **or** A ≥ 0.2.
- **Labels (evidence-justified, scenario-level):** positive = A1 credential access, A5
  drop-and-execute, A6 sudoers modification; negative = A7 benign control; **ambiguous
  (excluded)** = A2 nested shell, A3 discovery; E-series (observability baselines) excluded.
- **Train/eval split (no leakage).** The anomaly baseline is fit **only** on A2/A3 + E-series
  (`run.py:BASELINE_STREAM_PREFIXES`); those streams are excluded from the metrics. The benign
  control A7 is **held out** as the negative class (never used to fit the baseline).

## Results (current run)

| Method | TP | FP | TN | FN | Precision | Recall | F1 |
|--------|----|----|----|----|-----------|--------|----|
| rules_only | 20 | 0 | 6 | 26 | 1.00 (20) | 0.435 (46) | 0.606 |
| anomaly_only | 33 | 0 | 6 | 13 | 1.00 (33) | 0.717 (46) | 0.835 |
| **combined (TraceWeaver)** | **43** | **0** | **6** | **3** | **1.00 (43)** | **0.935 (46)** | **0.966** |

- Eligible trials: **52** (46 positive + 6 negative). Ineligible counts & reasons are in
  `evaluation.json` (`baseline/training split`, `ambiguous label`, `COLLECTION_FAILED`, `no
  supervised label (E-series)`).
- Denominators are shown for every rate; a zero denominator renders `N/A`, never a misleading 0.

## Interpretation

- **rules-only** has perfect precision but low recall — it only flags where a sensor rule/signature
  exists (Falco A1/A5; Tracee A6), missing the same malicious behavior on sensors that lack a rule.
- **TraceWeaver (combined)** recovers that recall (0.44 → 0.94) by surfacing the suspicious behavior
  via sequence + anomaly signals (e.g., Tracee/Tetragon sensitive-file reads on A1), while keeping
  **perfect precision** — the benign control A7 yields **0 false positives**.
- The single remaining FN is **Falco / A6** (3 trials): Falco has no sudoers-modification rule, so it
  genuinely cannot flag it. This is an honest **per-sensor coverage gap**, surfaced not hidden.

## Threats to validity

- **Small, exploratory sample** (52 eligible trials); not statistically powered. No broad claims.
- The suspicious-flag task is distinct from verified detection; the engine never reports `DETECTED`
  without P>0 (so rules-only and combined agree on *verified* detections by design — the value is in
  the suspicious-flag recall and the visibility-aware handling).
- Tetragon's live container-capture regression removes it from most eligible cells (COLLECTION_FAILED).
- Labels are scenario-level; per-sensor detectability differs by configuration.
