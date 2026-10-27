# TraceWeaver — Project Review / Viva Preparation

## 1. Problem statement
Runtime security sensors (Falco, Tracee, Tetragon) emit huge volumes of raw events, but a raw
event is not a verdict. Teams conflate *telemetry* (the kernel saw a syscall) with *detection*
(a policy flagged a threat), and they ignore *collection quality* (did the sensor even see it?).
The result is false confidence: missing events get read as "nothing happened," and noisy anomaly
scores get read as "attack."

## 2. Why raw sensor output alone is insufficient
- A sensor only detects what its rules/signatures cover — Falco catches sensitive-file reads but
  not sudoers edits; Tracee's signature catches sudoers but not everything. Pure rules → low recall.
- Raw anomaly scoring over-fires on benign novelty.
- Neither distinguishes "not detected" from "not collected." A reboot broke Tetragon's container
  capture; a naive pipeline would score those empty streams as clean negatives.

## 3. Architecture
Canonical events (Phase 1) → BehaviorGraph → three signals {A anomaly, S sequence, P policy} →
risk score → **visibility-aware verdict** → explanations with raw provenance. (See
`TRACEWEAVER_ARCHITECTURE.md`, Mermaid diagram.)

## 4. Algorithm & equations
`risk = 100·(0.2·A + 0.3·S + 0.5·P)`. A = suspicious-action share; S = max temporal-pattern
severity; P = 1 iff a verified qualifying alert/signature. Verdict precedence puts
EXECUTION/COLLECTION failure above any score; DETECTED requires P>0. (See `TRACEWEAVER_ALGORITHM.md`.)

## 5. Worked example (real evidence)
Stream `A6_tracee_t1`: Tracee emits a `sudoers_modification` signature (event `ev_77242f…`,
`results/raw/tracee_events/A6_tracee_t1.jsonl:8`). Engine: S=0.75 (`sudoers_modification` pattern),
P=1.0 (qualifying signature), A=0 → risk 72.5 (HIGH) → **DETECTED** with the signature cited as
evidence. Contrast `E04` Tetragon: workload ran (exit 0) but zero scoped events → **COLLECTION_FAILED**,
risk 0 — not promoted, not a false negative.

## 6. How visibility-awareness prevents false conclusions
A `COLLECTION_FAILED` stream can carry a high nominal risk, yet the verdict layer refuses to call it
NOT_DETECTED or DETECTED. Missing events are explicitly *not* evidence of absence. This is enforced
in code and pinned by regression tests (`test_engine.py::VerdictTests`).

## 7. Evaluation & results
52 eligible trials, 3 methods, held-out benign negatives, no leakage. rules-only F1 0.61 →
**TraceWeaver F1 0.97** (precision 1.0, recall 0.94, 0 false positives on the benign control). One
honest FN = Falco/A6 coverage gap. (See `TRACEWEAVER_EVALUATION.md`.)

## 8. Limitations & known failures
Tetragon live capture broken (documented); replay not live; small sample; scenario-level labels;
conservative anomaly; structured (not force-directed) graph view. (See `TRACEWEAVER_LIMITATIONS.md`.)

## 9. What is original
Not the individual signals (rule match, sequence, frequency anomaly are standard). The contribution is
the **integration**: a visibility-aware verdict layer that fuses the three signals under an explicit
collection-quality gate, with an **end-to-end evidence contract** (every finding → event_id →
raw file:line:sha256), proven by validators and tests that make invalid evidence un-promotable.

## 10. Five likely questions
- **Q: Isn't combined == rules-only for DETECTED?** Yes, by design — the engine never invents verified
  detections. The value is (a) the suspicious-flag recall that surfaces attacks pure rules miss, and
  (b) the visibility-aware verdict that stops empty/failed streams becoming false negatives.
- **Q: How do you avoid leakage?** The anomaly baseline is fit only on A2/A3/E-series; those are excluded
  from metrics, and the benign control (A7) is held out as the negative class.
- **Q: Why not ML?** The dataset is tiny and the goal is explainability + determinism. Deterministic
  rules + simple frequency stats are auditable and reproducible; an ML model would overfit and obscure.
- **Q: Why is Falco/A6 a false negative?** Falco has no sudoers rule — an honest sensor coverage gap,
  reported per-sensor, not hidden or patched over.
- **Q: Can I trust a verdict?** Every finding cites the exact raw record (file:line:sha256); the CLI
  `validate` command proves no finding cites a nonexistent event and no detection lacks policy evidence.

## Spoken scripts
**90s demo:** "This is TraceWeaver — it turns raw Falco/Tracee/Tetragon events into explainable,
visibility-aware verdicts. [Overview] 111 streams scored; 20 verified detections. [Evaluation]
rules-only gets F1 0.61 because a sensor only detects what it has a rule for; TraceWeaver reaches 0.97
by surfacing suspicious behavior through sequence and anomaly signals — with zero false positives on the
benign control. [Trial] Here's a Tracee sudoers detection: the engine cites the exact signature event
and its source line. [Visibility] And here's a Tetragon stream where collection failed — the engine
refuses to call it clean; missing events are never evidence of absence. Every number traces to raw
evidence."

**3-min technical:** cover the canonical schema + provenance, the three signals and the risk formula,
the verdict precedence (why failure beats score), the evaluation split and the honest FN, and the
originality (integration + evidence contract), then open the JSON drill-down to show traceability.
