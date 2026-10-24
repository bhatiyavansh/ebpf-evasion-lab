# Methodology

## Fair detection comparison study (primary)

The comparison study (`experiments/comparison_catalog.json`, `scripts/run_comparison.sh`,
`scripts/build_comparison.py`) evaluates each **scenario × tool × config** over **3 live trials**
with real captured detector output, under a 7-state outcome model:

`DETECTED · TELEMETRY_ONLY · NOT_DETECTED · NOT_EVALUATED · EXECUTION_FAILED · COLLECTION_FAILED · INCONCLUSIVE`

- **Qualifying detection is defined before the run**, per tool:
  - *Falco* — a fired rule at Warning+ priority that is **not** the lab's custom process-exec Notice
    rule (i.e. a built-in security rule, carrying mitre_*/security tags).
  - *Tracee* — an event with a non-empty `matchedPolicies` (a detection policy matched). Event-set-only
    config → telemetry, never a detection.
  - *Tetragon baseline* — generic tracing-policy telemetry → never a detection.
  - *Tetragon configured* — an event from the selective `ebpf-lab-sensitive-file-detect` policy whose
    `matchArgs` fires **only** on sensitive pathnames → a policy-based detection.
- **Classification is deterministic** (`build_comparison.py`), verified by independent recount
  (`validate_comparison.py`). No LLM decides an outcome; generated prose only *describes* it.
- **Fairness:** both an unmodified **baseline** and a documented **configured** track are reported.
  "Configured" enables a real detection policy; it never fabricates alerts. Where an equivalent
  config was not achieved (Tracee signatures), the result is `NOT_EVALUATED`, stated explicitly.
- **Detection rate = qualifying detections ÷ eligible, successfully-executed evaluations.** Execution
  failures and unavailable evaluations are excluded; a zero denominator yields `N/A`, not 0%.

## E01–E09 observability study (baseline controls) — variables

| Variable | Role | Values |
|----------|------|--------|
| Detector | independent | Falco (alerting engine), Tracee (telemetry), Tetragon (telemetry) |
| Behavior | independent | sensitive_file_read, process_execution, network_activity, file_access |
| Variant | independent (the adaptive manipulation) | baseline, indirect_execution, timing_variation, repeatability, comparative, policy_coverage |
| Execution status | dependent | completed / failed / not_run |
| Collection status | dependent | complete / partial / failed |
| Telemetry | dependent | observed / not_observed |
| Detection | dependent | detected / not_detected / not_evaluated |

The four dependent dimensions are tracked **independently** so that, e.g., "telemetry
observed + detection not_evaluated" (a telemetry-only tool) is never collapsed into a single
misleading pass/fail.

## Controlled workload procedure

1. A benign workload runs in a fresh `alpine:3.20` container (`docker run --rm`).
2. A detector observes. For Tetragon the capture is **live and container-scoped**: events are
   filtered to the workload container's cgroup id, so host noise is excluded
   (`scripts/capture_tetragon.sh`). Falco and Tracee evidence is recorded.
3. Raw evidence is written immutably (`results/raw/*.json`, `results/raw/tetragon_events/*.jsonl`)
   with a run manifest (`results/runs/*.json`: run_id, timestamps, tool version, policies,
   container id, counts).
4. `scripts/normalize.py` classifies status by explicit, auditable rules and attaches the four
   dimensions + provenance. `scripts/analyze.py` derives matrices and comparisons.
   `scripts/validate.py` enforces integrity invariants.

## Interpretation criteria

- **Telemetry observed** requires a relevant kernel event in a complete, applicable capture.
- **Confirmed detection** requires a rule/policy to produce a verified alert on the behavior.
  Falco's custom process-execution rule is labeled `custom_research`, distinct from a
  `builtin_security` rule (only E01), because a custom rule firing is not proof that a shipped
  security policy flagged malicious behavior.
- **not_evaluated** is used when no applicable policy/engine exists (e.g. Tracee/Tetragon
  detection; network detection without a network policy). It is **never** inferred from missing
  evidence and is **not** a detection failure.
- **Partial** is used when some evidence exists but the targeted claim is not established (e.g.
  Falco E03: process telemetry present, network detection not).

## Metric rules

- Detection rate is computed **only over eligible evaluations** of that tool (excludes
  `not_tested` and `not_applicable`). Numerator = confirmed detections; denominator = eligible
  cells.
- Unknown values are represented as `null` / `unknown`, never silently `0`.
- No latency, false-positive rate, precision/recall, throughput, or statistical significance is
  reported, because the supporting measurements are not collected. Repeatability (E06, n=5) is
  **described** (individual trials + whether identical), not aggregated into a significance claim.

## Reproducibility

`./scripts/pipeline.sh` regenerates all derived data deterministically from immutable raw
evidence and runs the 40-check validator. The dashboard consumes only generated artifacts.
