# TraceWeaver — Algorithm

Deterministic, stdlib-only. No ML model, no external API. All parameters live in
`scripts/traceweaver/engine_config.json` (versioned).

## 1. Behavior graph

Canonical events → nodes (process, file, container, network) + edges
(`parent_of`, `accessed`, `connected`). Correlation uses only concrete fields:

- a process node key is `proc:<container_id[:12]>:<pid>` **only when both are known**;
  otherwise an explicit `proc:unknown:<event_id>` key (never merged with others);
- a `parent_of` edge is drawn only when both pid and parent_pid are concrete;
- events are ordered by `(timestamp, event_id)` — deterministic even with missing timestamps;
- unrelated events are **not** correlated by time proximity.

Every node/edge preserves `event_id` + `raw_ref`.

## 2. Three interpretable signals (each 0–1)

**A — anomaly.** Share of a stream's events that perform an *actually suspicious action*:
access to a sensitive path (`/etc/shadow`, `/etc/sudoers`, …) or execution from a
world-writable dir (`/tmp/`, `/dev/shm/`). A novel process name alone is recorded as
*context only* and does **not** raise A (so common benign tools like `echo`/`ls` are not
flagged on a small baseline). `A = min(1, anomalous_events / total_events · 3)`. An **empty
stream yields A=0** — absence never raises anomaly.

**S — sequence.** `S = max(severity)` over triggered temporal patterns (0 if none). Patterns
require specific canonical types + fields (not a filename substring in an unrelated event):

| Pattern | Severity | Requires | MITRE |
|---------|----------|----------|-------|
| `sensitive_file_access` | 0.80 | `file_open/write` on a sensitive path | T1552.001/T1555 |
| `sudoers_modification` | 0.75 | file op on `/etc/sudoers*` | T1548.003 |
| `exec_from_suspicious_dir` | 0.70 | exec whose args reference `/tmp/`… | T1204/T1059 |
| `nested_shell_execution` | 0.45/0.30 | ≥2 shells (parent-child chain → 0.45) | T1059.004 |
| `discovery_sequence` | 0.40 | ≥3 distinct discovery tools | T1082/T1033 |

**P — policy.** `P = 1.0` iff a **real qualifying** security alert is present — a Falco
built-in rule or a Tracee behavioral signature. The lab's custom process-exec Notice rule is
**not** qualifying (`P=0`). This is the strongest, most evidence-grounded signal.

## 3. Risk score

```
risk_score = round(100 · (wA·A + wS·S + wP·P), 2)        wA=0.2, wS=0.3, wP=0.5
```

Weights are nonnegative and sum to 1.0 (enforced at load). P is weighted highest (most
evidence-grounded); A lowest (weakest/most environment-dependent). Risk bands:
`LOW < 40 ≤ SUSPICIOUS < 70 ≤ HIGH`. The risk score is **descriptive**; it never overrides the
verdict layer.

## 4. Visibility-aware verdict (precedence)

Visibility is assessed first (`COLLECTION_FAILED` / `EXECUTION_FAILED` / `NO_EVENTS` /
`PARTIAL` / `FULL`), then the verdict:

1. `EXECUTION_FAILED` — workload failed → not evaluable.
2. `COLLECTION_FAILED` — verified execution but zero scoped events → **a risk score cannot
   promote this to a detection**.
3. `DETECTED` — **requires P>0** (verified policy evidence) with valid provenance.
4. `TELEMETRY_ONLY` — suspicious behavior observed (S>0 or risk ≥ suspicious) but no qualifying alert.
5. `NOT_DETECTED` — execution + full visibility + no suspicious pattern/alert.
6. `INCONCLUSIVE` — partial visibility / no events.

**Invariants (tested):** missing events never become a detection; collection/execution failure
never becomes `NOT_DETECTED`; `DETECTED` never occurs with P=0; a high risk never overrides a failure.

## 5. Threshold choices

Initial weights/thresholds were chosen for interpretability (P strongest), not to inflate
results. The suspicious-flag task in evaluation uses a **strong-severity** rule (pattern severity
≥ 0.6) so weak/ambiguous patterns (nested-shell, discovery) do not flag alone — this is why the
benign control yields zero false positives. Any tuning is documented and uses only the train split.
