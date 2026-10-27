# Adaptive Evasion Analysis of eBPF-Based Runtime Security Systems


## TraceWeaver — explainable, visibility-aware detection engine

This repository now includes **TraceWeaver**, a detection engine that consumes normalized
Falco/Tracee/Tetragon events and returns explainable, provenance-backed verdicts.

- **Product (two tabs):** http://localhost:3000/ — **Main** (Scenario Explorer → *Run Analysis*) and
  **Outcome** (interactive behaviour graph + replay · verdict · risk · signals · timeline · visibility ·
  evaluation). Main's *Run Analysis* button executes the real engine on the selected stream via the
  allowlisted `POST /api/traceweaver/graph` endpoint and opens the full investigation on Outcome.
- **Interactive behaviour graph + replay (Outcome tab):** a dependency-free SVG graph of the
  correlated processes / files / containers / alerts for the selected trial, with Play / Pause /
  Step / Reset / speed / scrubber controls that progressively reveal events in real timestamp order.
  Nodes, edges and findings are all click-to-inspect and trace to `file:line:sha256`.
- **Graph API (read-only):** `python3 -m scripts.traceweaver.cli graph --stream <raw_path>` emits the
  ordered events + evidence-backed nodes/edges for one stream (reuses the engine's own BehaviorGraph —
  no second detector). Served to the UI by `POST /api/traceweaver/graph` (strict allowlist + traversal
  guard + bounded timeout).
- **Run the engine (CLI):** `python3 -m scripts.traceweaver.cli run --all --summary`
- **Validate output + explanations:** `python3 -m scripts.traceweaver.cli validate`
- **Evaluate (3 baselines):** `python3 -m scripts.traceweaver.evaluate`
- **One-command demo:** `./scripts/traceweaver_demo.sh`
- **Research archive (study internals):** http://localhost:3000/lab (linked from the product header)

> **Graph relationships are evidence-only.** Edges come from the engine's correlation
> (`parent_of`, `accessed`, `connected`) plus a `in_container` membership edge derived from a
> concrete `container_id` field. When identity fields (pid/parent_pid) are missing, the graph shows
> the disconnected nodes and a "why correlation is limited" panel instead of fabricating edges. A
> collection/execution failure renders a distinct failure state, never an empty graph read as "clean".

> **Live vs. replay (honest framing):** *Run Analysis* runs the TraceWeaver engine on demand — the
> computation is live — but the underlying sensor events are **recorded captures** (historical
> replay), not a live kernel feed. The UI states this explicitly; it never labels replay as live.

Pipeline: canonical events → behavior graph → {anomaly A, sequence S, policy P} →
`risk = 100·(0.2A+0.3S+0.5P)` → **visibility-aware verdict** (a risk score never overrides a
collection/execution failure; a verified DETECTED requires real policy evidence). Every finding cites
the exact raw record (`file:line:sha256`). Docs: `docs/TRACEWEAVER_ARCHITECTURE.md`,
`TRACEWEAVER_ALGORITHM.md`, `TRACEWEAVER_EVALUATION.md`, `TRACEWEAVER_DEMO.md`,
`TRACEWEAVER_LIMITATIONS.md`, `TRACEWEAVER_REVIEW.md`. Phase-1 data foundation:
`docs/TRACEWEAVER_PHASE1_AUDIT.md`.

Current evaluation (52 eligible trials, exploratory): rules-only F1 0.61 → **TraceWeaver F1 0.97**
(precision 1.0, 0 false positives on the benign control). Known limitation: Tetragon live container
capture is broken (COLLECTION_FAILED); Falco/Tracee unaffected.

---

**A reproducible runtime-security evaluation platform for Linux container environments.**

> **Research question** — How does adaptive modification of containerized execution
> behavior affect the observability and detection capability of eBPF-based runtime
> security systems?

This repository evaluates three eBPF runtime-security systems — **Falco**, **Tracee**,
and **Tetragon** — against controlled *baseline* and *adaptive* container behaviors, and
presents the evidence through an interactive, route-based research console. Its central
commitment is **scientific integrity**: it rigorously separates *kernel-event visibility*
from *security detection*, and never fabricates a result.

### Application routes

| Route | Purpose |
|-------|---------|
| `/` | **TraceWeaver product** — two primary tabs: **Main** (evidence selector + *Run Analysis*) and **Outcome** (real verdict, risk gauge, A/S/P signal breakdown, evidence timeline with raw provenance, visibility panel, evaluation comparison) |
| `/lab` | Research archive — Experiment Lab: **Detection Study** (fair comparison), baseline experiments, comparison matrix, E06–E09, live/replay, evidence explorer, analysis, exports |
| `/cve-lab` | Real-CVE compatibility & evaluation (Dirty Pipe, OverlayFS, nf_tables) with safe-simulation / recorded / blocked-reproduction modes |
| `/outcome` | Report-quality, **conclusion-first** findings: detection matrix, baseline-vs-configured detection rate, telemetry coverage, evidence-linked key findings |
| `/demo` | Guided 7-act faculty demonstration (live or recorded), keyboard-navigable |

### Fair detection comparison study (real captured alerts)

The flagship result is a **fair baseline-vs-configured comparison** over three MITRE-mapped
scenarios, **3 live trials each**, using **genuine captured detector output** (not hand-authored):

- **Real capture harnesses** — `scripts/capture_falco.sh` captures live Falco JSON alerts
  (modern eBPF); `scripts/capture_tracee.sh` captures live Tracee events; `scripts/capture_tetragon.sh`
  captures Tetragon. Each writes an immutable event stream + a run manifest.
- **Qualifying-detection criteria** are defined **before** classification (see
  `experiments/comparison_catalog.json`) and applied **deterministically** by
  `scripts/build_comparison.py` — no model decides whether a tool detected an attack.
- **Scenarios:** A1 Credential access (read `/etc/shadow`, T1552.001/T1555), A2 Nested shell
  (T1059.004), A3 Host/container discovery (T1082/T1033). All benign (alpine's throwaway
  `/etc/shadow` holds no real secret).

**Measured result (3 trials/cell, real evidence):**

| Scenario | Falco | Tracee | Tetragon (baseline) | Tetragon (configured) |
|----------|-------|--------|---------------------|-----------------------|
| A1 credential access | **DETECTED** 3/3 (built-in T1555 rule) | TELEMETRY_ONLY | TELEMETRY_ONLY | **DETECTED** 3/3 (selective policy) |
| A2 nested shell | TELEMETRY_ONLY | TELEMETRY_ONLY | TELEMETRY_ONLY | — |
| A3 discovery | TELEMETRY_ONLY | TELEMETRY_ONLY | TELEMETRY_ONLY | — |

**Confirmed detection rate = qualifying detections ÷ eligible executed evaluations:**
**baseline 0/6 (0%) → configured 2/4 (50%)**. The earlier telemetry-only picture reflected
*configuration*, not inherent tool capability: once given an equivalent sensitive-file policy,
Tetragon detects credential access as Falco does. Nested-shell and discovery remain telemetry-only
for **all** tools (including Falco) — its default rules genuinely do not flag these benign behaviors.

Outcome model (7 states): `DETECTED`, `TELEMETRY_ONLY`, `NOT_DETECTED`, `NOT_EVALUATED`,
`EXECUTION_FAILED`, `COLLECTION_FAILED`, `INCONCLUSIVE` — execution, collection, telemetry and
detection are tracked separately and never silently overwrite one another.

---

## Environment (this lab was captured on)

| | |
|---|---|
| OS | Kali GNU/Linux Rolling (ARM64) |
| Kernel | `7.1.5+kali-arm64` |
| Architecture | `aarch64` |
| BTF | `/sys/kernel/btf/vmlinux` present |
| Container runtime | Docker 28.5 |
| Falco | `falcosecurity/falco:0.45.0` |
| Tracee | `aquasec/tracee:latest` |
| Tetragon | `quay.io/cilium/tetragon:v1.6.0` |

Exact image digests captured at run time are in [`results/env/environment.json`](results/env/environment.json).

---

## The status model (scientific-integrity contract)

Every cell in the matrix is one of five statuses, assigned by auditable rules in
[`scripts/normalize.py`](scripts/normalize.py) — **never** copied blindly from a raw
`detected` flag:

| Status | Meaning |
|---|---|
| **Confirmed detection** | A rule/policy engine raised a security detection on the tested behavior. |
| **Telemetry observed** | A relevant kernel event was captured. Observability only — *no alert verdict*. |
| **Partial evidence** | Some evidence exists, but the targeted claim is not fully established. |
| **Not tested** | No result file exists for this experiment/tool. |
| **Confirmed miss** | The event was observed but an expected detection failed to fire. |

Two further distinctions are tracked as attributes, not statuses:
`context_enriched` (container/process metadata attached) and, for Falco,
`rule_class` = `builtin_security` vs `custom_research`.

**Tool semantics are explicit.** Falco has an alerting engine, so a rule firing is a
detection — but a *custom* research rule firing is **not** proof that a built-in security
policy flagged malicious behavior. Tracee and Tetragon are configured here as **telemetry
collectors only** (no signatures / no alerting), so their events are `telemetry_observed`,
never `confirmed_detection`, regardless of any `detected` field in their raw JSON.

---

## Results at a glance

| Exp | Behavior | Falco | Tracee | Tetragon |
|-----|----------|-------|--------|----------|
| E01 | Sensitive file read (`/etc/shadow`) | **Confirmed detection** (built-in rule) | Telemetry (openat) | Telemetry (openat **+ `/etc/shadow` pathname confirmed**) |
| E02 | Process execution | Detection (custom rule) | Telemetry (execve) | Telemetry (sched_process_exec) |
| E03 | Network activity (HTTPS) | **Partial** (process telemetry, no network detection) | Telemetry (**connect → :443**) | Telemetry (process only; no network policy) |
| E04 | Indirect execution (`sh → sh → id`) | Detection (custom rule) | Telemetry (execve ×3) | Telemetry (exec ×3) |
| E05 | Timing variation (2s delays) | Detection (custom rule) | Telemetry (execve ×4) | Telemetry (exec ×4) |

**Extended experiments (live Tetragon capture):**

| Exp | What it adds | Result |
|-----|--------------|--------|
| E06 | Repeated baseline (5 trials) | 5/5 identical captures — deterministic telemetry (small-n, descriptive) |
| E07 | Sensitive vs benign file read | Both pathnames captured in `openat`; Tetragon alerts on neither (telemetry ≠ detection) |
| E08 | Network observability & policy coverage | Process telemetry captured; network detection `not_evaluated` where no policy exists |
| E09 | Sequence & timing comparison (derived) | Process chain changes across variants; every stage stays observable |

**Headline finding.** Simple execution indirection (E04) and controlled timing variation
(E05) did **not** eliminate process-execution observability under any tested configuration —
every execution stage remained visible across all three tools. *This is specific to the
tested behaviors and configurations; it does not demonstrate immunity to adaptive evasion.*
See the [full report](docs/REPORT.md) and [methodology](docs/METHODOLOGY.md).

### CVE lab (safety model)

The `/cve-lab` assesses three real CVEs against the **actual host kernel** (`7.1.5`), not a
container image's version string. All three (Dirty Pipe 5.16.11-fixed, OverlayFS
Ubuntu-specific, nf_tables ≤6.7.3-fixed) assess as **not applicable** here. **No exploit is
executed on the project host.** Mode A = safe simulation (benign related telemetry), Mode B =
isolated reproduction (**blocked**, documented per CVE), Mode C = recorded evidence. A
simulation is never labeled a real reproduction.

### Evidence status definitions

Each cell carries a headline **status** plus four independent **dimensions**:

- **execution**: completed / failed / not_run
- **collection**: complete / partial / failed
- **telemetry**: observed / not_observed — *a relevant kernel event was captured*
- **detection**: detected / not_detected / **not_evaluated** — *a configured policy produced a verified alert*; `not_evaluated` means no applicable policy/engine, **never** inferred blindness

Each run also records **provenance** (`live` vs `recorded`), a `run_id`, and timestamps.

---

## Architecture / data pipeline

```
experiments/catalog.json         ← canonical experiment definitions (single source of truth)
        │
        ▼
scripts/lab.sh run-tetragon  →  scripts/capture_tetragon.sh   ← validated, allowlisted runner
        │                               │
        │                               ▼
        │                     results/raw/tetragon_events/*.jsonl   ← immutable captured eBPF events
        ▼                               │
results/raw/<EID>_<tool>.json  ◄────────┘  (derived by gen_tetragon_raw.py; Falco/Tracee authored)
        │
        ▼  scripts/normalize.py     (explicit status classification)
results/normalized/results.json  +  results/summary.csv   ← generated, not hand-maintained
        │
        ▼  scripts/analyze.py
results/analysis/analysis.json   ← matrices, coverage, detection-vs-telemetry, latency
        │
        ▼  scripts/validate.py      (34 integrity + schema tests)
        ▼
dashboard/ (Next.js)             ← consumes the GENERATED data; never re-derives status
```

Raw evidence is kept immutable wherever practical; the dashboard consumes generated
artifacts rather than a separately-edited copy.

---

## Quick start

### 1. Dashboard (view the evidence)

Node is required to build/run the Next.js dashboard. A pinned local toolchain installs
with no sudo:

```bash
./scripts/setup_node.sh          # downloads + verifies Node 24.21 into .toolchain/
source .toolchain/activate.sh    # put it on PATH for this shell
cd dashboard && npm install && npm run build && npm run start
# open http://localhost:3000
```

### 2. Regenerate all analysis from raw evidence

```bash
./scripts/pipeline.sh            # normalize → analyze → comparison → validate (+ comparison validation)
```

### 2b. Re-run the fair detection comparison study (live, ~20 min)

```bash
./scripts/run_comparison.sh          # 30 live captures: A1-A3 × tools/configs × 3 trials
python3 -I scripts/build_comparison.py   # deterministic classification → comparison.json
python3 -I scripts/validate_comparison.py  # independent recount vs computed outcomes
```

### 3. Run a controlled experiment live (Tetragon)

```bash
./scripts/lab.sh status                 # live environment + detector health (JSON)
./scripts/lab.sh run-tetragon E04       # start Tetragon, run allowlisted E04, capture evidence
./scripts/lab.sh down                    # stop lab-managed containers (only ours)
```

Live runs are also available in the dashboard's **Live & Replay** tab (Tetragon only;
Falco/Tracee are recorded-evidence/replay in this build). Only predefined, benign,
allowlisted experiment IDs are ever executed — there is no arbitrary-command endpoint.

---

## Repository layout

```
experiments/catalog.json          canonical experiment definitions
experiments/E0*_*.json             original per-run definitions (kept for provenance)
detectors/<tool>/                  launch scripts + rules/policies for each detector
results/raw/*.json                 raw per-experiment/tool evidence (immutable)
results/raw/tetragon_events/*.jsonl captured, container-scoped Tetragon event streams
results/normalized/results.json    GENERATED normalized records (schema.json describes it)
results/analysis/analysis.json     GENERATED analysis
results/summary.csv                GENERATED canonical summary
results/env/environment.json       captured environment + image digests
scripts/                           pipeline, runner, validator, node setup
dashboard/                         Next.js 15 + React 19 + Tailwind research dashboard
docs/                              research report, demo script, limitations
```

---

## Validation

```bash
python3 -I scripts/validate.py    # 34 checks: no dup IDs, evidence exists, status
                                  # invariants, CSV sync, denominators, no fake latency
cd dashboard && npm run build     # type-checks + production build
```

See [`docs/REPORT.md`](docs/REPORT.md) for the full research report, [`docs/DEMO.md`](docs/DEMO.md)
for the 5-minute demo script, and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for the
limitations and defensive recommendations.
