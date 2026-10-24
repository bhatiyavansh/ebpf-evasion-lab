# Adaptive Evasion Analysis of eBPF-Based Runtime Security Systems — Research Report

**Scope.** This report covers the experiments and evidence currently in the repository. It
deliberately separates four epistemic levels: **measured results**, **interpretations**,
**hypotheses**, and **future work**. Nothing here is asserted beyond what the captured
evidence supports.

---

## 0. Flagship result — fair detection comparison (real captured alerts)

The strongest empirical result is a **baseline-vs-configured** detection comparison over three
MITRE-mapped scenarios, **3 live trials each**, classified deterministically from **genuine
captured detector output** (`scripts/build_comparison.py`; criteria fixed in
`experiments/comparison_catalog.json` before classification).

| Scenario (MITRE) | Falco | Tracee | Tetragon baseline | Tetragon configured |
|---|---|---|---|---|
| A1 Credential access — read `/etc/shadow` (T1552.001/T1555) | **DETECTED 3/3** (built-in "Read sensitive file untrusted", T1555) | TELEMETRY_ONLY 0/3 | TELEMETRY_ONLY 0/3 | **DETECTED 3/3** (selective matchArgs policy) |
| A2 Nested shell (T1059.004) | TELEMETRY_ONLY 0/3 | TELEMETRY_ONLY 0/3 | TELEMETRY_ONLY 0/3 | — |
| A3 Discovery (T1082/T1033) | TELEMETRY_ONLY 0/3 | TELEMETRY_ONLY 0/3 | TELEMETRY_ONLY 0/3 | — |

**Confirmed detection rate = qualifying detections ÷ eligible executed evaluations:**
**baseline 0/6 → configured 2/4.**

- **OBSERVATION.** With an equivalent sensitive-file policy enabled, Tetragon detected credential
  access in 3/3 A1 trials — matching Falco's built-in T1555 detection. Baseline (telemetry-only)
  configurations detected 0/3. A2/A3 produced no qualifying detection from any tool, Falco included.
- **INTERPRETATION.** The earlier "Falco detects, Tracee/Tetragon don't" picture reflected
  *configuration*, not inherent capability: the detection layer (policy/signature), not kernel
  visibility, decides the outcome. Falco's default ruleset is behavior-specific — it flags
  sensitive-file access but not benign nested shells or discovery.
- **LIMITATION.** n=3 per cell (descriptive, not statistically powered). "Configured" was
  implemented for Falco (built-in rules) and Tetragon (selective policy); a Tracee signature-engine
  detection was not enabled, so Tracee configured detection is *not evaluated*, not a miss. A1 reads
  alpine's throwaway `/etc/shadow` (no real secret) — it exercises the detection path, not real
  credential theft.

Sections 1–8 below cover the original E01–E09 observability study, which remains as baseline
controls and supporting evidence.

## 1. Research question

> How does adaptive modification of containerized execution behavior affect the
> observability and detection capability of eBPF-based runtime security systems?

**Detectors:** Falco (`0.45.0`), Tracee (`latest`), Tetragon (`v1.6.0`).
**Environment:** Kali Linux ARM64, kernel `7.1.5+kali-arm64`, `aarch64`, BTF present, Docker.

### Detector configuration (important for interpretation)

- **Falco** runs with a custom container process-execution rule plus its shipped ruleset —
  it has an **alerting engine**.
- **Tracee** is configured with the event set `execve, openat, connect` and `--output json`,
  **no signatures engine** — a telemetry collector in this lab.
- **Tetragon** runs two tracing policies: `sched_process_exec` (tracepoint) and `sys_openat`
  (kprobe, pathname arg). These are **telemetry emitters**, with no alerting/enforcement.

This configuration is itself a finding: *two of the three systems are deployed in a
visibility-only posture*, which is exactly why the report never reports their telemetry as
security detections.

---

## 2. Method

Each experiment runs a benign workload in a controlled `alpine:3.20` container while a
detector observes. Five behaviors:

| ID | Behavior | Variant | Command (as `sh -c`) |
|----|----------|---------|----------------------|
| E01 | Sensitive file read | baseline | `cat /etc/shadow >/dev/null` |
| E02 | Process execution | baseline | `echo EXEC_TEST; id; uname -a` |
| E03 | Network activity | baseline | `wget -q -O /dev/null https://example.com` |
| E04 | Indirect execution | adaptive | `sh -c "echo ADAPTIVE_INDIRECT_EXEC; id"` |
| E05 | Timing variation | adaptive | `echo TIMING_TEST_1; sleep 2; echo TIMING_TEST_2; sleep 2; id` |

E04 and E05 are controlled adaptive modifications of the E02 baseline (extra shell layer;
inserted delays). Tetragon evidence was captured live in this work via a scripted,
container-scoped harness ([`scripts/capture_tetragon.sh`](../scripts/capture_tetragon.sh));
Falco and Tracee evidence is the repository's recorded results.

---

## 3. Measured results

Coverage is complete: **15 / 15** experiment×detector cells evaluated; every cell has a raw
evidence file; 5 cells additionally carry raw captured eBPF event streams.

### 3.1 Per-cell outcomes

| Exp | Falco | Tracee | Tetragon |
|-----|-------|--------|----------|
| E01 | **Confirmed detection** — built-in "Sensitive file opened for reading by non-trusted program" fired on `/etc/shadow` | Telemetry — `openat` for `/etc/shadow` | Telemetry — `sched_process_exec` for `cat` **and `sys_openat` pathname = `/etc/shadow`** |
| E02 | Detection — custom rule, 3 process execs | Telemetry — `execve` for `sh, id, uname` (container-enriched) | Telemetry — `sh, id, uname` |
| E03 | **Partial** — process-exec alerts fired; **no** network-specific rule; `network_connection_detection: false` | Telemetry — `connect`, incl. **successful TCP to :443** | Telemetry — `sh, wget, ssl_client` only; **no network policy configured** |
| E04 | Detection — custom rule, `sh, sh, id` | Telemetry — all 3 execve stages | Telemetry — both shell layers + `id` |
| E05 | Detection — custom rule, `sh, sleep, sleep, id` | Telemetry — all 4 execve stages | Telemetry — all 4 exec stages |

### 3.2 Detection vs. telemetry (over eligible evaluations only)

| Tool | Eligible | Confirmed detections | Telemetry observed | Partial | Miss | Detection rate |
|------|----------|---------------------|--------------------|---------|------|----------------|
| Falco | 5 | 4 | 5 | 1 | 0 | **0.80** |
| Tracee | 5 | 0 | 5 | 0 | 0 | 0.00 |
| Tetragon | 5 | 0 | 5 | 0 | 0 | 0.00 |

The Tracee/Tetragon detection rate of 0.00 reflects **configuration (telemetry-only
posture)**, *not* a detection failure — there is no alerting engine to fire. This is the
single most important thing not to misread in this dataset.

### 3.3 Detection latency

**No valid latency measurements were collected.** This lab records event visibility and
detection outcomes, not detector-internal timing. Latency is reported as *unavailable* rather
than fabricated.

### 3.4 Extended experiments E06–E09 (live Tetragon)

| Exp | Measured result |
|-----|-----------------|
| **E06** Repeated baseline | 5 trials, **5/5 identical** process chains (`sh → id`) and exec counts (2); run IDs `run-E06_t1…t5`. Telemetry capture is deterministic here. *n=5 is exploratory, not statistical.* |
| **E07** Sensitive vs benign file | `openat` captured both `/etc/shadow` (sensitive) and `/etc/alpine-release` (benign) pathnames. Tetragon raised **no alert for either** — the distinction exists in telemetry, not in a detection verdict. |
| **E08** Network coverage | Process-exec telemetry captured (`sh, wget, ssl_client`); **no connect event** (no network tracing policy). Tetragon network detection = `not_evaluated`. Tracee (E03) did capture the connect to :443; Falco network detection = `not_evaluated`. |
| **E09** Sequence/timing (derived) | Process chain changes across variants (`sh,id → sh,sh,id → sh,sleep,sleep,id`) while **every stage stays observable** in all tools. Describes observability, not evasion. |

### 3.5 CVE compatibility assessment

Three candidate CVEs were researched against the **actual host kernel** (`7.1.5+kali-arm64`,
`aarch64`; a second kernel `6.19.14` is also installed):

| CVE | Class | Affected | Fixed | Applicability status | Reproduction |
|-----|-------|----------|-------|----------------------|--------------|
| CVE-2022-0847 Dirty Pipe | uninit pipe_buffer.flags | ≥5.8 | 5.16.11 / 5.15.25 / 5.10.102 | `NOT_AFFECTED_OR_PATCHED` (kernel past fix) | `NOT_REPRODUCED` |
| CVE-2021-3493 OverlayFS | userns authz (Ubuntu patch) | Ubuntu ≤5.8.0-50 | 5.8.0-50.56 … | `INCOMPATIBLE_ENVIRONMENT` (Kali, not Ubuntu) | `NOT_REPRODUCED` |
| CVE-2024-1086 nf_tables | UAF (CWE-416) | 3.15–<6.8 | 5.15.149 / 6.1.76 / 6.6.15 / 6.7.3 | `NOT_AFFECTED_OR_PATCHED` (kernel past range) | `NOT_REPRODUCED` |

No genuine reproduction was performed. The host kernel is not vulnerable to any candidate, no
isolated snapshot-backed vulnerable VM is configured, and exploit execution on the project host
is out of scope. The CVE lab therefore offers compatibility assessment, safe simulation (Mode A,
benign related telemetry), and recorded replay (Mode C); isolated reproduction (Mode B) is
blocked and documented per CVE. **No simulation is represented as a real exploitation.**

---

## 4. Interpretations (supported by the evidence)

1. **Observability is strong and robust across all three tools.** Every execution stage of
   every experiment was captured by every tool. Neither the extra shell layer (E04) nor the
   2-second delays (E05) reduced process-execution visibility.

2. **Visibility ≠ detection.** Genuine security detections are scarce in this dataset, and
   for a precise reason: Tracee and Tetragon are telemetry-only here, and Falco's *built-in*
   coverage raised a security detection only for the sensitive-file case (E01). Falco's
   E02/E04/E05 alerts come from the lab's own process-execution rule — useful as an
   observability signal, but not a malicious-behavior verdict.

3. **E03 is a rule-coverage gap, not a visibility gap.** The outbound connection *was*
   visible — Tracee captured the `connect` to port 443. No tool, however, raised a
   network-specific detection (Falco's fired rule was process-exec; Tetragon had no network
   policy; Tracee had no signature). The event was available for a policy to evaluate; no
   policy evaluated it.

4. **Tetragon E01 pathname visibility is now established.** The `sys_openat` tracing policy
   captured the pathname argument `/etc/shadow`, upgrading the previously-incomplete
   pathname claim to confirmed *telemetry* (still not a detection verdict).

---

## 5. Hypotheses (not yet confirmed)

- **H1 — Exec-less mechanisms may reduce visibility.** All tested indirection still used
  `execve`. Mechanisms that avoid `execve` (io_uring-based execution, `memfd` + direct jump,
  interpreter-internal execution) are the plausible path to reduced process-execution
  visibility. *Untested here.*
- **H2 — Collection may degrade under load.** No experiment stressed the ring buffer. High
  event volume could in principle cause drops. *Untested here.*
- **H3 — Finer timing could matter.** 2-second delays are far from any aggregation/flush
  regime; a sweep of delay magnitudes and burst patterns is needed before claiming timing
  insensitivity in general.

Each hypothesis is mapped to a validating experiment in the dashboard's **Failure-Mechanism
Investigation** view. No layer is labeled a "confirmed blind spot" without evidence.

---

## 6. Future work

1. Add a Falco network rule and a Tetragon `connect` tracing policy, then re-run E03 to test
   whether the network event becomes a detection (directly validates interpretation #3).
2. Add Tracee signatures to convert its telemetry into detections, enabling a true
   like-for-like detection comparison.
3. Implement H1: an io_uring / `memfd` execution experiment (E06+), as an *advanced*
   experiment only after the core analysis stays reproducible.
4. Burst/throughput experiments for H2; a timing sweep for H3.
5. Collect detector-internal latency where the tooling exposes it.

---

## 7. Threats to validity

- **Single environment / single run per cell.** Results are from one kernel/arch and are not
  averaged over repeated trials; counts, not distributions.
- **Benign workloads.** By design (safety), no real exploitation; findings describe
  observability of benign analogues, not adversary tradecraft.
- **Configuration-bound.** Conclusions are bound to these specific detector configurations.
  A different Falco ruleset or Tracee signature set would change the detection columns
  entirely.
- **Telemetry-only tools.** Comparing a detection column (Falco) with telemetry columns
  (Tracee/Tetragon) is apples-to-oranges for *detection*; it is apples-to-apples for
  *visibility*. The dashboard keeps these separate for exactly this reason.

---

## 8. Conclusion

Within the tested behaviors and configurations, **simple execution indirection and controlled
timing variation did not eliminate process-execution observability** under Falco, Tracee, or
Tetragon. The more consequential observation is structural: **event visibility was near-total,
while security detection was sparse and concentrated in Falco's built-in sensitive-file rule.**
The gap between "the kernel saw it" and "a policy flagged it" — most sharply visible in the
E03 network case — is where runtime-security value is won or lost, and is the right target for
the next round of experiments. This study does **not** demonstrate immunity to adaptive
evasion; it establishes a reproducible, honest baseline against which stronger adaptive
techniques can be measured.
