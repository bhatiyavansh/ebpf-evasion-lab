# Limitations & Defensive Recommendations

## Comparison study limitations (A1–A3)

1. **Sample size.** 3 live trials per scenario×tool×config cell — descriptive repeatability, not a
   statistically powered claim. Per-trial outcomes and run IDs are preserved.
2. **Configured track is partial.** "Configured" detection was implemented for Falco (built-in rules)
   and Tetragon (selective sensitive-file policy). A Tracee signature-engine detection was **not**
   enabled, so Tracee's configured detection is `NOT_EVALUATED`, not a failure or a miss.
3. **Benign emulation.** A1 reads alpine's throwaway `/etc/shadow` (no real secret); A2/A3 run benign
   discovery/shell commands. These exercise detection *paths*, not real credential theft, privilege
   escalation, or exploitation.
4. **Scenario-bounded detection.** A2 (nested shell) and A3 (discovery) produced no qualifying
   detection from any tool, Falco included — because no shell/discovery-specific rule was enabled,
   not because the behavior was invisible (it was fully observed as telemetry).
5. **Single environment / single ruleset version.** One kernel, one arch, the shipped Falco 0.45.0
   ruleset; a different ruleset or signature set would change the detection columns.

## E01–E09 baseline limitations (what the observability study does and does not show)

1. **Telemetry-only posture for two of three tools.** Tracee and Tetragon are configured as
   event collectors (no signatures / no alerting policies). Their "no detections" result is a
   property of the *configuration*, not a weakness of the tools. Do not read their columns as
   detection failures.

2. **Falco process-execution alerts are from a custom rule.** E02/E04/E05 Falco "detections"
   come from the lab's own `EBPF_LAB` process-execution rule, not a built-in threat policy.
   Only E01 (sensitive file) is a shipped security rule. The dashboard tags this as
   `custom research` vs `builtin security`.

3. **No latency data.** Detector-internal timing was not measured; any latency figure would
   be fabricated and is reported as unavailable.

4. **Single run, single environment.** One kernel (`7.1.5+kali-arm64`), one architecture
   (`aarch64`), one trial per cell. Results are counts, not distributions; no statistical
   significance is claimed.

5. **Benign behaviors only.** For safety, all workloads are benign analogues (reading a file,
   running `id`, an HTTPS `wget`). The study measures *observability of these behaviors*, not
   real adversary tradecraft or container escape.

6. **Adaptive variants are deliberately mild.** An extra POSIX shell layer and 2-second
   delays are the weakest end of "adaptive." They do not exercise exec-less execution,
   ring-buffer pressure, or sub-sampling-scale timing. **No immunity to evasion is claimed or
   implied.**

7. **E03/E08 network coverage is uneven by configuration.** Only Tracee had a network event
   source (`connect`); Falco's fired rule was process-exec and Tetragon had no network
   policy, so cross-tool network *detection* comparison is `not_evaluated`, not failed.

8. **E06 repeatability is exploratory (n=5).** Five identical trials describe determinism of
   telemetry capture; they are not a statistical claim and no variance/significance is computed.

9. **E07/E08/E06 are Tetragon-only.** These extended experiments were captured live for
   Tetragon; Falco/Tracee cells for them are `not_applicable` (out of scope), not failures.

10. **No CVE was reproduced.** All three candidate CVEs assess as *not applicable* on the host
    kernel (`7.1.5`, far newer than every affected range). The CVE lab provides compatibility
    assessment and safe simulation only. Mode B (isolated reproduction) is blocked by design;
    no exploit is run on the project host, and no simulation is presented as real exploitation.
    A real reproduction would require a disposable, snapshot-backed VM pinned to an affected
    kernel — out of scope here.

## Defensive recommendations (supported by the findings)

These follow directly from the evidence — chiefly the visibility-vs-detection gap:

1. **Do not equate telemetry deployment with detection.** A tool emitting rich eBPF telemetry
   (as Tracee/Tetragon do here) provides *visibility*, but delivers *detection* only when
   paired with signatures/policies that evaluate those events. Deploy the alerting layer, not
   just the collector.

2. **Close the network-detection gap explicitly.** The E03 connection was visible but
   undetected. Add network-aware rules/policies (Falco network rules; Tetragon `connect`
   tracing/enforcement policies; Tracee signatures) and verify they fire — visibility of
   `connect` is necessary but not sufficient.

3. **Confirm pathname-level file policies, not just open telemetry.** Tetragon captured the
   `/etc/shadow` pathname but did not *act* on it. Pair sensitive-path tracing policies with
   enforcement or alerting so that a sensitive open is a detection, not just a log line.

4. **Instrument the detection layer, not only the kernel-event layer.** The six-layer failure
   model (kernel visibility → collection → enrichment → policy evaluation → timing → mechanism)
   shows that in this dataset the gaps live at the **policy-evaluation** layer, not the
   visibility layer. Monitoring and testing should target rule/policy coverage.

5. **Plan for exec-less execution.** Because all detection here keys on `execve`/exec
   telemetry, defenders should add coverage for mechanisms that avoid it (io_uring op
   auditing, `memfd_create` monitoring) before assuming process-execution rules are
   sufficient.

6. **Continuously validate detections, not just collection health.** The integrity model used
   here — never counting an observed event as a detection — is a useful discipline for
   production detection engineering: test that the *policy* fires on the behavior, with
   evidence, rather than trusting that visibility implies coverage.
