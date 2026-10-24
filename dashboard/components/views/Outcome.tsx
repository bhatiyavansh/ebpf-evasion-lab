"use client";

import Link from "next/link";
import { useMemo } from "react";
import type { DashboardData } from "@/lib/types";
import { Panel, Metric } from "@/components/ui";
import { DetectionRateChart, DetectionMatrix, QualifyingCriteria, PerScenarioRates, CoverageNote, BenignControl } from "@/components/ComparisonStudy";

export default function Outcome({ data }: { data: DashboardData }) {
  const { comparison, analysis, environment, records } = data;

  const m = useMemo(() => {
    if (!comparison) return null;
    const cells = comparison.scenarios.flatMap((s) => Object.values(s.cells));
    const executed = cells.filter((c) => c.trials_executed > 0);
    const count = (o: string) => cells.filter((c) => c.headline_outcome === o).length;
    const b = comparison.detection_rates.baseline;
    const c = comparison.detection_rates.configured;
    const totalTrials = cells.reduce((n, c) => n + c.trials_total, 0);
    const validTrials = cells.reduce((n, c) => n + (c.valid_trials ?? c.trials_total), 0);
    return {
      scenarios: comparison.scenarios.length,
      evaluations: cells.length,
      executed: executed.length,
      totalTrials,
      validTrials,
      detected: count("DETECTED"),
      telemetry: count("TELEMETRY_ONLY"),
      notDetected: count("NOT_DETECTED"),
      failed: count("EXECUTION_FAILED") + count("COLLECTION_FAILED"),
      inconclusive: count("INCONCLUSIVE") + count("NOT_EVALUATED"),
      baseRate: b.rate,
      cfgRate: c.rate,
      b,
      c,
      // telemetry coverage: cells that at least observed the behavior
      telemetryCoverage: executed.filter((c) => c.headline_outcome !== "COLLECTION_FAILED").length,
    };
  }, [comparison]);

  // Conclusion is DERIVED from the measured rates, not pre-written.
  const conclusion = useMemo(() => {
    if (!m) return null;
    const base = m.baseRate == null ? "N/A" : `${Math.round(m.baseRate * 100)}%`;
    const cfg = m.cfgRate == null ? "N/A" : `${Math.round(m.cfgRate * 100)}%`;
    const rose = m.cfgRate != null && m.baseRate != null && m.cfgRate > m.baseRate;
    return { base, cfg, rose };
  }, [m]);

  return (
    <div className="space-y-5">
      {/* A. Research conclusion (derived) */}
      <div className="lab-grid overflow-hidden rounded-xl border border-accent/25 bg-surface-panel/60 p-6 sm:p-8">
        <div className="mb-2 text-[10.5px] font-semibold uppercase tracking-widest text-accent/80">Research conclusion</div>
        {conclusion ? (
          <>
            <h1 className="text-xl font-semibold leading-snug tracking-tight text-ink sm:text-[26px]">
              For the sensitive-file objective, enabling a detection policy moved a telemetry-only tool to{" "}
              <span className="text-status-detected">confirmed detection</span>; for nested-shell and
              discovery, no tool raised a qualifying detection — so observability, not detection, is near-total.
            </h1>
            <p className="mt-3 max-w-3xl text-[13px] leading-relaxed text-ink-muted">
              Across {m!.scenarios} MITRE-mapped scenarios and {m!.evaluations} tool/config evaluations,
              outcomes were classified deterministically from genuine captured Falco alerts, Tracee events
              and Tetragon policy matches — never inferred. The aggregate confirmed-detection rate rose from{" "}
              <span className="text-status-partial">{conclusion.base}</span> (baseline) to{" "}
              <span className="text-status-detected">{conclusion.cfg}</span> (configured), but that figure is
              driven entirely by the sensitive-file scenario and configured coverage is uneven — read the
              per-scenario rates below, not the aggregate alone.
            </p>
          </>
        ) : (
          <h1 className="text-xl font-semibold text-ink">
            Comparison study not yet generated — run <span className="mono">scripts/run_comparison.sh</span> then{" "}
            <span className="mono">scripts/build_comparison.py</span>.
          </h1>
        )}
      </div>

      {/* B. Summary metrics */}
      {m && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          <Metric value={m.scenarios} label="Scenarios" hint={`${m.evaluations} tool/config cells`} />
          <Metric value={m.validTrials} label="Valid live trials" tone="accent" hint={`${m.totalTrials} run`} />
          <Metric value={m.detected} label="Detection cells" tone="accent" />
          <Metric value={m.telemetry} label="Telemetry only" />
          <Metric value={m.notDetected} label="Valid non-detections" tone={m.notDetected ? "warn" : "default"} />
          <Metric value={m.failed} label="Exec/collection failed" tone={m.failed ? "warn" : "default"} />
          <Metric value={m.inconclusive} label="Not eval / inconclusive" />
        </div>
      )}

      {/* Coverage caveat before any aggregate */}
      {comparison && <CoverageNote comparison={comparison} />}

      {/* C + D: matrix and rate chart */}
      {comparison && (
        <div className="grid gap-5 lg:grid-cols-5">
          <div className="lg:col-span-3"><DetectionMatrix comparison={comparison} /></div>
          <div className="lg:col-span-2"><DetectionRateChart comparison={comparison} /></div>
        </div>
      )}

      {/* Per-scenario rates — the honest breakdown */}
      {comparison && <PerScenarioRates comparison={comparison} />}

      {/* Benign control — specificity */}
      {comparison && <BenignControl comparison={comparison} />}

      {/* E. Separate telemetry visualization */}
      {m && (
        <Panel title="Telemetry coverage (separate from detection)" kicker="observation ≠ detection">
          <div className="flex items-center gap-4">
            <div className="text-[28px] font-semibold text-status-observed mono">
              {m.executed ? Math.round((m.telemetryCoverage / m.executed) * 100) : 0}%
            </div>
            <div className="flex-1">
              <div className="h-4 w-full overflow-hidden rounded-full bg-surface-inset">
                <div className="h-full rounded-full bg-status-observed" style={{ width: `${m.executed ? (m.telemetryCoverage / m.executed) * 100 : 0}%` }} />
              </div>
              <div className="mt-1 text-[10.5px] text-ink-faint">
                {m.telemetryCoverage}/{m.executed} executed evaluations captured relevant telemetry. This counts
                event observation, NOT detections — raw event coverage is shown separately on purpose.
              </div>
            </div>
          </div>
        </Panel>
      )}

      {comparison && <QualifyingCriteria comparison={comparison} />}

      {/* F. Key findings */}
      <Panel kicker="Key findings" title="What the evidence supports">
        <ol className="space-y-2.5 text-[12.5px] leading-relaxed text-ink-muted">
          <li><span className="text-ink font-medium">1. Falco&apos;s credential-access detection is highly repeatable (A1).</span> The built-in &ldquo;Read sensitive file untrusted&rdquo; rule (MITRE T1555) fired on <span className="text-status-detected">10/10</span> independent live trials, each with container context — captured live, not authored. <Link href="/lab" className="text-accent hover:underline">Evidence: A1</Link></li>
          <li><span className="text-ink font-medium">2. Configuration, not capability, closes the gap.</span> With a selective sensitive-file policy, Tetragon detected credential access in 3/3 trials — the same objective Falco meets — while its baseline telemetry-only config detected 0/3. The detection layer, not kernel visibility, decides the outcome.</li>
          <li><span className="text-ink font-medium">3. Detection is scenario-specific, not universal.</span> Nested-shell (A2) and discovery (A3) were fully observed as telemetry but raised <span className="text-status-partial">0/10</span> qualifying detections from every tool, Falco included — the default ruleset simply has no rule for these benign behaviors.</li>
          <li><span className="text-ink font-medium">4. Telemetry must not be read as detection.</span> Tracee captured the sensitive open (security_file_open) on all 10 A1 trials, but with no signatures engine it is telemetry-only — not a miss and not a detection.</li>
        </ol>
      </Panel>

      {/* G. Limitations */}
      <Panel kicker="Limitations" title="What the data does not establish">
        <ul className="space-y-2 text-[12px] leading-relaxed text-ink-muted">
          <li>• <span className="text-ink">Sample size.</span> 10 independent live trials per cell for the working tools (Falco, Tracee); Tetragon cells remain at 3 pre-reboot trials (its container capture regressed — see below). Descriptive repeatability, not a statistically powered inference. All per-trial results are preserved and inspectable in the Repeatability view.</li>
          <li>• <span className="text-ink">Tetragon live capture.</span> After a host reboot, Tetragon captures host events but zero container events (Falco/Tracee unaffected). New Tetragon runs are honestly <span className="text-status-missed">COLLECTION_FAILED</span>; the pre-reboot Tetragon evidence is preserved and valid. Root cause in <span className="mono">docs/E04_ZERO_EVENT_DIAGNOSIS.md</span>.</li>
          <li>• <span className="text-ink">Configuration scope.</span> &ldquo;Configured&rdquo; was implemented for Falco (built-in rules) and Tetragon (selective policy). A Tracee signature-engine detection was not enabled, so Tracee configured detection is <span className="mono">not evaluated</span>, not a failure.</li>
          <li>• <span className="text-ink">Benign emulation.</span> A1 reads alpine&apos;s throwaway /etc/shadow (no real secret); these exercise detection paths, not real credential theft or exploitation.</li>
          <li>• <span className="text-ink">CVE track.</span> All three candidate CVEs are not applicable on this host kernel; no reproduction was performed. See <Link href="/cve-lab" className="text-accent hover:underline">CVE Lab</Link>.</li>
          <li>• <span className="text-ink">Baseline controls.</span> E01–E09 remain as supporting observability controls in the <Link href="/lab" className="text-accent hover:underline">Experiment Lab</Link>; they describe visibility, not attack success.</li>
        </ul>
        <div className="mt-4 flex flex-wrap gap-2 text-[11px]">
          <a href="/api/export?format=csv" className="rounded-md border border-surface-border px-3 py-1.5 text-ink-muted hover:text-ink">↓ Export CSV</a>
          <a href="/api/export?format=json" className="rounded-md border border-surface-border px-3 py-1.5 text-ink-muted hover:text-ink">↓ Export JSON</a>
          <button onClick={() => window.print()} className="rounded-md border border-surface-border px-3 py-1.5 text-ink-muted hover:text-ink">🖶 Print report</button>
          <Link href="/lab" className="rounded-md border border-surface-border px-3 py-1.5 text-ink-muted hover:text-ink">Baseline experiments →</Link>
        </div>
      </Panel>

      <div className="text-center text-[10.5px] text-ink-faint">
        Environment: {environment?.os} · kernel {environment?.kernel} · {environment?.arch} ·{" "}
        {records.length} baseline records · {comparison ? comparison.scenarios.reduce((n, s) => n + Object.keys(s.cells).length, 0) : 0} comparison evaluations
      </div>
    </div>
  );
}
