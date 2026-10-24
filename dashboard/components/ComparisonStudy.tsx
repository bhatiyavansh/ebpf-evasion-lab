"use client";

import { useState } from "react";
import type { Comparison, ComparisonScenario } from "@/lib/types";
import { Panel, Metric, OutcomeBadge, OUTCOME_META, JsonBlock } from "./ui";

const TRACK_ORDER = ["falco", "tracee", "tetB", "tetC"];
const TRACK_LABEL: Record<string, string> = {
  falco: "Falco",
  tracee: "Tracee",
  tetB: "Tetragon (baseline)",
  tetC: "Tetragon (configured)",
};

export function DetectionRateChart({ comparison }: { comparison: Comparison }) {
  const b = comparison.detection_rates.baseline;
  const c = comparison.detection_rates.configured;
  return (
    <Panel title="Confirmed detection rate" kicker="qualifying detections / eligible executed evaluations">
      <div className="space-y-4">
        <RateBar label="Baseline configuration" num={b.detections} den={b.eligible_evaluations} rate={b.rate} />
        <RateBar label="Configured detection" num={c.detections} den={c.eligible_evaluations} rate={c.rate} />
      </div>
      <p className="mt-3 text-[10.5px] leading-relaxed text-ink-faint">
        Rate = qualifying detections ÷ eligible, successfully-executed evaluations. Execution failures
        and unavailable evaluations are excluded from the denominator. A zero denominator shows N/A, not
        0%. &ldquo;Configured&rdquo; enables a documented detection policy (Falco built-in rules;
        Tetragon selective sensitive-file policy); it does not fabricate detections.
      </p>
    </Panel>
  );
}

function RateBar({ label, num, den, rate }: { label: string; num: number; den: number; rate: number | null }) {
  const pct = rate == null ? 0 : Math.round(rate * 100);
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-[12px]">
        <span className="font-semibold text-ink">{label}</span>
        <span className="mono text-ink-muted">
          {rate == null ? "N/A" : `${pct}%`} <span className="text-ink-faint">({num}/{den})</span>
        </span>
      </div>
      <div className="h-4 w-full overflow-hidden rounded-full bg-surface-inset">
        <div className="h-full rounded-full bg-status-detected transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export function DetectionMatrix({ comparison, onScenario }: { comparison: Comparison; onScenario?: (id: string) => void }) {
  return (
    <Panel title="Detection matrix" kicker="scenario × tool/config · live trials (count shown per cell)">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider text-ink-faint">
              <th className="w-56 pb-3 pr-3 font-medium">Scenario</th>
              {TRACK_ORDER.map((t) => (
                <th key={t} className="pb-3 pr-3 font-medium">{TRACK_LABEL[t]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {comparison.scenarios.map((sc) => (
              <tr key={sc.id} className={`border-t border-surface-border ${onScenario ? "cursor-pointer hover:bg-surface-hover" : ""}`} onClick={() => onScenario?.(sc.id)}>
                <td className="py-3 pr-3">
                  <div className="text-[13px] font-medium text-ink">{sc.id} · {sc.title}</div>
                  <div className="text-[9.5px] text-ink-faint">{sc.mitre.join(" · ")}</div>
                </td>
                {TRACK_ORDER.map((t) => {
                  const cell = sc.cells[t];
                  if (!cell) return <td key={t} className="py-3 pr-3 text-ink-faint">—</td>;
                  const m = OUTCOME_META[cell.headline_outcome];
                  return (
                    <td key={t} className="py-3 pr-3">
                      <div className={`rounded-lg border ${m.border} ${m.bg} px-2.5 py-2`}>
                        <OutcomeBadge outcome={cell.headline_outcome} />
                        <div className="mt-1 text-[9.5px] text-ink-faint mono">
                          det {cell.detections}/{cell.valid_trials ?? cell.trials_total}
                          {cell.trials_total !== (cell.valid_trials ?? cell.trials_total)
                            ? ` · ${cell.trials_total} ran` : " trials"}
                        </div>
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export function ScenarioDetail({ scenario }: { scenario: ComparisonScenario }) {
  const [tKey, setTKey] = useState<string>(Object.keys(scenario.cells)[0]);
  const cell = scenario.cells[tKey];
  return (
    <Panel title={`${scenario.id} · ${scenario.title}`} kicker={scenario.mitre.join(" · ")}>
      <div className="grid gap-3 lg:grid-cols-2">
        <Field label="Technique">{scenario.technique_note}</Field>
        <Field label="Payload (executed)"><code className="text-accent-bright mono text-[12px]">{scenario.payload}</code></Field>
        <Field label="Hypothesis">{scenario.hypothesis}</Field>
        <Field label="Qualifying detection criterion">{scenario.success_criteria}</Field>
      </div>

      <div className="mt-4 flex flex-wrap gap-1.5">
        {Object.keys(scenario.cells).map((k) => (
          <button key={k} onClick={() => setTKey(k)} className={`rounded-full border px-3 py-1 text-[11px] font-medium ${tKey === k ? "border-accent/50 bg-accent/15 text-accent" : "border-surface-border text-ink-muted hover:text-ink"}`}>
            {TRACK_LABEL[k]}
          </button>
        ))}
      </div>

      {cell && (
        <div className="mt-3 rounded-lg border border-surface-border bg-surface-inset p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-ink">{TRACK_LABEL[tKey]}</span>
              <OutcomeBadge outcome={cell.headline_outcome} />
            </div>
            <span className="text-[10.5px] text-ink-faint">
              {cell.detections}/{cell.trials_total} trials detected · expected {cell.expected}
            </span>
          </div>
          <div className="mt-1 text-[10.5px] text-ink-faint">config: {cell.config_note}</div>
          <div className="mt-3 space-y-1.5">
            {cell.trials.map((tr) => {
              const m = OUTCOME_META[tr.outcome];
              return (
                <div key={tr.trial} className="flex items-start gap-2.5 rounded-md border border-surface-border bg-surface-raised px-3 py-1.5">
                  <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${m.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11.5px] text-ink">Trial {tr.trial} · <span className={m.text}>{m.label}</span></span>
                      <span className="text-[9.5px] text-ink-faint mono">{tr.run_id}</span>
                    </div>
                    <div className="text-[10.5px] text-ink-faint">{tr.detail}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Panel>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-wider text-ink-faint">{label}</div>
      <div className="mt-0.5 text-[12px] leading-relaxed text-ink-muted">{children}</div>
    </div>
  );
}

export function BenignControl({ comparison }: { comparison: Comparison }) {
  const bc = comparison.benign_control;
  if (!bc) return null;
  return (
    <Panel title="Benign control — specificity check" kicker="A7 · ordinary activity should raise NO detection">
      <div className="flex flex-wrap items-center gap-2">
        {bc.rows.map((r) => (
          <div
            key={`${r.tool}-${r.config}`}
            className={`rounded-lg border px-3 py-2 ${
              r.specific ? "border-status-detected/30 bg-status-detected/10" : "border-status-missed/40 bg-status-missed/10"
            }`}
          >
            <div className="text-[12px] font-semibold text-ink">{r.tool} <span className="text-ink-faint">({r.config})</span></div>
            <div className={`text-[12px] font-semibold ${r.specific ? "text-status-detected" : "text-status-missed"}`}>
              {r.specific ? "✓ no false positives" : `✕ ${r.false_positive_detections} false positive(s)`}
            </div>
            <div className="text-[9.5px] text-ink-faint mono">{r.false_positive_detections}/{r.valid_trials} benign trials</div>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-ink-faint">{bc.note}</p>
    </Panel>
  );
}

export function CoverageNote({ comparison }: { comparison: Comparison }) {
  if (!comparison.coverage_note) return null;
  return (
    <div className="rounded-lg border border-status-partial/30 bg-status-partial/5 p-4">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-status-partial">
        Read this before the aggregate rate
      </div>
      <p className="mt-1 text-[12px] leading-relaxed text-ink-muted">{comparison.coverage_note}</p>
    </div>
  );
}

export function PerScenarioRates({ comparison }: { comparison: Comparison }) {
  const rows = comparison.per_scenario_rates ?? [];
  const byScenario = new Map<string, { title: string; baseline?: typeof rows[0]; configured?: typeof rows[0] }>();
  rows.forEach((r) => {
    const e = byScenario.get(r.scenario) ?? { title: r.title };
    e[r.condition] = r;
    byScenario.set(r.scenario, e);
  });
  return (
    <Panel title="Per-scenario detection rate" kicker="where detection actually happens — not the aggregate">
      <div className="space-y-3">
        {[...byScenario.entries()].map(([sid, e]) => (
          <div key={sid} className="rounded-lg border border-surface-border bg-surface-raised p-3">
            <div className="mb-2 text-[12px] font-semibold text-ink">{sid} · {e.title}</div>
            <div className="grid gap-2 sm:grid-cols-2">
              <MiniRate label="Baseline" r={e.baseline} />
              <MiniRate label="Configured" r={e.configured} />
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function MiniRate({ label, r }: { label: string; r?: { detection_trials: number; valid_trials: number; rate: number | null } }) {
  if (!r) return (
    <div className="rounded-md border border-surface-border bg-surface-inset px-3 py-2 text-[11px] text-ink-faint">
      {label}: <span className="mono">N/A</span> (no eligible evaluations)
    </div>
  );
  const pct = r.rate == null ? null : Math.round(r.rate * 100);
  const detected = (pct ?? 0) > 0;
  return (
    <div className="rounded-md border border-surface-border bg-surface-inset px-3 py-2">
      <div className="flex items-center justify-between text-[11px]">
        <span className="text-ink-muted">{label}</span>
        <span className={`mono font-semibold ${detected ? "text-status-detected" : "text-ink-faint"}`}>
          {pct == null ? "N/A" : `${pct}%`} <span className="text-ink-faint font-normal">({r.detection_trials}/{r.valid_trials} trials)</span>
        </span>
      </div>
      <div className="mt-1 h-2 w-full overflow-hidden rounded-full bg-surface-panel">
        <div className="h-full rounded-full bg-status-detected" style={{ width: `${pct ?? 0}%` }} />
      </div>
    </div>
  );
}

export function RepeatabilityView({ scenario }: { scenario: ComparisonScenario }) {
  return (
    <Panel title="Trial-by-trial repeatability" kicker={`${scenario.id} · each square is one independent live trial`}>
      <div className="space-y-2.5">
        {Object.entries(scenario.cells).map(([k, cell]) => (
          <div key={k} className="flex flex-wrap items-center gap-2">
            <span className="w-44 shrink-0 text-[11.5px] font-medium text-ink">{TRACK_LABEL[k]}</span>
            <div className="flex flex-wrap gap-1">
              {cell.trials.map((tr) => {
                const m = OUTCOME_META[tr.outcome];
                return (
                  <span
                    key={tr.trial}
                    title={`Trial ${tr.trial}: ${tr.outcome} — ${tr.detail}`}
                    className={`inline-flex h-5 w-5 items-center justify-center rounded border text-[9px] font-bold ${m.border} ${m.bg} ${m.text}`}
                  >
                    {tr.trial}
                  </span>
                );
              })}
            </div>
            <span className="text-[10.5px] text-ink-faint">
              {cell.detections}/{cell.valid_trials ?? cell.trials_total} detected
              {cell.trials_total !== (cell.valid_trials ?? cell.trials_total) ? ` · ${cell.trials_total} total` : ""}
            </span>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[10.5px] text-ink-faint">
        Hover a square for that trial&apos;s outcome and reason. Failed / collection-failed trials are
        shown (not hidden) and excluded from valid-trial denominators.
      </p>
    </Panel>
  );
}

export function QualifyingCriteria({ comparison }: { comparison: Comparison }) {
  return (
    <Panel title="Qualifying-detection criteria" kicker="defined before classification; applied deterministically">
      <div className="space-y-2">
        {Object.entries(comparison.qualifying_detection_criteria).map(([k, v]) => (
          <div key={k} className="rounded-md border border-surface-border bg-surface-raised px-3 py-2">
            <div className="text-[11px] font-semibold text-ink">{k.replace(/_/g, " ")}</div>
            <div className="text-[10.5px] leading-relaxed text-ink-muted">{v}</div>
          </div>
        ))}
      </div>
      <p className="mt-2 text-[10.5px] text-ink-faint">
        Outcomes are computed by <span className="mono">scripts/build_comparison.py</span> from captured
        evidence — no model decides whether a tool detected an attack.
      </p>
    </Panel>
  );
}
