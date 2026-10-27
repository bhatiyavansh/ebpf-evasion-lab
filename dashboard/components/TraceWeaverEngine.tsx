"use client";

import { useMemo, useState } from "react";
import type { EngineResult, EngineSummary, Evaluation } from "@/lib/types";
import { Panel, Metric, JsonBlock } from "./ui";

const VERDICT_STYLE: Record<string, string> = {
  DETECTED: "border-status-detected/40 bg-status-detected/10 text-status-detected",
  TELEMETRY_ONLY: "border-status-observed/30 bg-status-observed/10 text-status-observed",
  NOT_DETECTED: "border-surface-border bg-surface-inset text-ink-muted",
  COLLECTION_FAILED: "border-status-missed/40 bg-status-missed/10 text-status-missed",
  EXECUTION_FAILED: "border-status-missed/40 bg-status-missed/10 text-status-missed",
  INCONCLUSIVE: "border-status-partial/30 bg-status-partial/10 text-status-partial",
};
const BAND_COLOR: Record<string, string> = { HIGH: "text-status-missed", SUSPICIOUS: "text-status-partial", LOW: "text-ink-faint" };

function VerdictChip({ v }: { v: string }) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider ${VERDICT_STYLE[v] ?? VERDICT_STYLE.INCONCLUSIVE}`}>{v.replace(/_/g, " ")}</span>;
}

export default function TraceWeaverEngine({
  summary,
  results,
  evaluation,
}: {
  summary: EngineSummary | null;
  results: EngineResult[];
  evaluation: Evaluation | null;
}) {
  const nonBaseline = useMemo(() => results.filter((r) => !r.is_baseline_stream), [results]);
  const [sel, setSel] = useState<string>(
    nonBaseline.find((r) => r.verdict === "DETECTED")?.stream ?? nonBaseline[0]?.stream ?? ""
  );
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [rawOpen, setRawOpen] = useState(false);

  if (!summary || results.length === 0) {
    return (
      <Panel title="TraceWeaver Engine" kicker="Phase 2 — detection engine">
        <div className="rounded-lg border border-surface-border bg-surface-inset p-6 text-center text-[12px] text-ink-faint">
          No engine output. Run <span className="mono text-ink-muted">python3 -m scripts.traceweaver.run</span>.
        </div>
      </Panel>
    );
  }

  const selected = results.find((r) => r.stream === sel);
  const filtered = nonBaseline.filter((r) => verdictFilter === "all" || r.verdict === verdictFilter);

  return (
    <div className="space-y-5">
      {/* Overview */}
      <Panel title="TraceWeaver Engine" kicker={`v${summary.engine_version} · visibility-aware, evidence-grounded`}>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          <Metric value={summary.total_streams} label="Streams scored" />
          {Object.entries(summary.verdict_distribution).map(([k, v]) => (
            <Metric key={k} value={v} label={k.replace(/_/g, " ").toLowerCase()} tone={k === "DETECTED" ? "accent" : k.includes("FAILED") ? "warn" : "default"} />
          ))}
        </div>
        <p className="mt-3 text-[10.5px] leading-relaxed text-ink-faint">
          Risk = 100·(wA·A + wS·S + wP·P). A verdict of <span className="text-status-detected">DETECTED</span> requires
          verified policy evidence (P&gt;0); a high risk score never overrides a{" "}
          <span className="text-status-missed">COLLECTION_FAILED</span> / EXECUTION_FAILED. Baseline/training
          streams ({summary.baseline_fit_on.length}) are excluded from the trial list below.
        </p>
      </Panel>

      {/* Evaluation */}
      {evaluation && (
        <Panel title="Evaluation" kicker={`${evaluation.eligible_count} eligible trials · exploratory (small sample)`}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-[12px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-ink-faint">
                  <th className="pb-2 pr-3 font-medium">Method</th>
                  <th className="pb-2 pr-3 font-medium">TP</th><th className="pb-2 pr-3 font-medium">FP</th>
                  <th className="pb-2 pr-3 font-medium">TN</th><th className="pb-2 pr-3 font-medium">FN</th>
                  <th className="pb-2 pr-3 font-medium">Precision</th><th className="pb-2 pr-3 font-medium">Recall</th><th className="pb-2 pr-3 font-medium">F1</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(evaluation.methods as Record<string, { metrics: Record<string, number | null> }>).map(([m, d]) => {
                  const x = d.metrics;
                  const hl = m === "combined";
                  return (
                    <tr key={m} className={`border-t border-surface-border ${hl ? "bg-accent/5" : ""}`}>
                      <td className={`py-2 pr-3 ${hl ? "font-semibold text-accent" : "text-ink"}`}>{m}{hl ? " (TraceWeaver)" : ""}</td>
                      <td className="py-2 pr-3 mono text-status-detected">{x.tp}</td>
                      <td className="py-2 pr-3 mono text-status-missed">{x.fp}</td>
                      <td className="py-2 pr-3 mono text-ink-muted">{x.tn}</td>
                      <td className="py-2 pr-3 mono text-status-partial">{x.fn}</td>
                      <td className="py-2 pr-3 mono text-ink">{x.precision ?? "N/A"} <span className="text-ink-faint">({x.precision_denom})</span></td>
                      <td className="py-2 pr-3 mono text-ink">{x.recall ?? "N/A"} <span className="text-ink-faint">({x.recall_denom})</span></td>
                      <td className="py-2 pr-3 mono text-ink">{x.f1 ?? "N/A"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-[10.5px] leading-relaxed text-ink-faint">
            &ldquo;Flag&rdquo; = surfaced-as-suspicious (not a verified detection). TraceWeaver lifts recall over
            rules-only by surfacing suspicious behavior via sequence + anomaly signals, while keeping perfect
            precision on the benign control. Any remaining FN is an honest per-sensor coverage gap. Denominators shown.
          </p>
        </Panel>
      )}

      {/* Trial explorer */}
      <div className="grid gap-5 lg:grid-cols-5">
        <div className="lg:col-span-2">
          <Panel title="Trials" kicker="select to inspect" right={
            <select value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value)} className="rounded-md border border-surface-border bg-surface-raised px-2 py-1 text-[11px] text-ink">
              <option value="all">all verdicts</option>
              {Object.keys(summary.verdict_distribution).map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          }>
            <div className="max-h-[32rem] space-y-1 overflow-auto">
              {filtered.map((r) => (
                <button key={r.stream} onClick={() => { setSel(r.stream); setRawOpen(false); }}
                  className={`w-full rounded-md border px-2.5 py-1.5 text-left text-[11px] transition ${sel === r.stream ? "border-accent/50 bg-accent/10" : "border-surface-border hover:bg-surface-hover"}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-ink">{r.scenario_id} · {r.sensor}</span>
                    <VerdictChip v={r.verdict} />
                  </div>
                  <div className="mt-0.5 text-[9.5px] text-ink-faint mono">risk {r.risk_score} · {r.trial_id}</div>
                </button>
              ))}
            </div>
          </Panel>
        </div>

        <div className="lg:col-span-3">
          {selected ? (
            <Panel title={`${selected.scenario_id} · ${selected.sensor}`} kicker={selected.stream}
              right={<span className="rounded bg-surface-inset px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-status-observed mono">{selected.capture_mode}</span>}>
              {/* verdict + visibility + risk */}
              <div className="flex flex-wrap items-center gap-3">
                <VerdictChip v={selected.verdict} />
                <span className="text-[11px] text-ink-faint">visibility: <span className="text-ink-muted">{selected.visibility_status}</span></span>
                <span className="ml-auto text-[13px] font-semibold mono">
                  risk <span className={BAND_COLOR[selected.risk_band]}>{selected.risk_score}</span> <span className="text-ink-faint text-[10px]">{selected.risk_band}</span>
                </span>
              </div>
              <p className="mt-1.5 text-[11.5px] text-ink-muted">{selected.verdict_reason}</p>

              {/* component scores */}
              <div className="mt-3 grid grid-cols-3 gap-2">
                {([["A_anomaly", "Anomaly (A)"], ["S_sequence", "Sequence (S)"], ["P_policy", "Policy (P)"]] as const).map(([k, label]) => (
                  <div key={k} className="rounded-md border border-surface-border bg-surface-raised p-2.5">
                    <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{label}</div>
                    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-inset">
                      <div className="h-full rounded-full bg-accent" style={{ width: `${selected.component_scores[k] * 100}%` }} />
                    </div>
                    <div className="mt-0.5 text-[11px] text-ink mono">{selected.component_scores[k]}</div>
                  </div>
                ))}
              </div>

              {/* findings */}
              {selected.findings.length > 0 && (
                <div className="mt-3">
                  <div className="text-[10px] uppercase tracking-wide text-ink-faint">Triggered patterns</div>
                  <div className="mt-1 space-y-1.5">
                    {selected.findings.map((f, i) => (
                      <div key={i} className="rounded-md border border-surface-border bg-surface-inset p-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[11.5px] font-semibold text-ink">{f.pattern}</span>
                          <span className="text-[10px] text-ink-faint">sev {f.severity} · {f.mitre.join(", ")}</span>
                        </div>
                        <div className="text-[10.5px] text-ink-muted">{f.explanation}</div>
                        <div className="mt-0.5 text-[9.5px] text-ink-faint mono">evidence: {f.raw_refs.slice(0, 2).map((r) => `${r.file.split("/").pop()}:${r.line}`).join(", ")}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* process timeline */}
              {selected.process_timeline.length > 0 && (
                <div className="mt-3">
                  <div className="text-[10px] uppercase tracking-wide text-ink-faint">Process timeline</div>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] mono">
                    {selected.process_timeline.slice(0, 12).map((p, i, arr) => (
                      <span key={i} className="flex items-center gap-1.5">
                        <span className="rounded bg-surface-inset px-1.5 py-0.5 text-ink" title={`${p.args} · ${p.raw_ref?.file}:${p.raw_ref?.line}`}>{p.process}</span>
                        {i < Math.min(arr.length, 12) - 1 && <span className="text-ink-faint">→</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* behavior graph summary */}
              <div className="mt-3 grid grid-cols-4 gap-2 text-[10.5px]">
                <GKV k="graph nodes" v={selected.graph_summary.nodes} />
                <GKV k="edges" v={selected.graph_summary.edges} />
                <GKV k="identity gaps" v={selected.graph_summary.identity_gaps} />
                <GKV k="events" v={selected.event_count} />
              </div>

              {/* explanation */}
              <div className="mt-3 rounded-md border border-accent/20 bg-accent/5 p-3">
                <div className="text-[10px] font-semibold uppercase tracking-widest text-accent/80">Explanation</div>
                <ul className="mt-1 space-y-1 text-[11px] leading-relaxed text-ink-muted">
                  {selected.explanations.map((e, i) => <li key={i}>• {e}</li>)}
                </ul>
              </div>

              {/* evidence drill-down */}
              <details className="mt-3" open={rawOpen} onToggle={(e) => setRawOpen((e.target as HTMLDetailsElement).open)}>
                <summary className="cursor-pointer text-[11px] text-accent hover:underline">Inspect full engine result (JSON)</summary>
                <div className="mt-2"><JsonBlock data={selected} maxH="max-h-96" /></div>
              </details>
            </Panel>
          ) : (
            <Panel title="Trial detail"><div className="text-[12px] text-ink-faint">Select a trial.</div></Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function GKV({ k, v }: { k: string; v: number }) {
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-2 py-1.5">
      <div className="text-[9px] uppercase tracking-wide text-ink-faint">{k}</div>
      <div className="text-[12px] text-ink mono">{v}</div>
    </div>
  );
}
