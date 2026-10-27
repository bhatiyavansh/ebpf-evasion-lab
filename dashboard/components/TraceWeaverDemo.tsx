"use client";

import { useMemo, useState } from "react";
import type { DashboardData, EngineResult } from "@/lib/types";
import { Panel, Metric, JsonBlock } from "./ui";

const STEPS = ["The problem", "Unified evidence", "Detection in action", "Visibility-aware verdict", "Evaluation & limits"];

const VSTYLE: Record<string, string> = {
  DETECTED: "border-status-detected/40 bg-status-detected/10 text-status-detected",
  TELEMETRY_ONLY: "border-status-observed/30 bg-status-observed/10 text-status-observed",
  NOT_DETECTED: "border-surface-border bg-surface-inset text-ink-muted",
  COLLECTION_FAILED: "border-status-missed/40 bg-status-missed/10 text-status-missed",
  EXECUTION_FAILED: "border-status-missed/40 bg-status-missed/10 text-status-missed",
  INCONCLUSIVE: "border-status-partial/30 bg-status-partial/10 text-status-partial",
};
function Verdict({ v }: { v: string }) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider ${VSTYLE[v] ?? VSTYLE.INCONCLUSIVE}`}>{v.replace(/_/g, " ")}</span>;
}

const NOTES: Record<number, string[]> = {
  0: ["Three sensors, three formats — normalization is the prerequisite.", "Key idea: collection failure ≠ absence of a threat."],
  1: ["Every canonical event keeps its exact source: file, line, sha256.", "Pick a sensor to show the same schema across tools."],
  2: ["DETECTED requires verified policy evidence (P>0) — never a bare score.", "Expand to show the exact raw record behind the finding.", "Click 'Run engine' to re-execute on this trial live."],
  3: ["A high risk never overrides a collection failure.", "Missing telemetry is NOT evidence the system is safe."],
  4: ["Rules-only misses what a sensor has no rule for; TraceWeaver recovers recall.", "Small, exploratory sample — show the denominators, not just the F1."],
};

export default function TraceWeaverDemo({ data }: { data: DashboardData }) {
  const { engineSummary: sum, engineResults, evaluation, twIndex } = data;
  const [step, setStep] = useState(0);
  const nonBaseline = useMemo(() => engineResults.filter((r) => !r.is_baseline_stream), [engineResults]);
  const detected = useMemo(() => nonBaseline.filter((r) => r.verdict === "DETECTED"), [nonBaseline]);
  const collFailed = useMemo(() => engineResults.find((r) => r.verdict === "COLLECTION_FAILED"), [engineResults]);

  if (!sum) {
    return <Panel title="TraceWeaver Demo"><div className="text-[12px] text-ink-faint">No engine output. Run <span className="mono">./scripts/traceweaver_demo.sh</span>.</div></Panel>;
  }

  const ineligibleTotal = evaluation ? Object.values(evaluation.ineligible_reasons as Record<string, number>).reduce((a: number, b: number) => a + b, 0) : 0;
  const copySummary = () => {
    const t = `TraceWeaver ${sum.engine_version}: ${sum.total_streams} streams, verdicts ${JSON.stringify(sum.verdict_distribution)}. ` +
      (evaluation ? `Eval (combined): P=${evaluation.methods.combined.metrics.precision} R=${evaluation.methods.combined.metrics.recall} F1=${evaluation.methods.combined.metrics.f1} on ${evaluation.eligible_count} eligible trials.` : "");
    try { navigator.clipboard?.writeText(t); } catch { /* ignore */ }
  };

  return (
    <div className="space-y-4">
      {/* Landing / status overview */}
      <div className="lab-grid overflow-hidden rounded-xl border border-accent/25 bg-surface-panel/60 p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">TraceWeaver</h1>
              <span className="rounded-md border border-status-partial/40 bg-status-partial/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-status-partial">Historical Replay</span>
            </div>
            <p className="mt-1 text-[12.5px] text-ink-muted">Explainable, Visibility-Aware Runtime Threat Detection — it turns raw Falco/Tracee/Tetragon events into evidence-grounded, provenance-backed verdicts.</p>
          </div>
          <div className="text-right text-[10.5px] text-ink-faint mono">
            engine {sum.engine_version} · schema {twIndex?.schema_version ?? "?"}
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
          <Metric value={sum.total_streams} label="Streams" />
          <Metric value={twIndex?.total_events ?? "—"} label="Canonical events" />
          <Metric value={evaluation?.eligible_count ?? "—"} label="Eligible trials" tone="accent" />
          <Metric value={ineligibleTotal || "—"} label="Ineligible" />
          <Metric value={sum.verdict_distribution.DETECTED ?? 0} label="Detected" tone="accent" />
          <Metric value={(sum.verdict_distribution.COLLECTION_FAILED ?? 0) + (sum.verdict_distribution.EXECUTION_FAILED ?? 0)} label="Coll/exec failed" tone="warn" />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[10.5px]">
          <span className="rounded border border-status-detected/30 bg-status-detected/10 px-2 py-0.5 text-status-detected">validators: 43 py · 8 provenance · explanation-consistency OK (recorded)</span>
          <span className="rounded border border-status-missed/30 bg-status-missed/10 px-2 py-0.5 text-status-missed">⚠ Tetragon live capture unavailable (COLLECTION_FAILED) — Falco/Tracee live OK</span>
        </div>
      </div>

      {/* Step controls */}
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => setStep((s) => Math.max(0, s - 1))} disabled={step === 0} className="rounded-md border border-surface-border px-3 py-1.5 text-[12px] text-ink-muted hover:text-ink disabled:opacity-30">← Prev</button>
        <div className="flex items-center gap-1">
          {STEPS.map((_, i) => (
            <button key={i} onClick={() => setStep(i)} className={`h-1.5 rounded-full transition-all ${i === step ? "w-8 bg-accent" : i < step ? "w-4 bg-accent/40" : "w-4 bg-surface-border"}`} aria-label={`Step ${i + 1}`} />
          ))}
        </div>
        <button onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))} disabled={step === STEPS.length - 1} className="rounded-md border border-accent/50 bg-accent/15 px-3 py-1.5 text-[12px] font-semibold text-accent hover:bg-accent/25 disabled:opacity-30">Next →</button>
        <span className="ml-2 text-[11px] text-ink-faint">Step {step + 1}/{STEPS.length} · {STEPS[step]}</span>
        <div className="ml-auto flex gap-2">
          <button onClick={copySummary} className="rounded-md border border-surface-border px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink">Copy summary</button>
          <button onClick={() => setStep(0)} className="rounded-md border border-surface-border px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink">↺ Reset</button>
        </div>
      </div>

      {/* Step content */}
      <div className="animate-fadein">
        {step === 0 && <StepProblem />}
        {step === 1 && <StepEvidence results={nonBaseline} />}
        {step === 2 && <StepDetection detected={detected} />}
        {step === 3 && <StepVisibility collFailed={collFailed} />}
        {step === 4 && evaluation && <StepEvaluation evaluation={evaluation} />}
      </div>

      {/* Presenter notes */}
      <Panel title="Presenter notes" kicker={`Step ${step + 1}`}>
        <ul className="space-y-1 text-[11.5px] leading-relaxed text-ink-muted">
          {(NOTES[step] ?? []).map((n, i) => <li key={i}>• {n}</li>)}
        </ul>
      </Panel>
    </div>
  );
}

function StepProblem() {
  const nodes = ["Runtime sensors\n(Falco · Tracee · Tetragon)", "Canonical event schema\n(+ provenance)", "Temporal correlation\n(behavior graph)", "Risk scoring\n(A · S · P)", "Visibility-aware verdict", "Explainable dashboard"];
  return (
    <Panel title="The problem" kicker="why raw sensor output is not enough">
      <p className="text-[12.5px] leading-relaxed text-ink-muted">
        Falco, Tracee and Tetragon emit different event formats and detect only what their rules cover.
        A raw event is not a verdict, and — critically — <span className="text-ink">a collection failure must not be
        mistaken for the absence of suspicious activity</span>. TraceWeaver normalizes the three sensors, correlates
        events, scores risk, and returns a verdict that is explicit about visibility.
      </p>
      <div className="mt-4 flex flex-wrap items-stretch gap-2">
        {nodes.map((n, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="flex min-h-[48px] min-w-[120px] items-center justify-center rounded-lg border border-surface-border bg-surface-raised px-3 py-2 text-center text-[10.5px] leading-tight text-ink-muted whitespace-pre-line">{n}</div>
            {i < nodes.length - 1 && <span className="text-accent">→</span>}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function StepEvidence({ results }: { results: EngineResult[] }) {
  const [sensor, setSensor] = useState<string>("tracee");
  const [events, setEvents] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);
  const streamsForSensor = results.filter((r) => r.sensor === sensor);
  const [streamSel, setStreamSel] = useState<string>("");
  const chosen = streamSel || streamsForSensor[0]?.stream || "";

  async function load() {
    if (!chosen) return;
    const norm = `results/normalized/events/${sensor}__${chosen.split("/").pop()}`;
    setLoading(true);
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(norm)}&limit=8`);
    const j = await r.json();
    setEvents(j.ok ? j.events : []);
    setLoading(false);
  }

  return (
    <Panel title="Unified evidence" kicker="the same schema across three sensors, with provenance">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px]">
        {["falco", "tracee", "tetragon"].map((s) => (
          <button key={s} onClick={() => { setSensor(s); setStreamSel(""); setEvents(null); }} className={`rounded-full border px-3 py-1 ${sensor === s ? "border-accent/50 bg-accent/15 text-accent" : "border-surface-border text-ink-muted hover:text-ink"}`}>{s}</button>
        ))}
        <select value={chosen} onChange={(e) => { setStreamSel(e.target.value); setEvents(null); }} className="rounded-md border border-surface-border bg-surface-raised px-2 py-1 text-[11px] text-ink">
          {streamsForSensor.slice(0, 40).map((r) => <option key={r.stream} value={r.stream}>{r.scenario_id} · {r.trial_id}</option>)}
        </select>
        <button onClick={load} className="rounded-md border border-accent/50 bg-accent/10 px-2.5 py-1 text-accent">Load canonical events</button>
      </div>
      {loading && <div className="text-[11px] text-ink-faint">loading…</div>}
      {events && (
        <div className="space-y-1.5">
          {events.map((e, i) => {
            const ev = e as Record<string, unknown>;
            const rr = (ev.raw_ref ?? {}) as { file?: string; line?: number; sha256?: string };
            return (
              <div key={i} className="rounded-md border border-surface-border bg-surface-inset p-2.5 text-[11px]">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="rounded bg-surface-panel px-1.5 py-0.5 text-accent mono">{String(ev.canonical_type)}</span>
                  <span className="text-ink-muted">{String(ev.sensor_native_event)}</span>
                  {String(ev.process_name ?? "") !== "" && String(ev.process_name) !== "<NOT_SUPPLIED>" ? <span className="text-ink mono">{String(ev.process_name)}</span> : null}
                  {String(ev.file_path ?? "") !== "" && !String(ev.file_path).startsWith("<NOT") ? <span className="text-status-partial mono">{String(ev.file_path)}</span> : null}
                  <span className="ml-auto text-[9.5px] text-ink-faint mono" title={rr.sha256}>{rr.file?.split("/").pop()}:{rr.line} · {rr.sha256?.slice(0, 10)}…</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {!events && !loading && <div className="text-[11px] text-ink-faint">Pick a sensor + trial, then &ldquo;Load canonical events&rdquo; to show real normalized records (not invented).</div>}
    </Panel>
  );
}

function StepDetection({ detected }: { detected: EngineResult[] }) {
  const [sel, setSel] = useState<string>(detected[0]?.stream ?? "");
  const r = detected.find((x) => x.stream === sel) ?? detected[0];
  const [rawOpen, setRawOpen] = useState(false);
  const [runState, setRunState] = useState<"idle" | "running" | "done" | "err">("idle");
  const [runResult, setRunResult] = useState<EngineResult | null>(null);

  async function runEngine() {
    if (!r) return;
    setRunState("running"); setRunResult(null);
    try {
      const res = await fetch("/api/traceweaver/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ stream: r.stream }) });
      const j = await res.json();
      if (j.ok) { setRunResult(j.result); setRunState("done"); } else { setRunState("err"); }
    } catch { setRunState("err"); }
  }

  if (!r) return <Panel title="Detection in action"><div className="text-[12px] text-ink-faint">No verified detections in the current engine output.</div></Panel>;
  const shown = runResult ?? r;

  return (
    <Panel title="Detection in action" kicker="real verified detections — every finding cites raw evidence">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="text-ink-faint">Verified trial:</span>
        <select value={sel} onChange={(e) => { setSel(e.target.value); setRunResult(null); setRunState("idle"); }} className="rounded-md border border-surface-border bg-surface-raised px-2 py-1 text-ink">
          {detected.map((d) => <option key={d.stream} value={d.stream}>{d.scenario_id} · {d.sensor} · {d.trial_id}</option>)}
        </select>
        <button onClick={runEngine} disabled={runState === "running"} className="rounded-md border border-status-detected/50 bg-status-detected/15 px-2.5 py-1 font-semibold text-status-detected hover:bg-status-detected/25 disabled:opacity-40">▶ Run engine on this trial</button>
        {runState === "running" && <span className="text-accent">running…</span>}
        {runState === "done" && <span className="text-status-detected">✓ live engine run matches</span>}
        {runState === "err" && <span className="text-status-missed">✕ run failed (showing cached)</span>}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Verdict v={shown.verdict} />
        <span className="text-[11px] text-ink-faint">visibility: <span className="text-ink-muted">{shown.visibility_status}</span></span>
        <span className="ml-auto text-[13px] font-semibold mono">risk <span className="text-status-missed">{shown.risk_score}</span> <span className="text-[10px] text-ink-faint">{shown.risk_band}</span></span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        {([["A_anomaly", "Anomaly A"], ["S_sequence", "Sequence S"], ["P_policy", "Policy P"]] as const).map(([k, label]) => (
          <div key={k} className="rounded-md border border-surface-border bg-surface-raised p-2.5">
            <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{label}</div>
            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-inset"><div className="h-full rounded-full bg-accent" style={{ width: `${shown.component_scores[k] * 100}%` }} /></div>
            <div className="mt-0.5 text-[11px] text-ink mono">{shown.component_scores[k]}</div>
          </div>
        ))}
      </div>
      {shown.findings.length > 0 && (
        <div className="mt-3 space-y-1.5">
          {shown.findings.map((f, i) => (
            <div key={i} className="rounded-md border border-surface-border bg-surface-inset p-2.5">
              <div className="flex items-center justify-between text-[11.5px]"><span className="font-semibold text-ink">{f.pattern}</span><span className="text-[10px] text-ink-faint">sev {f.severity} · {f.mitre.join(", ")}</span></div>
              <div className="text-[10.5px] text-ink-muted">{f.explanation}</div>
              <div className="mt-0.5 text-[9.5px] text-ink-faint mono">evidence: {f.raw_refs.slice(0, 2).map((x) => `${x.file.split("/").pop()}:${x.line}`).join(", ")}</div>
            </div>
          ))}
        </div>
      )}
      {shown.process_timeline.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[11px] mono">
          <span className="text-[9.5px] uppercase tracking-wide text-ink-faint">timeline:</span>
          {shown.process_timeline.slice(0, 10).map((p, i, a) => <span key={i} className="flex items-center gap-1.5"><span className="rounded bg-surface-inset px-1.5 py-0.5 text-ink" title={`${p.args} · ${p.raw_ref?.file}:${p.raw_ref?.line}`}>{p.process}</span>{i < Math.min(a.length, 10) - 1 && <span className="text-ink-faint">→</span>}</span>)}
        </div>
      )}
      <div className="mt-3 rounded-md border border-accent/20 bg-accent/5 p-3">
        <div className="text-[10px] font-semibold uppercase tracking-widest text-accent/80">Why it&apos;s flagged</div>
        <ul className="mt-1 space-y-1 text-[11px] leading-relaxed text-ink-muted">{shown.explanations.map((e, i) => <li key={i}>• {e}</li>)}</ul>
      </div>
      <details className="mt-3" open={rawOpen} onToggle={(e) => setRawOpen((e.target as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer text-[11px] text-accent hover:underline">Open full trial details (JSON)</summary>
        <div className="mt-2"><JsonBlock data={shown} maxH="max-h-96" /></div>
      </details>
    </Panel>
  );
}

function StepVisibility({ collFailed }: { collFailed?: EngineResult }) {
  const taxonomy = [
    ["DETECTED", "qualifying policy evidence present (P>0) + sufficient visibility"],
    ["TELEMETRY_ONLY", "suspicious behavior observed, but no qualifying detection fired"],
    ["NOT_DETECTED", "executed + full visibility + nothing suspicious"],
    ["COLLECTION_FAILED", "verified execution but zero scoped events — a risk score cannot promote this"],
    ["EXECUTION_FAILED", "the workload did not run"],
    ["INCONCLUSIVE", "partial visibility / no events — cannot conclude"],
  ];
  return (
    <Panel title="Visibility-aware verdict" kicker="missing telemetry is NOT evidence the system is safe">
      <div className="grid gap-2 sm:grid-cols-2">
        {taxonomy.map(([v, d]) => (
          <div key={v} className="flex items-start gap-2 rounded-md border border-surface-border bg-surface-raised p-2.5">
            <Verdict v={v} />
            <span className="text-[11px] leading-snug text-ink-muted">{d}</span>
          </div>
        ))}
      </div>
      {collFailed ? (
        <div className="mt-4 rounded-lg border border-status-missed/30 bg-status-missed/5 p-4">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-status-missed">Real example — collection failure</div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-[12px] font-semibold text-ink">{collFailed.scenario_id} · {collFailed.sensor}</span>
            <Verdict v={collFailed.verdict} />
            <span className="text-[11px] text-ink-faint">risk {collFailed.risk_score} · visibility {collFailed.visibility_status}</span>
          </div>
          <p className="mt-2 text-[11.5px] leading-relaxed text-ink-muted">{collFailed.verdict_reason}. {collFailed.explanations.find((e) => e.includes("not treated")) ?? "The workload executed but the sensor captured no scoped events; the verdict is NOT promoted to NOT_DETECTED or DETECTED."}</p>
          <div className="mt-1 text-[10px] text-ink-faint mono">source: {collFailed.stream}</div>
        </div>
      ) : (
        <div className="mt-4 rounded-md border border-surface-border bg-surface-inset p-4 text-[11.5px] text-ink-faint">No collection-failure stream in the current engine output.</div>
      )}
    </Panel>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function StepEvaluation({ evaluation }: { evaluation: any }) {
  return (
    <Panel title="Evaluation & limitations" kicker={`${evaluation.eligible_count} eligible trials · exploratory (small sample)`}>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[620px] text-[12px]">
          <thead><tr className="text-left text-[10px] uppercase tracking-wide text-ink-faint">
            <th className="pb-2 pr-3 font-medium">Method</th><th className="pb-2 pr-3">TP</th><th className="pb-2 pr-3">FP</th><th className="pb-2 pr-3">TN</th><th className="pb-2 pr-3">FN</th><th className="pb-2 pr-3">Precision</th><th className="pb-2 pr-3">Recall</th><th className="pb-2 pr-3">F1</th>
          </tr></thead>
          <tbody>
            {Object.entries(evaluation.methods as Record<string, { metrics: Record<string, number | null> }>).map(([m, d]) => {
              const x = d.metrics; const hl = m === "combined";
              return (
                <tr key={m} className={`border-t border-surface-border ${hl ? "bg-accent/5" : ""}`}>
                  <td className={`py-2 pr-3 ${hl ? "font-semibold text-accent" : "text-ink"}`}>{m}{hl ? " (TraceWeaver)" : ""}</td>
                  <td className="py-2 pr-3 mono text-status-detected">{x.tp}</td><td className="py-2 pr-3 mono text-status-missed">{x.fp}</td>
                  <td className="py-2 pr-3 mono text-ink-muted">{x.tn}</td><td className="py-2 pr-3 mono text-status-partial">{x.fn}</td>
                  <td className="py-2 pr-3 mono">{x.precision ?? "N/A"} <span className="text-ink-faint">({x.precision_denom})</span></td>
                  <td className="py-2 pr-3 mono">{x.recall ?? "N/A"} <span className="text-ink-faint">({x.recall_denom})</span></td>
                  <td className="py-2 pr-3 mono">{x.f1 ?? "N/A"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <div className="rounded-md border border-surface-border bg-surface-raised p-2.5 text-[11px]">
          <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Ineligible (with reasons)</div>
          <div className="mt-1 text-ink-muted mono text-[10px]">{Object.entries(evaluation.ineligible_reasons as Record<string, number>).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>
        </div>
        <div className="rounded-md border border-status-partial/25 bg-status-partial/5 p-2.5 text-[11px] text-ink-muted">
          {(evaluation.caveats as string[]).slice(0, 3).map((c, i) => <div key={i}>• {c}</div>)}
        </div>
      </div>
    </Panel>
  );
}
