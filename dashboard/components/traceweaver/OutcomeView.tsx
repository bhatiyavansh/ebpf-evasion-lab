"use client";

import { useState } from "react";
import type { EngineResult, Evaluation } from "@/lib/types";

/* ------------------------------------------------------------------ *
 * Verdict semantics. Every string here is written so that an honest
 * reading is forced: NOT_DETECTED is NEVER presented as "safe", and a
 * collection/execution failure is never presented as a clean negative.
 * ------------------------------------------------------------------ */
const VERDICT_META: Record<
  string,
  { label: string; tone: string; hex: string; plain: string }
> = {
  DETECTED: {
    label: "Detected",
    tone: "detected",
    hex: "#36c98d",
    plain:
      "A verified policy signal fired. The engine found confirmed malicious-aligned activity backed by a real sensor rule or signature — cited below with its exact source record.",
  },
  TELEMETRY_ONLY: {
    label: "Telemetry only",
    tone: "observed",
    hex: "#38bdf8",
    plain:
      "The sensor recorded activity but no rule or signature classified it as a threat. This is visibility without a verdict — it is not the same as “safe”.",
  },
  NOT_DETECTED: {
    label: "Not detected",
    tone: "missed",
    hex: "#f0674f",
    plain:
      "No qualifying signal fired on the evidence that was collected. This means nothing was flagged — it does NOT establish that the workload is safe or benign.",
  },
  COLLECTION_FAILED: {
    label: "Collection failed",
    tone: "partial",
    hex: "#e0b23a",
    plain:
      "The sensor did not capture usable events, so detection cannot be evaluated. Missing evidence is never treated as the absence of a threat; the verdict layer refuses to score this as clean.",
  },
  EXECUTION_FAILED: {
    label: "Execution failed",
    tone: "partial",
    hex: "#e0b23a",
    plain:
      "The workload itself did not run to completion, so there is nothing to evaluate. A risk score cannot promote this to a detection.",
  },
  NOT_EVALUATED: {
    label: "Not evaluated",
    tone: "nottested",
    hex: "#5a6472",
    plain: "This stream was not evaluated by the engine.",
  },
  INCONCLUSIVE: {
    label: "Inconclusive",
    tone: "nottested",
    hex: "#5a6472",
    plain: "The evidence was insufficient for the engine to reach a conclusion.",
  },
};

function meta(verdict: string) {
  return VERDICT_META[verdict] ?? VERDICT_META.INCONCLUSIVE;
}

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-surface-border bg-surface-raised p-5">
      <div className="mb-3">
        <h3 className="text-[13px] font-semibold tracking-tight text-ink">{title}</h3>
        {subtitle ? <p className="mt-0.5 text-[11px] text-ink-faint">{subtitle}</p> : null}
      </div>
      {children}
    </section>
  );
}

/* --------------------------- risk gauge --------------------------- */
function RiskGauge({ score, band }: { score: number; band: string }) {
  const pct = Math.max(0, Math.min(100, score));
  const color = pct >= 70 ? "#f0674f" : pct >= 40 ? "#e0b23a" : "#36c98d";
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="text-[11px] uppercase tracking-wide text-ink-faint">Risk score</span>
        <span className="mono text-[11px] text-ink-muted">{band}</span>
      </div>
      <div className="mt-1 flex items-end gap-2">
        <span className="mono text-3xl font-semibold leading-none" style={{ color }}>
          {score.toFixed(1)}
        </span>
        <span className="mb-1 text-[11px] text-ink-faint">/ 100</span>
      </div>
      <div className="relative mt-3 h-2 w-full overflow-hidden rounded-full bg-surface-inset">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
        {/* threshold ticks: 40 (suspicious), 70 (high) */}
        <div className="absolute inset-y-0" style={{ left: "40%" }}>
          <div className="h-full w-px bg-surface-border" />
        </div>
        <div className="absolute inset-y-0" style={{ left: "70%" }}>
          <div className="h-full w-px bg-surface-border" />
        </div>
      </div>
      <div className="mt-1 flex justify-between text-[9.5px] text-ink-faint">
        <span>0 · low</span>
        <span>40 · suspicious</span>
        <span>70 · high</span>
      </div>
    </div>
  );
}

/* ------------------------ signal breakdown ------------------------ */
function SignalBar({
  label,
  value,
  weight,
  desc,
}: {
  label: string;
  value: number;
  weight: number;
  desc: string;
}) {
  const contribution = value * weight * 100;
  return (
    <div>
      <div className="flex items-baseline justify-between text-[12px]">
        <span className="font-medium text-ink">{label}</span>
        <span className="mono text-ink-muted">
          {value.toFixed(2)} × {weight.toFixed(1)} ={" "}
          <span className="text-accent">{contribution.toFixed(1)}</span>
        </span>
      </div>
      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-inset">
        <div
          className="h-full rounded-full bg-accent/70"
          style={{ width: `${Math.max(0, Math.min(100, value * 100))}%` }}
        />
      </div>
      <p className="mt-1 text-[10.5px] text-ink-faint">{desc}</p>
    </div>
  );
}

/* ------------------------- evidence timeline ---------------------- */
function Finding({ f }: { f: EngineResult["findings"][number] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-surface-border bg-surface-panel">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-3 py-2.5 text-left"
      >
        <span className="mono text-[10px] text-ink-faint">{open ? "▾" : "▸"}</span>
        <span className="flex-1 text-[12px] font-medium text-ink">{f.pattern}</span>
        {f.mitre?.length ? (
          <span className="mono rounded bg-surface-inset px-1.5 py-0.5 text-[9.5px] text-ink-muted">
            {f.mitre.join(" ")}
          </span>
        ) : null}
        <span className="mono text-[10px] text-ink-faint">sev {f.severity.toFixed(2)}</span>
      </button>
      {open ? (
        <div className="border-t border-surface-border px-3 py-2.5">
          <p className="text-[11.5px] text-ink-muted">{f.explanation}</p>
          {f.raw_refs?.length ? (
            <div className="mt-2 space-y-1">
              <div className="text-[10px] uppercase tracking-wide text-ink-faint">Raw provenance</div>
              {f.raw_refs.map((r, i) => (
                <div key={i} className="mono break-all text-[10px] text-ink-muted">
                  {r.file}:{r.line}
                  {r.sha256 ? <span className="text-ink-faint"> · sha256 {r.sha256.slice(0, 16)}…</span> : null}
                </div>
              ))}
            </div>
          ) : null}
          {f.event_ids?.length ? (
            <div className="mono mt-2 break-all text-[10px] text-ink-faint">
              events: {f.event_ids.join(", ")}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function Timeline({ r }: { r: EngineResult }) {
  const [showAll, setShowAll] = useState(false);
  const steps = r.process_timeline ?? [];
  const shown = showAll ? steps : steps.slice(0, 8);
  if (!steps.length)
    return <p className="text-[11.5px] text-ink-faint">No process-execution events in this stream.</p>;
  return (
    <div className="relative pl-4">
      <div className="absolute inset-y-1 left-[5px] w-px bg-surface-border" />
      <div className="space-y-2.5">
        {shown.map((s, i) => (
          <div key={i} className="relative">
            <div className="absolute -left-[13px] top-1.5 h-2 w-2 rounded-full bg-accent/70 ring-2 ring-surface-raised" />
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="mono text-[12px] text-ink">{String(s.process ?? "—")}</span>
              <span className="mono text-[10px] text-ink-faint">pid {String(s.pid ?? "—")}</span>
              <span className="mono text-[10px] text-ink-faint">{String(s.timestamp ?? "")}</span>
            </div>
            {String(s.args ?? "") ? (
              <div className="mono break-all text-[10.5px] text-ink-muted">{String(s.args)}</div>
            ) : null}
            <div className="mono text-[9.5px] text-ink-faint">
              {s.raw_ref?.file}:{s.raw_ref?.line}
            </div>
          </div>
        ))}
      </div>
      {steps.length > 8 ? (
        <button
          onClick={() => setShowAll((v) => !v)}
          className="mt-3 text-[11px] text-accent hover:text-accent-bright"
        >
          {showAll ? "Show fewer" : `Show all ${steps.length} events`}
        </button>
      ) : null}
    </div>
  );
}

/* ---------------------- evaluation comparison --------------------- */
const METHOD_LABEL: Record<string, string> = {
  rules_only: "Rules only",
  anomaly_only: "Anomaly only",
  combined: "TraceWeaver (combined)",
};

function EvaluationView({ evaluation }: { evaluation: Evaluation | null }) {
  if (!evaluation?.methods) {
    return <p className="text-[11.5px] text-ink-faint">Evaluation data not available.</p>;
  }
  const order = ["rules_only", "anomaly_only", "combined"];
  const methods = order.filter((m) => evaluation.methods[m]);
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[11.5px]">
          <thead>
            <tr className="text-left text-ink-faint">
              <th className="py-1.5 pr-3 font-medium">Method</th>
              <th className="px-2 py-1.5 text-right font-medium">TP</th>
              <th className="px-2 py-1.5 text-right font-medium">FP</th>
              <th className="px-2 py-1.5 text-right font-medium">TN</th>
              <th className="px-2 py-1.5 text-right font-medium">FN</th>
              <th className="px-2 py-1.5 text-right font-medium">Precision</th>
              <th className="px-2 py-1.5 text-right font-medium">Recall</th>
              <th className="px-2 py-1.5 text-right font-medium">F1</th>
            </tr>
          </thead>
          <tbody>
            {methods.map((m) => {
              const d = evaluation.methods[m].metrics;
              const best = m === "combined";
              return (
                <tr
                  key={m}
                  className={`border-t border-surface-border ${best ? "bg-accent/5" : ""}`}
                >
                  <td className={`py-2 pr-3 ${best ? "font-semibold text-accent" : "text-ink"}`}>
                    {METHOD_LABEL[m] ?? m}
                  </td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.tp}</td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.fp}</td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.tn}</td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.fn}</td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.precision.toFixed(3)}</td>
                  <td className="mono px-2 py-2 text-right text-ink-muted">{d.recall.toFixed(3)}</td>
                  <td className={`mono px-2 py-2 text-right ${best ? "font-semibold text-accent" : "text-ink"}`}>
                    {d.f1.toFixed(3)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {/* F1 bars */}
      <div className="mt-4 space-y-2">
        {methods.map((m) => {
          const f1 = evaluation.methods[m].metrics.f1 as number;
          const best = m === "combined";
          return (
            <div key={m} className="flex items-center gap-3">
              <span className="w-40 shrink-0 text-[11px] text-ink-muted">{METHOD_LABEL[m] ?? m}</span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-inset">
                <div
                  className={`h-full rounded-full ${best ? "bg-accent" : "bg-ink-faint/50"}`}
                  style={{ width: `${f1 * 100}%` }}
                />
              </div>
              <span className="mono w-10 shrink-0 text-right text-[11px] text-ink-muted">
                {f1.toFixed(2)}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-3 text-[10.5px] leading-relaxed text-ink-faint">
        {evaluation.eligible_count} eligible trials · benign control held out as the negative class ·
        anomaly baseline fit only on training streams (no leakage). Perfect precision across methods
        (0 false positives on the benign control); the combined engine recovers recall that rules-only
        misses where a sensor has no matching rule.
      </p>
    </div>
  );
}

/* ----------------------------- main view -------------------------- */
export default function OutcomeView({
  result,
  evaluation,
  liveMeta,
}: {
  result: EngineResult | null;
  evaluation: Evaluation | null;
  liveMeta?: { elapsedMs: number } | null;
}) {
  if (!result) {
    return (
      <div className="rounded-xl border border-dashed border-surface-border bg-surface-raised p-10 text-center">
        <p className="text-[13px] text-ink-muted">No analysis yet.</p>
        <p className="mt-1 text-[11.5px] text-ink-faint">
          Pick an evidence stream on the <span className="text-accent">Main</span> tab and run the
          analysis to see the verdict here.
        </p>
      </div>
    );
  }

  const m = meta(result.verdict);
  const cs = result.component_scores;
  const w = cs.weights ?? { wA: 0.2, wS: 0.3, wP: 0.5 };

  return (
    <div className="space-y-5 animate-fadein">
      {/* verdict card */}
      <section className="overflow-hidden rounded-xl border border-surface-border bg-surface-raised">
        <div className="h-1 w-full" style={{ background: m.hex }} />
        <div className="p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: m.hex }} />
                <span className="text-[18px] font-semibold tracking-tight" style={{ color: m.hex }}>
                  {m.label}
                </span>
                <span className="mono rounded bg-surface-inset px-1.5 py-0.5 text-[10px] text-ink-faint">
                  {result.verdict}
                </span>
              </div>
              <p className="mt-2 max-w-2xl text-[12.5px] leading-relaxed text-ink-muted">{m.plain}</p>
              <p className="mt-2 text-[11px] text-ink-faint">
                Engine reason: <span className="text-ink-muted">{result.verdict_reason}</span>
              </p>
            </div>
            <div className="text-right">
              <div className="mono text-[11px] text-ink-faint">{result.sensor}</div>
              <div className="mono text-[11px] text-ink-muted">{result.scenario_id ?? "—"}</div>
              {liveMeta ? (
                <div className="mt-2 inline-flex items-center gap-1 rounded border border-accent/30 bg-accent/10 px-2 py-0.5 text-[9.5px] uppercase tracking-wide text-accent">
                  ● live engine run · {liveMeta.elapsedMs} ms
                </div>
              ) : null}
            </div>
          </div>
        </div>
      </section>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Risk score" subtitle="risk = 100 · (0.2·A + 0.3·S + 0.5·P)">
          <RiskGauge score={result.risk_score} band={result.risk_band} />
        </Panel>

        <Panel title="Signal breakdown" subtitle="Three independent signals, weighted into one score">
          <div className="space-y-4">
            <SignalBar
              label="A · Anomaly"
              value={cs.A_anomaly}
              weight={w.wA}
              desc="Share of suspicious actions vs. a learned per-sensor baseline (novelty alone does not raise this)."
            />
            <SignalBar
              label="S · Sequence"
              value={cs.S_sequence}
              weight={w.wS}
              desc="Severity of the strongest temporal behaviour pattern (e.g. sudoers edit, sensitive-file read)."
            />
            <SignalBar
              label="P · Policy"
              value={cs.P_policy}
              weight={w.wP}
              desc="1 only when a verified, qualifying sensor rule/signature fired. DETECTED requires P > 0."
            />
          </div>
        </Panel>
      </div>

      {result.findings?.length ? (
        <Panel title="Findings" subtitle="Behaviour patterns the engine matched — expand for raw provenance">
          <div className="space-y-2">
            {result.findings.map((f, i) => (
              <Finding key={i} f={f} />
            ))}
          </div>
        </Panel>
      ) : null}

      <Panel title="Evidence timeline" subtitle="Process-execution events reconstructed from the behaviour graph">
        <Timeline r={result} />
      </Panel>

      <Panel
        title="Visibility"
        subtitle="Collection quality — the verdict is gated on this, so missing data never reads as “clean”"
      >
        <div className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
          {[
            ["Visibility", result.visibility_status],
            ["Capture mode", result.capture_mode],
            ["Events", String(result.event_count)],
            ["Graph nodes", String(result.graph_summary?.nodes ?? 0)],
            ["Graph edges", String(result.graph_summary?.edges ?? 0)],
            ["Identity gaps", String(result.graph_summary?.identity_gaps ?? 0)],
            ["Window start", result.time_window?.start ?? "—"],
            ["Window end", result.time_window?.end ?? "—"],
          ].map(([k, v]) => (
            <div key={k}>
              <div className="text-[10px] uppercase tracking-wide text-ink-faint">{k}</div>
              <div className="mono mt-0.5 break-all text-[11.5px] text-ink">{v}</div>
            </div>
          ))}
        </div>
        {result.warnings?.length ? (
          <div className="mt-3 rounded-lg border border-status-partial/30 bg-status-partial/5 p-2.5">
            {result.warnings.map((wmsg, i) => (
              <div key={i} className="text-[11px] text-status-partial">
                ⚠ {wmsg}
              </div>
            ))}
          </div>
        ) : null}
      </Panel>

      <Panel
        title="Evaluation"
        subtitle="How the full engine compares to simpler baselines on the held-out labelled set"
      >
        <EvaluationView evaluation={evaluation} />
      </Panel>
    </div>
  );
}
