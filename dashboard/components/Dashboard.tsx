"use client";

import { useMemo, useState } from "react";
import type { ExperimentRow, StatusKind, Tool } from "@/lib/data";

const TOOLS: Tool[] = ["falco", "tracee", "tetragon"];

const TOOL_LABEL: Record<Tool, string> = {
  falco: "Falco",
  tracee: "Tracee",
  tetragon: "Tetragon",
};

const STATUS_STYLE: Record<StatusKind, { dot: string; text: string; bg: string; border: string }> = {
  detected: { dot: "bg-status-detected", text: "text-status-detected", bg: "bg-status-detected/10", border: "border-status-detected/30" },
  observed: { dot: "bg-status-observed", text: "text-status-observed", bg: "bg-status-observed/10", border: "border-status-observed/30" },
  partial: { dot: "bg-status-partial", text: "text-status-partial", bg: "bg-status-partial/10", border: "border-status-partial/30" },
  not_tested: { dot: "bg-status-nottested", text: "text-status-nottested", bg: "bg-status-nottested/10", border: "border-status-nottested/30" },
  missed: { dot: "bg-status-missed", text: "text-status-missed", bg: "bg-status-missed/10", border: "border-status-missed/30" },
};

const STATUS_LEGEND: { kind: StatusKind; label: string; desc: string }[] = [
  { kind: "detected", label: "Confirmed detection", desc: "A rule/policy engine fired on the tested behavior" },
  { kind: "observed", label: "Telemetry observed", desc: "Kernel/event visibility confirmed; no alerting engine evaluated" },
  { kind: "partial", label: "Partial / unconfirmed", desc: "Some telemetry observed, but the targeted claim is not fully established" },
  { kind: "not_tested", label: "Not tested", desc: "No result file exists in the repository for this combination" },
  { kind: "missed", label: "Confirmed missed", desc: "Event was observed as expected but no detection fired" },
];

function Badge({ status, children }: { status: StatusKind; children: React.ReactNode }) {
  const s = STATUS_STYLE[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium tracking-wide ${s.bg} ${s.border} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {children}
    </span>
  );
}

function MetricCard({ value, label }: { value: string | number; label: string }) {
  return (
    <div className="rounded-lg border border-surface-border bg-surface-panel p-5">
      <div className="text-3xl font-semibold text-ink mono">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-ink-muted">{label}</div>
    </div>
  );
}

function Section({ title, kicker, children }: { title: string; kicker?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-surface-border bg-surface-panel p-6">
      {kicker && <div className="mb-1 text-[11px] uppercase tracking-widest text-ink-faint">{kicker}</div>}
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-ink">{title}</h2>
      {children}
    </section>
  );
}

export default function Dashboard({ experiments }: { experiments: ExperimentRow[] }) {
  const [selectedId, setSelectedId] = useState(experiments[0]?.id ?? "E01");
  const [toolFilter, setToolFilter] = useState<Tool | "all">("all");
  const [reviewMode, setReviewMode] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState<string | null>(null);

  const selected = experiments.find((e) => e.id === selectedId) ?? experiments[0];

  const counts = useMemo(() => {
    const c: Record<StatusKind, number> = { detected: 0, observed: 0, partial: 0, not_tested: 0, missed: 0 };
    experiments.forEach((e) =>
      TOOLS.forEach((t) => {
        const cell = e.cells[t];
        if (cell) c[cell.status] += 1;
      })
    );
    return c;
  }, [experiments]);

  const evaluatedPerTool = useMemo(() => {
    const m: Record<Tool, number> = { falco: 0, tracee: 0, tetragon: 0 };
    experiments.forEach((e) =>
      TOOLS.forEach((t) => {
        if (e.cells[t] && e.cells[t]!.status !== "not_tested") m[t] += 1;
      })
    );
    return m;
  }, [experiments]);

  const visibleTools = toolFilter === "all" ? TOOLS : [toolFilter];

  return (
    <main className="min-h-screen bg-surface px-4 py-8 sm:px-8 lg:px-12">
      <div className="mx-auto max-w-6xl space-y-6">
        {/* HEADER */}
        <header className="flex flex-col gap-4 border-b border-surface-border pb-6 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-[11px] font-medium uppercase tracking-wide text-accent">
              Research Prototype — Experimental Evaluation in Progress
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-ink sm:text-3xl">
              Adaptive eBPF Security Lab
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-ink-muted">
              Evaluating the observability and detection robustness of eBPF-based runtime security
              systems under adaptive container behavior.
            </p>
          </div>
          <button
            onClick={() => setReviewMode((v) => !v)}
            className={`h-fit shrink-0 rounded-md border px-4 py-2 text-xs font-medium uppercase tracking-wide transition ${
              reviewMode
                ? "border-accent bg-accent/15 text-accent"
                : "border-surface-border bg-surface-raised text-ink-muted hover:text-ink"
            }`}
          >
            {reviewMode ? "Exit Review Mode" : "Review Mode"}
          </button>
        </header>

        {/* EXECUTIVE METRICS */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <MetricCard value={TOOLS.length} label="Runtime Security Systems" />
          <MetricCard value={experiments.length} label="Experiments Designed" />
          <MetricCard value={evaluatedPerTool.falco} label="Evaluated in Falco" />
          <MetricCard value={evaluatedPerTool.tracee} label="Evaluated in Tracee" />
        </div>

        {!reviewMode && (
          <Section title="Environment" kicker="Experimental Setup">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
              {[
                ["Operating System", "Kali Linux ARM64"],
                ["Kernel", "7.1.5+kali-arm64"],
                ["Architecture", "aarch64"],
                ["Container Runtime", "Docker"],
                ["BTF", "Available"],
                ["eBPF", "Modern eBPF"],
              ].map(([k, v]) => (
                <div key={k} className="rounded-md border border-surface-border bg-surface-raised p-3">
                  <div className="text-[10px] uppercase tracking-wide text-ink-faint">{k}</div>
                  <div className="mt-1 text-sm text-ink mono">{v}</div>
                </div>
              ))}
            </div>
            <div className="mt-3 text-xs text-ink-muted">
              Detectors under evaluation: Falco · Tracee · Tetragon v1.6.0
            </div>
          </Section>
        )}

        {/* STATUS LEGEND */}
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-surface-border bg-surface-panel px-4 py-3">
          {STATUS_LEGEND.map((s) => (
            <div key={s.kind} className="flex items-center gap-1.5" title={s.desc}>
              <span className={`h-2 w-2 rounded-full ${STATUS_STYLE[s.kind].dot}`} />
              <span className="text-[11px] text-ink-muted">{s.label}</span>
            </div>
          ))}
        </div>

        {/* EXPERIMENT MATRIX */}
        <Section title="Experiment Matrix" kicker="Detection vs. Telemetry">
          {!reviewMode && (
            <div className="mb-4 flex items-center gap-2 text-xs">
              <span className="text-ink-faint">Filter:</span>
              {(["all", ...TOOLS] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setToolFilter(t)}
                  className={`rounded-full border px-3 py-1 ${
                    toolFilter === t
                      ? "border-accent bg-accent/15 text-accent"
                      : "border-surface-border text-ink-muted hover:text-ink"
                  }`}
                >
                  {t === "all" ? "All tools" : TOOL_LABEL[t]}
                </button>
              ))}
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-ink-faint">
                  <th className="w-56 pb-3 pr-4 font-medium">Experiment</th>
                  {visibleTools.map((t) => (
                    <th key={t} className="pb-3 pr-4 font-medium">
                      {TOOL_LABEL[t]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {experiments.map((e) => (
                  <tr
                    key={e.id}
                    onClick={() => setSelectedId(e.id)}
                    className={`cursor-pointer border-t border-surface-border transition hover:bg-surface-raised ${
                      selectedId === e.id ? "bg-surface-raised" : ""
                    }`}
                  >
                    <td className="py-3 pr-4">
                      <div className="font-medium text-ink">{e.id} — {e.title}</div>
                      <div className="text-[11px] text-ink-faint">{e.variant.replace(/_/g, " ")}</div>
                    </td>
                    {visibleTools.map((t) => {
                      const cell = e.cells[t];
                      if (!cell) return <td key={t} className="py-3 pr-4" />;
                      return (
                        <td key={t} className="py-3 pr-4">
                          <Badge status={cell.status}>{cell.badge}</Badge>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>

        {/* EXPERIMENT DETAIL */}
        {selected && (
          <Section title={`${selected.id} — ${selected.title}`} kicker="Experiment Detail">
            <p className="mb-4 text-sm text-ink-muted">{selected.description}</p>
            <div className="mb-5 grid gap-3 sm:grid-cols-2">
              {Object.entries(selected.commands).map(([tool, cmd]) => (
                <div key={tool} className="rounded-md border border-surface-border bg-surface-raised p-3">
                  <div className="text-[10px] uppercase tracking-wide text-ink-faint">{TOOL_LABEL[tool as Tool]} command</div>
                  <code className="mt-1 block break-all text-xs text-ink mono">{cmd}</code>
                </div>
              ))}
            </div>
            <div className="space-y-3">
              {TOOLS.map((t) => {
                const cell = selected.cells[t];
                if (!cell) return null;
                const s = STATUS_STYLE[cell.status];
                return (
                  <div key={t} className={`rounded-md border p-4 ${s.border} ${s.bg}`}>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-ink">{TOOL_LABEL[t]}</span>
                        <Badge status={cell.status}>{cell.badge}</Badge>
                      </div>
                      {cell.evidencePath && (
                        <button
                          onClick={() => setEvidenceOpen(evidenceOpen === cell.evidencePath ? null : cell.evidencePath)}
                          className="text-[11px] text-accent hover:underline"
                        >
                          {evidenceOpen === cell.evidencePath ? "Hide evidence" : `Evidence: ${cell.evidencePath}`}
                        </button>
                      )}
                    </div>
                    <p className="mt-2 text-sm text-ink-muted">{cell.summary || "No notes recorded."}</p>
                    {cell.processesObserved && (
                      <div className="mt-2 text-xs text-ink-faint mono">
                        processes: {cell.processesObserved.join(" → ")}
                      </div>
                    )}
                    {evidenceOpen === cell.evidencePath && cell.raw && (
                      <pre className="mt-3 max-h-64 overflow-auto rounded border border-surface-border bg-surface p-3 text-[11px] text-ink-muted mono">
                        {JSON.stringify(cell.raw, null, 2)}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>
          </Section>
        )}

        {!reviewMode && (
          <Section title="Baseline → Adaptive" kicker="Behavioral Comparison">
            <div className="mb-6 flex flex-wrap items-center justify-center gap-2 text-xs text-ink-muted">
              {["Baseline execution", "Controlled modification", "Runtime security telemetry", "Detection / visibility", "Comparison"].map((step, i, arr) => (
                <div key={step} className="flex items-center gap-2">
                  <span className="rounded-md border border-surface-border bg-surface-raised px-3 py-1.5">{step}</span>
                  {i < arr.length - 1 && <span className="text-ink-faint">→</span>}
                </div>
              ))}
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-md border border-surface-border bg-surface-raised p-4">
                <div className="text-[10px] uppercase tracking-wide text-ink-faint">E04 — Indirect Execution</div>
                <div className="mt-2 text-xs text-ink-muted">Baseline: <span className="mono text-ink">sh → id</span></div>
                <div className="text-xs text-ink-muted">Adaptive: <span className="mono text-ink">sh → sh → id</span></div>
                <div className="mt-2 text-xs text-status-observed">Observed: Falco and Tracee both still recorded every execution event.</div>
              </div>
              <div className="rounded-md border border-surface-border bg-surface-raised p-4">
                <div className="text-[10px] uppercase tracking-wide text-ink-faint">E05 — Timing Variation</div>
                <div className="mt-2 text-xs text-ink-muted">Baseline: <span className="mono text-ink">sh → id</span></div>
                <div className="text-xs text-ink-muted">Adaptive: <span className="mono text-ink">sh → sleep → sleep → id</span></div>
                <div className="mt-2 text-xs text-status-observed">Observed: Falco and Tracee both still recorded every execution event across the two-second delays.</div>
              </div>
            </div>
          </Section>
        )}

        {/* KEY FINDING */}
        <Section title="Current Finding" kicker="Research Insight">
          <p className="text-base text-ink">
            Simple execution indirection and controlled timing variation have not yet reduced
            process-execution observability under the tested Falco and Tracee configurations.
          </p>
          <p className="mt-3 text-xs text-ink-faint">
            This does not mean the systems are immune to adaptive evasion. Stronger execution-mechanism
            variations and cross-layer failure analysis remain to be evaluated. Tetragon&apos;s process-execution
            path shows telemetry visibility (E01), but file-access (openat) tracing is not yet established under
            the current tracing policy, and E02–E05 have not been run against Tetragon in this repository.
          </p>
        </Section>

        {!reviewMode && (
          <>
            <Section title="Research Pipeline" kicker="Methodology">
              <div className="flex flex-wrap items-center gap-2 text-xs text-ink-muted">
                {[
                  "Controlled Behavior",
                  "Baseline",
                  "Adaptive Variant",
                  "eBPF Telemetry",
                  "Container Context",
                  "Detection / Observation",
                  "Normalized Result",
                  "Cross-Tool Comparison",
                ].map((step, i, arr) => (
                  <div key={step} className="flex items-center gap-2">
                    <span className="rounded-md border border-surface-border bg-surface-raised px-3 py-1.5 mono text-[11px]">{step}</span>
                    {i < arr.length - 1 && <span className="text-ink-faint">→</span>}
                  </div>
                ))}
              </div>
            </Section>

            <Section title="Where Can Evasion Occur?" kicker="Failure Taxonomy">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {[
                  ["Event Visibility", "The kernel never generates or exposes the underlying event to eBPF instrumentation."],
                  ["Event Collection", "The event is generated but the configured hooks/tracepoints don't capture it."],
                  ["Context / Enrichment", "The event is captured but container/process context is lost or incorrect."],
                  ["Detection Rule", "The event is captured with context, but no rule or policy evaluates it as suspicious."],
                  ["Timing / Mechanism", "The behavior changes fast enough or via a mechanism the collector doesn't sample."],
                ].map(([title, desc]) => (
                  <div key={title} className="rounded-md border border-surface-border bg-surface-raised p-3">
                    <div className="text-xs font-medium text-ink">{title}</div>
                    <div className="mt-1 text-[11px] text-ink-muted">{desc}</div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-[11px] text-ink-faint">
                This is a research framework for classifying future findings — no failure at any of these
                layers has been confirmed by the current result set.
              </p>
            </Section>

            <Section title="Next Steps" kicker="Research Roadmap">
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-ink-muted">
                <li>Complete Tetragon E02–E05</li>
                <li>Normalize all results into <span className="mono text-ink-faint">results/summary.csv</span></li>
                <li>Compare detection vs. telemetry across all three tools</li>
                <li>Introduce stronger execution-mechanism variations</li>
                <li>Investigate io_uring-based execution as an advanced experiment</li>
                <li>Measure detection latency</li>
                <li>Identify root causes of any observed degradation</li>
                <li>Develop mitigation recommendations</li>
              </ol>
            </Section>
          </>
        )}

        <footer className="pb-4 text-center text-[11px] text-ink-faint">
          Status derived directly from <span className="mono">results/raw/*.json</span> and{" "}
          <span className="mono">experiments/*.json</span> in this repository.
        </footer>
      </div>
    </main>
  );
}
