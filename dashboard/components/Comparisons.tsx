"use client";

import type { Analysis, NormRecord, Tool } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { Panel, StatusBadge, STATUS_META, STATUS_ORDER, TOOL_LABEL, Dot } from "./ui";

export function DetectorMatrix({
  analysis,
  onSelect,
}: {
  analysis: Analysis;
  onSelect?: (id: string) => void;
}) {
  const legendCounts: Record<string, number> = {};
  analysis.matrix.forEach((row) =>
    TOOLS.forEach((t) => {
      const s = row.cells[t]?.status ?? "not_tested";
      legendCounts[s] = (legendCounts[s] ?? 0) + 1;
    })
  );

  return (
    <Panel
      title="Comparative Detector Matrix"
      kicker="Falco · Tracee · Tetragon"
      right={
        <div className="hidden flex-wrap items-center gap-3 sm:flex">
          {STATUS_ORDER.filter((s) => legendCounts[s]).map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-[10.5px] text-ink-muted" title={STATUS_META[s].desc}>
              <Dot status={s} />
              {STATUS_META[s].label}
            </span>
          ))}
        </div>
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider text-ink-faint">
              <th className="w-56 pb-3 pr-3 font-medium">Experiment</th>
              {TOOLS.map((t) => (
                <th key={t} className="pb-3 pr-3 font-medium">
                  {TOOL_LABEL[t]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {analysis.matrix.map((row) => (
              <tr
                key={row.experiment_id}
                className={`border-t border-surface-border ${onSelect ? "cursor-pointer hover:bg-surface-hover" : ""}`}
                onClick={() => onSelect?.(row.experiment_id)}
              >
                <td className="py-3 pr-3">
                  <div className="text-[13px] font-medium text-ink">
                    {row.experiment_id} · {row.title}
                  </div>
                  <div className="text-[10px] text-ink-faint">{row.variant.replace(/_/g, " ")}</div>
                </td>
                {TOOLS.map((t) => {
                  const cell = row.cells[t];
                  const s = cell?.status ?? "not_tested";
                  const meta = STATUS_META[s];
                  return (
                    <td key={t} className="py-3 pr-3">
                      <div className={`rounded-lg border ${meta.border} ${meta.bg} px-3 py-2`}>
                        <StatusBadge status={s} />
                        {cell?.detection_type && (
                          <div className="mt-1.5 text-[10px] text-ink-faint mono">
                            {cell.detection_type}
                          </div>
                        )}
                        {cell?.rule_class && (
                          <div className="mt-0.5 text-[9.5px] uppercase tracking-wide text-ink-faint">
                            {cell.rule_class.replace(/_/g, " ")}
                          </div>
                        )}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 text-[11px] leading-relaxed text-ink-faint">
        Tracee and Tetragon are configured here as telemetry collectors (no signatures / alerting
        engine), so their cells are <span className="text-status-observed">telemetry observed</span>,
        never detections. Falco&apos;s process-execution cells fire via the lab&apos;s{" "}
        <span className="mono">custom research</span> rule; only E01 is a{" "}
        <span className="mono">built-in security</span> rule. E03 is{" "}
        <span className="text-status-partial">partial</span> because process telemetry exists but no
        network-connection detection was established.
      </p>
    </Panel>
  );
}

export function BaselineAdaptive({ analysis }: { analysis: Analysis }) {
  return (
    <Panel title="Baseline → Adaptive Laboratory" kicker="Controlled behavior modification">
      <div className="mb-5 space-y-4">
        {analysis.baseline_vs_adaptive.map((cmp) => (
          <div key={cmp.adaptive_id} className="rounded-lg border border-surface-border bg-surface-raised p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="text-[13px] font-semibold text-ink">
                {cmp.adaptive_id} · {cmp.adaptive_title}
              </div>
              <div className="text-[10px] uppercase tracking-wide text-ink-faint">
                baseline {cmp.baseline_id} → {cmp.variant.replace(/_/g, " ")}
              </div>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {TOOLS.map((t) => {
                const d = cmp.tools[t];
                if (!d) return null;
                const changeColor =
                  d.observability_change === "reduced"
                    ? "text-status-missed"
                    : d.observability_change === "increased"
                    ? "text-status-observed"
                    : "text-status-detected";
                return (
                  <div key={t} className="rounded-md border border-surface-border bg-surface-inset p-3">
                    <div className="mb-2 text-[11px] font-semibold text-ink">{TOOL_LABEL[t]}</div>
                    <SeqRow label="baseline" procs={d.baseline_processes} />
                    <SeqRow label="adaptive" procs={d.adaptive_processes} />
                    <div className={`mt-2 text-[10.5px] font-medium uppercase tracking-wide ${changeColor}`}>
                      observability {d.observability_change}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-accent/25 bg-accent/5 p-4">
        <div className="text-[13px] leading-relaxed text-ink">
          Simple execution indirection and controlled timing variation did not eliminate
          process-execution observability under the tested Falco, Tracee and Tetragon configurations.
        </div>
        <div className="mt-2 text-[11px] leading-relaxed text-ink-faint">
          This finding is specific to the tested behaviors, configurations, and observations. It does
          not demonstrate immunity to adaptive evasion. No percentage reduction is reported because no
          reduction was measured — every execution stage remained visible across both variants.
        </div>
      </div>
    </Panel>
  );
}

function SeqRow({ label, procs }: { label: string; procs: string[] | null }) {
  return (
    <div className="flex items-center gap-1.5 py-0.5 text-[11px] mono">
      <span className="w-16 shrink-0 text-[9.5px] uppercase tracking-wide text-ink-faint">{label}</span>
      {procs && procs.length ? (
        procs.map((p, i) => (
          <span key={i} className="flex items-center gap-1.5">
            <span className="rounded bg-surface-panel px-1.5 py-0.5 text-ink">{p}</span>
            {i < procs.length - 1 && <span className="text-ink-faint">→</span>}
          </span>
        ))
      ) : (
        <span className="text-ink-faint">—</span>
      )}
    </div>
  );
}
