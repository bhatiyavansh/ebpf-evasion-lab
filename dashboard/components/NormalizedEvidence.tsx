"use client";

import { useMemo, useState } from "react";
import type { TwIndex } from "@/lib/types";
import { Panel, Metric, Mode } from "./ui";

/**
 * TraceWeaver Phase 1 — read-only view of the canonical normalized-evidence
 * index. Shows schema version, per-sensor/capture-mode coverage, and per-stream
 * provenance (sha256, capture mode, canonical-type counts). Degrades gracefully
 * when no normalized output exists yet.
 */
export default function NormalizedEvidence({ twIndex }: { twIndex: TwIndex | null }) {
  const [sensor, setSensor] = useState<string>("all");
  const streams = useMemo(
    () => (twIndex ? twIndex.streams.filter((s) => sensor === "all" || s.sensor === sensor) : []),
    [twIndex, sensor]
  );

  if (!twIndex) {
    return (
      <Panel title="Normalized Evidence (TraceWeaver)" kicker="Phase 1 — canonical events">
        <div className="rounded-lg border border-surface-border bg-surface-inset p-6 text-center text-[12px] text-ink-faint">
          No normalized output yet. Run <span className="mono text-ink-muted">./scripts/traceweaver_pipeline.sh</span>{" "}
          to generate <span className="mono">results/normalized/events_index.json</span>.
        </div>
      </Panel>
    );
  }

  return (
    <div className="space-y-5">
      <Panel
        title="Normalized Evidence (TraceWeaver)"
        kicker={`Canonical schema v${twIndex.schema_version} · deterministic`}
        right={<Mode live={false} />}
      >
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric value={twIndex.total_streams} label="Evidence streams" />
          <Metric value={twIndex.total_events} label="Canonical events" tone="accent" />
          <Metric value={twIndex.total_quarantined} label="Quarantined" tone={twIndex.total_quarantined ? "warn" : "default"} />
          <Metric value={twIndex.total_normalization_warnings} label="Norm. warnings" />
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="rounded-md border border-surface-border bg-surface-raised p-3">
            <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">Events by sensor</div>
            <div className="flex flex-wrap gap-2 text-[11px]">
              {Object.entries(twIndex.events_by_sensor).map(([k, v]) => (
                <span key={k} className="rounded bg-surface-inset px-2 py-0.5 text-ink-muted mono">{k}: {v}</span>
              ))}
            </div>
          </div>
          <div className="rounded-md border border-surface-border bg-surface-raised p-3">
            <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">Events by capture mode (provenance)</div>
            <div className="flex flex-wrap gap-2 text-[11px]">
              {Object.entries(twIndex.events_by_capture_mode).map(([k, v]) => (
                <span key={k} className="rounded bg-surface-inset px-2 py-0.5 text-status-observed mono">{k}: {v}</span>
              ))}
            </div>
          </div>
        </div>
        <p className="mt-3 text-[10.5px] leading-relaxed text-ink-faint">
          Every canonical event carries a <span className="mono">raw_ref{"{"}file,line,sha256{"}"}</span> back to its
          exact source record. Capture mode separates live from historical/summary-derived evidence; a
          detection is never promoted from summary-derived or collection-failed input.
        </p>
      </Panel>

      <Panel
        title="Per-stream provenance"
        kicker="each normalized stream → source hash + canonical types"
        right={
          <div className="flex gap-1">
            {(["all", "falco", "tracee", "tetragon"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSensor(s)}
                className={`rounded-full border px-2.5 py-1 text-[11px] ${sensor === s ? "border-accent/50 bg-accent/15 text-accent" : "border-surface-border text-ink-muted hover:text-ink"}`}
              >
                {s}
              </button>
            ))}
          </div>
        }
      >
        <div className="max-h-[28rem] overflow-auto">
          <table className="w-full min-w-[720px] text-[11.5px]">
            <thead className="sticky top-0 bg-surface-panel">
              <tr className="text-left text-[9.5px] uppercase tracking-wide text-ink-faint">
                <th className="pb-2 pr-3 font-medium">Trial</th>
                <th className="pb-2 pr-3 font-medium">Sensor</th>
                <th className="pb-2 pr-3 font-medium">Mode</th>
                <th className="pb-2 pr-3 font-medium">Events</th>
                <th className="pb-2 pr-3 font-medium">Canonical types</th>
                <th className="pb-2 pr-3 font-medium">Source sha256</th>
              </tr>
            </thead>
            <tbody>
              {streams.map((s) => (
                <tr key={s.stream} className="border-t border-surface-border align-top">
                  <td className="py-2 pr-3 text-ink">{s.trial_id}</td>
                  <td className="py-2 pr-3 text-ink-muted">{s.sensor}</td>
                  <td className="py-2 pr-3"><span className="rounded bg-surface-inset px-1.5 py-0.5 text-[10px] text-status-observed mono">{s.capture_mode}</span></td>
                  <td className="py-2 pr-3 mono text-ink-muted">{s.event_count}</td>
                  <td className="py-2 pr-3 mono text-[10px] text-ink-faint">
                    {Object.entries(s.canonical_type_counts).map(([k, v]) => `${k}:${v}`).join("  ")}
                  </td>
                  <td className="py-2 pr-3 mono text-[10px] text-ink-faint">{s.stream_sha256.slice(0, 16)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
