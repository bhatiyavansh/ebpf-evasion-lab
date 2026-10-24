"use client";

import type { Analysis } from "@/lib/types";
import { Panel } from "./ui";

export function NewExperiments({ analysis }: { analysis: Analysis }) {
  const e06 = analysis.e06_repeatability;
  const e07 = analysis.e07_sensitive_vs_benign;
  const e08 = analysis.e08_network_coverage;
  const e09 = analysis.e09_sequence_timing;

  return (
    <div className="space-y-5">
      {/* E06 */}
      {e06 && (
        <Panel title="E06 · Repeated Baseline Consistency" kicker="Repeatability (exploratory)">
          <div className="mb-3 flex flex-wrap items-center gap-3 text-[12px]">
            <Stat label="Trials" value={e06.trial_count} />
            <Stat label="Distinct process chains" value={e06.distinct_process_chains} />
            <Stat label="Distinct exec counts" value={(e06.distinct_exec_counts || []).join(", ")} />
            <span
              className={`rounded-full border px-2.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${
                e06.repeatable
                  ? "border-status-detected/30 bg-status-detected/10 text-status-detected"
                  : "border-status-partial/30 bg-status-partial/10 text-status-partial"
              }`}
            >
              {e06.repeatable ? "Fully repeatable" : "Variation observed"}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[520px] text-[12px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-ink-faint">
                  <th className="pb-2 pr-3 font-medium">Trial</th>
                  <th className="pb-2 pr-3 font-medium">Process chain</th>
                  <th className="pb-2 pr-3 font-medium">Exec events</th>
                  <th className="pb-2 pr-3 font-medium">Run ID</th>
                </tr>
              </thead>
              <tbody>
                {(e06.trials || []).map((t: Record<string, unknown>) => (
                  <tr key={t.trial as number} className="border-t border-surface-border">
                    <td className="py-2 pr-3 text-ink">#{t.trial as number}</td>
                    <td className="py-2 pr-3 mono text-ink-muted">
                      {(t.processes_observed as string[]).join(" → ")}
                    </td>
                    <td className="py-2 pr-3 mono text-ink-muted">{t.process_exec_count as number}</td>
                    <td className="py-2 pr-3 mono text-[10.5px] text-ink-faint">{t.run_id as string}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-[10.5px] text-ink-faint">{e06.caveat}</p>
        </Panel>
      )}

      {/* E07 */}
      {e07 && (
        <Panel title="E07 · Sensitive vs Benign File Access" kicker="Comparative">
          <div className="grid gap-3 md:grid-cols-2">
            <FileCard
              title="Sensitive read"
              path={e07.sensitive?.path}
              paths={e07.sensitive?.openat_paths}
              hit={e07.sensitive?.target_observed_in_openat}
              tone="warn"
            />
            <FileCard
              title="Benign read"
              path={e07.benign?.path}
              paths={e07.benign?.openat_paths}
              hit={e07.benign?.target_observed_in_openat}
              tone="ok"
            />
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
            Both pathnames were captured in <span className="mono">openat</span> telemetry. Tetragon&apos;s
            tracing policy records the pathname for both but raises no alert for either — the sensitive
            vs benign distinction exists in the <span className="text-status-observed">telemetry</span>,
            not in a <span className="text-status-detected">detection verdict</span>.
          </p>
        </Panel>
      )}

      {/* E08 */}
      {e08 && (
        <Panel title="E08 · Network Observability & Policy Coverage" kicker="Telemetry ≠ detection">
          <div className="grid gap-3 md:grid-cols-3">
            <CoverageCard
              tool="Tetragon"
              telemetry={`process-exec: ${(e08.tetragon?.process_telemetry || []).join(", ")}`}
              detection={e08.tetragon?.network_detection_status}
              note={e08.tetragon?.policy?.explanation}
            />
            <CoverageCard
              tool="Tracee (E03)"
              telemetry={e08.tracee_reference_E03?.network_telemetry ? "connect → :443 observed" : "no connect"}
              detection="not_evaluated"
              note={e08.tracee_reference_E03?.note}
            />
            <CoverageCard
              tool="Falco (E03)"
              telemetry="process-exec only"
              detection={e08.falco_reference_E03?.network_detection_status}
              note={e08.falco_reference_E03?.note}
            />
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
            Only Tracee was configured with a network event source. Where no network policy exists,
            network detection is labeled <span className="mono text-status-partial">not_evaluated</span>{" "}
            — explicitly not a detection failure.
          </p>
        </Panel>
      )}

      {/* E09 */}
      {e09 && (
        <Panel title="E09 · Process Sequence & Timing Comparison" kicker="Derived from E02 · E04 · E05">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-[12px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-ink-faint">
                  <th className="pb-2 pr-3 font-medium">Variant</th>
                  <th className="pb-2 pr-3 font-medium">Falco chain</th>
                  <th className="pb-2 pr-3 font-medium">Tracee chain</th>
                  <th className="pb-2 pr-3 font-medium">Tetragon chain</th>
                </tr>
              </thead>
              <tbody>
                {(e09.rows || []).map((row: Record<string, unknown>) => {
                  const pt = row.per_tool as Record<string, { processes: string[] }>;
                  return (
                    <tr key={row.experiment_id as string} className="border-t border-surface-border">
                      <td className="py-2 pr-3 text-ink">
                        {row.experiment_id as string}{" "}
                        <span className="text-ink-faint">{(row.variant as string)?.replace(/_/g, " ")}</span>
                      </td>
                      {["falco", "tracee", "tetragon"].map((t) => (
                        <td key={t} className="py-2 pr-3 mono text-ink-muted">
                          {pt[t]?.processes ? pt[t].processes.join(" → ") : "—"}
                        </td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="mt-3 rounded-md border border-accent/20 bg-accent/5 p-3 text-[11px] leading-relaxed">
            <div className="text-ink">
              <span className="font-semibold text-accent">Observation.</span> {e09.observation}
            </div>
            <div className="mt-1 text-ink-faint">
              <span className="font-semibold">Limitation.</span> {e09.limitation}
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-3 py-1.5">
      <span className="text-[10px] uppercase tracking-wide text-ink-faint">{label}</span>{" "}
      <span className="mono text-ink">{value}</span>
    </div>
  );
}

function FileCard({
  title,
  path,
  paths,
  hit,
  tone,
}: {
  title: string;
  path?: string;
  paths?: string[];
  hit?: boolean;
  tone: "warn" | "ok";
}) {
  const border = tone === "warn" ? "border-status-partial/30" : "border-status-detected/30";
  return (
    <div className={`rounded-lg border ${border} bg-surface-raised p-4`}>
      <div className="flex items-center justify-between">
        <span className="text-[12px] font-semibold text-ink">{title}</span>
        {hit && <span className="text-[10px] text-status-detected">✓ pathname captured</span>}
      </div>
      <code className="mt-1 block text-[12px] text-accent-bright mono">{path}</code>
      <div className="mt-2 text-[10px] uppercase tracking-wide text-ink-faint">openat paths</div>
      <div className="mt-1 flex flex-wrap gap-1">
        {(paths || []).map((p) => (
          <span key={p} className="rounded bg-surface-inset px-1.5 py-0.5 text-[10.5px] text-ink-muted mono">
            {p}
          </span>
        ))}
      </div>
    </div>
  );
}

function CoverageCard({
  tool,
  telemetry,
  detection,
  note,
}: {
  tool: string;
  telemetry?: string;
  detection?: string;
  note?: string;
}) {
  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <div className="text-[12px] font-semibold text-ink">{tool}</div>
      <div className="mt-2 text-[10px] uppercase tracking-wide text-ink-faint">Telemetry</div>
      <div className="text-[11.5px] text-status-observed mono">{telemetry}</div>
      <div className="mt-2 text-[10px] uppercase tracking-wide text-ink-faint">Network detection</div>
      <div
        className={`text-[11.5px] font-medium mono ${
          detection === "not_evaluated" ? "text-status-partial" : "text-ink-muted"
        }`}
      >
        {detection}
      </div>
      {note && <p className="mt-2 text-[10.5px] leading-snug text-ink-faint">{note}</p>}
    </div>
  );
}
