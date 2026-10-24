"use client";

import { useMemo, useState } from "react";
import type { Catalog, NormRecord, Status, Tool } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { Panel, Pill, StatusBadge, STATUS_META, TOOL_LABEL, JsonBlock, Mode } from "./ui";
import { EvidenceCard } from "./EvidenceCard";

function EvidenceViewer({ rec }: { rec: NormRecord }) {
  const [open, setOpen] = useState<"none" | "raw" | "events">("none");
  const [raw, setRaw] = useState<unknown>(null);
  const [events, setEvents] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);

  async function fetchRaw() {
    if (open === "raw") return setOpen("none");
    setOpen("raw");
    if (raw || !rec.evidence_raw) return;
    setLoading(true);
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_raw)}`);
    const j = await r.json();
    setRaw(j.ok ? j.data : { error: j.error });
    setLoading(false);
  }
  async function fetchEvents() {
    if (open === "events") return setOpen("none");
    setOpen("events");
    if (events || !rec.evidence_events) return;
    setLoading(true);
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_events)}&limit=300`);
    const j = await r.json();
    setEvents(j.ok ? j.events : [{ error: j.error }]);
    setLoading(false);
  }

  return (
    <div className="mt-3">
      <div className="flex flex-wrap items-center gap-2">
        {rec.evidence_raw && (
          <button
            onClick={fetchRaw}
            className={`rounded-md border px-2.5 py-1 text-[11px] mono transition ${
              open === "raw"
                ? "border-accent/50 bg-accent/10 text-accent"
                : "border-surface-border text-ink-muted hover:text-ink"
            }`}
          >
            {open === "raw" ? "▾" : "▸"} {rec.evidence_raw}
          </button>
        )}
        {rec.evidence_events && (
          <button
            onClick={fetchEvents}
            className={`rounded-md border px-2.5 py-1 text-[11px] mono transition ${
              open === "events"
                ? "border-accent/50 bg-accent/10 text-accent"
                : "border-surface-border text-ink-muted hover:text-ink"
            }`}
          >
            {open === "events" ? "▾" : "▸"} {rec.evidence_events} (raw eBPF events)
          </button>
        )}
      </div>
      {loading && <div className="mt-2 text-[11px] text-ink-faint">loading evidence…</div>}
      {open === "raw" && raw != null && (
        <div className="mt-2">
          <JsonBlock data={raw} />
        </div>
      )}
      {open === "events" && events != null && (
        <div className="mt-2">
          <div className="mb-1.5 text-[10.5px] text-ink-faint">
            Showing {events.length} captured Tetragon event(s), scoped to the workload container.
          </div>
          <JsonBlock data={events} maxH="max-h-96" />
        </div>
      )}
    </div>
  );
}

export default function Explorer({
  catalog,
  records,
  selectedId,
  onSelect,
}: {
  catalog: Catalog;
  records: NormRecord[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const [toolFilter, setToolFilter] = useState<Tool | "all">("all");
  const [statusFilter, setStatusFilter] = useState<Status | "all">("all");
  const [variantFilter, setVariantFilter] = useState<string>("all");

  const recMap = useMemo(() => {
    const m = new Map<string, NormRecord>();
    records.forEach((r) => m.set(`${r.experiment_id}:${r.tool}`, r));
    return m;
  }, [records]);

  const variants = useMemo(
    () => Array.from(new Set(catalog.experiments.map((e) => e.variant))),
    [catalog]
  );

  const visibleTools = toolFilter === "all" ? TOOLS : [toolFilter];

  const rows = catalog.experiments.filter((e) => {
    if (variantFilter !== "all" && e.variant !== variantFilter) return false;
    if (statusFilter !== "all") {
      const hit = visibleTools.some(
        (t) => recMap.get(`${e.id}:${t}`)?.status === statusFilter
      );
      if (!hit) return false;
    }
    return true;
  });

  const selected = catalog.experiments.find((e) => e.id === selectedId) ?? catalog.experiments[0];

  return (
    <div className="space-y-5">
      <Panel
        title="Experiment Explorer"
        kicker="Evidence-traceable"
        right={<span className="text-[11px] text-ink-faint">{rows.length} shown</span>}
      >
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="text-ink-faint">Detector</span>
            {(["all", ...TOOLS] as const).map((t) => (
              <Pill key={t} active={toolFilter === t} onClick={() => setToolFilter(t)}>
                {t === "all" ? "All" : TOOL_LABEL[t]}
              </Pill>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-ink-faint">Variant</span>
            {(["all", ...variants] as const).map((v) => (
              <Pill key={v} active={variantFilter === v} onClick={() => setVariantFilter(v)}>
                {v === "all" ? "All" : v.replace(/_/g, " ")}
              </Pill>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-ink-faint">Status</span>
            {(["all", "confirmed_detection", "telemetry_observed", "partial"] as const).map((s) => (
              <Pill key={s} active={statusFilter === s} onClick={() => setStatusFilter(s)}>
                {s === "all" ? "All" : STATUS_META[s as Status].short}
              </Pill>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-ink-faint">
                <th className="w-64 pb-2.5 pr-4 font-medium">Experiment</th>
                {visibleTools.map((t) => (
                  <th key={t} className="pb-2.5 pr-4 font-medium">
                    {TOOL_LABEL[t]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr
                  key={e.id}
                  onClick={() => onSelect(e.id)}
                  tabIndex={0}
                  onKeyDown={(ev) => (ev.key === "Enter" || ev.key === " ") && onSelect(e.id)}
                  className={`cursor-pointer border-t border-surface-border outline-none transition hover:bg-surface-hover focus:bg-surface-hover ${
                    selectedId === e.id ? "bg-surface-hover" : ""
                  }`}
                >
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      {selectedId === e.id && <span className="text-accent">▸</span>}
                      <span className="font-medium text-ink">
                        {e.id} · {e.title}
                      </span>
                    </div>
                    <div className="mt-0.5 pl-0 text-[10.5px] text-ink-faint">
                      {e.behavior.replace(/_/g, " ")} · {e.variant.replace(/_/g, " ")}
                    </div>
                  </td>
                  {visibleTools.map((t) => {
                    const r = recMap.get(`${e.id}:${t}`);
                    return (
                      <td key={t} className="py-2.5 pr-4">
                        {r ? <StatusBadge status={r.status} /> : <span className="text-ink-faint">—</span>}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {selected && (
        <Panel title={`${selected.id} · ${selected.title}`} kicker="Experiment detail" right={<Mode live={false} />}>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2 space-y-3">
              <Field label="Purpose">{selected.purpose}</Field>
              <Field label="Command / procedure">
                <code className="mono text-[12.5px] text-accent-bright">{selected.command}</code>
              </Field>
              <Field label="Expected observation">{selected.expected_observation}</Field>
            </div>
            <div className="space-y-2">
              {selected.target_path && <MiniKV k="Target path" v={selected.target_path} />}
              {selected.baseline_reference && (
                <MiniKV k="Baseline reference" v={selected.baseline_reference} />
              )}
              {selected.timing_intervals_seconds && (
                <MiniKV k="Timing intervals" v={`${selected.timing_intervals_seconds.join("s, ")}s`} />
              )}
              <MiniKV k="Variant" v={selected.variant.replace(/_/g, " ")} />
            </div>
          </div>

          <div className="mt-5 space-y-3">
            <div className="text-[10px] font-medium uppercase tracking-wider text-ink-faint">
              Detector-by-detector result
            </div>
            {TOOLS.map((t) => {
              const r = recMap.get(`${selected.id}:${t}`);
              if (!r) return null;
              const s = STATUS_META[r.status];
              return (
                <div key={t} className={`rounded-lg border p-4 ${s.border} ${s.bg}`}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="text-[13px] font-semibold text-ink">{TOOL_LABEL[t]}</span>
                      <StatusBadge status={r.status} />
                      {r.rule_class && (
                        <span className="rounded border border-surface-border bg-surface-inset px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-ink-muted mono">
                          {r.rule_class.replace(/_/g, " ")}
                        </span>
                      )}
                      {r.context_enriched && (
                        <span className="text-[10px] text-ink-faint">context enriched</span>
                      )}
                    </div>
                    <span className="text-[10px] text-ink-faint">
                      confidence: <span className="text-ink-muted">{r.confidence}</span>
                    </span>
                  </div>
                  <p className="mt-2 text-[12.5px] leading-relaxed text-ink">{r.interpretation}</p>
                  {r.notes && r.notes !== r.interpretation && (
                    <p className="mt-1.5 text-[11.5px] leading-relaxed text-ink-muted">
                      <span className="text-ink-faint">Recorded note: </span>
                      {r.notes}
                    </p>
                  )}
                  {r.processes_observed && (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] mono">
                      <span className="text-ink-faint">processes:</span>
                      {r.processes_observed.map((p, i) => (
                        <span key={i} className="flex items-center gap-1.5">
                          <span className="rounded bg-surface-inset px-1.5 py-0.5 text-ink">{p}</span>
                          {i < r.processes_observed!.length - 1 && (
                            <span className="text-ink-faint">→</span>
                          )}
                        </span>
                      ))}
                    </div>
                  )}
                  {(r.detection_type || r.alert_count != null) && (
                    <div className="mt-2 flex flex-wrap gap-4 text-[10.5px] text-ink-faint">
                      {r.detection_type && (
                        <span>
                          type: <span className="text-ink-muted mono">{r.detection_type}</span>
                        </span>
                      )}
                      {r.alert_count != null && (
                        <span>
                          alerts: <span className="text-ink-muted mono">{r.alert_count}</span>
                        </span>
                      )}
                    </div>
                  )}
                  <details className="mt-3 group">
                    <summary className="cursor-pointer text-[11px] font-medium text-accent hover:underline">
                      What this means — plain-English interpretation
                    </summary>
                    <div className="mt-2">
                      <EvidenceCard rec={r} experiment={selected} />
                    </div>
                  </details>
                  <EvidenceViewer rec={r} />
                </div>
              );
            })}
          </div>
        </Panel>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-wider text-ink-faint">{label}</div>
      <div className="mt-1 text-[13px] leading-relaxed text-ink-muted">{children}</div>
    </div>
  );
}

function MiniKV({ k, v }: { k: string; v: string }) {
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-3 py-2">
      <div className="text-[9.5px] font-medium uppercase tracking-wide text-ink-faint">{k}</div>
      <div className="mt-0.5 text-[12.5px] text-ink mono">{v}</div>
    </div>
  );
}
