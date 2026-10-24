"use client";

import { useMemo, useState } from "react";
import type { RunRow, Tool } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { Panel, Pill, StatusBadge, TOOL_LABEL, JsonBlock, Mode } from "./ui";

export default function EvidenceExplorer({ runs }: { runs: RunRow[] }) {
  const [tool, setTool] = useState<Tool | "all">("all");
  const [prov, setProv] = useState<"all" | "live" | "recorded">("all");
  const [exp, setExp] = useState<string>("all");
  const [open, setOpen] = useState<string | null>(null);
  const [payload, setPayload] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  const experiments = useMemo(
    () => Array.from(new Set(runs.map((r) => r.experiment_id))).sort(),
    [runs]
  );

  const filtered = runs.filter(
    (r) =>
      (tool === "all" || r.tool === tool) &&
      (prov === "all" || r.provenance === prov) &&
      (exp === "all" || r.experiment_id === exp)
  );

  async function view(path: string | null, kind: "raw" | "events") {
    if (!path) return;
    const key = `${kind}:${path}`;
    if (open === key) {
      setOpen(null);
      return;
    }
    setOpen(key);
    setLoading(true);
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(path)}${kind === "events" ? "&limit=200" : ""}`);
    const j = await r.json();
    setPayload(j.ok ? (kind === "events" ? j.events : j.data) : { error: j.error });
    setLoading(false);
  }

  return (
    <Panel
      title="Evidence Explorer"
      kicker="Every record traces to a source file"
      right={<span className="text-[11px] text-ink-faint">{filtered.length} runs</span>}
    >
      <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px]">
        <div className="flex items-center gap-1.5">
          <span className="text-ink-faint">Detector</span>
          {(["all", ...TOOLS] as const).map((t) => (
            <Pill key={t} active={tool === t} onClick={() => setTool(t)}>
              {t === "all" ? "All" : TOOL_LABEL[t]}
            </Pill>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-ink-faint">Provenance</span>
          {(["all", "live", "recorded"] as const).map((p) => (
            <Pill key={p} active={prov === p} onClick={() => setProv(p)}>
              {p}
            </Pill>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-ink-faint">Experiment</span>
          <select
            value={exp}
            onChange={(e) => setExp(e.target.value)}
            className="rounded-md border border-surface-border bg-surface-raised px-2 py-1 text-[11px] text-ink"
          >
            <option value="all">All</option>
            {experiments.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-[12px]">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wide text-ink-faint">
              <th className="pb-2 pr-3 font-medium">Run ID</th>
              <th className="pb-2 pr-3 font-medium">Exp</th>
              <th className="pb-2 pr-3 font-medium">Tool</th>
              <th className="pb-2 pr-3 font-medium">Mode</th>
              <th className="pb-2 pr-3 font-medium">Status</th>
              <th className="pb-2 pr-3 font-medium">Processes</th>
              <th className="pb-2 pr-3 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.run_id} className="border-t border-surface-border align-top">
                <td className="py-2 pr-3 mono text-[10.5px] text-ink-faint">{r.run_id}</td>
                <td className="py-2 pr-3 text-ink">{r.experiment_id}</td>
                <td className="py-2 pr-3 text-ink-muted">{TOOL_LABEL[r.tool]}</td>
                <td className="py-2 pr-3">
                  <Mode live={r.provenance === "live"} />
                </td>
                <td className="py-2 pr-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="py-2 pr-3 mono text-[10.5px] text-ink-muted">
                  {r.processes_observed ? r.processes_observed.join(" → ") : "—"}
                </td>
                <td className="py-2 pr-3">
                  <div className="flex flex-col gap-1">
                    {r.evidence_raw && (
                      <button onClick={() => view(r.evidence_raw, "raw")} className="text-left text-[10.5px] text-accent hover:underline mono">
                        {open === `raw:${r.evidence_raw}` ? "▾" : "▸"} raw json
                      </button>
                    )}
                    {r.evidence_events && (
                      <button onClick={() => view(r.evidence_events, "events")} className="text-left text-[10.5px] text-accent hover:underline mono">
                        {open === `events:${r.evidence_events}` ? "▾" : "▸"} eBPF events
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {open && (
        <div className="mt-3">
          <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">{open.split(":").slice(1).join(":")}</div>
          {loading ? <div className="text-[11px] text-ink-faint">loading…</div> : <JsonBlock data={payload} maxH="max-h-96" />}
        </div>
      )}

      {filtered.length === 0 && (
        <div className="rounded-lg border border-surface-border bg-surface-inset p-6 text-center text-[12px] text-ink-faint">
          No runs match the current filters.
        </div>
      )}
    </Panel>
  );
}
