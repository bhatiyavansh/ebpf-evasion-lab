"use client";

import { useState } from "react";
import type { DashboardData } from "@/lib/types";
import Explorer from "@/components/Explorer";
import { DetectorMatrix, BaselineAdaptive } from "@/components/Comparisons";
import LiveReplay from "@/components/LiveReplay";
import { AnalysisEngine, FailureAnalysis } from "@/components/Analysis";
import { NewExperiments } from "@/components/NewExperiments";
import EvidenceExplorer from "@/components/EvidenceExplorer";
import LabComparison from "@/components/views/LabComparison";

type Sub = "study" | "explorer" | "matrix" | "live" | "extended" | "analysis" | "evidence";

const SUBS: { id: Sub; label: string }[] = [
  { id: "study", label: "Detection Study" },
  { id: "explorer", label: "Baseline Experiments" },
  { id: "matrix", label: "Comparisons" },
  { id: "extended", label: "E06–E09" },
  { id: "live", label: "Live & Replay" },
  { id: "evidence", label: "Evidence Explorer" },
  { id: "analysis", label: "Analysis" },
];

export default function Lab({ data }: { data: DashboardData }) {
  const { catalog, records, analysis, runs, comparison } = data;
  const [sub, setSub] = useState<Sub>("study");
  const [selectedId, setSelectedId] = useState(catalog.experiments[0]?.id ?? "E01");

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="-mx-1 flex items-center gap-1 overflow-x-auto">
          {SUBS.map((s) => (
            <button
              key={s.id}
              onClick={() => setSub(s.id)}
              className={`shrink-0 rounded-md px-3 py-1.5 text-[12px] font-medium transition ${
                sub === s.id ? "bg-accent/15 text-accent" : "text-ink-faint hover:bg-surface-hover hover:text-ink"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-[11px]">
          <a href="/api/export?format=csv" className="rounded-md border border-surface-border px-2.5 py-1 text-ink-muted hover:text-ink">
            ↓ CSV
          </a>
          <a href="/api/export?format=json" className="rounded-md border border-surface-border px-2.5 py-1 text-ink-muted hover:text-ink">
            ↓ JSON
          </a>
        </div>
      </div>

      {sub === "study" && <LabComparison comparison={comparison} />}
      {sub === "explorer" && (
        <Explorer catalog={catalog} records={records} selectedId={selectedId} onSelect={setSelectedId} />
      )}
      {sub === "matrix" && analysis && (
        <div className="space-y-5">
          <DetectorMatrix analysis={analysis} onSelect={(id) => { setSelectedId(id); setSub("explorer"); }} />
          <BaselineAdaptive analysis={analysis} />
        </div>
      )}
      {sub === "extended" && analysis && <NewExperiments analysis={analysis} />}
      {sub === "live" && <LiveReplay catalog={catalog} records={records} />}
      {sub === "evidence" && <EvidenceExplorer runs={runs} />}
      {sub === "analysis" && analysis && (
        <div className="space-y-5">
          <AnalysisEngine analysis={analysis} />
          <FailureAnalysis />
        </div>
      )}
    </div>
  );
}
