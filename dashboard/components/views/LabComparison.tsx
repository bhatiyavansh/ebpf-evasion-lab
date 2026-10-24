"use client";

import { useState } from "react";
import type { Comparison } from "@/lib/types";
import { Panel } from "@/components/ui";
import { DetectionMatrix, DetectionRateChart, ScenarioDetail, QualifyingCriteria, PerScenarioRates, RepeatabilityView, CoverageNote, BenignControl } from "@/components/ComparisonStudy";

export default function LabComparison({ comparison }: { comparison: Comparison | null }) {
  const [sid, setSid] = useState<string>(comparison?.scenarios[0]?.id ?? "A1");
  if (!comparison) {
    return (
      <Panel title="Detection Comparison Study">
        <div className="text-[12px] text-ink-faint">
          Comparison study not generated yet. Run <span className="mono">./scripts/run_comparison.sh</span>{" "}
          then <span className="mono">python3 -I scripts/build_comparison.py</span>.
        </div>
      </Panel>
    );
  }
  const scenario = comparison.scenarios.find((s) => s.id === sid) ?? comparison.scenarios[0];
  return (
    <div className="space-y-5">
      <CoverageNote comparison={comparison} />
      <div className="grid gap-5 lg:grid-cols-5">
        <div className="lg:col-span-3"><DetectionMatrix comparison={comparison} onScenario={setSid} /></div>
        <div className="lg:col-span-2"><DetectionRateChart comparison={comparison} /></div>
      </div>
      <PerScenarioRates comparison={comparison} />
      <BenignControl comparison={comparison} />
      <RepeatabilityView scenario={scenario} />
      <ScenarioDetail scenario={scenario} />
      <QualifyingCriteria comparison={comparison} />
    </div>
  );
}
