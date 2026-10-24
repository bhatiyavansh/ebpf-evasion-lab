"use client";

import { useState } from "react";
import type { CveCatalog, CveEntry, DashboardData } from "@/lib/types";
import { Panel, JsonBlock } from "@/components/ui";

const APPLIC_STYLE: Record<string, { label: string; cls: string }> = {
  NOT_AFFECTED_OR_PATCHED: { label: "Not affected / patched", cls: "border-status-detected/40 bg-status-detected/10 text-status-detected" },
  INCOMPATIBLE_ENVIRONMENT: { label: "Incompatible environment", cls: "border-status-nottested/40 bg-status-nottested/10 text-ink-muted" },
  AFFECTED_AND_VALIDATED: { label: "Affected & validated", cls: "border-status-missed/40 bg-status-missed/10 text-status-missed" },
  NOT_REPRODUCED: { label: "Not reproduced", cls: "border-status-partial/40 bg-status-partial/10 text-status-partial" },
  NOT_TESTED: { label: "Not tested", cls: "border-surface-border bg-surface-inset text-ink-faint" },
  // legacy
  not_applicable: { label: "Not applicable", cls: "border-status-nottested/40 bg-status-nottested/10 text-ink-muted" },
};

export default function CveLab({ data }: { data: DashboardData }) {
  const cve = data.cve;
  const [selected, setSelected] = useState(0);
  if (!cve) {
    return (
      <Panel title="CVE Lab">
        <div className="text-[12px] text-ink-faint">CVE catalog not found.</div>
      </Panel>
    );
  }
  const entry = cve.cves[selected];

  return (
    <div className="space-y-5">
      <Panel title="Real-CVE Compatibility & Evaluation" kicker="Applicability assessed against the actual host">
        <p className="text-[12px] leading-relaxed text-ink-muted">{cve.description}</p>
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {Object.entries(cve.host_assessment_basis)
            .filter(([k]) => ["kernel", "arch", "distro", "config_user_ns", "config_nf_tables", "unprivileged_userns_clone"].includes(k))
            .map(([k, v]) => (
              <div key={k} className="rounded-md border border-surface-border bg-surface-raised px-3 py-2">
                <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{k.replace(/_/g, " ")}</div>
                <div className="mt-0.5 text-[11.5px] text-ink mono">{String(v)}</div>
              </div>
            ))}
        </div>
        <div className="mt-3 rounded-md border border-status-partial/25 bg-status-partial/5 p-3 text-[11px] leading-relaxed text-ink-muted">
          <span className="font-semibold text-status-partial">Safety model.</span> No exploit is
          executed on the project host. Mode B (isolated reproduction) is blocked and documented per
          CVE. Safe simulations exercise related event categories and are never labeled as real
          exploitation.
        </div>
      </Panel>

      <div className="grid gap-5 lg:grid-cols-4">
        {/* CVE list */}
        <div className="space-y-2 lg:col-span-1">
          {cve.cves.map((c, i) => {
            const st = APPLIC_STYLE[c.applicability.status] ?? APPLIC_STYLE.partial;
            return (
              <button
                key={c.id}
                onClick={() => setSelected(i)}
                className={`w-full rounded-lg border p-3 text-left transition ${
                  selected === i ? "border-accent/50 bg-accent/10" : "border-surface-border bg-surface-raised hover:bg-surface-hover"
                }`}
              >
                <div className="text-[12px] font-semibold text-ink">{c.id}</div>
                <div className="text-[11px] text-ink-muted">{c.name}</div>
                <div className={`mt-1.5 inline-block rounded-full border px-2 py-0.5 text-[9.5px] font-semibold uppercase tracking-wide ${st.cls}`}>
                  {st.label}
                </div>
              </button>
            );
          })}
        </div>

        {/* CVE detail */}
        <div className="lg:col-span-3">
          <CveDetail entry={entry} modes={cve.modes} />
        </div>
      </div>
    </div>
  );
}

function CveDetail({ entry, modes }: { entry: CveEntry; modes: Record<string, string> }) {
  const [mode, setMode] = useState<"A" | "B" | "C">("C");
  const [simData, setSimData] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const st = APPLIC_STYLE[entry.applicability.status] ?? APPLIC_STYLE.partial;

  async function loadRelated(expId: string) {
    setLoading(true);
    setSimData(null);
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(`results/raw/${expId}_tetragon.json`)}`);
    const j = await r.json();
    setSimData(j.ok ? j.data : { error: j.error });
    setLoading(false);
  }

  return (
    <Panel title={`${entry.id} · ${entry.name}`} kicker={entry.class}>
      {/* Key facts */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Fact k="CVSS v3" v={`${entry.cvss_v3} ${entry.cvss_severity}`} />
        <Fact k="Affected" v={entry.affected_range} />
        <Fact k="Fixed in" v={entry.fixed_versions.slice(0, 2).join(", ") + (entry.fixed_versions.length > 2 ? "…" : "")} />
        <Fact k="Applicability" v={st.label} />
      </div>

      <div className="mt-3 text-[12px] leading-relaxed text-ink-muted">{entry.impact}</div>

      {/* Applicability + reproduction status */}
      <div className={`mt-3 rounded-lg border p-4 ${st.cls}`}>
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold uppercase tracking-wide">
          <span>Applicability: {st.label} · confidence {entry.applicability.confidence}</span>
          {entry.reproduction_status && (
            <span className="rounded-full border border-status-partial/40 bg-status-partial/10 px-2 py-0.5 text-status-partial">
              reproduction: {entry.reproduction_status.replace(/_/g, " ")}
            </span>
          )}
        </div>
        <p className="mt-1.5 text-[11.5px] leading-relaxed text-ink-muted">{entry.applicability.reason}</p>
        {entry.reproduction_note && (
          <p className="mt-1 text-[10.5px] leading-relaxed text-ink-faint">{entry.reproduction_note}</p>
        )}
      </div>

      {/* Mode selector */}
      <div className="mt-4">
        <div className="mb-2 text-[10px] uppercase tracking-wide text-ink-faint">Run mode</div>
        <div className="flex flex-wrap gap-2">
          {(["A", "B", "C"] as const).map((mk) => {
            const blocked = mk === "B";
            return (
              <button
                key={mk}
                onClick={() => setMode(mk)}
                className={`rounded-md border px-3 py-1.5 text-[11px] font-medium transition ${
                  mode === mk
                    ? blocked
                      ? "border-status-missed/50 bg-status-missed/15 text-status-missed"
                      : "border-accent/50 bg-accent/15 text-accent"
                    : blocked
                    ? "border-status-missed/30 bg-status-missed/5 text-status-missed/70 hover:bg-status-missed/10"
                    : "border-surface-border text-ink-muted hover:text-ink"
                }`}
              >
                Mode {mk} {mk === "A" ? "· Safe simulation" : mk === "B" ? "· Isolated repro (blocked)" : "· Recorded"}
              </button>
            );
          })}
        </div>
      </div>

      {/* Mode content */}
      <div className="mt-3 rounded-lg border border-surface-border bg-surface-inset p-4">
        <p className="text-[11px] leading-relaxed text-ink-faint">{modes[mode]}</p>

        {mode === "B" && (
          <div className="mt-2 rounded-md border border-status-missed/30 bg-status-missed/5 p-3">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-status-missed">
              Blocked
            </div>
            <p className="mt-1 text-[11.5px] leading-relaxed text-ink-muted">{entry.mode_b_blocked_reason}</p>
          </div>
        )}

        {(mode === "A" || mode === "C") && (
          <div className="mt-3">
            <div className="rounded-md border border-status-partial/25 bg-status-partial/5 p-3 text-[11px] leading-relaxed text-ink-muted">
              <span className="font-semibold text-status-partial">Not exploitation.</span>{" "}
              {entry.simulation.disclaimer}
            </div>
            <div className="mt-2 text-[11px] text-ink-muted">
              <span className="text-ink-faint">Related event category: </span>
              {entry.simulation.category}
            </div>
            <div className="mt-1 text-[11px] text-ink-muted">
              <span className="text-ink-faint">Benign workload: </span>
              {entry.simulation.benign_workload}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="text-[10px] uppercase tracking-wide text-ink-faint">Related evidence:</span>
              {entry.simulation.related_evidence_experiments.map((e) => (
                <button
                  key={e}
                  onClick={() => loadRelated(e)}
                  className="rounded border border-surface-border bg-surface-raised px-2 py-0.5 text-[10.5px] text-accent hover:bg-surface-hover mono"
                >
                  {e} evidence
                </button>
              ))}
            </div>
            {loading && <div className="mt-2 text-[11px] text-ink-faint">loading recorded evidence…</div>}
            {simData != null && (
              <div className="mt-2">
                <JsonBlock data={simData} maxH="max-h-80" />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Sources */}
      <div className="mt-3 flex flex-wrap items-center gap-3 text-[11px]">
        <span className="text-ink-faint">Sources:</span>
        {entry.sources.map((s) => (
          <a key={s.url} href={s.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
            {s.label} ↗
          </a>
        ))}
      </div>
    </Panel>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-3 py-2">
      <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{k}</div>
      <div className="mt-0.5 text-[11.5px] text-ink mono">{v}</div>
    </div>
  );
}
