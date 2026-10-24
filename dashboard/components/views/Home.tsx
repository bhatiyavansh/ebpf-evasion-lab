"use client";

import Link from "next/link";
import { useMemo } from "react";
import type { DashboardData, Status } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { Panel, Metric, KV, Dot, STATUS_META, STATUS_ORDER } from "@/components/ui";
import { DetectorMatrix } from "@/components/Comparisons";

export default function Home({ data }: { data: DashboardData }) {
  const { catalog, records, analysis, environment } = data;

  const m = useMemo(() => {
    const evaluated = records.filter((r) => r.status !== "not_tested").length;
    const withEvidence = records.filter((r) => r.evidence_raw).length;
    const live = records.filter((r) => r.provenance === "live").length;
    const counts: Record<Status, number> = {
      confirmed_detection: records.filter((r) => r.status === "confirmed_detection").length,
      telemetry_observed: records.filter((r) => r.status === "telemetry_observed").length,
      partial: records.filter((r) => r.status === "partial").length,
      not_tested: records.filter((r) => r.status === "not_tested").length,
      confirmed_miss: records.filter((r) => r.status === "confirmed_miss").length,
      collection_failed: records.filter((r) => r.status === "collection_failed").length,
    };
    const defined = catalog.experiments.length;
    const derived = catalog.experiments.filter((e) => e.derived).length;
    return { evaluated, withEvidence, live, counts, defined, derived };
  }, [catalog, records]);

  return (
    <div className="space-y-5">
      {/* Hero */}
      <div className="lab-grid overflow-hidden rounded-xl border border-surface-border bg-surface-panel/60 p-6 sm:p-8">
        <div className="max-w-3xl">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-[10.5px] font-medium uppercase tracking-wide text-accent">
            Adaptive Evasion Analysis · eBPF Runtime Security
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-ink sm:text-[30px]">
            How does adaptive container behavior affect eBPF detection?
          </h1>
          <p className="mt-3 text-[13.5px] leading-relaxed text-ink-muted">
            This platform evaluates <span className="text-ink">Falco</span>,{" "}
            <span className="text-ink">Tracee</span> and <span className="text-ink">Tetragon</span>{" "}
            against controlled baseline and adaptive container behaviors, rigorously separating{" "}
            <span className="text-status-observed">kernel-event visibility</span> from{" "}
            <span className="text-status-detected">verified security detection</span>.
          </p>
          <div className="mt-4 flex flex-wrap gap-2 text-[10.5px]">
            {[
              environment?.os ?? "Kali Linux ARM64",
              `kernel ${environment?.kernel ?? "7.1.5+kali-arm64"}`,
              environment?.arch ?? "aarch64",
              "Docker",
              environment?.btf_vmlinux ? "BTF available" : "BTF unknown",
            ].map((c) => (
              <span key={c} className="rounded-md border border-surface-border bg-surface-inset px-2.5 py-1 text-ink-muted mono">
                {c}
              </span>
            ))}
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            <Link href="/lab" className="rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-[12px] font-semibold text-accent hover:bg-accent/25">
              Open Experiment Lab →
            </Link>
            <Link href="/demo" className="rounded-md border border-surface-border px-4 py-2 text-[12px] font-medium text-ink-muted hover:text-ink">
              ▶ Start guided demo
            </Link>
            <Link href="/outcome" className="rounded-md border border-surface-border px-4 py-2 text-[12px] font-medium text-ink-muted hover:text-ink">
              Research findings
            </Link>
          </div>
        </div>
      </div>

      {/* Overview metrics */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Metric value={TOOLS.length} label="Detectors" />
        <Metric value={m.defined} label="Experiments defined" hint={`${m.derived} derived`} />
        <Metric value={m.evaluated} label="Evaluations" tone="accent" hint="experiment×tool cells" />
        <Metric value={m.withEvidence} label="With evidence" />
        <Metric value={m.live} label="Live-captured" tone="accent" />
        <Metric value={records.length - m.live} label="Recorded" />
      </div>

      {/* Status model */}
      <Panel title="Status model" kicker="Scientific-integrity contract">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {STATUS_ORDER.map((s) => (
            <div key={s} className="flex items-start gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2">
              <Dot status={s} />
              <div>
                <div className={`text-[11.5px] font-semibold ${STATUS_META[s].text}`}>
                  {STATUS_META[s].label} <span className="text-ink-faint">· {m.counts[s]}</span>
                </div>
                <div className="text-[10.5px] leading-snug text-ink-faint">{STATUS_META[s].desc}</div>
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10.5px] leading-relaxed text-ink-faint">
          Each cell also carries four independent dimensions — execution, collection, telemetry,
          detection — so telemetry is never conflated with an alert. Telemetry-only tools
          (Tracee/Tetragon) have detection = <span className="mono">not_evaluated</span>, never a
          detection failure.
        </p>
      </Panel>

      {/* Environment spec */}
      <Panel
        title="Environment specification"
        kicker="Recorded at evidence capture"
        right={
          <span className="text-[10px] text-ink-faint">
            captured {environment?.captured_at?.slice(0, 16).replace("T", " ") ?? "—"}
          </span>
        }
      >
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
          <KV k="Operating system" v={environment?.os ?? "Kali GNU/Linux"} />
          <KV k="Kernel" v={environment?.kernel ?? "7.1.5+kali-arm64"} />
          <KV k="Architecture" v={environment?.arch ?? "aarch64"} />
          <KV k="BTF (vmlinux)" v={environment?.btf_vmlinux ? "available" : "unknown"} />
          <KV k="Falco" v={catalog.detectors.falco.image.split(":").pop()!} />
          <KV k="Tracee" v={catalog.detectors.tracee.image.split("/").pop()!} />
          <KV k="Tetragon" v={catalog.detectors.tetragon.image.split(":").pop()!} />
          <KV k="Docker" v={(environment?.docker_version ?? "Docker").replace("Docker version ", "").split(",")[0]} />
        </div>
        <p className="mt-3 text-[10.5px] text-ink-faint">
          Recorded specification from capture time. A past successful run does not imply a detector is
          running now — the <Link href="/lab" className="text-accent hover:underline">Experiment Lab</Link>{" "}
          performs a live health check.
        </p>
      </Panel>

      {/* Quick matrix + headline */}
      {analysis && (
        <div className="grid gap-5 lg:grid-cols-5">
          <div className="lg:col-span-3">
            <DetectorMatrix analysis={analysis} />
          </div>
          <div className="lg:col-span-2">
            <Panel title="Headline finding" kicker="Evidence-backed">
              <p className="text-[13px] leading-relaxed text-ink">
                Simple execution indirection (E04) and controlled timing variation (E05) did not
                eliminate process-execution observability under any tested configuration — every
                execution stage remained visible across Falco, Tracee and Tetragon.
              </p>
              <ul className="mt-3 space-y-2 text-[11.5px] text-ink-muted">
                <li className="flex gap-2">
                  <span className="text-status-detected">▪</span> Falco raised a built-in security
                  detection only for E01 (sensitive file); its process-exec alerts are a custom rule.
                </li>
                <li className="flex gap-2">
                  <span className="text-status-partial">▪</span> E03/E08 network: process telemetry
                  everywhere, Tracee saw the connect to :443, but no tool raised a network detection.
                </li>
                <li className="flex gap-2">
                  <span className="text-status-observed">▪</span> E06 repeatability: 5/5 identical
                  captures. E07: sensitive vs benign openat distinguished in telemetry, not by an alert.
                </li>
              </ul>
              <Link href="/outcome" className="mt-4 inline-block text-[11.5px] text-accent hover:underline">
                Read the full findings →
              </Link>
            </Panel>
          </div>
        </div>
      )}
    </div>
  );
}
