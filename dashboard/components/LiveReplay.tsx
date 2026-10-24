"use client";

import { useEffect, useState } from "react";
import type { Catalog, NormRecord, Tool } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { Panel, Pill, StatusBadge, TOOL_LABEL, JsonBlock, Mode, Dot } from "./ui";

type RunState = "ready" | "running" | "completed" | "failed" | "timed_out" | "unsupported";

interface LiveStatus {
  ok: boolean;
  docker_available?: boolean;
  btf_vmlinux?: boolean;
  detectors_live?: Record<Tool, boolean>;
  images_present?: Record<Tool, boolean>;
  error?: string;
}

export default function LiveReplay({
  catalog,
  records,
}: {
  catalog: Catalog;
  records: NormRecord[];
}) {
  const [tab, setTab] = useState<"live" | "replay">("replay");
  return (
    <Panel
      title="Live Experiment & Evidence Replay"
      kicker="Controlled execution"
      right={
        <div className="flex items-center gap-1.5">
          <Pill active={tab === "replay"} onClick={() => setTab("replay")}>
            Recorded replay
          </Pill>
          <Pill active={tab === "live"} onClick={() => setTab("live")}>
            Live run
          </Pill>
        </div>
      }
    >
      {tab === "live" ? <LivePanel catalog={catalog} /> : <ReplayPanel catalog={catalog} records={records} />}
    </Panel>
  );
}

function LivePanel({ catalog }: { catalog: Catalog }) {
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [expId, setExpId] = useState(catalog.experiments[0].id);
  const [state, setState] = useState<RunState>("ready");
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [log, setLog] = useState("");
  const [elapsed, setElapsed] = useState<number | null>(null);

  async function refresh() {
    setStatus(null);
    try {
      const r = await fetch("/api/status");
      setStatus(await r.json());
    } catch (e) {
      setStatus({ ok: false, error: String(e) });
    }
  }
  useEffect(() => {
    refresh();
  }, []);

  const exp = catalog.experiments.find((e) => e.id === expId)!;
  const tetragonReady = status?.docker_available && status?.images_present?.tetragon;

  async function run() {
    setConfirming(false);
    setState("running");
    setResult(null);
    setLog("");
    setElapsed(null);
    try {
      const r = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ experimentId: expId, tool: "tetragon" }),
      });
      const j = await r.json();
      setElapsed(j.elapsed_ms ?? null);
      setLog(j.log ?? "");
      if (j.ok && j.state === "completed") {
        setState("completed");
        setResult(j.result);
      } else {
        setState((j.state as RunState) ?? "failed");
        setResult(j.error ? { error: j.error } : null);
      }
      refresh();
    } catch (e) {
      setState("failed");
      setResult({ error: String(e) });
    }
  }

  const stateColor: Record<RunState, string> = {
    ready: "text-ink-muted",
    running: "text-accent",
    completed: "text-status-detected",
    failed: "text-status-missed",
    timed_out: "text-status-partial",
    unsupported: "text-ink-faint",
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Mode live />
        <button
          onClick={refresh}
          className="rounded-md border border-surface-border px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink"
        >
          ↻ Re-check health
        </button>
      </div>

      {/* Live detector health */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <HealthCell label="Docker" ok={status?.docker_available} loading={!status} />
        <HealthCell label="BTF" ok={status?.btf_vmlinux} loading={!status} />
        <HealthCell label="Tetragon image" ok={status?.images_present?.tetragon} loading={!status} />
        <HealthCell
          label="Tetragon live"
          ok={status?.detectors_live?.tetragon}
          loading={!status}
          neutralOff
        />
      </div>
      <p className="text-[10.5px] text-ink-faint">
        Live execution is supported for <span className="text-ink-muted">Tetragon</span> only — its
        capture harness is scripted and safe. Falco and Tracee are recorded-evidence / replay in this
        build. &ldquo;Tetragon live&rdquo; reflects a running detector container now, not whether past
        evidence exists.
      </p>

      {/* Controls */}
      <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-[11px] text-ink-faint">Allowlisted experiment:</span>
          {catalog.experiments.map((e) => (
            <Pill key={e.id} active={expId === e.id} onClick={() => setExpId(e.id)}>
              {e.id}
            </Pill>
          ))}
        </div>
        <div className="mb-3 rounded-md border border-surface-border bg-surface-inset p-3">
          <div className="text-[10px] uppercase tracking-wide text-ink-faint">
            {exp.id} · {exp.title} — exact command
          </div>
          <code className="mt-1 block break-all text-[12.5px] text-accent-bright mono">
            docker run --rm alpine:3.20 {exp.command}
          </code>
          <div className="mt-1.5 text-[10.5px] text-ink-faint">{exp.purpose}</div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {!confirming && state !== "running" && (
            <button
              disabled={!tetragonReady}
              onClick={() => setConfirming(true)}
              className="rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-[12px] font-semibold text-accent transition hover:bg-accent/25 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Prepare run
            </button>
          )}
          {confirming && (
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-ink-muted">
                Start Tetragon + run benign workload under bounded timeout?
              </span>
              <button
                onClick={run}
                className="rounded-md border border-status-detected/50 bg-status-detected/15 px-3 py-1.5 text-[12px] font-semibold text-status-detected hover:bg-status-detected/25"
              >
                Confirm & start
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="rounded-md border border-surface-border px-3 py-1.5 text-[12px] text-ink-muted hover:text-ink"
              >
                Cancel
              </button>
            </div>
          )}
          {state === "running" && (
            <div className="flex items-center gap-2 text-[12px] text-accent">
              <span className="h-2 w-2 animate-pulsedot rounded-full bg-accent" />
              running — starting detector, executing workload, capturing scoped events…
            </div>
          )}
          <span className={`ml-auto text-[11px] font-semibold uppercase tracking-wide ${stateColor[state]}`}>
            state: {state}
            {elapsed != null && <span className="ml-2 text-ink-faint">{(elapsed / 1000).toFixed(1)}s</span>}
          </span>
        </div>
      </div>

      {result != null && (
        <div className="animate-fadein rounded-lg border border-surface-border bg-surface-inset p-4">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-ink-muted">
            Captured result (derived from live Tetragon events)
          </div>
          <JsonBlock data={result} />
        </div>
      )}
      {log && (
        <details className="rounded-lg border border-surface-border bg-surface-inset p-3">
          <summary className="cursor-pointer text-[11px] text-ink-muted">Run log</summary>
          <pre className="mt-2 max-h-48 overflow-auto text-[10.5px] text-ink-faint mono">{log}</pre>
        </details>
      )}
    </div>
  );
}

function HealthCell({
  label,
  ok,
  loading,
  neutralOff,
}: {
  label: string;
  ok?: boolean;
  loading?: boolean;
  neutralOff?: boolean;
}) {
  const color = loading
    ? "border-surface-border text-ink-faint"
    : ok
    ? "border-status-detected/30 text-status-detected"
    : neutralOff
    ? "border-surface-border text-ink-faint"
    : "border-status-missed/30 text-status-missed";
  return (
    <div className={`rounded-md border bg-surface-inset px-3 py-2 ${color}`}>
      <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{label}</div>
      <div className="mt-0.5 flex items-center gap-1.5 text-[12px] font-semibold">
        {loading ? "…" : ok ? "✓ available" : neutralOff ? "idle" : "✕ unavailable"}
      </div>
    </div>
  );
}

function ReplayPanel({ catalog, records }: { catalog: Catalog; records: NormRecord[] }) {
  const [expId, setExpId] = useState(catalog.experiments[0].id);
  const [tool, setTool] = useState<Tool>("tetragon");
  const [events, setEvents] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);

  const rec = records.find((r) => r.experiment_id === expId && r.tool === tool);

  useEffect(() => {
    setEvents(null);
    if (!rec?.evidence_events) return;
    setLoading(true);
    fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_events)}&limit=200`)
      .then((r) => r.json())
      .then((j) => setEvents(j.ok ? j.events : null))
      .finally(() => setLoading(false));
  }, [rec?.evidence_events]);

  const exp = catalog.experiments.find((e) => e.id === expId)!;

  return (
    <div className="space-y-4">
      <Mode live={false} />
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px]">
        <div className="flex items-center gap-1.5">
          <span className="text-ink-faint">Experiment</span>
          {catalog.experiments.map((e) => (
            <Pill key={e.id} active={expId === e.id} onClick={() => setExpId(e.id)}>
              {e.id}
            </Pill>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-ink-faint">Detector</span>
          {TOOLS.map((t) => (
            <Pill key={t} active={tool === t} onClick={() => setTool(t)}>
              {TOOL_LABEL[t]}
            </Pill>
          ))}
        </div>
      </div>

      {!rec ? (
        <div className="rounded-lg border border-surface-border bg-surface-inset p-6 text-center text-[12px] text-ink-faint">
          No recorded evidence for {expId} · {TOOL_LABEL[tool]}.
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-ink">
              {exp.id} · {exp.title} · {TOOL_LABEL[tool]}
            </span>
            <StatusBadge status={rec.status} />
          </div>
          <p className="text-[12px] leading-relaxed text-ink-muted">{rec.interpretation}</p>

          {rec.processes_observed && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">
                Recorded execution sequence
              </div>
              <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] mono">
                {rec.processes_observed.map((p, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    <span className="rounded bg-surface-inset px-2 py-1 text-ink">{p}</span>
                    {i < rec.processes_observed!.length - 1 && (
                      <span className="text-ink-faint">→</span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">
              Recorded result — {rec.evidence_raw}
            </div>
            <RecJson rec={rec} />
          </div>

          {rec.evidence_events && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-ink-faint">
                Raw captured eBPF events — {rec.evidence_events}
              </div>
              {loading ? (
                <div className="text-[11px] text-ink-faint">loading recorded events…</div>
              ) : events ? (
                <JsonBlock data={events} maxH="max-h-96" />
              ) : (
                <div className="text-[11px] text-ink-faint">no event stream available</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function RecJson({ rec }: { rec: NormRecord }) {
  const [data, setData] = useState<unknown>(null);
  useEffect(() => {
    if (!rec.evidence_raw) return;
    fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_raw)}`)
      .then((r) => r.json())
      .then((j) => setData(j.ok ? j.data : { error: j.error }));
  }, [rec.evidence_raw]);
  return data ? <JsonBlock data={data} /> : <div className="text-[11px] text-ink-faint">loading…</div>;
}
