"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { DashboardData, NormRecord, Tool } from "@/lib/types";
import { TOOLS } from "@/lib/types";
import { StatusBadge, STATUS_META, TOOL_LABEL, JsonBlock, Mode, Dot } from "@/components/ui";
import { buildTimeline } from "@/lib/interpret";

const ACTS = [
  "The research question",
  "Execute an experiment",
  "The real process chain",
  "Compare all three tools",
  "Open raw evidence",
  "Reveal the finding",
  "CVE follow-up",
];

export default function Demo({ data }: { data: DashboardData }) {
  const { catalog, records, analysis, environment, comparison } = data;
  const [act, setAct] = useState(0);
  const a1 = comparison?.scenarios.find((s) => s.id === "A1");
  const demoExp = "E04";
  const expDef = catalog.experiments.find((e) => e.id === demoExp)!;
  const cells = TOOLS.map((t) => records.find((r) => r.experiment_id === demoExp && r.tool === t)).filter(
    Boolean
  ) as NormRecord[];
  // For the raw-evidence act, pick a record with INTACT captured events (E04
  // Tetragon is COLLECTION_FAILED post-reboot). Prefer a Tetragon stream with
  // the richest intact evidence; fall back to any record with events.
  const evidenceRecord =
    records
      .filter((r) => r.evidence_events && r.status !== "collection_failed")
      .sort((a, b) => (b.processes_observed?.length ?? 0) - (a.processes_observed?.length ?? 0))[0] ??
    cells[0];

  function next() {
    setAct((a) => Math.min(a + 1, ACTS.length - 1));
  }
  function prev() {
    setAct((a) => Math.max(a - 1, 0));
  }
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "ArrowRight") next();
      if (e.key === "ArrowLeft") prev();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-surface">
      {/* Top bar */}
      <div className="border-b border-surface-border px-5 py-3">
        <div className="mx-auto flex max-w-5xl items-center gap-3">
          <Link href="/" className="text-[12px] text-ink-faint hover:text-ink">
            ✕ Exit demo
          </Link>
          <div className="mx-auto flex items-center gap-1.5">
            {ACTS.map((_, i) => (
              <button
                key={i}
                onClick={() => setAct(i)}
                className={`h-1.5 rounded-full transition-all ${
                  i === act ? "w-8 bg-accent" : i < act ? "w-4 bg-accent/40" : "w-4 bg-surface-border"
                }`}
                aria-label={`Act ${i + 1}`}
              />
            ))}
          </div>
          <button onClick={() => setAct(0)} className="text-[12px] text-ink-faint hover:text-ink">
            ↺ Restart
          </button>
        </div>
      </div>

      {/* Act content */}
      <div className="flex flex-1 items-center justify-center px-5 py-8">
        <div className="mx-auto w-full max-w-4xl animate-fadein">
          <div className="mb-4 flex items-center gap-2 text-[11px] uppercase tracking-widest text-accent/70">
            Act {act + 1} / {ACTS.length} · {ACTS[act]}
          </div>

          {act === 0 && (
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-ink sm:text-[32px]">
                Event visibility and security detection are not the same thing.
              </h1>
              <p className="mt-4 max-w-2xl text-[14px] leading-relaxed text-ink-muted">
                We evaluate three eBPF runtime-security systems — <b className="text-ink">Falco</b>,{" "}
                <b className="text-ink">Tracee</b>, <b className="text-ink">Tetragon</b> — against
                controlled baseline and adaptive container behaviors. The question: does adapting how a
                workload executes reduce what these tools can see or detect?
              </p>
              <div className="mt-5 flex flex-wrap gap-2 text-[11px]">
                {[environment?.os, `kernel ${environment?.kernel}`, environment?.arch, "Docker", "BTF"].map(
                  (c) => (
                    <span key={c} className="rounded-md border border-surface-border bg-surface-inset px-2.5 py-1 text-ink-muted mono">
                      {c}
                    </span>
                  )
                )}
              </div>
            </div>
          )}

          {act === 1 && <ExecuteAct expDef={expDef} />}

          {act === 2 && (
            <div>
              <h2 className="text-xl font-semibold text-ink">The real process chain — {demoExp}</h2>
              <p className="mt-2 text-[13px] text-ink-muted">{expDef.purpose}</p>
              <div className="mt-5 space-y-3">
                {cells.map((r) => (
                  <div key={r.tool} className="rounded-lg border border-surface-border bg-surface-raised p-4">
                    <div className="mb-2 flex items-center gap-2">
                      <span className="text-[13px] font-semibold text-ink">{TOOL_LABEL[r.tool]}</span>
                      <Mode live={r.provenance === "live"} />
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[13px] mono">
                      {(r.processes_observed || []).map((p, i, arr) => (
                        <span key={i} className="flex items-center gap-2">
                          <span className="rounded bg-surface-inset px-2.5 py-1 text-ink">{p}</span>
                          {i < arr.length - 1 && <span className="text-accent">→</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {act === 3 && (
            <div>
              <h2 className="text-xl font-semibold text-ink">All three tools, one view — {demoExp}</h2>
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                {cells.map((r) => {
                  const s = STATUS_META[r.status];
                  return (
                    <div key={r.tool} className={`rounded-lg border ${s.border} ${s.bg} p-4`}>
                      <div className="text-[13px] font-semibold text-ink">{TOOL_LABEL[r.tool]}</div>
                      <div className="mt-2">
                        <StatusBadge status={r.status} />
                      </div>
                      <dl className="mt-3 space-y-1 text-[10.5px]">
                        {r.dimensions &&
                          Object.entries(r.dimensions).map(([k, v]) => (
                            <div key={k} className="flex justify-between">
                              <dt className="text-ink-faint">{k}</dt>
                              <dd className="text-ink-muted mono">{v as string}</dd>
                            </div>
                          ))}
                      </dl>
                    </div>
                  );
                })}
              </div>
              <p className="mt-4 text-[12px] leading-relaxed text-ink-faint">
                Telemetry, verified alerts, and &ldquo;not evaluated&rdquo; are kept distinct. Falco
                fired a (custom) rule; Tracee and Tetragon captured the same chain as telemetry with no
                alerting engine — not a failure.
              </p>

              {a1 && (
                <div className="mt-6 rounded-lg border border-accent/25 bg-accent/5 p-4">
                  <div className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-accent/80">
                    And when it&apos;s a real technique — A1 credential access (T1555), 3 live trials
                  </div>
                  <div className="grid gap-2 sm:grid-cols-4">
                    {[
                      ["falco", "Falco"],
                      ["tracee", "Tracee"],
                      ["tetB", "Tetragon (baseline)"],
                      ["tetC", "Tetragon (configured)"],
                    ].map(([k, label]) => {
                      const cell = a1.cells[k];
                      if (!cell) return null;
                      const detected = cell.headline_outcome === "DETECTED";
                      return (
                        <div
                          key={k}
                          className={`rounded-md border p-3 ${detected ? "border-status-detected/40 bg-status-detected/10" : "border-status-observed/30 bg-status-observed/5"}`}
                        >
                          <div className="text-[11px] font-semibold text-ink">{label}</div>
                          <div className={`mt-1 text-[12px] font-semibold ${detected ? "text-status-detected" : "text-status-observed"}`}>
                            {detected ? "DETECTED" : "Telemetry only"}
                          </div>
                          <div className="text-[9.5px] text-ink-faint mono">{cell.detections}/3 trials</div>
                        </div>
                      );
                    })}
                  </div>
                  <p className="mt-2 text-[11px] leading-relaxed text-ink-faint">
                    Falco&apos;s built-in rule and Tetragon&apos;s selective policy both detect it; a
                    telemetry-only config observes but does not detect. Configuration — not kernel
                    visibility — decides the outcome.
                  </p>
                </div>
              )}
            </div>
          )}

          {act === 4 && <EvidenceAct record={evidenceRecord} />}

          {act === 5 && (
            <div>
              <h2 className="text-xl font-semibold text-ink">The finding</h2>
              <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-ink">
                Simple execution indirection and controlled timing variation did{" "}
                <span className="text-status-detected">not eliminate</span> process-execution
                observability under any tested configuration. But verified{" "}
                <span className="text-status-detected">detection</span> is sparse — concentrated in
                Falco&apos;s built-in sensitive-file rule — while{" "}
                <span className="text-status-observed">telemetry</span> is near-total.
              </p>
              <p className="mt-3 max-w-2xl text-[12.5px] leading-relaxed text-ink-faint">
                The gap between &ldquo;the kernel saw it&rdquo; and &ldquo;a policy flagged it&rdquo; —
                clearest in the network case — is where runtime-security value is won or lost. This does
                not demonstrate immunity to adaptive evasion.
              </p>
              <Link
                href="/outcome"
                className="mt-5 inline-block rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-[12px] font-semibold text-accent hover:bg-accent/25"
              >
                Open full research findings →
              </Link>
            </div>
          )}

          {act === 6 && (
            <div>
              <h2 className="text-xl font-semibold text-ink">CVE follow-up — honest by construction</h2>
              <p className="mt-3 max-w-2xl text-[13px] leading-relaxed text-ink-muted">
                We assessed three real CVEs (Dirty Pipe, OverlayFS, nf_tables) against the actual host
                kernel. All three are <span className="text-ink">not applicable</span> — the kernel
                ({environment?.kernel}) is far newer than every affected range. No exploit is run on the
                host; the CVE lab shows compatibility and safe simulation only, never claiming
                reproduction.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <Link href="/cve-lab" className="rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-[12px] font-semibold text-accent hover:bg-accent/25">
                  Open CVE Lab →
                </Link>
                <Link href="/" className="rounded-md border border-surface-border px-4 py-2 text-[12px] text-ink-muted hover:text-ink">
                  Back to Command Center
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Nav */}
      <div className="border-t border-surface-border px-5 py-4">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <button
            onClick={prev}
            disabled={act === 0}
            className="rounded-md border border-surface-border px-4 py-2 text-[12px] text-ink-muted hover:text-ink disabled:opacity-30"
          >
            ← Previous
          </button>
          <span className="text-[11px] text-ink-faint">Use ← → arrow keys</span>
          <button
            onClick={next}
            disabled={act === ACTS.length - 1}
            className="rounded-md border border-accent/50 bg-accent/15 px-4 py-2 text-[12px] font-semibold text-accent hover:bg-accent/25 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  );
}

function ExecuteAct({ expDef }: { expDef: { id: string; title: string; command: string; purpose: string } }) {
  const [state, setState] = useState<"idle" | "running" | "done" | "failed">("idle");
  const [result, setResult] = useState<unknown>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);

  async function runLive() {
    setState("running");
    setResult(null);
    try {
      const r = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ experimentId: expDef.id, tool: "tetragon" }),
      });
      const j = await r.json();
      setElapsed(j.elapsed_ms ?? null);
      if (j.ok && j.state === "completed") {
        setState("done");
        setResult(j.result);
      } else {
        setState("failed");
        setResult({ state: j.state, error: j.error, log: j.log });
      }
    } catch (e) {
      setState("failed");
      setResult({ error: String(e) });
    }
  }

  async function replay() {
    setState("running");
    const r = await fetch(`/api/evidence?path=${encodeURIComponent(`results/raw/${expDef.id}_tetragon.json`)}`);
    const j = await r.json();
    setResult(j.ok ? j.data : { error: j.error });
    setState("done");
    setElapsed(null);
  }

  return (
    <div>
      <h2 className="text-xl font-semibold text-ink">
        Execute {expDef.id} · {expDef.title}
      </h2>
      <p className="mt-2 text-[13px] text-ink-muted">{expDef.purpose}</p>
      <code className="mt-3 block break-all rounded-md border border-surface-border bg-surface-inset p-3 text-[12.5px] text-accent-bright mono">
        docker run --rm alpine:3.20 {expDef.command}
      </code>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          onClick={runLive}
          disabled={state === "running"}
          className="rounded-md border border-status-detected/50 bg-status-detected/15 px-4 py-2 text-[12px] font-semibold text-status-detected hover:bg-status-detected/25 disabled:opacity-40"
        >
          ▶ Run live (Tetragon)
        </button>
        <button
          onClick={replay}
          disabled={state === "running"}
          className="rounded-md border border-surface-border px-4 py-2 text-[12px] font-medium text-ink-muted hover:text-ink disabled:opacity-40"
        >
          ⟳ Replay recorded evidence
        </button>
        {state === "running" && (
          <span className="flex items-center gap-2 text-[12px] text-accent">
            <span className="h-2 w-2 animate-pulsedot rounded-full bg-accent" /> working…
          </span>
        )}
        {state === "done" && (
          <span className="text-[12px] text-status-detected">
            ✓ completed{elapsed != null ? ` in ${(elapsed / 1000).toFixed(1)}s` : ""}
          </span>
        )}
        {state === "failed" && <span className="text-[12px] text-status-missed">✕ failed — try replay</span>}
      </div>
      {result != null && (
        <div className="mt-4">
          <JsonBlock data={result} maxH="max-h-80" />
        </div>
      )}
    </div>
  );
}

const TL_COLOR: Record<string, string> = {
  exec: "bg-status-observed", file: "bg-status-partial", network: "bg-accent",
  alert: "bg-status-detected", exit: "bg-ink-faint", other: "bg-ink-faint",
};

function EvidenceAct({ record }: { record: NormRecord }) {
  const [events, setEvents] = useState<Record<string, unknown>[] | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  useEffect(() => {
    if (!record.evidence_events) return;
    fetch(`/api/evidence?path=${encodeURIComponent(record.evidence_events)}&limit=120`)
      .then((r) => r.json())
      .then((j) => setEvents(j.ok ? j.events : []));
  }, [record.evidence_events]);
  const timeline = events ? buildTimeline(events) : [];
  return (
    <div>
      <h2 className="text-xl font-semibold text-ink">The event timeline — in plain English</h2>
      <p className="mt-2 text-[13px] text-ink-muted">
        {record.experiment_id} · {TOOL_LABEL[record.tool]} · real captured events, scoped to the
        workload container. Source: <span className="mono text-ink">{record.evidence_events}</span>.
        The audience reads the timeline, not JSON.
      </p>
      <div className="mt-4 space-y-1.5">
        {!events && <div className="text-[12px] text-ink-faint">loading recorded events…</div>}
        {events && timeline.length === 0 && (
          <div className="text-[12px] text-ink-faint">No parseable events in this record.</div>
        )}
        {timeline.slice(0, 12).map((e, i) => (
          <div key={i} className="flex items-start gap-3 rounded-md border border-surface-border bg-surface-raised px-3 py-2">
            <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${TL_COLOR[e.kind]}`} />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] text-ink">{e.title}</div>
              {e.detail && <div className="truncate text-[11px] text-ink-faint mono">{e.detail}</div>}
            </div>
            <span className="shrink-0 text-[9.5px] uppercase tracking-wide text-ink-faint">{e.kind}</span>
          </div>
        ))}
      </div>
      {events && events.length > 0 && (
        <details className="mt-3" open={showRaw} onToggle={(e) => setShowRaw((e.target as HTMLDetailsElement).open)}>
          <summary className="cursor-pointer text-[11px] text-ink-muted hover:text-ink">Inspect raw evidence (JSON)</summary>
          <div className="mt-2"><JsonBlock data={events} maxH="max-h-80" /></div>
        </details>
      )}
    </div>
  );
}
