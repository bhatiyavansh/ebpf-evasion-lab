"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import type { DashboardData, EngineResult, GraphPayload, GraphEdge } from "@/lib/types";
import OutcomeView from "@/components/traceweaver/OutcomeView";
import Investigation from "@/components/traceweaver/Investigation";
import BehaviorGraph from "@/components/traceweaver/BehaviorGraph";

type Tab = "main" | "outcome";

const VERDICT_TONE: Record<string, string> = {
  DETECTED: "#36c98d",
  TELEMETRY_ONLY: "#38bdf8",
  NOT_DETECTED: "#f0674f",
  COLLECTION_FAILED: "#e0b23a",
  EXECUTION_FAILED: "#e0b23a",
  NOT_EVALUATED: "#5a6472",
  INCONCLUSIVE: "#5a6472",
};

// scenario → human category (drives the Scenario Explorer grouping)
const SCENARIO_META: Record<string, { title: string; category: string }> = {
  A1: { title: "Credential access", category: "Credential access" },
  A2: { title: "Nested shell", category: "Suspicious sequence" },
  A3: { title: "System discovery", category: "Suspicious sequence" },
  A5: { title: "Drop-and-execute", category: "Suspicious sequence" },
  A6: { title: "Sudoers modification", category: "Config modification" },
  A7: { title: "Benign control", category: "Benign control" },
};
function categoryFor(r: EngineResult): string {
  if (r.visibility_status === "COLLECTION_FAILED" || r.visibility_status === "EXECUTION_FAILED")
    return "Collection / visibility gap";
  if (r.scenario_id && SCENARIO_META[r.scenario_id]) return SCENARIO_META[r.scenario_id].category;
  if (r.scenario_id?.startsWith("E")) return "Observability baseline";
  return "Other";
}
function titleFor(r: EngineResult): string {
  if (r.scenario_id && SCENARIO_META[r.scenario_id]) return SCENARIO_META[r.scenario_id].title;
  if (r.scenario_id?.startsWith("E")) return "Observability baseline";
  return r.scenario_id ?? "Stream";
}

function TwMark() {
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden>
      <rect x="1" y="1" width="26" height="26" rx="7" stroke="#2dd4bf" strokeOpacity="0.5" />
      <path d="M6 18 L11 9 L14 15 L17 7 L22 18" stroke="#2dd4bf" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="17" cy="7" r="2" fill="#5eead4" />
    </svg>
  );
}

function Pipeline() {
  const steps = [
    ["Raw sensors", "Falco · Tracee · Tetragon"],
    ["Canonical events", "one schema, provenance kept"],
    ["Behaviour graph", "processes · files · correlation"],
    ["Signals A·S·P", "anomaly · sequence · policy"],
    ["Risk + verdict", "visibility-aware gate"],
    ["Explained outcome", "every claim → raw record"],
  ];
  return (
    <div className="flex flex-wrap items-stretch gap-1.5">
      {steps.map(([t, s], i) => (
        <div key={t} className="flex items-stretch gap-1.5">
          <div className="rounded-lg border border-surface-border bg-surface-panel px-3 py-2">
            <div className="text-[11px] font-medium text-ink">{t}</div>
            <div className="text-[9.5px] text-ink-faint">{s}</div>
          </div>
          {i < steps.length - 1 ? <div className="flex items-center text-ink-faint">→</div> : null}
        </div>
      ))}
    </div>
  );
}

export default function TraceWeaverApp({ data }: { data: DashboardData }) {
  const results = data.engineResults ?? [];

  const byStream = useMemo(() => {
    const m = new Map<string, EngineResult>();
    for (const r of results) m.set(r.stream, r);
    return m;
  }, [results]);

  // Scenario Explorer: group by category, with real trial counts
  const categories = useMemo(() => {
    const g = new Map<string, EngineResult[]>();
    for (const r of results) {
      const c = categoryFor(r);
      if (!g.has(c)) g.set(c, []);
      g.get(c)!.push(r);
    }
    for (const v of g.values()) v.sort((a, b) => a.stream.localeCompare(b.stream));
    const order = [
      "Credential access",
      "Config modification",
      "Suspicious sequence",
      "Benign control",
      "Collection / visibility gap",
      "Observability baseline",
      "Other",
    ];
    return [...g.entries()].sort((a, b) => {
      const ia = order.indexOf(a[0]);
      const ib = order.indexOf(b[0]);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
  }, [results]);

  const recommended = useMemo(() => {
    const find = (p: (r: EngineResult) => boolean) => results.find(p)?.stream;
    return [
      { label: "Sudoers edit", sub: "Tracee · Detected", stream: find((r) => r.scenario_id === "A6" && r.sensor === "tracee" && r.verdict === "DETECTED") },
      { label: "Credential access", sub: "Falco · Detected", stream: find((r) => r.scenario_id === "A1" && r.sensor === "falco" && r.verdict === "DETECTED") },
      { label: "Drop-and-execute", sub: "Tracee", stream: find((r) => r.scenario_id === "A5" && r.sensor === "tracee") },
      { label: "Benign control", sub: "Tracee · telemetry", stream: find((r) => r.scenario_id === "A7" && r.sensor === "tracee") },
      { label: "Collection failure", sub: "Tetragon · visibility", stream: find((r) => r.verdict === "COLLECTION_FAILED") },
    ].filter((f): f is { label: string; sub: string; stream: string } => Boolean(f.stream));
  }, [results]);

  const [tab, setTab] = useState<Tab>("main");
  const [selected, setSelected] = useState<string>(() => recommended[0]?.stream ?? results[0]?.stream ?? "");
  const [query, setQuery] = useState("");
  const [sensorFilter, setSensorFilter] = useState<string>("all");
  const [openCat, setOpenCat] = useState<string | null>(() => "Credential access");

  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [liveMeta, setLiveMeta] = useState<{ elapsedMs: number } | null>(null);
  const reqSeq = useRef(0);

  const preview = selected ? byStream.get(selected) ?? null : null;

  // fetch the behavior-graph payload for the selected stream (read-only)
  const fetchGraph = useCallback(async (stream: string, markLive: boolean) => {
    if (!stream) return;
    const seq = ++reqSeq.current;
    if (markLive) setRunning(true);
    else setGraphLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/traceweaver/graph", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ stream }),
      });
      const json: GraphPayload = await res.json();
      if (seq !== reqSeq.current) return; // stale response — ignore
      if (!json.ok) {
        setError(json.error ?? "engine run failed");
        setGraph(null);
      } else {
        setGraph(json);
        if (markLive) {
          setLiveMeta({ elapsedMs: json.elapsed_ms ?? 0 });
          setTab("outcome");
        }
      }
    } catch (e) {
      if (seq === reqSeq.current) setError(e instanceof Error ? e.message : "network error");
    } finally {
      if (seq === reqSeq.current) {
        setRunning(false);
        setGraphLoading(false);
      }
    }
  }, []);

  // load a preview graph whenever the selection changes
  useEffect(() => {
    setGraph(null);
    setLiveMeta(null);
    if (selected) fetchGraph(selected, false);
  }, [selected, fetchGraph]);

  function onSelect(stream: string) {
    setSelected(stream);
    setError(null);
  }

  const activeResult: EngineResult | null = graph?.result ?? preview ?? null;
  const tone = activeResult ? VERDICT_TONE[activeResult.verdict] ?? "#5a6472" : "#5a6472";

  // filtered stream list for the explorer
  const matches = useCallback(
    (r: EngineResult) => {
      if (sensorFilter !== "all" && r.sensor !== sensorFilter) return false;
      if (!query.trim()) return true;
      const q = query.toLowerCase();
      return (
        r.stream.toLowerCase().includes(q) ||
        (r.scenario_id ?? "").toLowerCase().includes(q) ||
        r.sensor.toLowerCase().includes(q) ||
        r.verdict.toLowerCase().includes(q) ||
        titleFor(r).toLowerCase().includes(q)
      );
    },
    [query, sensorFilter]
  );

  return (
    <div className="min-h-screen bg-surface">
      <header className="sticky top-0 z-30 border-b border-surface-border bg-surface/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3 sm:px-8">
          <div className="flex items-center gap-2.5">
            <TwMark />
            <div>
              <div className="text-[14px] font-semibold tracking-tight text-ink">TraceWeaver</div>
              <div className="text-[10px] text-ink-faint">Explainable runtime threat detection</div>
            </div>
          </div>
          <nav className="flex items-center gap-1 rounded-lg border border-surface-border bg-surface-raised p-1">
            {(["main", "outcome"] as Tab[]).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                aria-current={tab === t}
                className={`rounded-md px-4 py-1.5 text-[12.5px] font-medium capitalize transition ${
                  tab === t ? "bg-accent/15 text-accent" : "text-ink-faint hover:bg-surface-hover hover:text-ink"
                }`}
              >
                {t}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            {activeResult ? (
              <span className="hidden items-center gap-1.5 text-[11px] text-ink-faint sm:inline-flex">
                <span className="h-2 w-2 rounded-full" style={{ background: tone }} />
                {activeResult.verdict}
              </span>
            ) : null}
            <Link href="/lab" className="text-[11px] text-ink-faint underline-offset-2 hover:text-ink hover:underline">
              Research archive →
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1280px] px-4 py-6 sm:px-8">
        {tab === "main" ? (
          <div className="space-y-6 animate-fadein">
            <section>
              <h1 className="text-[22px] font-semibold tracking-tight text-ink">
                Investigate runtime behaviour, not just raw alerts
              </h1>
              <p className="mt-1.5 max-w-2xl text-[13px] leading-relaxed text-ink-muted">
                TraceWeaver normalizes Falco, Tracee and Tetragon output into one canonical stream,
                correlates it into an interactive <span className="text-ink">behaviour graph</span>,
                and produces a visibility-aware verdict where every node, edge and score traces back
                to the exact raw record.
              </p>
            </section>

            <section className="rounded-xl border border-surface-border bg-surface-raised p-5">
              <h2 className="mb-3 text-[12px] font-semibold tracking-tight text-ink">Pipeline</h2>
              <Pipeline />
            </section>

            <section className="grid gap-5 lg:grid-cols-[1.05fr_1.25fr]">
              {/* Scenario Explorer */}
              <div className="rounded-xl border border-surface-border bg-surface-raised p-5">
                <div className="flex items-center justify-between">
                  <h2 className="text-[12px] font-semibold tracking-tight text-ink">Scenario Explorer</h2>
                  <span className="text-[10px] text-ink-faint">{results.length} real trials</span>
                </div>

                {/* recommended */}
                {recommended.length ? (
                  <div className="mt-3">
                    <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Recommended</div>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {recommended.map((f) => (
                        <button
                          key={f.stream}
                          onClick={() => onSelect(f.stream)}
                          className={`rounded-md border px-2.5 py-1.5 text-left text-[11px] transition ${
                            selected === f.stream
                              ? "border-accent/50 bg-accent/10 text-accent"
                              : "border-surface-border bg-surface-panel text-ink-muted hover:border-surface-hover hover:text-ink"
                          }`}
                        >
                          <div className="font-medium">{f.label}</div>
                          <div className="text-[9px] uppercase tracking-wide text-ink-faint">{f.sub}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null}

                {/* search + sensor filter */}
                <div className="mt-4 flex gap-2">
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Search scenario, sensor, verdict…"
                    className="mono flex-1 rounded-lg border border-surface-border bg-surface-inset px-3 py-1.5 text-[11px] text-ink outline-none placeholder:text-ink-faint focus:border-accent/50"
                  />
                  <select
                    value={sensorFilter}
                    onChange={(e) => setSensorFilter(e.target.value)}
                    className="rounded-lg border border-surface-border bg-surface-inset px-2 py-1.5 text-[11px] text-ink-muted outline-none focus:border-accent/50"
                  >
                    <option value="all">all sensors</option>
                    <option value="falco">falco</option>
                    <option value="tracee">tracee</option>
                    <option value="tetragon">tetragon</option>
                  </select>
                </div>

                {/* categories */}
                <div className="mt-3 max-h-[360px] space-y-1 overflow-y-auto pr-1">
                  {categories.map(([cat, rs]) => {
                    const visible = rs.filter(matches);
                    if (!visible.length) return null;
                    const open = openCat === cat || query.trim().length > 0;
                    return (
                      <div key={cat} className="rounded-lg border border-surface-border bg-surface-panel">
                        <button
                          onClick={() => setOpenCat(open && !query ? null : cat)}
                          className="flex w-full items-center justify-between px-3 py-2 text-left"
                        >
                          <span className="text-[11.5px] font-medium text-ink">{cat}</span>
                          <span className="mono text-[10px] text-ink-faint">{visible.length}</span>
                        </button>
                        {open ? (
                          <div className="border-t border-surface-border">
                            {visible.map((r) => {
                              const t = VERDICT_TONE[r.verdict] ?? "#5a6472";
                              return (
                                <button
                                  key={r.stream}
                                  onClick={() => onSelect(r.stream)}
                                  className={`flex w-full items-center gap-2 px-3 py-1.5 text-left transition ${
                                    selected === r.stream ? "bg-accent/10" : "hover:bg-surface-hover"
                                  }`}
                                >
                                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: t }} />
                                  <span className="mono flex-1 truncate text-[10.5px] text-ink-muted">
                                    {r.stream.replace("results/raw/", "").replace("_events/", "/")}
                                  </span>
                                  <span className="shrink-0 text-[9px] uppercase tracking-wide text-ink-faint">
                                    {r.verdict}
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Selected input + graph preview + run */}
              <div className="rounded-xl border border-surface-border bg-surface-raised p-5">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <h2 className="text-[12px] font-semibold tracking-tight text-ink">Selected input</h2>
                    {preview ? (
                      <div className="mono mt-0.5 break-all text-[11px] text-ink">
                        {preview.stream.replace("results/raw/", "")}
                      </div>
                    ) : null}
                  </div>
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-status-observed/30 bg-status-observed/10 px-2 py-1 text-[9.5px] font-medium uppercase tracking-wide text-status-observed">
                    ● Historical Replay
                  </span>
                </div>

                {preview ? (
                  <div className="mt-3 grid grid-cols-3 gap-x-4 gap-y-2.5">
                    {[
                      ["Sensor", preview.sensor],
                      ["Scenario", preview.scenario_id ?? "—"],
                      ["Events", String(preview.event_count)],
                      ["Capture", preview.capture_mode],
                      ["Visibility", preview.visibility_status],
                      ["Pre-scored", preview.verdict],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <div className="text-[9px] uppercase tracking-wide text-ink-faint">{k}</div>
                        <div className="mono mt-0.5 text-[11px] text-ink">{v}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-3 text-[11.5px] text-ink-faint">Select a scenario to see its inputs.</p>
                )}

                {/* graph preview */}
                <div className="mt-4">
                  <div className="mb-1.5 flex items-center justify-between">
                    <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Behaviour graph preview</div>
                    {graph ? (
                      <div className="text-[9.5px] text-ink-faint">
                        {graph.nodes.length} nodes · {graph.edges.length} edges
                      </div>
                    ) : null}
                  </div>
                  {graphLoading ? (
                    <div className="flex h-[200px] items-center justify-center rounded-xl border border-surface-border bg-[#070a0e] text-[11px] text-ink-faint">
                      <span className="mr-2 h-2 w-2 animate-pulsedot rounded-full bg-accent" /> building graph…
                    </div>
                  ) : graph && graph.nodes.length ? (
                    <PreviewGraph payload={graph} />
                  ) : (
                    <div className="flex h-[200px] items-center justify-center rounded-xl border border-dashed border-surface-border bg-[#070a0e] text-center text-[11px] text-ink-faint">
                      {graph ? "No graphable entities — inspect events on the Outcome tab." : "—"}
                    </div>
                  )}
                </div>

                <button
                  onClick={() => fetchGraph(selected, true)}
                  disabled={!selected || running}
                  className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-[12.5px] font-semibold text-surface transition hover:bg-accent-bright disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {running ? (
                    <>
                      <span className="h-2 w-2 animate-pulsedot rounded-full bg-surface" /> Running engine…
                    </>
                  ) : (
                    <>▶ Run Analysis</>
                  )}
                </button>
                {error ? <p className="mt-2 text-[11px] text-status-missed">Engine error: {error}</p> : null}
                <p className="mt-2 text-[10.5px] leading-relaxed text-ink-faint">
                  Run Analysis executes the real TraceWeaver engine on this stream and opens the full
                  investigation on the Outcome tab. The engine computation is live; the sensor events
                  are <span className="text-ink-muted">recorded captures</span> (historical replay),
                  not a live kernel feed.
                </p>
              </div>
            </section>
          </div>
        ) : (
          <div className="space-y-6 animate-fadein">
            {/* Investigation: the graph is the centrepiece */}
            {graph && graph.ok ? (
              <section>
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <h2 className="text-[13px] font-semibold tracking-tight text-ink">Behaviour graph &amp; replay</h2>
                    <p className="text-[11px] text-ink-faint">
                      {titleFor(graph.result)} · {graph.sensor} · {graph.scenario_id ?? "—"}
                    </p>
                  </div>
                  <button
                    onClick={() => setTab("main")}
                    className="rounded-md border border-surface-border px-2.5 py-1.5 text-[11px] text-ink-muted hover:bg-surface-hover"
                  >
                    ↺ Change scenario
                  </button>
                </div>
                <Investigation payload={graph} />
              </section>
            ) : graphLoading ? (
              <div className="flex h-[200px] items-center justify-center rounded-xl border border-surface-border bg-surface-raised text-[12px] text-ink-faint">
                <span className="mr-2 h-2 w-2 animate-pulsedot rounded-full bg-accent" /> running engine…
              </div>
            ) : null}

            {/* Verdict / signals / timeline / visibility / evaluation */}
            <OutcomeView result={activeResult} evaluation={data.evaluation} liveMeta={liveMeta} />
          </div>
        )}
      </main>

      <footer className="mx-auto max-w-[1280px] px-4 pb-8 pt-2 text-[10px] text-ink-faint sm:px-8">
        Verdicts and graphs are generated by the TraceWeaver engine from immutable{" "}
        <span className="mono">results/raw/*</span> evidence; every node, edge and finding cites{" "}
        <span className="mono">file:line:sha256</span>. Research prototype — findings are specific to
        the tested configurations.
      </footer>
    </div>
  );
}

/* a non-interactive-ish compact preview (same component, short, no selection side-effects) */
function PreviewGraph({ payload }: { payload: GraphPayload }) {
  const [sel, setSel] = useState<string | null>(null);
  const [, setEdge] = useState<GraphEdge | null>(null);
  return (
    <BehaviorGraph
      payload={payload}
      revealCount={payload.events.length}
      currentEventId={null}
      selectedNodeId={sel}
      onSelectNode={setSel}
      onSelectEdge={setEdge}
      height={240}
    />
  );
}
