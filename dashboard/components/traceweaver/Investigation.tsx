"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { GraphPayload, GraphEdge, GraphNode } from "@/lib/types";
import BehaviorGraph from "./BehaviorGraph";

const CANON_TONE: Record<string, string> = {
  process_exec: "#38bdf8",
  process_exit: "#64748b",
  file_open: "#8aa0b8",
  file_write: "#8aa0b8",
  network_connect: "#a78bfa",
  security_alert: "#f0674f",
  other: "#64748b",
};

const SPEEDS = [0.5, 1, 2, 4];

function val(v: unknown): string {
  if (v === null || v === undefined) return "—";
  const s = String(v);
  if (s.startsWith("<") && s.endsWith(">")) return s.replace(/[<>]/g, ""); // sentinel → readable
  return s;
}

/* ------------------------------- timeline ------------------------------- */
function EventTimeline({
  payload,
  reveal,
  currentId,
  onPick,
}: {
  payload: GraphPayload;
  reveal: number;
  currentId: string | null;
  onPick: (order: number) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const curRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    curRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [currentId]);

  if (!payload.events.length)
    return <p className="p-4 text-[11.5px] text-ink-faint">This stream has no canonical events.</p>;

  return (
    <div ref={ref} className="max-h-[460px] overflow-y-auto">
      {payload.events.map((e) => {
        const revealed = e.order < reveal;
        const isCurrent = e.event_id === currentId;
        const tone = CANON_TONE[e.canonical_type] ?? "#64748b";
        const subject =
          val(e.process_name) !== "—"
            ? val(e.process_name)
            : val(e.file_path) !== "—"
            ? val(e.file_path)
            : val(e.native_event);
        return (
          <button
            key={e.event_id}
            ref={isCurrent ? curRef : undefined}
            onClick={() => onPick(e.order)}
            className={`flex w-full items-start gap-2.5 border-l-2 px-3 py-2 text-left transition ${
              isCurrent
                ? "border-l-accent bg-accent/10"
                : revealed
                ? "border-l-surface-border bg-transparent hover:bg-surface-hover"
                : "border-l-transparent opacity-40 hover:opacity-70"
            }`}
          >
            <span className="mono mt-0.5 w-5 shrink-0 text-right text-[10px] text-ink-faint">{e.order + 1}</span>
            <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: tone }} />
            <span className="min-w-0 flex-1">
              <span className="flex items-baseline justify-between gap-2">
                <span className="mono truncate text-[11.5px] text-ink">{subject}</span>
                <span className="mono shrink-0 text-[9.5px] text-ink-faint">{e.canonical_type}</span>
              </span>
              <span className="mono block truncate text-[10px] text-ink-faint">
                {val(e.timestamp)}
                {val(e.container_name) !== "—" ? ` · ${val(e.container_name)}` : ""}
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

/* ----------------------------- detail panel ----------------------------- */
function Detail({
  payload,
  selectedNode,
  selectedEdge,
  selectedEventId,
}: {
  payload: GraphPayload;
  selectedNode: GraphNode | null;
  selectedEdge: GraphEdge | null;
  selectedEventId: string | null;
}) {
  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of payload.nodes) m.set(n.id, n);
    return m;
  }, [payload]);

  if (selectedNode) {
    const rr = selectedNode.raw_refs.find(Boolean);
    const relatedFinding = payload.findings.find((f) =>
      f.event_ids.some((id) => selectedNode.event_ids.includes(id))
    );
    return (
      <div className="space-y-2.5 text-[11.5px]">
        <div className="flex items-center gap-2">
          <span className="rounded bg-surface-inset px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-ink-muted">
            {selectedNode.kind.replace("_", " ")}
          </span>
          {selectedNode.is_finding ? (
            <span className="rounded bg-status-missed/15 px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-status-missed">
              finding
            </span>
          ) : null}
        </div>
        <div>
          <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Label</div>
          <div className="mono break-all text-ink">{selectedNode.label}</div>
        </div>
        <div>
          <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Identifier</div>
          <div className="mono break-all text-ink-muted">{selectedNode.identifier}</div>
        </div>
        {!selectedNode.identity_known ? (
          <p className="rounded border border-status-partial/30 bg-status-partial/5 p-2 text-[10.5px] text-status-partial">
            ⚠ Identity incomplete — this entity could not be merged with others because key
            identifiers (e.g. pid/container) were not supplied by the sensor. It is shown as a
            distinct unknown node rather than fabricating a link.
          </p>
        ) : null}
        <div>
          <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">
            Related events ({selectedNode.event_ids.length})
          </div>
          <div className="mono break-all text-[10px] text-ink-muted">{selectedNode.event_ids.join(", ")}</div>
        </div>
        {rr ? (
          <div>
            <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Source</div>
            <div className="mono break-all text-[10px] text-ink-muted">
              {rr.file}:{rr.line}
              {rr.sha256 ? ` · ${rr.sha256.slice(0, 16)}…` : ""}
            </div>
          </div>
        ) : null}
        {relatedFinding ? (
          <div className="rounded-lg border border-surface-border bg-surface-panel p-2.5">
            <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Related finding</div>
            <div className="text-[11px] text-ink">{relatedFinding.pattern}</div>
            <div className="text-[10.5px] text-ink-muted">{relatedFinding.explanation}</div>
          </div>
        ) : null}
      </div>
    );
  }

  if (selectedEdge) {
    const src = nodeById.get(selectedEdge.source);
    const dst = nodeById.get(selectedEdge.target);
    return (
      <div className="space-y-2.5 text-[11.5px]">
        <span className="rounded bg-surface-inset px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-ink-muted">
          relationship · {selectedEdge.type.replace("_", " ")}
        </span>
        <div className="mono text-ink">
          {src?.label ?? selectedEdge.source} <span className="text-accent">→</span>{" "}
          {dst?.label ?? selectedEdge.target}
        </div>
        {selectedEdge.derived ? (
          <p className="text-[10.5px] text-ink-faint">
            Derived from the event&apos;s concrete <span className="mono">container_id</span> field —
            a membership relationship, not a causal one.
          </p>
        ) : (
          <p className="text-[10.5px] text-ink-faint">
            Established by the correlation engine from matching identity fields on the supporting
            event.
          </p>
        )}
        {selectedEdge.event_id ? (
          <div>
            <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Supporting event</div>
            <div className="mono break-all text-[10px] text-ink-muted">{selectedEdge.event_id}</div>
          </div>
        ) : null}
        {selectedEdge.raw_ref ? (
          <div>
            <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Source</div>
            <div className="mono break-all text-[10px] text-ink-muted">
              {selectedEdge.raw_ref.file}:{selectedEdge.raw_ref.line}
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  if (selectedEventId) {
    const e = payload.events.find((x) => x.event_id === selectedEventId);
    if (e)
      return (
        <div className="space-y-2 text-[11.5px]">
          <span className="rounded bg-surface-inset px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide text-ink-muted">
            event · {e.canonical_type}
          </span>
          {[
            ["Native event", val(e.native_event)],
            ["Process", val(e.process_name)],
            ["Args", val(e.process_args)],
            ["PID", val(e.pid)],
            ["Parent PID", val(e.parent_pid)],
            ["Container", val(e.container_name)],
            ["File", val(e.file_path)],
            ["Network", val(e.network_dest)],
            ["Timestamp", val(e.timestamp)],
          ]
            .filter(([, v]) => v !== "—")
            .map(([k, v]) => (
              <div key={k}>
                <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">{k}</div>
                <div className="mono break-all text-ink-muted">{v}</div>
              </div>
            ))}
          {e.raw_ref ? (
            <div>
              <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">Source</div>
              <div className="mono break-all text-[10px] text-ink-muted">
                {e.raw_ref.file}:{e.raw_ref.line}
              </div>
            </div>
          ) : null}
        </div>
      );
  }

  return (
    <p className="text-[11.5px] leading-relaxed text-ink-faint">
      Select a node, an edge, or a timeline event to inspect its evidence. Every element here maps to
      a real normalized record.
    </p>
  );
}

/* ---------------------------- main component ---------------------------- */
export default function Investigation({ payload }: { payload: GraphPayload }) {
  const total = payload.events.length;
  const [reveal, setReveal] = useState(total); // start on the completed graph
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // reset all state when the stream changes
  useEffect(() => {
    setReveal(payload.events.length);
    setPlaying(false);
    setSpeed(1);
    setSelectedNodeId(null);
    setSelectedEdge(null);
    setSelectedEventId(null);
  }, [payload]);

  // playback loop
  useEffect(() => {
    if (!playing) return;
    if (reveal >= total) {
      setPlaying(false);
      return;
    }
    const interval = 900 / speed;
    const t = setTimeout(() => setReveal((r) => Math.min(total, r + 1)), interval);
    return () => clearTimeout(t);
  }, [playing, reveal, speed, total]);

  const currentEventId =
    reveal > 0 && reveal <= total ? payload.events[reveal - 1]?.event_id ?? null : null;
  // during replay the "current" highlight follows playback; otherwise it follows selection
  const highlightEventId = playing || reveal < total ? currentEventId : selectedEventId;

  const selectedNode = selectedNodeId
    ? payload.nodes.find((n) => n.id === selectedNodeId) ?? null
    : null;

  function play() {
    if (reveal >= total) setReveal(0);
    setSelectedEventId(null);
    setSelectedNodeId(null);
    setSelectedEdge(null);
    setPlaying(true);
  }
  function pause() {
    setPlaying(false);
  }
  function step() {
    setPlaying(false);
    setReveal((r) => Math.min(total, r + 1));
  }
  function resetReplay() {
    setPlaying(false);
    setReveal(0);
    setSelectedEventId(null);
  }
  function complete() {
    setPlaying(false);
    setReveal(total);
    setSelectedEventId(null);
  }
  function pickEvent(order: number) {
    setPlaying(false);
    setReveal(Math.max(reveal, order + 1)); // ensure it's visible
    setSelectedEventId(payload.events[order].event_id);
    setSelectedNodeId(null);
    setSelectedEdge(null);
  }

  // failure state (distinct from an empty graph)
  const failed =
    payload.visibility_status === "COLLECTION_FAILED" || payload.visibility_status === "EXECUTION_FAILED";

  return (
    <div className="space-y-3">
      {/* mode banner */}
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        <span className="inline-flex items-center gap-1.5 rounded-md border border-status-observed/30 bg-status-observed/10 px-2 py-1 font-medium uppercase tracking-wide text-status-observed">
          ● Historical Replay
        </span>
        {payload.is_synthetic ? (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-status-partial/30 bg-status-partial/10 px-2 py-1 font-medium uppercase tracking-wide text-status-partial">
            Synthetic demo data
          </span>
        ) : null}
        <span className="text-ink-faint">
          Playback of recorded evidence in real timestamp order — not live monitoring.
        </span>
      </div>

      {failed ? (
        <div className="rounded-xl border border-status-partial/30 bg-status-partial/5 p-5">
          <div className="text-[13px] font-semibold text-status-partial">
            {payload.visibility_status === "COLLECTION_FAILED" ? "Collection failed" : "Execution failed"}
          </div>
          <p className="mt-1 text-[11.5px] text-ink-muted">{payload.verdict_reason}</p>
          <p className="mt-2 text-[11px] text-ink-faint">
            This is distinct from a graph with no relationships: the sensor did not produce usable
            events, so there is nothing to correlate. Missing evidence is never treated as absence of
            a threat.
          </p>
        </div>
      ) : (
        <>
          {/* replay controls */}
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-surface-border bg-surface-raised px-3 py-2.5">
            <div className="flex items-center gap-1">
              {playing ? (
                <button onClick={pause} className="rounded-md bg-accent px-3 py-1.5 text-[12px] font-semibold text-surface hover:bg-accent-bright">
                  ❚❚ Pause
                </button>
              ) : (
                <button onClick={play} className="rounded-md bg-accent px-3 py-1.5 text-[12px] font-semibold text-surface hover:bg-accent-bright">
                  ▶ Play
                </button>
              )}
              <button onClick={step} disabled={reveal >= total} className="rounded-md border border-surface-border px-2.5 py-1.5 text-[12px] text-ink-muted hover:bg-surface-hover disabled:opacity-40">
                ⇥ Step
              </button>
              <button onClick={resetReplay} className="rounded-md border border-surface-border px-2.5 py-1.5 text-[12px] text-ink-muted hover:bg-surface-hover">
                ↺ Reset
              </button>
              <button onClick={complete} className="rounded-md border border-surface-border px-2.5 py-1.5 text-[12px] text-ink-muted hover:bg-surface-hover">
                ⊕ Full graph
              </button>
            </div>
            <div className="ml-1 flex items-center gap-1">
              <span className="text-[10px] text-ink-faint">speed</span>
              {SPEEDS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  className={`rounded px-1.5 py-1 text-[10.5px] ${speed === s ? "bg-accent/15 text-accent" : "text-ink-faint hover:text-ink"}`}
                >
                  {s}×
                </button>
              ))}
            </div>
            {/* scrubber */}
            <div className="ml-auto flex min-w-[180px] flex-1 items-center gap-2">
              <input
                type="range"
                min={0}
                max={total}
                value={reveal}
                onChange={(e) => {
                  setPlaying(false);
                  setReveal(Number(e.target.value));
                }}
                className="h-1 flex-1 cursor-pointer accent-accent"
              />
              <span className="mono w-14 shrink-0 text-right text-[10.5px] text-ink-faint">
                {Math.min(reveal, total)}/{total}
              </span>
            </div>
          </div>

          {/* graph + timeline/detail */}
          <div className="grid gap-3 lg:grid-cols-[1.7fr_1fr]">
            <div>
              {payload.nodes.length === 0 ? (
                <div className="rounded-xl border border-dashed border-surface-border bg-surface-raised p-8 text-center">
                  <p className="text-[12.5px] text-ink-muted">No graphable entities</p>
                  <p className="mx-auto mt-1 max-w-sm text-[11px] text-ink-faint">
                    This stream has no processes, files, containers or endpoints to place on a graph.
                    Use the event timeline on the right to inspect the raw records.
                  </p>
                </div>
              ) : (
                <BehaviorGraph
                  payload={payload}
                  revealCount={reveal}
                  currentEventId={highlightEventId}
                  selectedNodeId={selectedNodeId}
                  onSelectNode={(id) => {
                    setSelectedNodeId(id);
                    if (id) setSelectedEventId(null);
                  }}
                  onSelectEdge={(e) => {
                    setSelectedEdge(e);
                    if (e) setSelectedEventId(null);
                  }}
                />
              )}

              {/* correlation limits — makes a sparse graph informative */}
              {payload.correlation_limits.length ? (
                <div className="mt-2 rounded-lg border border-surface-border bg-surface-panel p-2.5">
                  <div className="text-[9.5px] uppercase tracking-wide text-ink-faint">
                    Why correlation is limited here
                  </div>
                  <ul className="mt-1 space-y-0.5">
                    {payload.correlation_limits.map((c) => (
                      <li key={c.field} className="text-[10.5px] text-ink-muted">
                        <span className="mono text-status-partial">{c.field}</span> missing on{" "}
                        {c.events_missing} event{c.events_missing === 1 ? "" : "s"} — {c.effect}.
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>

            {/* right column: detail + timeline */}
            <div className="space-y-3">
              <div className="rounded-xl border border-surface-border bg-surface-raised p-4">
                <div className="mb-2 text-[11px] font-semibold tracking-tight text-ink">Inspector</div>
                <Detail
                  payload={payload}
                  selectedNode={selectedNode}
                  selectedEdge={selectedEdge}
                  selectedEventId={selectedEventId}
                />
              </div>
              <div className="rounded-xl border border-surface-border bg-surface-raised">
                <div className="flex items-center justify-between border-b border-surface-border px-4 py-2.5">
                  <span className="text-[11px] font-semibold tracking-tight text-ink">Event timeline</span>
                  <span className="mono text-[10px] text-ink-faint">{total} events</span>
                </div>
                <EventTimeline payload={payload} reveal={reveal} currentId={highlightEventId} onPick={pickEvent} />
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
