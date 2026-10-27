"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { GraphPayload, GraphNode, GraphEdge } from "@/lib/types";
import { computeLayout } from "@/lib/graphLayout";

const KIND_STYLE: Record<string, { fill: string; stroke: string; label: string }> = {
  process: { fill: "#0e2a33", stroke: "#38bdf8", label: "Process" },
  security_event: { fill: "#331417", stroke: "#f0674f", label: "Security alert" },
  file: { fill: "#161b23", stroke: "#8aa0b8", label: "File" },
  network: { fill: "#241a33", stroke: "#a78bfa", label: "Network" },
  container: { fill: "#2a2410", stroke: "#e0b23a", label: "Container" },
};

const EDGE_LABEL: Record<string, string> = {
  parent_of: "parent of",
  accessed: "accessed",
  connected: "connected to",
  in_container: "in container",
};

function NodeShape({ node, cx, cy, r }: { node: GraphNode; cx: number; cy: number; r: number }) {
  const s = KIND_STYLE[node.kind] ?? KIND_STYLE.process;
  if (node.kind === "file") {
    return <rect x={cx - r} y={cy - r * 0.8} width={r * 2} height={r * 1.6} rx={3} fill={s.fill} stroke={s.stroke} strokeWidth={1.5} />;
  }
  if (node.kind === "container") {
    return <rect x={cx - r * 1.2} y={cy - r} width={r * 2.4} height={r * 2} rx={6} fill={s.fill} stroke={s.stroke} strokeWidth={1.5} strokeDasharray="1 0" />;
  }
  if (node.kind === "security_event") {
    // diamond
    return <path d={`M ${cx} ${cy - r} L ${cx + r} ${cy} L ${cx} ${cy + r} L ${cx - r} ${cy} Z`} fill={s.fill} stroke={s.stroke} strokeWidth={1.5} />;
  }
  if (node.kind === "network") {
    // hexagon
    const pts = [0, 1, 2, 3, 4, 5]
      .map((i) => {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        return `${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`;
      })
      .join(" ");
    return <polygon points={pts} fill={s.fill} stroke={s.stroke} strokeWidth={1.5} />;
  }
  return <circle cx={cx} cy={cy} r={r} fill={s.fill} stroke={s.stroke} strokeWidth={1.5} />;
}

export default function BehaviorGraph({
  payload,
  revealCount,
  currentEventId,
  selectedNodeId,
  onSelectNode,
  onSelectEdge,
  height = 480,
}: {
  payload: GraphPayload;
  revealCount: number; // events revealed so far (for replay). >= events.length => all
  currentEventId: string | null;
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  onSelectEdge: (edge: GraphEdge | null) => void;
  height?: number;
}) {
  const W = 900;
  const H = 560;
  const layout = useMemo(
    () => computeLayout(payload.nodes, payload.edges, { width: W, height: H }),
    [payload]
  );

  // zoom / pan
  const [view, setView] = useState({ scale: 1, tx: 0, ty: 0 });
  const drag = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const [hover, setHover] = useState<string | null>(null);

  // reset view whenever the graph changes
  useEffect(() => setView({ scale: 1, tx: 0, ty: 0 }), [payload]);

  const total = payload.events.length;
  const reveal = Math.min(Math.max(revealCount, 0), total);
  const showAll = reveal >= total;

  const visibleNodeIds = useMemo(() => {
    const s = new Set<string>();
    for (const nd of payload.nodes) if (showAll || nd.first_order < reveal) s.add(nd.id);
    return s;
  }, [payload, reveal, showAll]);

  const visibleEdges = useMemo(
    () => payload.edges.filter((e) => (showAll || e.reveal_order < reveal) && visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)),
    [payload, reveal, showAll, visibleNodeIds]
  );

  // dedupe visible edges by (source,target,type) for rendering
  const renderEdges = useMemo(() => {
    const seen = new Set<string>();
    const out: GraphEdge[] = [];
    for (const e of visibleEdges) {
      const key = `${e.source}|${e.target}|${e.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(e);
    }
    return out;
  }, [visibleEdges]);

  const currentNodeIds = useMemo(() => {
    const s = new Set<string>();
    if (!currentEventId) return s;
    for (const nd of payload.nodes) if (nd.event_ids.includes(currentEventId)) s.add(nd.id);
    return s;
  }, [payload, currentEventId]);

  function onWheel(e: React.WheelEvent) {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    setView((v) => ({ ...v, scale: Math.min(4, Math.max(0.4, v.scale * factor)) }));
  }
  function onPointerDown(e: React.PointerEvent) {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    drag.current = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty };
  }
  function onPointerMove(e: React.PointerEvent) {
    if (!drag.current) return;
    setView((v) => ({ ...v, tx: drag.current!.tx + (e.clientX - drag.current!.x), ty: drag.current!.ty + (e.clientY - drag.current!.y) }));
  }
  function onPointerUp() {
    drag.current = null;
  }
  function fit() {
    setView({ scale: 1, tx: 0, ty: 0 });
  }

  const nodeR = payload.nodes.length > 18 ? 13 : 17;
  const usedKinds = [...new Set(payload.nodes.map((n) => n.kind))];

  return (
    <div className="relative overflow-hidden rounded-xl border border-surface-border bg-[#070a0e]">
      {/* controls */}
      <div className="absolute right-3 top-3 z-10 flex flex-col gap-1">
        {([
          ["+", () => setView((v) => ({ ...v, scale: Math.min(4, v.scale * 1.2) })), "Zoom in"],
          ["−", () => setView((v) => ({ ...v, scale: Math.max(0.4, v.scale / 1.2) })), "Zoom out"],
          ["⤢", fit, "Fit / reset view"],
        ] as [string, () => void, string][]).map(([lab, fn, title], i) => (
          <button
            key={i}
            onClick={fn}
            className="h-7 w-7 rounded-md border border-surface-border bg-surface-raised text-[13px] text-ink-muted hover:bg-surface-hover hover:text-ink"
            title={title}
          >
            {lab}
          </button>
        ))}
      </div>

      {/* legend */}
      <div className="absolute left-3 top-3 z-10 rounded-lg border border-surface-border bg-surface-raised/90 px-2.5 py-2 backdrop-blur">
        <div className="mb-1 text-[9px] uppercase tracking-wide text-ink-faint">Legend</div>
        <div className="flex flex-col gap-1">
          {usedKinds.map((kd) => {
            const s = KIND_STYLE[kd] ?? KIND_STYLE.process;
            return (
              <div key={kd} className="flex items-center gap-1.5 text-[10px] text-ink-muted">
                <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.fill, border: `1.5px solid ${s.stroke}` }} />
                {s.label}
              </div>
            );
          })}
          <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-ink-muted">
            <span className="inline-block h-2.5 w-2.5 rounded-full ring-2 ring-status-missed" />
            Finding
          </div>
        </div>
      </div>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full cursor-grab touch-none active:cursor-grabbing"
        style={{ height }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onClick={() => {
          onSelectNode(null);
          onSelectEdge(null);
        }}
      >
        <defs>
          <marker id="arrowc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#5a6472" />
          </marker>
        </defs>
        <g transform={`translate(${view.tx},${view.ty}) scale(${view.scale})`}>
          {/* edges */}
          {renderEdges.map((e) => {
            const a = layout.positions[e.source];
            const b = layout.positions[e.target];
            if (!a || !b) return null;
            const isCurrent = e.event_id === currentEventId;
            const color = isCurrent ? "#5eead4" : e.derived ? "#3a4250" : "#4a5568";
            return (
              <g key={e.id} className="cursor-pointer" onClick={(ev) => { ev.stopPropagation(); onSelectEdge(e); onSelectNode(null); }}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={10} />
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={color}
                  strokeWidth={isCurrent ? 2 : 1.3}
                  strokeDasharray={e.derived ? "4 3" : undefined}
                  markerEnd="url(#arrowc)"
                  opacity={0.9}
                />
              </g>
            );
          })}

          {/* nodes */}
          {payload.nodes.map((nd) => {
            if (!visibleNodeIds.has(nd.id)) return null;
            const p = layout.positions[nd.id];
            if (!p) return null;
            const isCurrent = currentNodeIds.has(nd.id);
            const isSel = selectedNodeId === nd.id;
            const isHover = hover === nd.id;
            return (
              <g
                key={nd.id}
                transform={`translate(0,0)`}
                className="cursor-pointer"
                onClick={(ev) => { ev.stopPropagation(); onSelectNode(nd.id); onSelectEdge(null); }}
                onMouseEnter={() => setHover(nd.id)}
                onMouseLeave={() => setHover(null)}
              >
                {(nd.is_finding || isCurrent || isSel) && (
                  <circle cx={p.x} cy={p.y} r={nodeR + 7} fill="none" stroke={isCurrent ? "#5eead4" : nd.is_finding ? "#f0674f" : "#2dd4bf"} strokeWidth={isSel ? 2 : 1.4} opacity={0.85} />
                )}
                <NodeShape node={nd} cx={p.x} cy={p.y} r={nodeR} />
                {!nd.identity_known && (
                  <text x={p.x + nodeR - 2} y={p.y - nodeR + 2} fontSize={13} fill="#e0b23a" className="select-none">?</text>
                )}
                <text
                  x={p.x}
                  y={p.y + nodeR + 12}
                  textAnchor="middle"
                  fontSize={10.5}
                  fill={isHover || isSel ? "#e8ecf1" : "#9aa4b1"}
                  className="pointer-events-none select-none"
                >
                  {(nd.label ?? "").length > 22 ? nd.label.slice(0, 20) + "…" : nd.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* footer line */}
      <div className="flex items-center justify-between border-t border-surface-border px-3 py-1.5 text-[10px] text-ink-faint">
        <span>
          {visibleNodeIds.size} node{visibleNodeIds.size === 1 ? "" : "s"} · {renderEdges.length} edge
          {renderEdges.length === 1 ? "" : "s"} shown
          {!showAll ? ` · revealing ${reveal}/${total}` : ""}
        </span>
        <span>scroll to zoom · drag to pan</span>
      </div>
    </div>
  );
}
