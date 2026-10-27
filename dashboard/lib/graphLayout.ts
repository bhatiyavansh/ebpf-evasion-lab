// Deterministic, dependency-free force-directed layout for small behavior
// graphs (<~40 nodes). No RNG: initial positions are seeded from the node
// index on a circle, so the same payload always yields the same layout.
import type { GraphNode, GraphEdge } from "@/lib/types";

export interface Positioned {
  id: string;
  x: number;
  y: number;
}

export interface LayoutResult {
  positions: Record<string, Positioned>;
  width: number;
  height: number;
}

export function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  opts: { width?: number; height?: number; iterations?: number } = {}
): LayoutResult {
  const width = opts.width ?? 900;
  const height = opts.height ?? 560;
  const iterations = opts.iterations ?? 320;
  const cx = width / 2;
  const cy = height / 2;
  const n = nodes.length;

  if (n === 0) return { positions: {}, width, height };
  if (n === 1) {
    return { positions: { [nodes[0].id]: { id: nodes[0].id, x: cx, y: cy } }, width, height };
  }

  // seed on a circle (deterministic, index-based)
  const pos: Record<string, { x: number; y: number }> = {};
  const radius = Math.min(width, height) * 0.34;
  nodes.forEach((nd, i) => {
    const a = (2 * Math.PI * i) / n;
    pos[nd.id] = { x: cx + radius * Math.cos(a), y: cy + radius * Math.sin(a) };
  });

  const idToIndex: Record<string, number> = {};
  nodes.forEach((nd, i) => (idToIndex[nd.id] = i));

  // dedupe adjacency (an edge list may repeat the same pair many times)
  const links = new Set<string>();
  for (const e of edges) {
    if (idToIndex[e.source] === undefined || idToIndex[e.target] === undefined) continue;
    if (e.source === e.target) continue;
    const key = e.source < e.target ? `${e.source}|${e.target}` : `${e.target}|${e.source}`;
    links.add(key);
  }
  const adj = [...links].map((k) => k.split("|"));

  const k = Math.sqrt((width * height) / n) * 0.9; // ideal distance
  let temp = width * 0.1;
  const cool = temp / (iterations + 1);

  for (let it = 0; it < iterations; it++) {
    const disp: Record<string, { x: number; y: number }> = {};
    for (const nd of nodes) disp[nd.id] = { x: 0, y: 0 };

    // repulsion (all pairs)
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = nodes[i].id;
        const b = nodes[j].id;
        let dx = pos[a].x - pos[b].x;
        let dy = pos[a].y - pos[b].y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        if (dist < 0.01) {
          dx = (i - j) * 0.01;
          dy = 0.01;
          dist = 0.02;
        }
        const force = (k * k) / dist;
        const ux = (dx / dist) * force;
        const uy = (dy / dist) * force;
        disp[a].x += ux;
        disp[a].y += uy;
        disp[b].x -= ux;
        disp[b].y -= uy;
      }
    }

    // attraction (along deduped edges)
    for (const [a, b] of adj) {
      const dx = pos[a].x - pos[b].x;
      const dy = pos[a].y - pos[b].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist * dist) / k;
      const ux = (dx / dist) * force;
      const uy = (dy / dist) * force;
      disp[a].x -= ux;
      disp[a].y -= uy;
      disp[b].x += ux;
      disp[b].y += uy;
    }

    // gentle gravity toward center so disconnected nodes don't fly off
    for (const nd of nodes) {
      disp[nd.id].x += (cx - pos[nd.id].x) * 0.015;
      disp[nd.id].y += (cy - pos[nd.id].y) * 0.015;
    }

    // apply with temperature cap
    for (const nd of nodes) {
      const d = disp[nd.id];
      const len = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
      pos[nd.id].x += (d.x / len) * Math.min(len, temp);
      pos[nd.id].y += (d.y / len) * Math.min(len, temp);
    }
    temp = Math.max(temp - cool, width * 0.002);
  }

  // normalize into a padded box
  const pad = 56;
  const xs = nodes.map((nd) => pos[nd.id].x);
  const ys = nodes.map((nd) => pos[nd.id].y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const spanX = maxX - minX || 1;
  const spanY = maxY - minY || 1;
  const scale = Math.min((width - 2 * pad) / spanX, (height - 2 * pad) / spanY);

  const positions: Record<string, Positioned> = {};
  for (const nd of nodes) {
    positions[nd.id] = {
      id: nd.id,
      x: pad + (pos[nd.id].x - minX) * scale,
      y: pad + (pos[nd.id].y - minY) * scale,
    };
  }
  return { positions, width, height };
}
