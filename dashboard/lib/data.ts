import fs from "fs";
import path from "path";
import type {
  Analysis,
  Catalog,
  Comparison,
  CveCatalog,
  DashboardData,
  Environment,
  NormRecord,
  RunRow,
  Tool,
} from "./types";

export * from "./types";

/**
 * Server-side data layer. The dashboard consumes GENERATED artifacts
 * (results/normalized/results.json + results/analysis/analysis.json), produced
 * by scripts/pipeline.sh from immutable raw evidence. Status classification is
 * NOT re-derived here — it lives in scripts/normalize.py as the single source
 * of truth. This module only reads the generated files.
 */
export const REPO_ROOT = path.join(process.cwd(), "..");

function readJson<T>(rel: string): T | null {
  const full = path.join(REPO_ROOT, rel);
  if (!fs.existsSync(full)) return null;
  try {
    return JSON.parse(fs.readFileSync(full, "utf-8")) as T;
  } catch {
    return null;
  }
}

export function loadCatalog(): Catalog {
  return readJson<Catalog>("experiments/catalog.json")!;
}

export function loadNormalized(): NormRecord[] {
  const d = readJson<{ records: NormRecord[] }>("results/normalized/results.json");
  return d?.records ?? [];
}

export function loadAnalysis(): Analysis | null {
  return readJson<Analysis>("results/analysis/analysis.json");
}

export function loadEnvironment(): Environment | null {
  return readJson<Environment>("results/env/environment.json");
}

export function loadCve(): CveCatalog | null {
  return readJson<CveCatalog>("experiments/cve_catalog.json");
}

export function loadRuns(): RunRow[] {
  const d = readJson<{ runs: RunRow[] }>("results/runs.json");
  return d?.runs ?? [];
}

export function loadComparison(): Comparison | null {
  return readJson<Comparison>("results/analysis/comparison.json");
}

export function isSafeEvidencePath(rel: string): boolean {
  const norm = path.normalize(rel);
  if (norm.startsWith("..") || path.isAbsolute(norm)) return false;
  return (
    norm.startsWith("results/raw/") ||
    norm.startsWith("results/normalized/") ||
    norm.startsWith("results/runs/") ||
    norm.startsWith("results/analysis/") ||
    norm.startsWith("experiments/")
  );
}

export function readEvidenceJson(rel: string): unknown | null {
  if (!isSafeEvidencePath(rel) || !rel.endsWith(".json")) return null;
  return readJson(rel);
}

export function readEventStream(rel: string, limit = 500): Record<string, unknown>[] {
  if (!isSafeEvidencePath(rel) || !rel.endsWith(".jsonl")) return [];
  const full = path.join(REPO_ROOT, rel);
  if (!fs.existsSync(full)) return [];
  const out: Record<string, unknown>[] = [];
  for (const line of fs.readFileSync(full, "utf-8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      /* skip malformed */
    }
    if (out.length >= limit) break;
  }
  return out;
}

export function loadDashboardData(): DashboardData {
  return {
    catalog: loadCatalog(),
    records: loadNormalized(),
    analysis: loadAnalysis(),
    environment: loadEnvironment(),
    cve: loadCve(),
    runs: loadRuns(),
    comparison: loadComparison(),
  };
}

export function recordFor(records: NormRecord[], experimentId: string, tool: Tool): NormRecord | undefined {
  return records.find((r) => r.experiment_id === experimentId && r.tool === tool);
}
