import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { REPO_ROOT } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Read-only behavior-graph payload for ONE allowlisted stream: ordered events,
 * evidence-backed nodes/edges, findings and correlation limits. Reuses the
 * engine's own BehaviorGraph via `cli graph` — it does NOT detect or mutate
 * anything. Strict allowlist + traversal guard + bounded timeout.
 */
const TIMEOUT_MS = 60_000;

function allowedStreams(): Set<string> {
  try {
    const idx = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "results/normalized/events_index.json"), "utf-8")
    );
    return new Set<string>((idx.streams ?? []).map((s: { stream: string }) => s.stream));
  } catch {
    return new Set();
  }
}

export async function POST(req: NextRequest) {
  let body: { stream?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON" }, { status: 400 });
  }
  const stream = body.stream ?? "";
  const norm = path.normalize(stream);
  if (norm.startsWith("..") || path.isAbsolute(norm) || !allowedStreams().has(stream)) {
    return NextResponse.json({ ok: false, error: "stream not in allowlist" }, { status: 400 });
  }
  const started = Date.now();
  return new Promise<NextResponse>((resolve) => {
    execFile(
      "python3",
      ["-m", "scripts.traceweaver.cli", "graph", "--stream", stream],
      { cwd: REPO_ROOT, timeout: TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const elapsed = Date.now() - started;
        if (err) {
          resolve(NextResponse.json({ ok: false, error: stderr || err.message, elapsed_ms: elapsed }));
          return;
        }
        try {
          const payload = JSON.parse(stdout);
          resolve(NextResponse.json({ ...payload, elapsed_ms: elapsed }));
        } catch {
          resolve(NextResponse.json({ ok: false, error: "unparseable graph output", elapsed_ms: elapsed }));
        }
      }
    );
  });
}
