import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { REPO_ROOT } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Run the REAL TraceWeaver engine on ONE allowlisted stream and return its
 * result. The stream is validated against the normalized events index (no
 * arbitrary paths, no shell). Bounded timeout. This is a fixed, allowlisted
 * server action — NOT an arbitrary command endpoint.
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
  // strict allowlist + traversal guard
  const norm = path.normalize(stream);
  if (norm.startsWith("..") || path.isAbsolute(norm) || !allowedStreams().has(stream)) {
    return NextResponse.json({ ok: false, error: "stream not in allowlist" }, { status: 400 });
  }
  const started = Date.now();
  return new Promise<NextResponse>((resolve) => {
    execFile(
      "python3",
      ["-m", "scripts.traceweaver.cli", "run", "--stream", stream, "--no-write"],
      { cwd: REPO_ROOT, timeout: TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const elapsed = Date.now() - started;
        if (err) {
          resolve(NextResponse.json({ ok: false, error: stderr || err.message, elapsed_ms: elapsed }));
          return;
        }
        try {
          const result = JSON.parse(stdout);
          resolve(NextResponse.json({ ok: true, mode: "live_engine_run", elapsed_ms: elapsed, result }));
        } catch {
          resolve(NextResponse.json({ ok: false, error: "unparseable engine output", elapsed_ms: elapsed }));
        }
      }
    );
  });
}
