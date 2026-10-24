import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";
import { REPO_ROOT, loadCatalog } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Live experiment runner — STRICTLY allowlisted.
 *
 * Accepts { experimentId } only. The command executed is resolved inside
 * scripts/lab.sh from experiments/catalog.json (shell_payload), never from the
 * request. Only Tetragon is supported live (its capture harness is scripted and
 * safe). Falco/Tracee are recorded-evidence/replay only in this build.
 *
 * There is intentionally NO arbitrary-command endpoint.
 */
const RUN_TIMEOUT_MS = 90_000;

export async function POST(req: NextRequest) {
  let body: { experimentId?: string; tool?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }

  const { experimentId, tool } = body;
  const catalog = loadCatalog();
  const validIds = new Set(catalog.experiments.map((e) => e.id));

  if (!experimentId || !validIds.has(experimentId)) {
    return NextResponse.json(
      { ok: false, state: "unsupported", error: `unknown experiment id: ${experimentId}` },
      { status: 400 }
    );
  }
  if (tool && tool !== "tetragon") {
    return NextResponse.json(
      {
        ok: false,
        state: "unsupported",
        error: `live execution is only supported for Tetragon in this build; ${tool} is replay-only`,
      },
      { status: 400 }
    );
  }

  const script = path.join(REPO_ROOT, "scripts", "lab.sh");
  const started = Date.now();

  return new Promise<NextResponse>((resolve) => {
    execFile(
      "bash",
      [script, "run-tetragon", experimentId],
      { timeout: RUN_TIMEOUT_MS, cwd: REPO_ROOT, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const elapsed = Date.now() - started;
        if (err) {
          const killed = Boolean((err as Error & { killed?: boolean }).killed);
          const timedOut = killed && elapsed >= RUN_TIMEOUT_MS - 500;
          resolve(
            NextResponse.json({
              ok: false,
              state: timedOut ? "timed_out" : "failed",
              elapsed_ms: elapsed,
              log: stderr || "",
              error: err.message,
            })
          );
          return;
        }
        let result: unknown = null;
        // stdout should be exactly the raw tetragon result JSON; be tolerant of
        // any leading noise by parsing from the first "{".
        const brace = stdout.indexOf("{");
        if (brace >= 0) {
          try {
            result = JSON.parse(stdout.slice(brace));
          } catch {
            /* leave result null; the run log is surfaced to the UI */
          }
        }
        resolve(
          NextResponse.json({
            ok: true,
            state: "completed",
            experimentId,
            tool: "tetragon",
            elapsed_ms: elapsed,
            result,
            log: stderr || "",
          })
        );
      }
    );
  });
}
