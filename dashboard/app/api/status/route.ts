import { NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";
import { REPO_ROOT } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Live detector/environment health check. Shells out to scripts/lab.sh status. */
export async function GET() {
  const script = path.join(REPO_ROOT, "scripts", "lab.sh");
  return new Promise<NextResponse>((resolve) => {
    execFile(
      "bash",
      [script, "status"],
      { timeout: 15000, cwd: REPO_ROOT, maxBuffer: 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          resolve(
            NextResponse.json(
              { ok: false, error: stderr || err.message, live: false },
              { status: 200 }
            )
          );
          return;
        }
        try {
          const data = JSON.parse(stdout);
          resolve(NextResponse.json({ ok: true, ...data }));
        } catch {
          resolve(NextResponse.json({ ok: false, error: "unparseable status output" }));
        }
      }
    );
  });
}
