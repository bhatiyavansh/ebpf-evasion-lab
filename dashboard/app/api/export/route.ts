import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { REPO_ROOT, loadNormalized } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Export the canonical pipeline outputs. CSV = results/summary.csv verbatim;
 * JSON = normalized records. Both are generated artifacts, not re-derived here. */
export async function GET(req: NextRequest) {
  const format = req.nextUrl.searchParams.get("format") ?? "json";
  if (format === "csv") {
    const csvPath = path.join(REPO_ROOT, "results", "summary.csv");
    if (!fs.existsSync(csvPath)) {
      return NextResponse.json({ ok: false, error: "summary.csv not found" }, { status: 404 });
    }
    const csv = fs.readFileSync(csvPath, "utf-8");
    return new NextResponse(csv, {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": 'attachment; filename="ebpf-lab-summary.csv"',
      },
    });
  }
  const records = loadNormalized();
  return new NextResponse(JSON.stringify({ records }, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": 'attachment; filename="ebpf-lab-results.json"',
    },
  });
}
