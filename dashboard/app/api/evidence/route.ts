import { NextRequest, NextResponse } from "next/server";
import { readEvidenceJson, readEventStream, isSafeEvidencePath } from "@/lib/data";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Serve a path-restricted evidence file (raw JSON or event .jsonl). */
export async function GET(req: NextRequest) {
  const rel = req.nextUrl.searchParams.get("path") ?? "";
  if (!isSafeEvidencePath(rel)) {
    return NextResponse.json({ ok: false, error: "path not permitted" }, { status: 400 });
  }
  if (rel.endsWith(".jsonl")) {
    const limit = Number(req.nextUrl.searchParams.get("limit") ?? 500);
    const events = readEventStream(rel, Math.min(Math.max(limit, 1), 2000));
    return NextResponse.json({ ok: true, kind: "events", path: rel, count: events.length, events });
  }
  const data = readEvidenceJson(rel);
  if (data == null) {
    return NextResponse.json({ ok: false, error: "not found" }, { status: 404 });
  }
  return NextResponse.json({ ok: true, kind: "json", path: rel, data });
}
