"use client";

import { useState } from "react";
import { interpretRecord, buildTimeline, type Interpretation } from "@/lib/interpret";
import { JsonBlock } from "./ui";

const CONF_STYLE: Record<Interpretation["confidence"], string> = {
  "directly-confirmed": "text-status-detected",
  "partially-supported": "text-status-partial",
  inconclusive: "text-ink-faint",
};

/** "What this means" card: plain-English interpretation above collapsed raw evidence. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function EvidenceCard({ rec, experiment, title }: { rec: any; experiment?: any; title?: string }) {
  const [rawOpen, setRawOpen] = useState(false);
  const [raw, setRaw] = useState<unknown>(null);
  const [events, setEvents] = useState<Record<string, unknown>[] | null>(null);
  const [tlOpen, setTlOpen] = useState(false);
  const i = interpretRecord(rec, experiment);

  async function loadRaw() {
    if (!rawOpen && raw == null && rec.evidence_raw) {
      const r = await fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_raw)}`);
      const j = await r.json();
      setRaw(j.ok ? j.data : { error: j.error });
    }
    setRawOpen((v) => !v);
  }
  async function loadTimeline() {
    if (!tlOpen && events == null && rec.evidence_events) {
      const r = await fetch(`/api/evidence?path=${encodeURIComponent(rec.evidence_events)}&limit=120`);
      const j = await r.json();
      setEvents(j.ok ? j.events : []);
    }
    setTlOpen((v) => !v);
  }

  const timeline = events ? buildTimeline(events) : [];

  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
      {title && <div className="mb-2 text-[13px] font-semibold text-ink">{title}</div>}
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-accent/70">What this means</div>
      <dl className="space-y-1.5 text-[12px] leading-relaxed">
        <Row k="What happened" v={i.whatHappened} />
        <Row k="Why it matters" v={i.whyItMatters} />
        <Row k="What the tool observed" v={i.whatObserved} />
        <Row k="Detection result" v={i.detectionResult} />
        <Row k="Evidence confidence" v={<span className={CONF_STYLE[i.confidence]}>{i.confidence}</span>} />
        <Row k="What this does not prove" v={i.doesNotProve} />
      </dl>

      <div className="mt-3 flex flex-wrap gap-2">
        {rec.evidence_events && (
          <button onClick={loadTimeline} className="rounded-md border border-surface-border px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink">
            {tlOpen ? "▾" : "▸"} Event timeline
          </button>
        )}
        {rec.evidence_raw && (
          <button onClick={loadRaw} className="rounded-md border border-surface-border px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink mono">
            {rawOpen ? "▾" : "▸"} Inspect raw evidence
          </button>
        )}
      </div>

      {tlOpen && events && (
        <div className="mt-3 space-y-1.5">
          {timeline.length === 0 && <div className="text-[11px] text-ink-faint">No parseable events in this record.</div>}
          {timeline.map((e, idx) => (
            <div key={idx} className="flex items-start gap-2.5 rounded-md border border-surface-border bg-surface-inset px-3 py-1.5">
              <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${TL_COLOR[e.kind]}`} />
              <div className="min-w-0">
                <div className="text-[11.5px] text-ink">{e.title}</div>
                {e.detail && <div className="truncate text-[10.5px] text-ink-faint mono">{e.detail}</div>}
              </div>
            </div>
          ))}
        </div>
      )}

      {rawOpen && raw != null && (
        <div className="mt-3">
          <JsonBlock data={raw} maxH="max-h-80" />
        </div>
      )}
    </div>
  );
}

const TL_COLOR: Record<string, string> = {
  exec: "bg-status-observed",
  file: "bg-status-partial",
  network: "bg-accent",
  alert: "bg-status-detected",
  exit: "bg-ink-faint",
  other: "bg-ink-faint",
};

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-2">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-ink-faint">{k}</dt>
      <dd className="text-ink-muted">{v}</dd>
    </div>
  );
}
