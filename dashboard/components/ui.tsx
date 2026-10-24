"use client";

import React from "react";
import type { Status, Tool } from "@/lib/types";

export const TOOL_LABEL: Record<Tool, string> = {
  falco: "Falco",
  tracee: "Tracee",
  tetragon: "Tetragon",
};

export const STATUS_META: Record<
  string,
  { label: string; short: string; dot: string; text: string; bg: string; border: string; desc: string }
> = {
  not_applicable: {
    label: "Not applicable",
    short: "N/A",
    dot: "bg-status-nottested",
    text: "text-ink-faint",
    bg: "bg-surface-inset",
    border: "border-surface-border",
    desc: "This detector was not part of this experiment's scope.",
  },
  collection_failed: {
    label: "Collection failed",
    short: "COLLECTION FAILED",
    dot: "bg-status-missed",
    text: "text-status-missed",
    bg: "bg-status-missed/10",
    border: "border-status-missed/30",
    desc: "The workload executed but the sensor captured no events — not a detector miss and not telemetry.",
  },
  confirmed_detection: {
    label: "Confirmed detection",
    short: "DETECTION",
    dot: "bg-status-detected",
    text: "text-status-detected",
    bg: "bg-status-detected/10",
    border: "border-status-detected/30",
    desc: "A rule/policy engine raised a security detection on the tested behavior.",
  },
  telemetry_observed: {
    label: "Telemetry observed",
    short: "TELEMETRY",
    dot: "bg-status-observed",
    text: "text-status-observed",
    bg: "bg-status-observed/10",
    border: "border-status-observed/30",
    desc: "A relevant kernel event was captured. Observability only — no alert verdict.",
  },
  partial: {
    label: "Partial evidence",
    short: "PARTIAL",
    dot: "bg-status-partial",
    text: "text-status-partial",
    bg: "bg-status-partial/10",
    border: "border-status-partial/30",
    desc: "Some evidence exists, but the targeted claim is not fully established.",
  },
  not_tested: {
    label: "Not tested",
    short: "NOT TESTED",
    dot: "bg-status-nottested",
    text: "text-ink-faint",
    bg: "bg-status-nottested/10",
    border: "border-status-nottested/30",
    desc: "No result file exists in the repository for this experiment/tool.",
  },
  confirmed_miss: {
    label: "Confirmed miss",
    short: "MISS",
    dot: "bg-status-missed",
    text: "text-status-missed",
    bg: "bg-status-missed/10",
    border: "border-status-missed/30",
    desc: "The event was observed but an expected detection failed to fire.",
  },
};

export const OUTCOME_META: Record<
  string,
  { label: string; dot: string; text: string; bg: string; border: string }
> = {
  DETECTED: { label: "Detected", dot: "bg-status-detected", text: "text-status-detected", bg: "bg-status-detected/10", border: "border-status-detected/30" },
  TELEMETRY_ONLY: { label: "Telemetry only", dot: "bg-status-observed", text: "text-status-observed", bg: "bg-status-observed/10", border: "border-status-observed/30" },
  NOT_DETECTED: { label: "Not detected", dot: "bg-status-partial", text: "text-status-partial", bg: "bg-status-partial/10", border: "border-status-partial/30" },
  NOT_EVALUATED: { label: "Not evaluated", dot: "bg-status-nottested", text: "text-ink-faint", bg: "bg-surface-inset", border: "border-surface-border" },
  EXECUTION_FAILED: { label: "Execution failed", dot: "bg-status-missed", text: "text-status-missed", bg: "bg-status-missed/10", border: "border-status-missed/30" },
  COLLECTION_FAILED: { label: "Collection failed", dot: "bg-status-missed", text: "text-status-missed", bg: "bg-status-missed/10", border: "border-status-missed/30" },
  INCONCLUSIVE: { label: "Inconclusive", dot: "bg-status-nottested", text: "text-ink-muted", bg: "bg-surface-inset", border: "border-surface-border" },
};

export function OutcomeBadge({ outcome, sub }: { outcome: string; sub?: string }) {
  const m = OUTCOME_META[outcome] ?? OUTCOME_META.INCONCLUSIVE;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider ${m.bg} ${m.border} ${m.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}{sub ? ` · ${sub}` : ""}
    </span>
  );
}

export const STATUS_ORDER: Status[] = [
  "confirmed_detection",
  "telemetry_observed",
  "partial",
  "collection_failed",
  "confirmed_miss",
  "not_tested",
];

export function StatusBadge({ status, children }: { status: Status | string; children?: React.ReactNode }) {
  const s = STATUS_META[status] ?? STATUS_META.not_tested;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider ${s.bg} ${s.border} ${s.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {children ?? s.short}
    </span>
  );
}

export function Dot({ status, pulse }: { status: Status | string; pulse?: boolean }) {
  const s = STATUS_META[status] ?? STATUS_META.not_tested;
  return (
    <span
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${s.dot} ${
        pulse ? "animate-pulsedot" : ""
      }`}
    />
  );
}

export function Panel({
  title,
  kicker,
  right,
  children,
  className = "",
}: {
  title?: string;
  kicker?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-surface-border bg-surface-panel/80 p-5 shadow-[0_1px_0_0_rgba(255,255,255,0.02)_inset] sm:p-6 ${className}`}
    >
      {(title || right) && (
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            {kicker && (
              <div className="mb-1 text-[10px] font-medium uppercase tracking-[0.18em] text-accent/70">
                {kicker}
              </div>
            )}
            {title && (
              <h2 className="text-[13px] font-semibold uppercase tracking-wide text-ink">{title}</h2>
            )}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function Metric({
  value,
  label,
  hint,
  tone = "default",
}: {
  value: React.ReactNode;
  label: string;
  hint?: string;
  tone?: "default" | "accent" | "warn";
}) {
  const toneCls =
    tone === "accent" ? "text-accent" : tone === "warn" ? "text-status-partial" : "text-ink";
  return (
    <div className="rounded-lg border border-surface-border bg-surface-raised p-4">
      <div className={`mono text-[28px] font-semibold leading-none ${toneCls}`}>{value}</div>
      <div className="mt-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">
        {label}
      </div>
      {hint && <div className="mt-1 text-[10.5px] text-ink-faint">{hint}</div>}
    </div>
  );
}

export function KV({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-3 py-2.5">
      <div className="text-[9.5px] font-medium uppercase tracking-wide text-ink-faint">{k}</div>
      <div className={`mt-1 text-[13px] text-ink ${mono ? "mono" : ""}`}>{v}</div>
    </div>
  );
}

export function Pill({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-[11px] font-medium transition ${
        active
          ? "border-accent/50 bg-accent/15 text-accent"
          : "border-surface-border text-ink-muted hover:border-surface-hover hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

export function JsonBlock({ data, maxH = "max-h-80" }: { data: unknown; maxH?: string }) {
  return (
    <pre
      className={`${maxH} overflow-auto rounded-lg border border-surface-border bg-surface-inset p-3 text-[11px] leading-relaxed text-ink-muted mono`}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export function Mode({ live }: { live: boolean }) {
  return live ? (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-status-detected/40 bg-status-detected/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-status-detected">
      <span className="h-1.5 w-1.5 animate-pulsedot rounded-full bg-status-detected" /> Live
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-raised px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-ink-faint" /> Recorded evidence
    </span>
  );
}
