// Deterministic plain-English interpretation of evidence records and event
// streams. This module describes an ALREADY-ESTABLISHED outcome (computed by the
// Python pipeline); it never decides detection outcomes itself. Every sentence is
// derived from actual fields present in the record.

export interface Interpretation {
  whatHappened: string;
  whyItMatters: string;
  whatObserved: string;
  detectionResult: string;
  confidence: "directly-confirmed" | "partially-supported" | "inconclusive";
  doesNotProve: string;
}

const STATUS_PLAIN: Record<string, string> = {
  confirmed_detection: "a security rule produced a verified alert",
  telemetry_observed: "the behavior was observed as telemetry, with no alert",
  partial: "some evidence exists but the targeted claim is not fully established",
  not_tested: "this combination was not evaluated",
  confirmed_miss: "the event was observed but an expected detection did not fire",
  not_applicable: "this detector was out of scope for the experiment",
  DETECTED: "a qualifying security detection fired",
  TELEMETRY_ONLY: "the behavior was observed as telemetry, with no qualifying detection",
  NOT_DETECTED: "the scenario ran and the detector was configured, but no qualifying detection occurred",
  NOT_EVALUATED: "a prerequisite (tool, policy, or event source) was unavailable",
  EXECUTION_FAILED: "the scenario did not execute successfully",
  COLLECTION_FAILED: "evidence collection failed or was insufficient",
  INCONCLUSIVE: "the available evidence cannot reliably establish the result",
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function interpretRecord(rec: any, experiment?: any): Interpretation {
  const tool = (rec.tool ?? "the tool") as string;
  const toolCap = tool.charAt(0).toUpperCase() + tool.slice(1);
  const procs: string[] = rec.processes_observed ?? [];
  const status: string = rec.status ?? "";
  const dims = rec.dimensions ?? {};
  const live = rec.provenance === "live";

  const chain = procs.length ? procs.join(" → ") : "the configured workload";
  const behavior = (experiment?.behavior ?? rec.behavior ?? "").replace(/_/g, " ");

  const whatHappened = procs.length
    ? `Inside a controlled container, ${toolCap} captured the execution sequence ${chain}` +
      (experiment?.target_path ? `, including access to ${experiment.target_path}.` : ".")
    : `${toolCap} observed the ${behavior || "configured"} behavior in a controlled container.`;

  const whyItMatters =
    experiment?.purpose ??
    `This tests whether ${toolCap} observes and/or detects ${behavior || "the tested behavior"}.`;

  const whatObserved = [
    rec.event_observed ? "a relevant kernel event was captured" : "no relevant event was captured",
    rec.detection_type ? `via ${rec.detection_type}` : "",
    rec.context_enriched ? "with container context attached" : "",
    rec.alert_count != null ? `${rec.alert_count} alert(s) recorded` : "",
  ]
    .filter(Boolean)
    .join(", ") + ".";

  let detectionResult = `${toolCap}: ${STATUS_PLAIN[status] ?? status}.`;
  if (rec.rule_class === "builtin_security") {
    detectionResult += " This is a shipped security rule, not a lab-authored rule.";
  } else if (rec.rule_class === "custom_research") {
    detectionResult +=
      " This alert came from the lab's custom process-execution rule, which flags execution but is not a threat verdict.";
  }
  if (dims.detection) detectionResult += ` (detection dimension: ${dims.detection})`;

  const confidence: Interpretation["confidence"] =
    status === "confirmed_detection" || status === "DETECTED"
      ? "directly-confirmed"
      : status === "partial" || status === "NOT_DETECTED"
      ? "partially-supported"
      : status === "telemetry_observed" || status === "TELEMETRY_ONLY"
      ? "directly-confirmed"
      : "inconclusive";

  const doesNotProve =
    status === "telemetry_observed" || status === "TELEMETRY_ONLY"
      ? "Observing these events does not prove a security alert fired or that an attack was prevented. Opening a file is not the same as reading its contents; a connection attempt is not a confirmed connection."
      : status === "confirmed_detection" || status === "DETECTED"
      ? "A detection confirms the rule fired on this behavior; it does not prove the behavior was malicious or that evasion is impossible under other configurations."
      : "The evidence is bounded to this specific run, configuration, and observation window.";

  return {
    whatHappened,
    whyItMatters,
    whatObserved,
    detectionResult,
    confidence,
    doesNotProve: doesNotProve + (live ? "" : " (Recorded evidence.)"),
  };
}

// --- Human-readable event timeline from a Tetragon/Tracee/Falco event stream ---

export interface TimelineEvent {
  kind: "exec" | "file" | "network" | "alert" | "exit" | "other";
  title: string;
  detail: string;
  ts?: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildTimeline(events: any[]): TimelineEvent[] {
  const out: TimelineEvent[] = [];
  for (const ev of events.slice(0, 200)) {
    // Tetragon shapes
    if (ev.process_exec) {
      const p = ev.process_exec.process ?? {};
      out.push({
        kind: "exec",
        title: `Process executed: ${basename(p.binary)}`,
        detail: `${p.binary ?? ""} ${p.arguments ?? ""}`.trim(),
        ts: ev.time,
      });
      continue;
    }
    if (ev.process_kprobe) {
      const k = ev.process_kprobe;
      const path = (k.args ?? []).map((a: any) => a.string_arg).find(Boolean);
      if ((k.function_name ?? "").includes("openat")) {
        out.push({
          kind: "file",
          title: `File opened: ${path ?? "(path)"}`,
          detail: `${sensitive(path) ? "Sensitive path. " : ""}kprobe ${k.function_name}`,
          ts: ev.time,
        });
      }
      continue;
    }
    // Tracee shape
    if (ev.eventName) {
      const args: Record<string, any> = {};
      (ev.args ?? []).forEach((a: any) => (args[a.name] = a.value));
      if (ev.eventName === "execve") {
        out.push({ kind: "exec", title: `Process executed: ${basename(args.pathname)}`, detail: JSON.stringify(args.argv ?? "") });
      } else if (ev.eventName === "openat" || ev.eventName === "security_file_open") {
        const p = args.pathname ?? args.syscall_pathname;
        out.push({ kind: "file", title: `File opened: ${p ?? "(path)"}`, detail: sensitive(p) ? "Sensitive path." : ev.eventName });
      } else if (ev.eventName.includes("connect")) {
        out.push({ kind: "network", title: "Network connection attempt", detail: ev.eventName });
      }
      continue;
    }
    // Falco alert shape
    if (ev.rule) {
      out.push({
        kind: "alert",
        title: `ALERT: ${ev.rule}`,
        detail: `priority ${ev.priority}${ev.tags ? ` · ${(ev.tags as string[]).filter((t) => t.startsWith("T1") || t.startsWith("mitre")).join(", ")}` : ""}`,
        ts: ev.time,
      });
    }
  }
  return out;
}

function basename(p?: string): string {
  if (!p) return "(unknown)";
  return p.split("/").filter(Boolean).pop() ?? p;
}
function sensitive(p?: string): boolean {
  return !!p && ["/etc/shadow", "/etc/sudoers", "ssh_host"].some((s) => p.includes(s));
}

export const OUTCOME_PLAIN = STATUS_PLAIN;
