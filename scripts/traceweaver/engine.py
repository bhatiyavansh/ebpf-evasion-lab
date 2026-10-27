"""
TraceWeaver detection engine (Phase 2).

Deterministic, stdlib-only, no live sensors or external API required. Consumes
Phase-1 canonical events (+ provenance) and returns an explainable, visibility-
aware verdict with traceable evidence.

Pipeline:  events -> BehaviorGraph -> {A anomaly, S sequence, P policy} signals
           -> risk_score -> visibility-aware verdict -> explanations.

Key invariants (enforced + tested):
  * missing events never raise the anomaly score and never become a detection;
  * a high risk score never overrides a COLLECTION_FAILED / EXECUTION_FAILED;
  * a verified DETECTED requires real qualifying policy evidence (P>0) with
    valid provenance; the lab's custom telemetry rule is NOT qualifying;
  * every finding cites real event_ids + raw_refs (no invented references).
"""
from __future__ import annotations
import json
import os

from . import schema as S

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ENGINE_VERSION = "2.0.0"

FALCO_CUSTOM_RULE = "EBPF Lab Container Process Execution"


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def load_config(path=None):
    path = path or os.path.join(HERE, "engine_config.json")
    with open(path) as _fh:
        cfg = json.load(_fh)
    w = cfg["risk_weights"]
    total = round(w["wA"] + w["wS"] + w["wP"], 6)
    if total != 1.0 or min(w["wA"], w["wS"], w["wP"]) < 0:
        raise ValueError(f"invalid risk_weights (must be nonneg and sum to 1.0): {w} sum={total}")
    return cfg


# --------------------------------------------------------------------------- #
# behavior graph
# --------------------------------------------------------------------------- #
class BehaviorGraph:
    """Deterministic correlation of canonical events into process/file/network
    relationships. Unknown identities stay explicit; unrelated events are not
    correlated merely by time proximity."""

    def __init__(self, events):
        # stable ordering: by (timestamp string, event_id) — deterministic even
        # when timestamps are missing/sentinel (sorts sentinels together).
        self.events = sorted(events, key=lambda e: (str(e.get("timestamp")), e.get("event_id", "")))
        self.nodes = {}   # key -> node
        self.edges = []   # list of dicts
        self._build()

    def _proc_key(self, e):
        pid = e.get("pid")
        cid = e.get("container_id")
        if isinstance(pid, int) and isinstance(cid, str) and cid not in S.MISSING_SENTINELS:
            return f"proc:{cid[:12]}:{pid}"
        # identity gap -> explicit unknown key tied to the event, never merged
        return f"proc:unknown:{e.get('event_id')}"

    def _add_node(self, key, kind, label, ev):
        n = self.nodes.get(key)
        if not n:
            n = {"key": key, "kind": kind, "label": label,
                 "event_ids": [], "raw_refs": [], "identity_known": not key.startswith(("proc:unknown",))}
            self.nodes[key] = n
        n["event_ids"].append(ev.get("event_id"))
        n["raw_refs"].append(ev.get("raw_ref"))
        return n

    def _build(self):
        for e in self.events:
            ct = e.get("canonical_type")
            pkey = self._proc_key(e)
            self._add_node(pkey, "process", e.get("process_name"), e)
            # parent-child (only when both ids are concretely known)
            ppid = e.get("parent_pid")
            cid = e.get("container_id")
            if isinstance(ppid, int) and isinstance(cid, str) and cid not in S.MISSING_SENTINELS:
                parent_key = f"proc:{cid[:12]}:{ppid}"
                self.edges.append({"type": "parent_of", "src": parent_key, "dst": pkey,
                                   "event_id": e.get("event_id"), "raw_ref": e.get("raw_ref")})
            if ct == "file_open" or ct == "file_write":
                fp = e.get("file_path")
                if isinstance(fp, str) and fp not in S.MISSING_SENTINELS:
                    fkey = f"file:{fp}"
                    self._add_node(fkey, "file", fp, e)
                    self.edges.append({"type": "accessed", "src": pkey, "dst": fkey,
                                       "event_id": e.get("event_id"), "raw_ref": e.get("raw_ref")})
            if ct == "network_connect":
                dest = e.get("network_dest")
                dkey = f"net:{dest}"
                self._add_node(dkey, "network", str(dest), e)
                self.edges.append({"type": "connected", "src": pkey, "dst": dkey,
                                   "event_id": e.get("event_id"), "raw_ref": e.get("raw_ref")})

    def process_timeline(self):
        """Ordered exec timeline (process_exec events) with provenance."""
        out = []
        for e in self.events:
            if e.get("canonical_type") in ("process_exec",):
                out.append({"process": e.get("process_name"), "args": e.get("process_args"),
                            "pid": e.get("pid"), "timestamp": e.get("timestamp"),
                            "event_id": e.get("event_id"), "raw_ref": e.get("raw_ref")})
        return out

    def summary(self):
        kinds = {}
        for n in self.nodes.values():
            kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "node_kinds": kinds,
                "identity_gaps": sum(1 for n in self.nodes.values() if not n["identity_known"])}


# --------------------------------------------------------------------------- #
# anomaly baseline (fit ONLY on designated baseline data)
# --------------------------------------------------------------------------- #
def fit_anomaly_baseline(baseline_streams_events):
    """Frequency profile of process names + file paths observed in benign/baseline
    data. Used to decide what is 'rare'. Fitting is separate from evaluation."""
    procs, files = {}, {}
    for events in baseline_streams_events:
        for e in events:
            pn = e.get("process_name")
            if isinstance(pn, str) and pn not in S.MISSING_SENTINELS:
                procs[pn] = procs.get(pn, 0) + 1
            fp = e.get("file_path")
            if isinstance(fp, str) and fp not in S.MISSING_SENTINELS:
                files[fp] = files.get(fp, 0) + 1
    return {"process_names": procs, "file_paths": files,
            "n_streams": len(baseline_streams_events)}


def score_anomaly(events, baseline, cfg):
    """A in [0,1]. Anomalous = sensitive-path access, exec from suspicious dirs,
    or a process name never seen in baseline. Missing events cannot raise A."""
    if not events:
        return 0.0, []  # absence is NOT anomalous
    sens = set(cfg["anomaly"]["sensitive_paths"])
    susp_dirs = cfg["anomaly"]["suspicious_exec_dirs"]
    known_procs = baseline.get("process_names", {})
    anomalous = 0
    reasons = []
    for e in events:
        a_hit = False
        fp = e.get("file_path")
        if isinstance(fp, str) and fp in sens:
            a_hit = True
            reasons.append(("sensitive_path", fp, e.get("event_id")))
        pn = e.get("process_name")
        args = e.get("process_args")
        if e.get("canonical_type") == "process_exec" and isinstance(args, str):
            for d in susp_dirs:
                if d in args:
                    a_hit = True
                    reasons.append(("exec_from_suspicious_dir", d, e.get("event_id")))
                    break
        # A novel process name alone is NOT treated as anomalous (common benign
        # tools like echo/ls would be flagged on a small baseline). It is recorded
        # as context only; it does not raise the anomaly score by itself.
        if isinstance(pn, str) and pn not in S.MISSING_SENTINELS and known_procs and pn not in known_procs:
            reasons.append(("novel_process_context", pn, e.get("event_id")))
        if a_hit:
            anomalous += 1
    a = min(1.0, anomalous / max(1, len(events)) * 3.0)  # scale; capped at 1
    return round(a, 4), reasons


# --------------------------------------------------------------------------- #
# sequence patterns
# --------------------------------------------------------------------------- #
SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/ssh/ssh_host_rsa_key", "/etc/gshadow")


def detect_patterns(events, graph, cfg):
    """Return findings. Each finding = pattern name, severity, event_ids,
    raw_refs, explanation. Patterns require specific types+fields; they do NOT
    fire on a mere filename substring in an unrelated event."""
    findings = []

    def _mk(name, severity, evids, refs, text, mitre=None):
        return {"pattern": name, "severity": severity, "event_ids": evids,
                "raw_refs": refs, "explanation": text, "mitre": mitre or []}

    file_events = [e for e in events if e.get("canonical_type") in ("file_open", "file_write")]
    exec_events = [e for e in events if e.get("canonical_type") == "process_exec"]
    alert_events = [e for e in events if e.get("canonical_type") == "security_alert"]

    # P1 sensitive-file access
    sens_hits = [e for e in file_events if isinstance(e.get("file_path"), str)
                 and e["file_path"] in SENSITIVE]
    if sens_hits:
        findings.append(_mk("sensitive_file_access", 0.8,
                            [e["event_id"] for e in sens_hits],
                            [e["raw_ref"] for e in sens_hits],
                            f"Access to sensitive file(s): {sorted({e['file_path'] for e in sens_hits})}",
                            ["T1552.001", "T1555"]))

    # P2 sudoers modification (file op on /etc/sudoers*)
    sudo_hits = [e for e in file_events if isinstance(e.get("file_path"), str)
                 and "/etc/sudoers" in e["file_path"]]
    if sudo_hits:
        findings.append(_mk("sudoers_modification", 0.75,
                            [e["event_id"] for e in sudo_hits],
                            [e["raw_ref"] for e in sudo_hits],
                            "File operation on the sudoers configuration.", ["T1548.003"]))

    # P3 execution from a suspicious directory (drop-and-execute shape)
    susp = [e for e in exec_events if isinstance(e.get("process_args"), str)
            and any(d in e["process_args"] for d in cfg["anomaly"]["suspicious_exec_dirs"])]
    if susp:
        findings.append(_mk("exec_from_suspicious_dir", 0.7,
                            [e["event_id"] for e in susp], [e["raw_ref"] for e in susp],
                            "Process executed from a world-writable/temp directory.",
                            ["T1204", "T1059"]))

    # P4 nested shell chain: >=2 shell execs correlated by parent-of in the graph
    shells = [e for e in exec_events if e.get("process_name") in ("sh", "bash", "dash", "ash")]
    if len(shells) >= 2:
        # require a parent_of edge among shells to avoid counting unrelated shells
        shell_keys = {graph._proc_key(e) for e in shells}
        chained = any(edge["type"] == "parent_of" and edge["src"] in shell_keys and edge["dst"] in shell_keys
                      for edge in graph.edges)
        severity = 0.45 if chained else 0.3
        findings.append(_mk("nested_shell_execution", severity,
                            [e["event_id"] for e in shells], [e["raw_ref"] for e in shells],
                            f"{len(shells)} shell executions"
                            + (" with a parent-child chain." if chained else " (chain not established from available fields)."),
                            ["T1059.004"]))

    # P5 discovery sequence: several discovery tools in one stream
    disc_tools = {"id", "uname", "hostname", "whoami", "ps", "cat"}
    disc = [e for e in exec_events if e.get("process_name") in disc_tools]
    distinct = {e.get("process_name") for e in disc}
    if len(distinct) >= 3:
        findings.append(_mk("discovery_sequence", 0.4,
                            [e["event_id"] for e in disc], [e["raw_ref"] for e in disc],
                            f"Host/container discovery commands observed: {sorted(distinct)}",
                            ["T1082", "T1033"]))

    return findings


def score_sequence(findings):
    """S in [0,1] = max severity among triggered patterns (0 if none)."""
    if not findings:
        return 0.0
    return round(max(f["severity"] for f in findings), 4)


# --------------------------------------------------------------------------- #
# policy evidence
# --------------------------------------------------------------------------- #
def score_policy(events):
    """P in [0,1]. 1.0 iff a REAL qualifying security alert is present (Falco
    built-in rule or Tracee behavioral signature). The lab's custom process-exec
    Notice rule is NOT qualifying. Returns (P, qualifying_events)."""
    qualifying = []
    for e in events:
        if e.get("canonical_type") != "security_alert":
            continue
        native = e.get("sensor_native_event")
        if native == FALCO_CUSTOM_RULE:
            continue  # telemetry-grade, not a detection
        qualifying.append(e)
    return (1.0 if qualifying else 0.0), qualifying


# --------------------------------------------------------------------------- #
# visibility + verdict
# --------------------------------------------------------------------------- #
def assess_visibility(stream_meta, events):
    """Return (visibility_status, warnings). Separate from detection."""
    warnings = []
    cstatus = str(stream_meta.get("collection_status", "")).lower()
    if cstatus.startswith("collection_failed"):
        return "COLLECTION_FAILED", ["sensor captured no scoped events for a verified execution"]
    if cstatus.startswith("execution_failed"):
        return "EXECUTION_FAILED", ["workload did not execute successfully"]
    if not events:
        return "NO_EVENTS", ["no normalized events in this stream"]
    # partial if a large share of events have identity gaps
    gaps = sum(1 for e in events if not (isinstance(e.get("container_id"), str)
               and e.get("container_id") not in S.MISSING_SENTINELS))
    if gaps and gaps / len(events) > 0.5:
        warnings.append(f"{gaps}/{len(events)} events lack a concrete container id (partial attribution)")
        return "PARTIAL", warnings
    return "FULL", warnings


def compute_verdict(visibility, P, S_sig, risk, cfg):
    """Visibility-aware verdict. A high risk score NEVER overrides a failure."""
    if visibility == "EXECUTION_FAILED":
        return "EXECUTION_FAILED", "workload execution failed; detection not evaluable"
    if visibility == "COLLECTION_FAILED":
        return "COLLECTION_FAILED", "collection failed; a risk score cannot promote this to a detection"
    if visibility == "NO_EVENTS":
        return "INCONCLUSIVE", "no events captured; cannot conclude detection or absence"
    if P > 0:
        return "DETECTED", "verified qualifying policy evidence present"
    if S_sig > 0 or risk >= cfg["thresholds"]["risk_suspicious"]:
        return "TELEMETRY_ONLY", "suspicious behavior observed as telemetry but no qualifying detection fired"
    if visibility == "FULL":
        return "NOT_DETECTED", "execution + full visibility + no suspicious pattern or qualifying alert"
    return "INCONCLUSIVE", "partial visibility and no qualifying evidence"


def risk_band(risk, cfg):
    if risk >= cfg["thresholds"]["risk_high"]:
        return "HIGH"
    if risk >= cfg["thresholds"]["risk_suspicious"]:
        return "SUSPICIOUS"
    return "LOW"


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def run_engine(events, stream_meta, baseline, cfg):
    """Core entry: produce an EngineResult for one stream (one sensor's view of
    one trial). Deterministic."""
    graph = BehaviorGraph(events)
    A, a_reasons = score_anomaly(events, baseline, cfg)
    findings = detect_patterns(events, graph, cfg)
    S_sig = score_sequence(findings)
    P, qualifying = score_policy(events)
    w = cfg["risk_weights"]
    risk = round(100 * (w["wA"] * A + w["wS"] * S_sig + w["wP"] * P), 2)

    visibility, vwarn = assess_visibility(stream_meta, events)
    verdict, vreason = compute_verdict(visibility, P, S_sig, risk, cfg)

    # supporting event ids (deduped, ordered) + policy evidence
    support = []
    for f in findings:
        support.extend(f["event_ids"])
    for q in qualifying:
        support.append(q["event_id"])
    support = list(dict.fromkeys(support))

    # time window from available sensor_native timestamps
    ts = [e["timestamp"] for e in events
          if isinstance(e.get("timestamp"), str) and e["timestamp"] not in S.MISSING_SENTINELS]
    time_window = {"start": min(ts), "end": max(ts)} if ts else {"start": None, "end": None}

    explanations = build_explanations(verdict, vreason, findings, qualifying, visibility, vwarn)

    return {
        "engine_version": ENGINE_VERSION,
        "schema_version": S.SCHEMA_VERSION,
        "config_version": cfg["config_version"],
        "trial_id": stream_meta.get("trial_id"),
        "stream": stream_meta.get("stream"),
        "sensor": stream_meta.get("sensor"),
        "scenario_id": stream_meta.get("scenario_id"),
        "capture_mode": stream_meta.get("capture_mode"),
        "visibility_status": visibility,
        "verdict": verdict,
        "verdict_reason": vreason,
        "risk_score": risk,
        "risk_band": risk_band(risk, cfg),
        "component_scores": {"A_anomaly": A, "S_sequence": S_sig, "P_policy": P,
                             "weights": {"wA": w["wA"], "wS": w["wS"], "wP": w["wP"]}},
        "findings": findings,
        "qualifying_policy_events": [
            {"event_id": q["event_id"], "native_event": q["sensor_native_event"],
             "raw_ref": q["raw_ref"]} for q in qualifying],
        "supporting_event_ids": support,
        "graph_summary": graph.summary(),
        "process_timeline": graph.process_timeline(),
        "anomaly_reasons": [{"kind": k, "value": v, "event_id": ev} for k, v, ev in a_reasons],
        "explanations": explanations,
        "warnings": vwarn,
        "time_window": time_window,
        "event_count": len(events),
    }


def build_explanations(verdict, vreason, findings, qualifying, visibility, vwarn):
    out = [f"Verdict {verdict}: {vreason}."]
    out.append(f"Visibility: {visibility}." + ("" if not vwarn else " " + " ".join(vwarn)))
    for f in findings:
        out.append(f"Pattern '{f['pattern']}' (severity {f['severity']}): {f['explanation']} "
                   f"[events: {', '.join(f['event_ids'][:5])}{'…' if len(f['event_ids'])>5 else ''}]")
    for q in qualifying:
        rr = q.get("raw_ref", {})
        out.append(f"Qualifying policy evidence: '{q['sensor_native_event']}' "
                   f"(event {q['event_id']}, source {rr.get('file')}:{rr.get('line')}).")
    if verdict in ("COLLECTION_FAILED", "EXECUTION_FAILED", "INCONCLUSIVE"):
        out.append("Note: missing events are NOT treated as evidence that the behavior did not occur.")
    return out
