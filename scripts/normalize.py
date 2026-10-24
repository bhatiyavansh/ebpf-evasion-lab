#!/usr/bin/env python3
"""
normalize.py — canonical normalization for the Adaptive eBPF Security Lab.

Reads:
  experiments/catalog.json           (definitions, single source of truth)
  results/raw/<EID>_<tool>.json      (raw evidence per experiment/tool)

Writes:
  results/normalized/results.json    (array of normalized records)
  results/summary.csv                (flat CSV generated FROM the normalized data)

Scientific-integrity contract (see README "Status model"):
  The status of every cell is derived here by explicit, auditable rules, never
  copied blindly from a raw `detected` boolean. The six concepts the lab tracks:

    confirmed_detection  a security-relevant rule/policy fired on the behavior
    telemetry_observed   a relevant kernel event was captured (no alert verdict)
    partial              some evidence exists but the targeted claim is not
                         established (e.g. process telemetry but no network det.)
    not_tested           no raw result file exists for this experiment/tool
    confirmed_miss       the event was observed but an expected detection failed

  `context_enriched` (container metadata attached) is recorded as a separate
  boolean attribute, not a mutually-exclusive status.

Tool semantics are explicit:
  - Falco has an alerting engine. A rule firing is a detection. We additionally
    record whether the rule is a BUILT-IN security rule or this lab's CUSTOM
    research rule, because "a custom rule firing is not proof that a built-in
    security policy detected malicious behavior."
  - Tracee and Tetragon are configured here as telemetry collectors only (no
    signatures / no alerting). Their events are therefore telemetry_observed,
    never confirmed_detection, regardless of any `detected` field in raw JSON.

Run:  python3 -I scripts/normalize.py
"""
import csv
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(REPO, "results", "raw")
NORM_DIR = os.path.join(REPO, "results", "normalized")
CATALOG = os.path.join(REPO, "experiments", "catalog.json")

STATUS = {
    "confirmed_detection": "Confirmed detection",
    "telemetry_observed": "Telemetry observed",
    "partial": "Partial evidence",
    "not_tested": "Not tested",
    "confirmed_miss": "Confirmed miss",
}


def read_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def raw_path(eid, tool):
    return os.path.join(RAW, f"{eid}_{tool}.json")


def load_manifest(eid, tool):
    """Live-run manifest for a tetragon capture, if one exists."""
    if tool != "tetragon":
        return None
    p = os.path.join(REPO, "results", "runs", f"{eid}.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    return None


def run_metadata(eid, tool, raw, env):
    """Provenance, run id, timestamps, tool version — real where available."""
    mani = load_manifest(eid, tool)
    if mani:
        return {
            "run_id": mani.get("run_id"),
            "provenance": "live",
            "started_at": mani.get("started_at"),
            "ended_at": mani.get("ended_at"),
            "tool_version": mani.get("tool_version"),
        }
    # Recorded evidence: stable synthetic run id; timestamp from env capture.
    return {
        "run_id": f"rec-{eid}-{tool}",
        "provenance": "recorded",
        "started_at": (env or {}).get("captured_at"),
        "ended_at": (env or {}).get("captured_at"),
        "tool_version": (env or {}).get("detectors", {}).get(tool),
    }


def derive_dimensions(tool, eid, raw, status, detectors):
    """Four independent status dimensions (see README status model)."""
    event_observed = bool(raw.get("event_observed"))
    processes = raw.get("processes_detected") or None
    has_engine = detectors[tool]["has_alerting_engine"]

    cstatus = str(raw.get("collection_status", "complete"))
    coll_failed = cstatus.startswith("collection_failed")
    # execution: a collection failure here still had a verified workload exec
    execution = "completed" if (event_observed or processes or raw.get("workload_exit_code") == "0") else "failed"
    collection = "failed" if coll_failed else (
        "complete" if event_observed else ("partial" if processes else "failed"))
    telemetry = "observed" if event_observed else "not_observed"

    if not has_engine:
        detection = "not_evaluated"      # telemetry-only tool, no alerting engine
    elif status == "confirmed_detection":
        detection = "detected"
    elif status == "partial" and eid in ("E03",):
        detection = "not_evaluated"      # network-specific detection not configured
    elif status == "confirmed_miss":
        detection = "not_detected"
    else:
        detection = "not_evaluated"
    return {
        "execution": execution,
        "collection": collection,
        "telemetry": telemetry,
        "detection": detection,
    }


def classify(eid, tool, exp, raw, detectors):
    """Return a normalized record dict. All reasoning is explicit here."""
    rel_raw = os.path.relpath(raw_path(eid, tool), REPO) if raw else None

    base = {
        "experiment_id": eid,
        "tool": tool,
        "behavior": exp["behavior"],
        "variant": exp["variant"],
        "status": "not_tested",
        "status_label": STATUS["not_tested"],
        "detected": None,
        "event_observed": False,
        "containerized": False,
        "context_enriched": False,
        "detection_type": None,
        "rule_class": None,
        "alert_count": None,
        "latency_ms": None,
        "processes_observed": None,
        "evidence_raw": None,
        "evidence_events": None,
        "confidence": "n/a",
        "run_id": None,
        "provenance": None,
        "started_at": None,
        "ended_at": None,
        "tool_version": None,
        "dimensions": None,
        "notes": "",
        "interpretation": "",
    }

    if raw is None:
        base["interpretation"] = (
            f"No raw result file exists for {tool} on {eid}; this combination has "
            f"not been evaluated."
        )
        return base

    notes = raw.get("notes", "") or ""
    processes = raw.get("processes_detected") or None
    containerized = bool(raw.get("containerized"))
    event_observed = bool(raw.get("event_observed"))
    detection_type = raw.get("detection_type")
    alert_count = raw.get("alert_count")
    context_enriched = containerized and (
        bool(processes) or "enrich" in notes.lower() or "metadata" in notes.lower()
        or bool(raw.get("container_cgroup_ids"))
    )

    base.update({
        "detected": raw.get("detected"),
        "event_observed": event_observed,
        "containerized": containerized,
        "context_enriched": context_enriched,
        "detection_type": detection_type,
        "alert_count": alert_count,
        "latency_ms": raw.get("latency_ms"),
        "processes_observed": processes,
        "evidence_raw": rel_raw,
        "evidence_events": raw.get("evidence_events"),
        "notes": notes,
    })

    has_engine = detectors[tool]["has_alerting_engine"]

    # ---- Telemetry-only tools: Tracee, Tetragon ----
    if not has_engine:
        # Collection failure: workload executed but the sensor captured nothing
        # for the container. Never report this as telemetry or a detector miss.
        cstatus = raw.get("collection_status", "complete")
        if str(cstatus).startswith("collection_failed") or (not event_observed and str(cstatus) != "complete"):
            base["status"] = "collection_failed"
            base["status_label"] = "Collection failed"
            base["confidence"] = "n/a"
            base["interpretation"] = (
                raw.get("collection_note")
                or f"{detectors[tool]['label']} did not capture events for a verified execution "
                   f"(collection failure, not a detector miss and not telemetry)."
            )
            return base
        base["status"] = "telemetry_observed"
        base["confidence"] = "high" if event_observed else "low"
        # E03 network sub-claim: is connection visibility established?
        if eid == "E03":
            net = raw.get("network_connection_detection")
            if net is True:
                base["interpretation"] = (
                    f"{detectors[tool]['label']} captured socket-level connect telemetry "
                    f"(network visibility established) in addition to process execution. "
                    f"Telemetry only — no alert verdict."
                )
            else:
                base["interpretation"] = (
                    f"{detectors[tool]['label']} captured process-execution telemetry but no "
                    f"network-connection event (no network source configured). Network-specific "
                    f"visibility is NOT established here."
                )
        else:
            base["interpretation"] = (
                f"{detectors[tool]['label']} captured kernel telemetry for this behavior "
                f"({detection_type or 'event set'}). This is observability, not a security "
                f"detection — no alerting engine evaluated the events."
            )
        return base

    # ---- Falco: alerting engine present ----
    detected = raw.get("detected") is True
    # Built-in vs custom research rule.
    is_builtin_security = eid == "E01" and "sensitive file" in notes.lower()
    base["rule_class"] = (
        "builtin_security" if is_builtin_security
        else ("custom_research" if detected else None)
    )

    # E03 special case: the fired rule is process-execution, not network.
    if eid == "E03" and raw.get("network_connection_detection") is False:
        base["status"] = "partial"
        base["confidence"] = "medium"
        base["interpretation"] = (
            "Falco's process-execution rule fired, but no network-specific rule detected the "
            "connection. Process telemetry is established; network-connection detection is NOT."
        )
        return base

    if detected and is_builtin_security:
        base["status"] = "confirmed_detection"
        base["confidence"] = "high"
        base["interpretation"] = (
            "Falco's BUILT-IN rule 'Sensitive file opened for reading by non-trusted program' "
            "fired on /etc/shadow — a genuine security detection by a shipped policy."
        )
        return base

    if detected:
        base["status"] = "confirmed_detection"
        base["confidence"] = "medium"
        base["interpretation"] = (
            "A Falco rule fired on every execution event. NOTE: this is the lab's CUSTOM "
            "process-execution research rule (EBPF_LAB), not a built-in malicious-behavior "
            "policy — it confirms process-execution detectability, not a threat verdict."
        )
        return base

    # Rule engine present but nothing fired, yet event was observed -> miss.
    if event_observed:
        base["status"] = "confirmed_miss"
        base["confidence"] = "high"
        base["interpretation"] = (
            "The event was observed but no Falco rule fired — a confirmed detection miss "
            "under the configured ruleset."
        )
        return base

    base["status"] = "not_tested"
    base["interpretation"] = "Insufficient evidence to classify."
    return base


def main():
    catalog = read_json(CATALOG)
    detectors = catalog["detectors"]
    env = read_json(os.path.join(REPO, "results", "env", "environment.json"))
    records = []
    for exp in catalog["experiments"]:
        if exp.get("derived"):
            continue  # derived experiments (e.g. E09) are computed in analyze.py
        eid = exp["id"]
        for tool in exp["tools"]:
            raw = read_json(raw_path(eid, tool))
            rec = classify(eid, tool, exp, raw, detectors)
            rec.update(run_metadata(eid, tool, raw or {}, env))
            if raw is not None:
                rec["dimensions"] = derive_dimensions(
                    tool, eid, {**raw, "evidence_raw": rec["evidence_raw"]},
                    rec["status"], detectors)
            else:
                rec["dimensions"] = {"execution": "not_run", "collection": "n/a",
                                     "telemetry": "n/a", "detection": "n/a"}
            records.append(rec)

    os.makedirs(NORM_DIR, exist_ok=True)
    out = os.path.join(NORM_DIR, "results.json")
    with open(out, "w") as f:
        f.write(json.dumps({
            "generated_from": "results/raw/*.json via scripts/normalize.py",
            "catalog": "experiments/catalog.json",
            "records": records,
        }, indent=2) + "\n")
    print(f"wrote {os.path.relpath(out, REPO)}  ({len(records)} records)")

    # Canonical CSV generated from normalized data.
    csv_path = os.path.join(REPO, "results", "summary.csv")
    cols = ["experiment_id", "tool", "behavior", "variant", "status",
            "detected", "event_observed", "containerized", "context_enriched",
            "detection_type", "rule_class", "latency_ms", "alert_count",
            "evidence_raw", "notes"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = dict(r)
            if isinstance(row.get("processes_observed"), list):
                row["processes_observed"] = "|".join(row["processes_observed"])
            w.writerow(row)
    print(f"wrote {os.path.relpath(csv_path, REPO)}  ({len(records)} rows)")


if __name__ == "__main__":
    main()
