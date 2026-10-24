#!/usr/bin/env python3
"""
analyze.py — reproducible analysis over the normalized results.

Reads results/normalized/results.json and experiments/catalog.json (+ run
manifests). Writes results/analysis/analysis.json and results/runs.json.

Integrity rules enforced here:
  * Detection rates are computed ONLY over eligible evaluations (tested cells of
    that tool), never the full grid. not_tested/not_applicable are excluded.
  * Unknown values are null / "unknown", never silently 0.
  * Latency is reported only where a numeric measurement exists.
  * Nothing manufactures an "evasion rate" from missing data.
  * Repeatability (E06) is described (individual trials + whether identical), not
    turned into a significance claim.

Run:  python3 -I scripts/analyze.py
"""
import json
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NORM = os.path.join(REPO, "results", "normalized", "results.json")
CATALOG = os.path.join(REPO, "experiments", "catalog.json")
RUNS_DIR = os.path.join(REPO, "results", "runs")
OUT_DIR = os.path.join(REPO, "results", "analysis")

TOOLS = ["falco", "tracee", "tetragon"]


def load(p):
    with open(p) as f:
        return json.load(f)


def read_raw(eid, tool):
    p = os.path.join(REPO, "results", "raw", f"{eid}_{tool}.json")
    return load(p) if os.path.exists(p) else None


def main():
    catalog = load(CATALOG)
    data = load(NORM)
    records = data["records"]
    by = {(r["experiment_id"], r["tool"]): r for r in records}
    exps = [e for e in catalog["experiments"] if not e.get("derived")]
    all_exps = catalog["experiments"]
    eids = [e["id"] for e in exps]

    # --- Experiment x detector matrix ---
    matrix = []
    for e in exps:
        row = {"experiment_id": e["id"], "title": e["title"],
               "behavior": e["behavior"], "variant": e["variant"],
               "tools_in_scope": e["tools"], "cells": {}}
        for t in TOOLS:
            r = by.get((e["id"], t))
            if r:
                row["cells"][t] = {
                    "status": r["status"],
                    "detection_type": r["detection_type"],
                    "event_observed": r["event_observed"],
                    "context_enriched": r["context_enriched"],
                    "rule_class": r["rule_class"],
                    "provenance": r["provenance"],
                    "dimensions": r["dimensions"],
                }
            elif t in e["tools"]:
                row["cells"][t] = {"status": "not_tested"}
            else:
                row["cells"][t] = {"status": "not_applicable"}
        matrix.append(row)

    # --- Detection vs telemetry (per tool, eligible cells only) ---
    det_vs_tel = {}
    for t in TOOLS:
        cells = [r for r in records if r["tool"] == t and r["status"] != "not_tested"]
        detections = [c for c in cells if c["status"] == "confirmed_detection"]
        telemetry = [c for c in cells if c["event_observed"]]
        det_vs_tel[t] = {
            "eligible_evaluations": len(cells),
            "confirmed_detections": len(detections),
            "telemetry_observed": len(telemetry),
            "partial": len([c for c in cells if c["status"] == "partial"]),
            "confirmed_miss": len([c for c in cells if c["status"] == "confirmed_miss"]),
            "detection_rate": round(len(detections) / len(cells), 3) if cells else None,
            "telemetry_rate": round(len(telemetry) / len(cells), 3) if cells else None,
            "has_alerting_engine": catalog["detectors"][t]["has_alerting_engine"],
        }

    # --- Baseline vs adaptive ---
    baseline_adaptive = []
    for e in exps:
        ref = e.get("baseline_reference")
        if not ref:
            continue
        cmp = {"adaptive_id": e["id"], "adaptive_title": e["title"],
               "variant": e["variant"], "baseline_id": ref, "tools": {}}
        for t in TOOLS:
            b = by.get((ref, t))
            a = by.get((e["id"], t))
            if not (b and a):
                continue
            cmp["tools"][t] = {
                "baseline_status": b["status"],
                "adaptive_status": a["status"],
                "baseline_processes": b["processes_observed"],
                "adaptive_processes": a["processes_observed"],
                "observability_change": (
                    "unchanged" if b["event_observed"] == a["event_observed"]
                    else ("reduced" if b["event_observed"] and not a["event_observed"]
                          else "increased")),
            }
        baseline_adaptive.append(cmp)

    # --- Data completeness (grid = experiments in scope x tools in scope) ---
    grid_cells = sum(len(e["tools"]) for e in exps)
    tested = [r for r in records if r["status"] != "not_tested"]
    completeness = {
        "experiments_defined": len(all_exps),
        "experiments_evaluated": len(exps),
        "derived_experiments": len(all_exps) - len(exps),
        "detectors": len(TOOLS),
        "grid_cells": grid_cells,
        "evaluated_cells": len(tested),
        "not_tested_cells": grid_cells - len(tested),
        "coverage_fraction": round(len(tested) / grid_cells, 3) if grid_cells else None,
        "cells_with_evidence_file": len([r for r in records if r["evidence_raw"]]),
        "cells_with_event_evidence": len([r for r in records if r["evidence_events"]]),
        "live_cells": len([r for r in records if r["provenance"] == "live"]),
        "recorded_cells": len([r for r in records if r["provenance"] == "recorded"]),
    }

    # --- Evidence coverage per experiment ---
    evidence_coverage = []
    for e in exps:
        tools_with_evidence = [t for t in e["tools"]
                               if (e["id"], t) in by and by[(e["id"], t)]["evidence_raw"]]
        evidence_coverage.append({
            "experiment_id": e["id"],
            "tools_defined": e["tools"],
            "tools_with_evidence": tools_with_evidence,
            "complete": sorted(tools_with_evidence) == sorted(e["tools"]),
        })

    # --- Latency (real measurements only) ---
    latencies = [r["latency_ms"] for r in records
                 if isinstance(r.get("latency_ms"), (int, float))]
    latency_summary = {
        "measurements_available": len(latencies),
        "note": ("No valid detection-latency measurements were recorded in this dataset. "
                 "Latency is intentionally reported as unavailable rather than fabricated.")
        if not latencies else "Latency measurements present.",
        "values_ms": latencies or None,
    }

    # --- Cross-tool status counts ---
    cross_tool = {}
    for t in TOOLS:
        counts = {}
        for r in records:
            if r["tool"] == t:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
        cross_tool[t] = counts

    # --- E06 repeatability ---
    e06 = read_raw("E06", "tetragon")
    e06_summary = None
    if e06:
        e06_summary = {
            "trial_count": e06.get("trial_count"),
            "distinct_process_chains": e06.get("distinct_process_chains"),
            "distinct_exec_counts": e06.get("distinct_exec_counts"),
            "repeatable": e06.get("repeatable"),
            "trials": e06.get("trials"),
            "caveat": "Small-n exploratory evidence; descriptive only, no statistical significance.",
        }

    # --- E07 sensitive vs benign ---
    e07 = read_raw("E07", "tetragon")
    e07_summary = e07.get("comparison") if e07 else None

    # --- E08 network policy coverage ---
    e08 = read_raw("E08", "tetragon")
    e08_summary = None
    if e08:
        tracee_e03 = read_raw("E03", "tracee")
        e08_summary = {
            "tetragon": {
                "process_telemetry": e08.get("processes_detected"),
                "network_detection_status": e08.get("network_detection_status"),
                "policy": e08.get("policy_coverage"),
            },
            "tracee_reference_E03": {
                "network_telemetry": bool(tracee_e03 and tracee_e03.get("network_connection_detection")),
                "note": "Tracee (E03) captured the connect to :443 — network telemetry observed.",
            },
            "falco_reference_E03": {
                "network_detection_status": "not_evaluated",
                "note": "Falco's E03 alert was process-exec; no network rule verified.",
            },
        }

    # --- E09 derived sequence/timing comparison (from E02/E04/E05) ---
    e09 = next((e for e in all_exps if e["id"] == "E09"), None)
    e09_summary = None
    if e09:
        rows = []
        for ref in e09.get("derived_from", []):
            tref = next((x for x in all_exps if x["id"] == ref), None)
            per_tool = {}
            for t in TOOLS:
                r = by.get((ref, t))
                if r:
                    per_tool[t] = {
                        "processes": r["processes_observed"],
                        "status": r["status"],
                        "event_observed": r["event_observed"],
                    }
            rows.append({
                "experiment_id": ref,
                "variant": tref["variant"] if tref else None,
                "per_tool": per_tool,
            })
        e09_summary = {
            "rows": rows,
            "observation": ("Process chain changes across variants "
                            "(sh,id -> sh,sh,id -> sh,sleep,sleep,id) while every stage "
                            "remained observable in all tools."),
            "limitation": ("Describes observability across controlled variants. Does NOT "
                           "establish evasion: no stage disappeared from any tool's capture."),
        }

    analysis = {
        "generated_from": "results/normalized/results.json via scripts/analyze.py",
        "matrix": matrix,
        "detection_vs_telemetry": det_vs_tel,
        "baseline_vs_adaptive": baseline_adaptive,
        "data_completeness": completeness,
        "evidence_coverage": evidence_coverage,
        "latency_summary": latency_summary,
        "cross_tool_status_counts": cross_tool,
        "e06_repeatability": e06_summary,
        "e07_sensitive_vs_benign": e07_summary,
        "e08_network_coverage": e08_summary,
        "e09_sequence_timing": e09_summary,
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "analysis.json"), "w") as f:
        f.write(json.dumps(analysis, indent=2) + "\n")

    # --- runs.json index (live manifests + recorded synthetic) ---
    runs = []
    for r in records:
        runs.append({
            "run_id": r["run_id"],
            "experiment_id": r["experiment_id"],
            "tool": r["tool"],
            "provenance": r["provenance"],
            "status": r["status"],
            "started_at": r["started_at"],
            "ended_at": r["ended_at"],
            "evidence_raw": r["evidence_raw"],
            "evidence_events": r["evidence_events"],
            "processes_observed": r["processes_observed"],
        })
    runs.sort(key=lambda x: (x["provenance"] != "live", x["experiment_id"], x["tool"]))
    with open(os.path.join(REPO, "results", "runs.json"), "w") as f:
        f.write(json.dumps({"runs": runs}, indent=2) + "\n")

    print(f"wrote results/analysis/analysis.json + results/runs.json")
    print(f"  coverage: {len(tested)}/{grid_cells} cells; "
          f"{completeness['live_cells']} live, {completeness['recorded_cells']} recorded")
    for t in TOOLS:
        d = det_vs_tel[t]
        print(f"  {t:9} detections={d['confirmed_detections']} "
              f"telemetry={d['telemetry_observed']} eligible={d['eligible_evaluations']}")


if __name__ == "__main__":
    main()
