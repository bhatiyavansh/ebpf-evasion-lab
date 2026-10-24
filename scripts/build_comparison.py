#!/usr/bin/env python3
"""
build_comparison.py — deterministic classification of the fair detection
comparison study from REAL captured evidence (A-series run manifests).

Outcome model (per tool-scenario-config, aggregated over trials):
  DETECTED, TELEMETRY_ONLY, NOT_DETECTED, NOT_EVALUATED,
  EXECUTION_FAILED, COLLECTION_FAILED, INCONCLUSIVE.

Classification is deterministic and based on the predefined qualifying-detection
criteria in experiments/comparison_catalog.json. No LLM decides outcomes.

Writes results/analysis/comparison.json.
Run:  python3 -I scripts/build_comparison.py
"""
import json
import os
import glob

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(REPO, "results", "runs")
CAT = os.path.join(REPO, "experiments", "comparison_catalog.json")
OUT = os.path.join(REPO, "results", "analysis", "comparison.json")

SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/ssh/ssh_host_rsa_key")

# (tool key in files, display, config label, catalog track key)
TRACKS = [
    ("falco", "Falco", "configured", "falco"),
    ("tracee", "Tracee", "baseline", "tracee"),
    ("tetB", "Tetragon", "baseline", "tetragon_baseline"),
    ("tetC", "Tetragon", "configured", "tetragon_configured"),
]


def load(p):
    return json.load(open(p)) if os.path.exists(p) else None


def manifest_path(scenario, tkey, trial):
    if tkey == "falco":
        return os.path.join(RUNS, f"{scenario}_falco_t{trial}_falco.json")
    if tkey == "tracee":
        return os.path.join(RUNS, f"{scenario}_tracee_t{trial}_tracee.json")
    # tetragon baseline/configured use the tetragon capture naming (results/runs/<label>.json)
    return os.path.join(RUNS, f"{scenario}_tet{tkey[-1]}_t{trial}.json")


def discover_trials(scenario, tkey):
    """Return the sorted list of trial numbers that actually have a manifest on
    disk, so the number of trials is driven by real evidence, not hardcoded."""
    if tkey == "falco":
        pat = os.path.join(RUNS, f"{scenario}_falco_t*_falco.json")
    elif tkey == "tracee":
        pat = os.path.join(RUNS, f"{scenario}_tracee_t*_tracee.json")
    else:
        pat = os.path.join(RUNS, f"{scenario}_tet{tkey[-1]}_t*.json")
    import re
    nums = []
    for p in glob.glob(pat):
        base = os.path.basename(p)
        # the trial token is _t<digits> (e.g. _t4); avoid matching "_tracee"
        m = re.search(r"_t(\d+)(?:_|\.)", base)
        if m:
            nums.append(int(m.group(1)))
    return sorted(set(nums))


def classify_trial(scenario, tkey, m):
    """Return (outcome, detail) for a single trial manifest."""
    if m is None:
        return "EXECUTION_FAILED", "no run manifest (capture did not complete)"
    # execution: did the workload container run?
    if not m.get("container_id"):
        return "EXECUTION_FAILED", "workload container id missing"

    if tkey == "falco":
        qual = m.get("qualifying_detections", [])
        notices = m.get("custom_rule_notices", [])
        if m.get("total_alerts", 0) == 0 and not notices:
            # Falco up but no events at all -> collection suspicious
            return "COLLECTION_FAILED", "Falco produced no alerts for the run window"
        if qual:
            rules = ", ".join(sorted({d["rule"] for d in qual}))
            mitre = sorted({t for d in qual for t in d.get("mitre", [])})
            return "DETECTED", f"built-in rule fired: {rules} {mitre}"
        return "TELEMETRY_ONLY", "only the custom process-execution Notice rule fired (telemetry-grade)"

    if tkey == "tracee":
        n = m.get("scoped_event_count", 0)
        if n == 0:
            return "COLLECTION_FAILED", "no scoped Tracee events captured"
        sigs = m.get("signature_detections") or {}
        if sigs:
            names = ", ".join(sorted(sigs))
            return "DETECTED", f"Tracee behavioral signature fired: {names}"
        if m.get("matched_policies"):
            return "DETECTED", f"matched policy: {m['matched_policies']}"
        return "TELEMETRY_ONLY", f"{n} telemetry events, no qualifying signature fired"

    if tkey == "tetB":
        ec = m.get("event_counts", {})
        if (ec.get("process_exec", 0) + ec.get("openat_kprobe", 0)) == 0:
            return "COLLECTION_FAILED", "no scoped Tetragon telemetry captured"
        return "TELEMETRY_ONLY", "generic tracing-policy telemetry (no selective detection policy)"

    if tkey == "tetC":
        paths = m.get("openat_paths", [])
        hit = [p for p in paths if p in SENSITIVE]
        # selective policy emits ONLY on sensitive paths; a match == detection
        if hit:
            return "DETECTED", f"selective sensitive-file policy matched: {hit}"
        # policy loaded but no sensitive open in this run
        ec = m.get("event_counts", {})
        if ec.get("process_exec", 0) > 0:
            return "NOT_DETECTED", "exec telemetry present but selective policy did not match a sensitive path"
        return "COLLECTION_FAILED", "no scoped Tetragon events captured"

    return "INCONCLUSIVE", "unknown track"


AGG_PRIORITY = ["EXECUTION_FAILED", "COLLECTION_FAILED", "INCONCLUSIVE",
                "NOT_EVALUATED", "NOT_DETECTED", "TELEMETRY_ONLY", "DETECTED"]


def aggregate(trial_outcomes):
    """Aggregate per-trial outcomes into a headline + per-trial breakdown."""
    counts = {}
    for o, _ in trial_outcomes:
        counts[o] = counts.get(o, 0) + 1
    # Headline = the most frequent; ties broken by AGG_PRIORITY (prefer stronger signal).
    best = max(counts.items(), key=lambda kv: (kv[1], AGG_PRIORITY.index(kv[0]) if kv[0] in AGG_PRIORITY else -1))
    headline = best[0]
    # Consistency: detected in N of M trials
    det = counts.get("DETECTED", 0)
    return headline, counts, det


def main():
    cat = json.load(open(CAT))
    scenarios = []
    for sc in cat["scenarios"]:
        sid = sc["id"]
        row = {**{k: sc[k] for k in ("id", "title", "mitre", "technique_note",
                                     "payload", "hypothesis", "success_criteria",
                                     "detection_objective")},
               "cells": {}}
        for tkey, disp, cfg, catkey in TRACKS:
            if catkey not in sc["tracks"]:
                continue
            trial_nums = discover_trials(sid, tkey)
            # Skip tracks that were never run for this scenario (e.g. Tetragon on
            # A5-A7, excluded due to the live-capture regression) — do not invent
            # EXECUTION_FAILED rows for runs that were intentionally not attempted.
            if not trial_nums:
                continue
            trial_outcomes = []
            trials_detail = []
            for trial in trial_nums:
                m = load(manifest_path(sid, tkey, trial))
                outcome, detail = classify_trial(sid, tkey, m)
                trial_outcomes.append((outcome, detail))
                trials_detail.append({
                    "trial": trial, "outcome": outcome, "detail": detail,
                    "run_id": (m or {}).get("run_id"),
                    "evidence_events": (m or {}).get("evidence_events"),
                    "started_at": (m or {}).get("started_at"),
                })
            headline, counts, det = aggregate(trial_outcomes)
            executed = sum(1 for o, _ in trial_outcomes if o not in ("EXECUTION_FAILED",))
            # valid trials = executed AND collection not failed AND not inconclusive
            valid = sum(1 for o, _ in trial_outcomes
                        if o in ("DETECTED", "TELEMETRY_ONLY", "NOT_DETECTED"))
            row["cells"][f"{tkey}"] = {
                "tool": disp, "config": cfg, "track_key": catkey,
                "headline_outcome": headline,
                "trial_counts": counts,
                "trials_executed": executed,
                "trials_total": len(trial_nums),
                "valid_trials": valid,
                "detections": det,
                "expected": sc["tracks"][catkey].get("expected"),
                "config_note": sc["tracks"][catkey].get("config"),
                "trials": trials_detail,
            }
        scenarios.append(row)

    # Detection rates: numerator = qualifying detections, denominator = eligible
    # successfully-executed evaluations (cells, not trials). Baseline vs configured.
    def rate(filter_fn):
        num = den = 0
        for sc in scenarios:
            if sc["id"] == "A7":
                continue  # benign control is a specificity check, not a detection target
            for key, cell in sc["cells"].items():
                if not filter_fn(cell):
                    continue
                if cell["trials_executed"] == 0:
                    continue  # exclude execution failures
                den += 1
                if cell["headline_outcome"] == "DETECTED":
                    num += 1
        return num, den

    baseline_num, baseline_den = rate(lambda c: c["config"] == "baseline")
    configured_num, configured_den = rate(lambda c: c["config"] == "configured")

    # Per-tool breakdown (baseline track, since every tool has a baseline-ish cell)
    per_tool = {}
    for sc in scenarios:
        for key, cell in sc["cells"].items():
            tool = cell["tool"]
            cfg = cell["config"]
            d = per_tool.setdefault(f"{tool} ({cfg})", {"detected": 0, "eligible": 0, "trials": 0})
            if cell["trials_executed"] > 0:
                d["eligible"] += 1
                d["trials"] += cell.get("valid_trials", cell["trials_total"])
                if cell["headline_outcome"] == "DETECTED":
                    d["detected"] += 1

    # Per-SCENARIO detection rates (trial-weighted): numerator = qualifying
    # detection trials, denominator = valid executed trials. This avoids the
    # uneven aggregate hiding per-scenario differences.
    per_scenario = []
    for sc in scenarios:
        if sc["id"] == "A7":
            continue  # benign control reported separately
        for cond in ("baseline", "configured"):
            cells = [c for c in sc["cells"].values() if c["config"] == cond]
            if not cells:
                continue
            det_trials = sum(c["detections"] for c in cells)
            valid_trials = sum(c.get("valid_trials", c["trials_total"]) for c in cells)
            per_scenario.append({
                "scenario": sc["id"], "title": sc["title"], "condition": cond,
                "tools": sorted({c["tool"] for c in cells}),
                "detection_trials": det_trials, "valid_trials": valid_trials,
                "rate": round(det_trials / valid_trials, 3) if valid_trials else None,
            })

    # Benign-control specificity: on A7 (benign), a DETECTED outcome is a false
    # positive (over-broad rule). We report per-tool detections on the control.
    benign_control = None
    a7 = next((s for s in scenarios if s["id"] == "A7"), None)
    if a7:
        rows = []
        for key, cell in a7["cells"].items():
            rows.append({
                "tool": cell["tool"], "config": cell["config"],
                "false_positive_detections": cell["detections"],
                "valid_trials": cell.get("valid_trials", cell["trials_total"]),
                "specific": cell["detections"] == 0,
            })
        benign_control = {
            "scenario": "A7", "rows": rows,
            "all_specific": all(r["specific"] for r in rows),
            "note": ("On the benign control, a qualifying detection would indicate an over-broad "
                     "rule/signature. Zero detections across tools confirms the configured "
                     "detections are specific to the targeted behaviors."),
        }

    analysis = {
        "generated_from": "results/runs/A*_*.json via scripts/build_comparison.py",
        "qualifying_detection_criteria": cat["qualifying_detection_criteria"],
        "scenarios": scenarios,
        "benign_control": benign_control,
        "detection_rates": {
            "baseline": {"detections": baseline_num, "eligible_evaluations": baseline_den,
                         "rate": round(baseline_num / baseline_den, 3) if baseline_den else None},
            "configured": {"detections": configured_num, "eligible_evaluations": configured_den,
                           "rate": round(configured_num / configured_den, 3) if configured_den else None},
        },
        "per_scenario_rates": per_scenario,
        "per_tool_config": per_tool,
        "coverage_note": (
            "Configured coverage is uneven: Falco ran all scenarios; Tetragon-configured ran only "
            "the sensitive-file objective (A1); Tracee-configured was not implemented (no signatures "
            "engine). The aggregate configured rate is therefore NOT a universal improvement — see "
            "per-scenario rates, where detection is concentrated in A1."
        ),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(json.dumps(analysis, indent=2) + "\n")
    print(f"wrote {os.path.relpath(OUT, REPO)}")
    print(f"  baseline detection rate: {baseline_num}/{baseline_den}")
    print(f"  configured detection rate: {configured_num}/{configured_den}")
    for sc in scenarios:
        for key, cell in sc["cells"].items():
            print(f"  {sc['id']} {cell['tool']:9} ({cell['config']:10}) -> "
                  f"{cell['headline_outcome']:16} det {cell['detections']}/3")


if __name__ == "__main__":
    main()
