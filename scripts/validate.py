#!/usr/bin/env python3
"""
validate.py — validation + integrity tests for the Adaptive eBPF Security Lab.

Checks (fails the build on any error):
  1. Catalog has no duplicate experiment IDs.
  2. Every raw result JSON parses and matches its filename's experiment/tool.
  3. Every referenced evidence file (raw + event streams) exists on disk.
  4. Normalized records conform to the expected schema/enum.
  5. Status-classification invariants hold:
       - telemetry-only tools (tracee, tetragon) are never confirmed_detection
       - Falco E01 is a built-in-security confirmed_detection
       - Falco E03 is partial (process telemetry, no network detection)
       - no confirmed_detection without event_observed
  6. summary.csv is in sync with normalized results (no manual drift).
  7. Analysis denominators exclude not_tested cells (detection rate <= 1.0 and
     computed over eligible evaluations only).
  8. No fabricated latency values.

Run:  python3 -I scripts/validate.py
Exit code 0 = all checks pass.
"""
import csv
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PASS, FAIL = [], []


def ok(msg):
    PASS.append(msg)
    print(f"  PASS  {msg}")


def bad(msg):
    FAIL.append(msg)
    print(f"  FAIL  {msg}")


def load(rel):
    with open(os.path.join(REPO, rel)) as f:
        return json.load(f)


def main():
    print("== validate: catalog ==")
    catalog = load("experiments/catalog.json")
    ids = [e["id"] for e in catalog["experiments"]]
    if len(ids) == len(set(ids)):
        ok(f"no duplicate experiment IDs ({len(ids)} experiments)")
    else:
        bad(f"duplicate experiment IDs: {ids}")
    tools = set(catalog["detectors"].keys())

    print("== validate: raw result files ==")
    for e in catalog["experiments"]:
        if e.get("derived"):
            ok(f"{e['id']} is derived (no raw files expected)")
            continue
        for t in e["tools"]:
            rel = f"results/raw/{e['id']}_{t}.json"
            full = os.path.join(REPO, rel)
            if not os.path.exists(full):
                bad(f"missing raw result: {rel}")
                continue
            try:
                raw = json.load(open(full))
            except Exception as ex:
                bad(f"{rel} does not parse: {ex}")
                continue
            if raw.get("experiment_id") != e["id"] or raw.get("tool") != t:
                bad(f"{rel} experiment_id/tool mismatch "
                    f"({raw.get('experiment_id')}/{raw.get('tool')})")
            else:
                ok(f"{rel} parses and matches id/tool")
            ev = raw.get("evidence_events")
            if ev and not os.path.exists(os.path.join(REPO, ev)):
                bad(f"{rel} references missing evidence file {ev}")
            elif ev:
                ok(f"{rel} evidence file present ({ev})")

    print("== validate: normalized schema + invariants ==")
    norm = load("results/normalized/results.json")["records"]
    valid_status = {"confirmed_detection", "telemetry_observed", "partial",
                    "not_tested", "confirmed_miss", "collection_failed"}
    telemetry_only = {t for t, d in catalog["detectors"].items()
                      if not d["has_alerting_engine"]}
    for r in norm:
        if r["status"] not in valid_status:
            bad(f"{r['experiment_id']}/{r['tool']} invalid status {r['status']}")
        if r["tool"] in telemetry_only and r["status"] == "confirmed_detection":
            bad(f"{r['experiment_id']}/{r['tool']}: telemetry-only tool marked "
                f"confirmed_detection (integrity violation)")
        if r["status"] == "confirmed_detection" and not r["event_observed"]:
            bad(f"{r['experiment_id']}/{r['tool']}: confirmed_detection without "
                f"event_observed")
        if r["evidence_raw"] and not os.path.exists(os.path.join(REPO, r["evidence_raw"])):
            bad(f"{r['experiment_id']}/{r['tool']}: evidence_raw missing on disk")
        # dimensions present and telemetry-only tools never "detected"
        dims = r.get("dimensions") or {}
        if not dims:
            bad(f"{r['experiment_id']}/{r['tool']}: missing dimensions")
        elif r["tool"] in telemetry_only and dims.get("detection") == "detected":
            bad(f"{r['experiment_id']}/{r['tool']}: telemetry-only tool detection=detected")
        if r["provenance"] not in ("live", "recorded"):
            bad(f"{r['experiment_id']}/{r['tool']}: invalid provenance {r['provenance']}")
    if not any(f for f in FAIL):
        ok(f"all {len(norm)} normalized records conform to schema (+ dimensions, provenance)")

    def rec(eid, tool):
        return next((r for r in norm if r["experiment_id"] == eid and r["tool"] == tool), None)

    e01f = rec("E01", "falco")
    if e01f and e01f["status"] == "confirmed_detection" and e01f["rule_class"] == "builtin_security":
        ok("Falco E01 = confirmed_detection via built-in security rule")
    else:
        bad(f"Falco E01 classification unexpected: {e01f and (e01f['status'], e01f['rule_class'])}")

    e03f = rec("E03", "falco")
    if e03f and e03f["status"] == "partial":
        ok("Falco E03 = partial (process telemetry, no network detection)")
    else:
        bad(f"Falco E03 expected partial, got {e03f and e03f['status']}")

    e01t = rec("E01", "tetragon")
    if e01t and e01t["status"] == "telemetry_observed":
        ok("Tetragon E01 = telemetry_observed (pathname confirmed, no alert verdict)")
    else:
        bad(f"Tetragon E01 unexpected: {e01t and e01t['status']}")

    print("== validate: summary.csv in sync ==")
    with open(os.path.join(REPO, "results/summary.csv")) as f:
        rows = list(csv.DictReader(f))
    if len(rows) == len(norm):
        ok(f"summary.csv row count matches normalized ({len(rows)})")
    else:
        bad(f"summary.csv has {len(rows)} rows, normalized has {len(norm)}")
    norm_keys = {(r["experiment_id"], r["tool"], r["status"]) for r in norm}
    csv_keys = {(r["experiment_id"], r["tool"], r["status"]) for r in rows}
    if norm_keys == csv_keys:
        ok("summary.csv status values match normalized (no drift)")
    else:
        bad(f"summary.csv drift: {norm_keys ^ csv_keys}")

    print("== validate: analysis denominators ==")
    analysis = load("results/analysis/analysis.json")
    for t, d in analysis["detection_vs_telemetry"].items():
        rate = d["detection_rate"]
        if rate is None or 0.0 <= rate <= 1.0:
            ok(f"{t} detection_rate within [0,1] over eligible cells ({rate})")
        else:
            bad(f"{t} detection_rate out of range: {rate}")
        tested = [r for r in norm if r["tool"] == t and r["status"] != "not_tested"]
        if d["eligible_evaluations"] == len(tested):
            ok(f"{t} eligible_evaluations excludes not_tested ({len(tested)})")
        else:
            bad(f"{t} eligible count mismatch {d['eligible_evaluations']} != {len(tested)}")

    print("== validate: no fabricated latency ==")
    ls = analysis["latency_summary"]
    real = [r for r in norm if isinstance(r.get("latency_ms"), (int, float))]
    if ls["measurements_available"] == len(real):
        ok(f"latency summary reflects real measurements only ({len(real)})")
    else:
        bad("latency summary count mismatch")

    print()
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
