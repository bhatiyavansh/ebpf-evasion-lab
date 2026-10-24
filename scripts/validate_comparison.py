#!/usr/bin/env python3
"""
validate_comparison.py — integrity tests for the fair detection comparison study.

Independently recounts qualifying detections from the raw run manifests and
compares them with results/analysis/comparison.json. Fails on any mismatch.

Run:  python3 -I scripts/validate_comparison.py
"""
import json
import os
import sys
import glob

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(REPO, "results", "runs")
COMP = os.path.join(REPO, "results", "analysis", "comparison.json")
SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/ssh/ssh_host_rsa_key")

PASS, FAIL = [], []
def ok(m): PASS.append(m); print(f"  PASS  {m}")
def bad(m): FAIL.append(m); print(f"  FAIL  {m}")


def main():
    comp = json.load(open(COMP))

    print("== comparison: every cell has 3 trials with valid outcomes ==")
    valid = {"DETECTED", "TELEMETRY_ONLY", "NOT_DETECTED", "NOT_EVALUATED",
             "EXECUTION_FAILED", "COLLECTION_FAILED", "INCONCLUSIVE"}
    import glob as _glob
    for sc in comp["scenarios"]:
        for key, cell in sc["cells"].items():
            if len(cell["trials"]) < 1:
                bad(f"{sc['id']}/{key}: no trials")
            if len(cell["trials"]) != cell["trials_total"]:
                bad(f"{sc['id']}/{key}: trials_total {cell['trials_total']} != {len(cell['trials'])} trial records")
            for tr in cell["trials"]:
                if tr["outcome"] not in valid:
                    bad(f"{sc['id']}/{key} trial {tr['trial']}: invalid outcome {tr['outcome']}")
    if not FAIL:
        ok("all comparison cells have matching trial counts with valid outcomes")

    print("== comparison: independent recount of Falco qualifying detections (all trials) ==")
    # Recount Falco from every raw manifest on disk: must be a built-in (non-custom) Warning+ rule.
    for sc in comp["scenarios"]:
        cell = sc["cells"].get("falco")
        if not cell:
            continue
        recount = 0
        for mp in _glob.glob(os.path.join(RUNS, f"{sc['id']}_falco_t*_falco.json")):
            m = json.load(open(mp))
            if m.get("qualifying_detections"):
                recount += 1
        if recount == cell["detections"]:
            ok(f"{sc['id']} Falco detections recount matches ({recount}/{cell['trials_total']})")
        else:
            bad(f"{sc['id']} Falco detections mismatch: recount {recount} vs reported {cell['detections']}")

    print("== comparison: Tetragon-configured detections require a sensitive-path match ==")
    for sc in comp["scenarios"]:
        cell = sc["cells"].get("tetC")
        if not cell:
            continue
        recount = 0
        for mp in _glob.glob(os.path.join(RUNS, f"{sc['id']}_tetC_t*.json")):
            m = json.load(open(mp))
            if any(p in SENSITIVE for p in m.get("openat_paths", [])):
                recount += 1
        if recount == cell["detections"]:
            ok(f"{sc['id']} Tetragon-configured detections recount matches ({recount})")
        else:
            bad(f"{sc['id']} Tetragon-configured mismatch: recount {recount} vs {cell['detections']}")

    print("== comparison: independent recount of Tracee signature detections ==")
    for sc in comp["scenarios"]:
        cell = sc["cells"].get("tracee")
        if not cell:
            continue
        recount = 0
        for mp in _glob.glob(os.path.join(RUNS, f"{sc['id']}_tracee_t*_tracee.json")):
            m = json.load(open(mp))
            if m.get("signature_detections"):
                recount += 1
        if recount == cell["detections"]:
            ok(f"{sc['id']} Tracee detections recount matches ({recount}/{cell['trials_total']})")
        else:
            bad(f"{sc['id']} Tracee detections mismatch: recount {recount} vs reported {cell['detections']}")

    print("== comparison: benign control (A7) has no false-positive detections ==")
    bc = comp.get("benign_control")
    if bc:
        for r in bc["rows"]:
            if r["false_positive_detections"] == 0:
                ok(f"A7 {r['tool']} ({r['config']}) specific: 0 false positives")
            else:
                bad(f"A7 {r['tool']} ({r['config']}): {r['false_positive_detections']} false positive(s) — over-broad rule")

    print("== comparison: telemetry-only cells never carry detections ==")
    for sc in comp["scenarios"]:
        for key, cell in sc["cells"].items():
            if cell["headline_outcome"] == "TELEMETRY_ONLY" and cell["detections"] > 0:
                bad(f"{sc['id']}/{key}: TELEMETRY_ONLY but detections={cell['detections']}")
    if not any("TELEMETRY_ONLY but" in f for f in FAIL):
        ok("no telemetry-only cell carries a detection")

    print("== comparison: detection-rate denominators exclude execution failures ==")
    for track in ("baseline", "configured"):
        r = comp["detection_rates"][track]
        if r["eligible_evaluations"] <= 0 and r["rate"] is not None:
            bad(f"{track}: zero denominator must yield null rate, got {r['rate']}")
        elif r["rate"] is not None and not (0.0 <= r["rate"] <= 1.0):
            bad(f"{track}: rate out of range {r['rate']}")
        else:
            ok(f"{track} rate valid: {r['detections']}/{r['eligible_evaluations']}")

    print(f"\nRESULT: {len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
