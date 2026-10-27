"""
TraceWeaver engine runner (Phase 2).

Loads Phase-1 canonical event streams, fits the anomaly baseline ONLY on
designated baseline data (benign control A7 + baseline-config streams) to avoid
evaluation leakage, runs the engine per stream, and writes deterministic results
under results/engine/.

Public functions are imported by the CLI and the evaluation harness.
"""
from __future__ import annotations
import glob
import json
import os

from . import engine as E
from .inventory import REPO

NORM = os.path.join(REPO, "results", "normalized")
ENGINE_OUT = os.path.join(REPO, "results", "engine")

# Streams used to FIT the anomaly baseline (normal process/file behavior).
# Deliberately EXCLUDES the benign control A7 so A7 can serve as a held-out
# NEGATIVE evaluation set (no leakage). A2/A3 are ambiguous (excluded from
# supervised metrics) and E-series are observability baselines, so using them to
# establish "normal" does not contaminate the A1/A5/A6 (positive) vs A7 (negative) test.
BASELINE_STREAM_PREFIXES = ("tracee__A2", "tracee__A3", "falco__A2", "falco__A3",
                            "tetragon__E01", "tetragon__E02", "tetragon__E03", "tetragon__E05")


def load_index():
    p = os.path.join(NORM, "events_index.json")
    return json.load(open(p)) if os.path.exists(p) else {"streams": []}


def load_stream_events(normalized_rel):
    p = os.path.join(REPO, normalized_rel)
    if not os.path.exists(p):
        return []
    out = []
    for line in open(p):
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _manifest_collection_status(stream_entry):
    """Pull collection/execution status from the stream's run manifest, if any."""
    mrel = stream_entry.get("manifest")
    if not mrel:
        return {}
    p = os.path.join(REPO, mrel)
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p))
    except Exception:
        return {}


def fit_baseline(index, cfg):
    baseline_events = []
    used = []
    for st in index["streams"]:
        name = os.path.basename(st.get("normalized_events") or st["stream"])
        key = name[:-len(".jsonl")] if name.endswith(".jsonl") else name
        if any(key.startswith(pref) for pref in BASELINE_STREAM_PREFIXES):
            baseline_events.append(load_stream_events(st["normalized_events"]))
            used.append(key)
    return E.fit_anomaly_baseline(baseline_events), used


def run_all(write=True, cfg=None):
    cfg = cfg or E.load_config()
    index = load_index()
    baseline, baseline_used = fit_baseline(index, cfg)
    results = []
    for st in sorted(index["streams"], key=lambda s: s["stream"]):
        events = load_stream_events(st.get("normalized_events"))
        man = _manifest_collection_status(st)
        stream_meta = {
            "trial_id": st.get("trial_id"), "stream": st.get("stream"),
            "sensor": st.get("sensor"), "scenario_id": _scenario(st),
            "capture_mode": st.get("capture_mode"),
            "collection_status": man.get("collection_status", "complete"),
        }
        res = E.run_engine(events, stream_meta, baseline, cfg)
        res["is_baseline_stream"] = _is_baseline(st)
        results.append(res)

    if write:
        os.makedirs(ENGINE_OUT, exist_ok=True)
        with open(os.path.join(ENGINE_OUT, "results.jsonl"), "w") as f:
            for r in results:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        summary = summarize(results, baseline_used, cfg)
        with open(os.path.join(ENGINE_OUT, "summary.json"), "w") as f:
            f.write(json.dumps(summary, indent=2) + "\n")
    return results, baseline_used


def _scenario(st):
    import re
    tid = st.get("trial_id") or ""
    m = re.search(r"-(A\d+|E\d+)[_-]", "-" + os.path.basename(st.get("stream", "")))
    if m:
        return m.group(1)
    m2 = re.match(r"([AE]\d+)", os.path.basename(st.get("stream", ""))[:4])
    return m2.group(1) if m2 else None


def _is_baseline(st):
    key = os.path.basename(st.get("normalized_events") or "")
    key = key[:-len(".jsonl")] if key.endswith(".jsonl") else key
    return any(key.startswith(p) for p in BASELINE_STREAM_PREFIXES)


def summarize(results, baseline_used, cfg):
    by_verdict, by_visibility, by_sensor = {}, {}, {}
    for r in results:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        by_visibility[r["visibility_status"]] = by_visibility.get(r["visibility_status"], 0) + 1
        by_sensor[r["sensor"]] = by_sensor.get(r["sensor"], 0) + 1
    return {
        "engine_version": E.ENGINE_VERSION, "config_version": cfg["config_version"],
        "total_streams": len(results),
        "verdict_distribution": by_verdict,
        "visibility_distribution": by_visibility,
        "by_sensor": by_sensor,
        "baseline_fit_on": baseline_used,
        "detected_streams": [r["stream"] for r in results if r["verdict"] == "DETECTED"],
    }


def main():
    results, baseline_used = run_all(write=True)
    cfg = E.load_config()
    s = summarize(results, baseline_used, cfg)
    print("wrote results/engine/results.jsonl + summary.json")
    print(f"  streams={s['total_streams']} verdicts={s['verdict_distribution']}")
    print(f"  visibility={s['visibility_distribution']}")
    print(f"  baseline fit on {len(baseline_used)} streams (excluded from supervised metrics)")


if __name__ == "__main__":
    main()
