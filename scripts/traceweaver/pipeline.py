"""
TraceWeaver deterministic evidence pipeline (Phase 1).

Discovers raw event streams, normalizes each supported record into canonical
events (adapters), validates against the schema, quarantines malformed records
with diagnostics, preserves source provenance (file + line + sha256), and reports
record/trial counts by provenance and status.

Reads ONLY (never mutates) raw evidence. Writes derived artifacts under
results/normalized/ (events/, events_index.json, quarantine.jsonl).

Deterministic: identical inputs produce byte-identical outputs.
"""
from __future__ import annotations
import glob
import json
import os

from . import schema as S
from . import adapters as A
from . import manifest as M
from .inventory import sha256_file, REPO

RAW = os.path.join(REPO, "results", "raw")
NORM = os.path.join(REPO, "results", "normalized")
EVENTS_DIR = os.path.join(NORM, "events")


def _manifest_for(stream_path, sensor):
    label = os.path.basename(stream_path)[:-len(".jsonl")]
    if sensor == "tetragon":
        mp = os.path.join(REPO, "results", "runs", f"{label}.json")
    else:
        mp = os.path.join(REPO, "results", "runs", f"{label}_{sensor}.json")
    if os.path.exists(mp):
        try:
            return json.load(open(mp)), os.path.relpath(mp, REPO)
        except Exception:
            return None, os.path.relpath(mp, REPO)
    return None, None


def _ctx_from_manifest(m, sensor, raw_rel, raw_sha):
    import re
    label = (m or {}).get("run_label", "")
    scn = re.match(r"([AE]\d+)", label).group(1) if re.match(r"([AE]\d+)", label) else S.NOT_SUPPLIED
    return {
        "trial_id": (m or {}).get("run_id", S.NOT_SUPPLIED),
        "scenario_id": scn,
        "sensor_version": (m or {}).get("tool_version", S.NOT_SUPPLIED),
        "policy_mode": (m or {}).get("mode", S.NOT_APPLICABLE),
        "capture_mode": M.capture_mode(m) if m else "live",
        "collection_status": (m or {}).get("collection_status", "complete"),
        "raw_sha": raw_sha, "raw_rel": raw_rel,
    }


def run(write=True):
    os.makedirs(EVENTS_DIR, exist_ok=True)
    index = []
    quarantine = []
    total_events = 0
    warnings_total = 0

    streams = []
    for sub, sensor in (("falco_events", "falco"), ("tracee_events", "tracee"),
                        ("tetragon_events", "tetragon")):
        for p in sorted(glob.glob(os.path.join(RAW, sub, "*.jsonl"))):
            streams.append((p, sensor))

    for stream_path, sensor in streams:
        raw_rel = os.path.relpath(stream_path, REPO)
        raw_sha = sha256_file(stream_path)
        m, mrel = _manifest_for(stream_path, sensor)
        ctx_base = _ctx_from_manifest(m, sensor, raw_rel, raw_sha)
        adapter = A.ADAPTERS[sensor]

        out_events = []
        seen_ids = set()
        with open(stream_path) as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception as e:
                    quarantine.append({"file": raw_rel, "line": lineno,
                                       "reason": f"json parse error: {e}", "excerpt": line[:200]})
                    continue
                ctx = dict(ctx_base)
                ctx["raw_ref"] = {"file": raw_rel, "line": lineno, "sha256": raw_sha}
                try:
                    ev = adapter(rec, ctx)
                except A.AdapterQuarantine as q:
                    quarantine.append({"file": raw_rel, "line": lineno,
                                       "reason": q.reason, "excerpt": q.record_excerpt})
                    continue
                errs = S.validate_event(ev)
                if errs:
                    quarantine.append({"file": raw_rel, "line": lineno,
                                       "reason": "schema validation failed: " + "; ".join(errs),
                                       "excerpt": line[:200]})
                    continue
                if ev["event_id"] in seen_ids:
                    # deterministic de-dup guard (same source coords) — keep first
                    ev["normalization_warnings"].append("duplicate_event_id_in_stream")
                seen_ids.add(ev["event_id"])
                warnings_total += len(ev["normalization_warnings"])
                out_events.append(ev)

        total_events += len(out_events)
        trial = ctx_base["trial_id"]
        out_name = f"{sensor}__{os.path.basename(stream_path)}"  # stable, collision-free
        out_rel = os.path.join("results", "normalized", "events", out_name)
        if write:
            with open(os.path.join(REPO, out_rel), "w") as f:
                for ev in out_events:
                    f.write(json.dumps(ev, sort_keys=True) + "\n")
        index.append({
            "stream": raw_rel, "stream_sha256": raw_sha, "manifest": mrel,
            "sensor": sensor, "trial_id": trial,
            "capture_mode": ctx_base["capture_mode"],
            "normalized_events": out_rel if write else None,
            "event_count": len(out_events),
            "canonical_type_counts": _type_counts(out_events),
        })

    index.sort(key=lambda r: r["stream"])
    report = {
        "schema_version": S.SCHEMA_VERSION,
        "generated_by": "scripts/traceweaver/pipeline.py",
        "total_streams": len(index),
        "total_events": total_events,
        "total_quarantined": len(quarantine),
        "total_normalization_warnings": warnings_total,
        "events_by_sensor": _sensor_counts(index),
        "events_by_capture_mode": _mode_counts(index),
        "streams": index,
    }
    if write:
        with open(os.path.join(NORM, "events_index.json"), "w") as f:
            f.write(json.dumps(report, indent=2) + "\n")
        with open(os.path.join(NORM, "quarantine.jsonl"), "w") as f:
            for q in quarantine:
                f.write(json.dumps(q, sort_keys=True) + "\n")
    return report, quarantine


def _type_counts(events):
    c = {}
    for e in events:
        c[e["canonical_type"]] = c.get(e["canonical_type"], 0) + 1
    return c


def _sensor_counts(index):
    c = {}
    for r in index:
        c[r["sensor"]] = c.get(r["sensor"], 0) + r["event_count"]
    return c


def _mode_counts(index):
    c = {}
    for r in index:
        c[r["capture_mode"]] = c.get(r["capture_mode"], 0) + r["event_count"]
    return c


def main():
    report, quarantine = run(write=True)
    print("wrote results/normalized/events/*.jsonl + events_index.json + quarantine.jsonl")
    print(f"  streams={report['total_streams']} events={report['total_events']} "
          f"quarantined={report['total_quarantined']} warnings={report['total_normalization_warnings']}")
    print(f"  events_by_sensor={report['events_by_sensor']}")
    print(f"  events_by_capture_mode={report['events_by_capture_mode']}")


if __name__ == "__main__":
    main()
