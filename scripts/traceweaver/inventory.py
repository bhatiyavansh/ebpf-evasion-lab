"""
TraceWeaver historical-evidence inventory (Phase 1).

Read-only. Walks the existing evidence without modifying it and records, for
every raw stream and run manifest, only what the source actually supports:
source file + sha256, capture mode, sensor/version (if known), scenario/config
(if known), and completeness/limitations. Curated summaries are labelled; nothing
is invented.
"""
from __future__ import annotations
import glob
import hashlib
import json
import os

from . import manifest as M

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _scenario_from_label(label):
    if not label:
        return None
    # A1, E04, A6_falco_t3 -> A1/E04/A6
    import re
    m = re.match(r"([AE]\d+)", label)
    return m.group(1) if m else None


def build_inventory():
    streams, manifests = [], []

    # Raw event streams (immutable evidence)
    for sub, sensor in (("falco_events", "falco"), ("tracee_events", "tracee"),
                        ("tetragon_events", "tetragon")):
        for p in sorted(glob.glob(os.path.join(REPO, "results", "raw", sub, "*.jsonl"))):
            rel = os.path.relpath(p, REPO)
            try:
                nlines = sum(1 for _ in open(p))
            except Exception:
                nlines = None
            streams.append({
                "path": rel, "sensor": sensor, "sha256": sha256_file(p),
                "record_count": nlines, "kind": "raw_event_stream",
                "capture_mode": "live",  # these .jsonl were written by live capture harnesses
            })

    # Raw result summaries (results/raw/E0x_tool.json) — curated/summary-derived
    for p in sorted(glob.glob(os.path.join(REPO, "results", "raw", "*.json"))):
        rel = os.path.relpath(p, REPO)
        try:
            d = json.load(open(p))
        except Exception:
            d = {}
        has_stream = bool(d.get("evidence_events"))
        manifests_like = {
            "path": rel, "sensor": d.get("tool"), "sha256": sha256_file(p),
            "kind": "raw_result_summary",
            # if it references an event stream it is live-derived; otherwise it is
            # a hand-authored/curated summary and its events are summary_derived.
            "capture_mode": "live" if has_stream else "summary_derived",
            "scenario_id": d.get("experiment_id"),
        }
        streams.append(manifests_like)

    # Run manifests
    for p in sorted(glob.glob(os.path.join(REPO, "results", "runs", "*.json"))):
        rel = os.path.relpath(p, REPO)
        try:
            m = json.load(open(p))
        except Exception:
            m = {}
        outcome, reason = M.classify_outcome(m)
        manifests.append({
            "path": rel, "sha256": sha256_file(p),
            "trial_id": m.get("run_id"), "tool": m.get("tool"),
            "tool_version": m.get("tool_version"),
            "scenario_id": _scenario_from_label(m.get("run_label")),
            "policy_mode": m.get("mode"),
            "capture_mode": M.capture_mode(m),
            "lifecycle_stage": M.lifecycle_stage(m),
            "collection_status": m.get("collection_status"),
            "workload_exit_code": m.get("workload_exit_code"),
            "derived_outcome": outcome, "derived_outcome_reason": reason,
            "evidence_events": m.get("evidence_events"),
        })

    by_mode = {}
    for s in streams:
        by_mode[s["capture_mode"]] = by_mode.get(s["capture_mode"], 0) + 1
    by_outcome = {}
    for m in manifests:
        by_outcome[m["derived_outcome"]] = by_outcome.get(m["derived_outcome"], 0) + 1

    return {
        "generated_by": "scripts/traceweaver/inventory.py (read-only)",
        "repo": REPO,
        "evidence_streams": streams,
        "run_manifests": manifests,
        "summary": {
            "stream_count": len(streams),
            "manifest_count": len(manifests),
            "streams_by_capture_mode": by_mode,
            "manifests_by_derived_outcome": by_outcome,
        },
    }


def main():
    inv = build_inventory()
    out = os.path.join(REPO, "results", "inventory.json")
    with open(out, "w") as f:
        f.write(json.dumps(inv, indent=2) + "\n")
    s = inv["summary"]
    print(f"wrote {os.path.relpath(out, REPO)}")
    print(f"  streams={s['stream_count']} manifests={s['manifest_count']}")
    print(f"  streams_by_capture_mode={s['streams_by_capture_mode']}")
    print(f"  manifests_by_derived_outcome={s['manifests_by_derived_outcome']}")


if __name__ == "__main__":
    main()
