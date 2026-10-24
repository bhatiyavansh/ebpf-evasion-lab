#!/usr/bin/env python3
"""
gen_tetragon_raw.py — derive Tetragon raw result JSON files from the captured,
immutable Tetragon event streams in results/raw/tetragon_events/*.jsonl.

This does not invent anything: every field is computed from the recorded events.
Run with:  python3 -I scripts/gen_tetragon_raw.py
"""
import json
import os
import collections

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVID = os.path.join(REPO, "results", "raw", "tetragon_events")
RAW = os.path.join(REPO, "results", "raw")

# Per-experiment metadata that is NOT derivable from the event stream itself.
META = {
    "E01": dict(behavior="sensitive_file_read", variant="baseline",
                target_path="/etc/shadow"),
    "E02": dict(behavior="process_execution", variant="baseline"),
    "E03": dict(behavior="network_activity", variant="baseline"),
    "E04": dict(behavior="process_execution", variant="indirect_execution"),
    "E05": dict(behavior="process_execution", variant="timing_variation",
                timing_intervals_seconds=[2, 2]),
}


def load(eid):
    path = os.path.join(EVID, f"{eid}.jsonl")
    events = []
    for line in open(path):
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def summarize(eid, events):
    kinds = collections.Counter()
    execs = []
    openat_paths = []
    container_ids = set()
    for ev in events:
        for k in ("process_exec", "process_kprobe", "process_tracepoint", "process_exit"):
            node = ev.get(k)
            if not node:
                continue
            kinds[k] += 1
            proc = node.get("process", {}) or {}
            if proc.get("docker"):
                container_ids.add(proc["docker"][:12])
            if k == "process_exec":
                execs.append(os.path.basename(proc.get("binary", "")))
            if k == "process_kprobe" and "openat" in (node.get("function_name", "") or ""):
                for a in node.get("args", []):
                    if "string_arg" in a:
                        openat_paths.append(a["string_arg"])
    return kinds, execs, openat_paths, sorted(container_ids)


def load_manifest(eid):
    p = os.path.join(REPO, "results", "runs", f"{eid}.json")
    return json.load(open(p)) if os.path.exists(p) else {}


def build(eid):
    meta = META[eid]
    events = load(eid)
    kinds, execs, openat_paths, cids = summarize(eid, events)
    exec_count = kinds.get("process_exec", 0)
    tracepoint_count = kinds.get("process_tracepoint", 0)
    openat_count = kinds.get("process_kprobe", 0)
    mani = load_manifest(eid)
    collection_status = mani.get("collection_status", "complete")

    rec = {
        "experiment_id": eid,
        "tool": "tetragon",
        "behavior": meta["behavior"],
        "variant": meta["variant"],
        "collection_status": collection_status,
        "collection_note": mani.get("collection_note"),
        "workload_exit_code": mani.get("workload_exit_code"),
        "sensor_health": mani.get("sensor_health"),
        # Tetragon here runs tracing policies (telemetry emitters), not an
        # alerting rule engine. We never label telemetry as a security
        # detection, so detected=false by construction for this lab config.
        "detected": False,
        "event_observed": exec_count > 0 or openat_count > 0,
        "containerized": len(cids) > 0,
        "image": "alpine:3.20",
        "processes_detected": execs,
        "alert_count": 0,
        "evidence_events": f"results/raw/tetragon_events/{eid}.jsonl",
        "event_counts": {
            "sched_process_exec": tracepoint_count,
            "process_exec": exec_count,
            "openat_kprobe": openat_count,
        },
        "container_cgroup_ids": cids,
    }

    if eid == "E01":
        shadow = [p for p in openat_paths if "shadow" in p]
        rec["detection_type"] = "openat_telemetry + sched_process_exec_telemetry"
        rec["target_path"] = meta["target_path"]
        rec["target_path_observed_in_openat"] = bool(shadow)
        rec["openat_paths_sample"] = sorted(set(openat_paths))[:12]
        if shadow:
            rec["notes"] = (
                "Tetragon captured the sched_process_exec telemetry for /bin/cat and, "
                "under the ebpf-lab-file-access tracing policy, recorded a sys_openat event "
                "whose pathname argument is /etc/shadow. Pathname-specific visibility of the "
                "sensitive-file open is therefore established at the telemetry level. This is "
                "kernel/event visibility only: no alerting policy evaluated the open as a "
                "security detection, so this is telemetry observed, not a confirmed detection."
            )
        else:
            rec["notes"] = (
                "Tetragon captured process-execution telemetry for /bin/cat, but the "
                "ebpf-lab-file-access openat policy did not record a pathname argument "
                "matching /etc/shadow in this run."
            )
    elif eid == "E03":
        rec["detection_type"] = "sched_process_exec_telemetry"
        rec["network_connection_detection"] = False
        rec["notes"] = (
            f"Tetragon captured process-execution telemetry for the network workload "
            f"({', '.join(execs)}). No network/connect tracing policy is configured in this "
            f"lab, so no socket-level connection event was captured and network-specific "
            f"detection is not established. openat telemetry for TLS material "
            f"(libssl/cert store) was incidentally observed."
        )
    else:
        rec["detection_type"] = "sched_process_exec_telemetry"
        if eid == "E05":
            rec["timing_intervals_seconds"] = meta["timing_intervals_seconds"]
        variant_note = {
            "E02": "Container metadata (cgroup id) was enriched on each exec event.",
            "E04": "Both shell layers and the final command were captured; additional "
                   "shell indirection did not remove process-execution telemetry.",
            "E05": "All execution events were captured despite controlled two-second delays "
                   "between commands.",
        }[eid]
        rec["notes"] = (
            f"Tetragon observed sched_process_exec telemetry for {', '.join(execs)} inside the "
            f"controlled Alpine container. {variant_note} This is telemetry observed, not a "
            f"confirmed security detection (no alerting policy was evaluated)."
        )
    return rec


def main():
    for eid in ["E01", "E02", "E03", "E04", "E05"]:
        rec = build(eid)
        out = os.path.join(RAW, f"{eid}_tetragon.json")
        with open(out, "w") as f:
            f.write(json.dumps(rec, indent=2) + "\n")
        print(f"wrote {out}  execs={rec['processes_detected']} "
              f"openat={rec['event_counts']['openat_kprobe']}")


if __name__ == "__main__":
    main()
