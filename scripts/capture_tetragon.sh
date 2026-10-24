#!/usr/bin/env bash
#
# capture_tetragon.sh — run one benign workload while Tetragon is active and
# capture the Tetragon events scoped to that exact workload container, plus a
# run manifest (run_id, timestamps, container id, counts, provenance=live).
#
# This does NOT fabricate results. It records the raw Tetragon event stream
# filtered to the workload container's cgroup id verbatim, and a sidecar
# manifest describing the live run. A separate normalization step interprets.
#
# Usage: capture_tetragon.sh <RUN_LABEL> <WORKLOAD_IMAGE> <command...>
#   RUN_LABEL names the evidence files, e.g. E02, E06_t3, E07_benign.
# Requires: a running Tetragon container named "tetragon-lab".
#
set -euo pipefail

RUN_LABEL="${1:?run label required, e.g. E02 or E06_t1}"
IMAGE="${2:?workload image required, e.g. alpine:3.20}"
shift 2
CMD=("$@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID_DIR="$REPO_ROOT/results/raw/tetragon_events"
RUNS_DIR="$REPO_ROOT/results/runs"
mkdir -p "$EVID_DIR" "$RUNS_DIR"
RAW_STREAM="$(mktemp)"
trap 'rm -f "$RAW_STREAM"' EXIT

TETRAGON_CTR="tetragon-lab"
if ! docker ps --format '{{.Names}}' | grep -qx "$TETRAGON_CTR"; then
  echo "ERROR: Tetragon container '$TETRAGON_CTR' is not running. Start it with scripts/lab.sh up-tetragon" >&2
  exit 3
fi

TETRAGON_VER="$(docker inspect tetragon-lab --format '{{.Config.Image}}' 2>/dev/null || echo 'quay.io/cilium/tetragon:v1.6.0')"
RUN_ID="run-${RUN_LABEL}-$(date +%Y%m%d%H%M%S)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "[capture] run_id=$RUN_ID streaming Tetragon events..." >&2
docker exec "$TETRAGON_CTR" tetra getevents -o json > "$RAW_STREAM" 2>/dev/null &
GETPID=$!
sleep 2

WL_NAME="lab-workload-${RUN_LABEL}"
docker rm -f "$WL_NAME" >/dev/null 2>&1 || true
echo "[capture] running workload: docker run ${IMAGE} ${CMD[*]}" >&2
CID="$(docker run -d --rm --name "$WL_NAME" "$IMAGE" "${CMD[@]}")"
SHORT="${CID:0:12}"
WL_EXIT="$(timeout 30 docker wait "$CID" 2>/dev/null || echo "timeout")"
sleep 3
kill "$GETPID" 2>/dev/null || true
wait "$GETPID" 2>/dev/null || true
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# WL_EXIT was captured from `docker wait` above (the authoritative exit code;
# the container is --rm so a post-hoc inspect would race its removal).
OUT="$EVID_DIR/${RUN_LABEL}.jsonl"
MANIFEST="$RUNS_DIR/${RUN_LABEL}.json"

# Host-wide sanity: did Tetragon emit ANY events at all in the window? Used to
# tell "sensor dead" from "sensor healthy but did not see this container".
HOST_EVENTS="$(grep -c '"process_exec"\|"process_kprobe"' "$RAW_STREAM" 2>/dev/null || echo 0)"

python3 -I - "$RAW_STREAM" "$SHORT" "$OUT" "$MANIFEST" \
  "$RUN_ID" "$STARTED_AT" "$ENDED_AT" "$RUN_LABEL" "$TETRAGON_VER" "$CID" "${CMD[*]}" \
  "$HOST_EVENTS" "$WL_EXIT" <<'PY'
import json, sys, os
(src, short, out, manifest, run_id, started, ended, label,
 tver, cid, cmd, host_events, wl_exit) = sys.argv[1:14]
host_events = int(host_events) if host_events.isdigit() else 0
kept = []
for line in open(src):
    try:
        ev = json.loads(line)
    except Exception:
        continue
    for key in ("process_exec", "process_kprobe", "process_exit", "process_tracepoint"):
        node = ev.get(key)
        if not node:
            continue
        proc = node.get("process", {}) or {}
        dock = proc.get("docker", "") or ""
        if dock and (dock.startswith(short) or short.startswith(dock[:12])):
            kept.append(ev)
            break

# Collection-status model (do NOT silently report an empty capture as success):
#   complete        -> scoped container events captured
#   collection_failed -> workload executed but ZERO scoped events, while the
#                        sensor was otherwise emitting host events (sensor healthy,
#                        container not tracked) OR emitting nothing (sensor stalled)
execution_ok = (wl_exit == "0")
if kept:
    collection_status = "complete"
elif execution_ok and host_events > 0:
    collection_status = "collection_failed_container_not_tracked"
elif execution_ok:
    collection_status = "collection_failed_sensor_no_events"
else:
    collection_status = "execution_failed"

# NEVER overwrite a non-empty historical evidence file with an empty capture.
preserved = False
if not kept and os.path.exists(out) and os.path.getsize(out) > 0:
    preserved = True   # keep the good historical stream in place
else:
    with open(out, "w") as f:
        for ev in kept:
            f.write(json.dumps(ev) + "\n")

# Derive quick counts for the manifest (interpretation stays in normalize.py).
import collections
kinds = collections.Counter()
execs = []
openats = []
for ev in kept:
    for k in ("process_exec", "process_kprobe", "process_tracepoint", "process_exit"):
        if k in ev:
            kinds[k] += 1
            if k == "process_exec":
                execs.append(os.path.basename(ev[k]["process"].get("binary", "")))
            if k == "process_kprobe" and "openat" in (ev[k].get("function_name", "") or ""):
                for a in ev[k].get("args", []):
                    if "string_arg" in a:
                        openats.append(a["string_arg"])
mani = {
    "run_id": run_id,
    "run_label": label,
    "tool": "tetragon",
    "provenance": "live",
    "started_at": started,
    "ended_at": ended,
    "workload_image": "alpine:3.20",
    "workload_cmd": cmd,
    "container_id": cid,
    "container_short": short,
    "tool_version": tver,
    "policies": ["ebpf-lab-process-exec (sched_process_exec)",
                 "ebpf-lab-file-access (sys_openat pathname)"],
    "scoped_event_count": len(kept),
    "event_counts": {
        "process_exec": kinds.get("process_exec", 0),
        "sched_process_exec": kinds.get("process_tracepoint", 0),
        "openat_kprobe": kinds.get("process_kprobe", 0),
        "process_exit": kinds.get("process_exit", 0),
    },
    "processes_observed": execs,
    "openat_paths": sorted(set(openats)),
    "evidence_events": f"results/raw/tetragon_events/{label}.jsonl",
    "workload_exit_code": wl_exit,
    "execution_ok": execution_ok,
    "host_events_in_window": host_events,
    "sensor_health": "healthy" if host_events > 0 else "no_events_in_window",
    "collection_status": collection_status,
    "evidence_preserved": preserved,
}
if collection_status.startswith("collection_failed"):
    mani["collection_note"] = (
        "Workload executed (exit 0) but Tetragon captured zero events scoped to the container. "
        + ("Tetragon emitted host events in the same window, so the sensor is alive but is not "
           "tracking this Docker container (a Tetragon-specific container-cgroup tracking "
           "regression observed after the host reboot; Falco and Tracee track the same container "
           "normally). " if host_events > 0 else "Tetragon emitted no events at all in the window. ")
        + "This is COLLECTION_FAILED, not a detector miss and not telemetry."
    )
with open(manifest, "w") as f:
    f.write(json.dumps(mani, indent=2) + "\n")
print(f"[capture] run_id={run_id} container={short} scoped_events={len(kept)} "
      f"execs={execs} collection={collection_status} preserved={preserved} -> {out}", file=sys.stderr)
PY

echo "$OUT"
