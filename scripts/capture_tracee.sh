#!/usr/bin/env bash
#
# capture_tracee.sh — run one workload while Tracee is active and capture the
# REAL Tracee JSON events scoped to that workload container, plus a manifest.
#
# Replaces hand-authored Tracee summaries with genuine captured telemetry.
# Qualifying-detection criterion (documented): Tracee is configured here with an
# event set only (no signatures engine) UNLESS a policy file is supplied. A
# qualifying detection = an event carrying a non-empty matchedPolicies entry
# (i.e. a documented detection policy matched). Otherwise the outcome is
# telemetry-only — raw events are NEVER counted as detections.
#
# Usage: capture_tracee.sh <RUN_LABEL> <MODE> <EVENTS> <WORKLOAD_IMAGE> <command...>
#   MODE   = baseline | configured
#   EVENTS = comma list, e.g. execve,openat,security_file_open,security_socket_connect
# Requires: Docker, aquasec/tracee:latest.
#
set -euo pipefail

RUN_LABEL="${1:?run label required}"
MODE="${2:?mode required}"
EVENTS="${3:?events list required}"
IMAGE="${4:?workload image required}"
shift 4
CMD=("$@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID_DIR="$REPO_ROOT/results/raw/tracee_events"
RUNS_DIR="$REPO_ROOT/results/runs"
mkdir -p "$EVID_DIR" "$RUNS_DIR"

TRACEE_CTR="tracee-lab"
RUN_ID="run-${RUN_LABEL}-tracee-$(date +%Y%m%d%H%M%S)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

docker rm -f "$TRACEE_CTR" >/dev/null 2>&1 || true
docker run -d --rm --name "$TRACEE_CTR" \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest \
  --events "$EVENTS" --scope container --output json >/dev/null 2>&1

# Wait (bounded) for Tracee to finish loading its probes.
for _ in $(seq 1 40); do
  docker logs "$TRACEE_CTR" 2>&1 | grep -qiE "Tracee is initialized|started|listening" && break
  sleep 1
done
sleep 4

WL_NAME="lab-workload-${RUN_LABEL}-tracee"
docker rm -f "$WL_NAME" >/dev/null 2>&1 || true
echo "[tracee] $MODE run: docker run ${IMAGE} ${CMD[*]}" >&2
CID="$(docker run -d --rm --name "$WL_NAME" "$IMAGE" "${CMD[@]}")"
SHORT="${CID:0:12}"
timeout 30 docker wait "$CID" >/dev/null 2>&1 || true
sleep 3

EVENTS_FILE="$(mktemp)"; trap 'rm -f "$EVENTS_FILE"' EXIT
docker logs "$TRACEE_CTR" 2>&1 | grep -E '^\{"timestamp"' > "$EVENTS_FILE" || true
docker stop "$TRACEE_CTR" >/dev/null 2>&1 || true
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

OUT="$EVID_DIR/${RUN_LABEL}.jsonl"
MANIFEST="$RUNS_DIR/${RUN_LABEL}_tracee.json"

python3 -I - "$EVENTS_FILE" "$SHORT" "$OUT" "$MANIFEST" \
  "$RUN_ID" "$STARTED_AT" "$ENDED_AT" "$RUN_LABEL" "$MODE" "$CID" "${CMD[*]}" "$EVENTS" <<'PY'
import json, sys, os, collections
evfile, short, out, manifest, run_id, started, ended, label, mode, cid, cmd, events = sys.argv[1:13]
kept = []
for line in open(evfile):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        ev = json.loads(line)
    except Exception:
        continue
    cont = ev.get("container", {}) or {}
    cidf = cont.get("id", "") or ev.get("containerId", "") or ""
    if cidf and cidf.startswith(short[:12]):
        kept.append(ev)

# Tracee behavioral SIGNATURE events = qualifying detections (not raw telemetry).
SIGNATURES = {
    "dropped_executable", "sudoers_modification", "anti_debugging", "hidden_file_created",
    "fileless_execution", "illegitimate_shell", "ld_preload", "proc_mem_code_injection",
    "stdio_over_socket", "docker_abuse", "scheduled_task_mod", "core_pattern_modification",
    "kernel_module_loading", "syscall_hooking", "proc_kcore_read", "proc_mem_access",
    "ptrace_code_injection", "process_vm_write_inject", "dynamic_code_loading",
    "system_request_key_mod", "sched_debug_recon", "k8s_cert_theft", "aslr_inspection",
    "default_loader_mod", "rcd_modification", "cgroup_release_agent", "disk_mount",
}
by_event = collections.Counter()
execs, openat_paths, connects = [], [], []
matched_policies = []
signature_detections = collections.Counter()
for ev in kept:
    name = ev.get("eventName", "")
    by_event[name] += 1
    if name in SIGNATURES:
        signature_detections[name] += 1
    args = {a.get("name"): a.get("value") for a in ev.get("args", []) if isinstance(a, dict)}
    if name == "execve":
        p = args.get("pathname")
        if p:
            execs.append(os.path.basename(p))
    if name in ("openat", "security_file_open"):
        p = args.get("pathname") or args.get("syscall_pathname")
        if p:
            openat_paths.append(p)
    if name in ("security_socket_connect", "connect"):
        connects.append(args.get("remote_addr") or args.get("addr") or "connect")
    mp = [m for m in (ev.get("matchedPolicies") or []) if m]
    if mp:
        matched_policies.extend(mp)

with open(out, "w") as f:
    for ev in kept:
        f.write(json.dumps(ev) + "\n")

mani = {
    "run_id": run_id, "run_label": label, "tool": "tracee", "mode": mode,
    "provenance": "live", "started_at": started, "ended_at": ended,
    "workload_image": "alpine:3.20", "workload_cmd": cmd,
    "container_id": cid, "container_short": short,
    "tool_version": "aquasec/tracee:latest",
    "events_configured": events,
    "scoped_event_count": len(kept),
    "event_counts": dict(by_event),
    "processes_observed": execs,
    "openat_paths": sorted(set(openat_paths)),
    "connects": connects,
    "matched_policies": sorted(set(matched_policies)),
    "signature_detections": dict(signature_detections),
    "evidence_events": f"results/raw/tracee_events/{label}.jsonl",
}
with open(manifest, "w") as f:
    f.write(json.dumps(mani, indent=2) + "\n")
print(f"[tracee] run_id={run_id} scoped={len(kept)} execs={execs} "
      f"signatures={dict(signature_detections)} -> {out}",
      file=sys.stderr)
PY

echo "$OUT"
