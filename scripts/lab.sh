#!/usr/bin/env bash
#
# lab.sh — detector lifecycle + live experiment control for the eBPF Evasion Lab.
#
# Subcommands:
#   status                 Print environment + which lab detectors are running (JSON).
#   up-tetragon            Start the Tetragon detector container (tetragon-lab) with repo policies.
#   down-tetragon          Stop the Tetragon detector container.
#   run-tetragon <EID>     Run an allowlisted experiment (E01..E05) under Tetragon and capture
#                          scoped evidence. Regenerates raw + normalized + analysis on success.
#   down                   Stop all lab-managed detector/workload containers (only our named ones).
#
# Safety: only containers named tetragon-lab / falco-lab / tracee-lab / lab-workload-* are
# ever touched. Experiment commands come from experiments/catalog.json (allowlist), never
# from arbitrary input. Workloads run with a bounded timeout.
#
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TETRAGON_CTR="tetragon-lab"
TETRAGON_IMAGE="quay.io/cilium/tetragon:v1.6.0"

is_running() { docker ps --format '{{.Names}}' | grep -qx "$1"; }

cmd_status() {
  python3 -I - "$REPO" <<'PY'
import json, os, shutil, subprocess, sys
repo = sys.argv[1]
def sh(c):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception: return None
def running(name):
    out = sh("docker ps --format '{{.Names}}'") or ""
    return name in out.split()
docker_ok = shutil.which("docker") is not None and sh("docker info >/dev/null 2>&1 && echo ok") == "ok"
status = {
    "kernel": sh("uname -r"),
    "arch": sh("uname -m"),
    "btf_vmlinux": os.path.exists("/sys/kernel/btf/vmlinux"),
    "docker_available": docker_ok,
    "detectors_live": {
        "falco": running("falco-lab"),
        "tracee": running("tracee-lab"),
        "tetragon": running("tetragon-lab"),
    },
    "images_present": {
        "falco": bool(sh("docker image inspect falcosecurity/falco:0.45.0 >/dev/null 2>&1 && echo 1")),
        "tracee": bool(sh("docker image inspect aquasec/tracee:latest >/dev/null 2>&1 && echo 1")),
        "tetragon": bool(sh("docker image inspect quay.io/cilium/tetragon:v1.6.0 >/dev/null 2>&1 && echo 1")),
    },
    "note": "detectors_live is a LIVE health check; it does not reflect whether past evidence exists.",
}
print(json.dumps(status, indent=2))
PY
}

cmd_up_tetragon() {
  # Optional first arg: policy subdir under detectors/tetragon/ (default "policies").
  local policy_dir="${1:-policies}"
  if is_running "$TETRAGON_CTR"; then echo "$TETRAGON_CTR already running"; return 0; fi
  docker rm -f "$TETRAGON_CTR" >/dev/null 2>&1 || true
  docker run -d --rm --name "$TETRAGON_CTR" \
    --pid=host --cgroupns=host --privileged \
    -v /sys/kernel:/sys/kernel:ro \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v "$REPO/detectors/tetragon/${policy_dir}:/etc/tetragon/tetragon.tp.d:ro" \
    "$TETRAGON_IMAGE" >/dev/null
  # wait (bounded) for a tracing policy to load
  for _ in $(seq 1 20); do
    if docker logs "$TETRAGON_CTR" 2>&1 | grep -qE "ebpf-lab-process-exec|ebpf-lab-sensitive-file-detect"; then
      echo "$TETRAGON_CTR up (policies loaded from ${policy_dir})"; return 0
    fi
    sleep 1
  done
  echo "$TETRAGON_CTR started but policy-load confirmation timed out" >&2
  return 0
}

cmd_down_tetragon() {
  docker stop "$TETRAGON_CTR" >/dev/null 2>&1 && echo "$TETRAGON_CTR stopped" || echo "$TETRAGON_CTR not running"
}

cmd_run_tetragon() {
  local eid="${1:?experiment id required (E01..E05)}"
  # Resolve the allowlisted shell payload from the catalog. The container always
  # runs exactly `sh -c "<payload>"` — one shell layer — so E04's intentional
  # indirection lives inside the payload, not in an accidental extra wrapper.
  local payload
  payload="$(python3 -I - "$REPO" "$eid" <<'PY'
import json, sys
repo, eid = sys.argv[1], sys.argv[2]
cat = json.load(open(f"{repo}/experiments/catalog.json"))
exp = next((e for e in cat["experiments"] if e["id"] == eid), None)
if not exp:
    sys.exit(f"unknown experiment {eid}")
print(exp["shell_payload"])
PY
)"
  if [ -z "$payload" ]; then echo "no payload resolved for $eid" >&2; return 2; fi
  if ! is_running "$TETRAGON_CTR"; then
    echo "Tetragon not running; starting it..." >&2
    cmd_up_tetragon >&2
  fi
  echo "[run-tetragon] $eid : sh -c '$payload'" >&2
  "$REPO/scripts/capture_tetragon.sh" "$eid" alpine:3.20 sh -c "$payload" >/dev/null
  python3 -I "$REPO/scripts/gen_tetragon_raw.py" >/dev/null
  "$REPO/scripts/pipeline.sh" >/dev/null
  echo "[run-tetragon] $eid complete; evidence + normalized data regenerated." >&2
  cat "$REPO/results/raw/${eid}_tetragon.json"
}

cmd_down() {
  for c in "$TETRAGON_CTR" falco-lab tracee-lab; do
    docker stop "$c" >/dev/null 2>&1 && echo "stopped $c" || true
  done
  for c in $(docker ps -a --format '{{.Names}}' | grep '^lab-workload-' || true); do
    docker rm -f "$c" >/dev/null 2>&1 && echo "removed $c" || true
  done
}

case "${1:-}" in
  status) cmd_status ;;
  up-tetragon) shift || true; cmd_up_tetragon "$@" ;;
  down-tetragon) cmd_down_tetragon ;;
  run-tetragon) shift; cmd_run_tetragon "$@" ;;
  down) cmd_down ;;
  *) echo "usage: $0 {status|up-tetragon|down-tetragon|run-tetragon <EID>|down}" >&2; exit 2 ;;
esac
