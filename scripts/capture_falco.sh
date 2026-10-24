#!/usr/bin/env bash
#
# capture_falco.sh — run one benign/benign-emulation workload while Falco is
# active (modern eBPF) and capture the REAL Falco JSON alerts scoped to that
# workload container, plus a run manifest.
#
# This replaces hand-authored Falco summaries with genuine captured alerts.
# Qualifying-detection criterion (documented): a fired rule whose priority is
# Warning or higher AND which is NOT the lab's own process-execution Notice rule
# ("EBPF Lab Container Process Execution"). Such rules are Falco's built-in
# security rules (they carry mitre_* / security tags). The custom process-exec
# rule is retained as telemetry-grade signal, never counted as a detection.
#
# Usage: capture_falco.sh <RUN_LABEL> <MODE> <WORKLOAD_IMAGE> <command...>
#   MODE = baseline | configured   (recorded in the manifest; both load the same
#          ruleset here because Falco ships its security rules by default — the
#          distinction is documented, not faked)
# Requires: Docker, falcosecurity/falco:0.45.0, BTF.
#
set -euo pipefail

RUN_LABEL="${1:?run label required}"
MODE="${2:?mode required: baseline|configured}"
IMAGE="${3:?workload image required}"
shift 3
CMD=("$@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID_DIR="$REPO_ROOT/results/raw/falco_events"
RUNS_DIR="$REPO_ROOT/results/runs"
mkdir -p "$EVID_DIR" "$RUNS_DIR"

FALCO_CTR="falco-lab"
FALCO_IMAGE="falcosecurity/falco:0.45.0"
RUN_ID="run-${RUN_LABEL}-falco-$(date +%Y%m%d%H%M%S)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# (Re)start Falco fresh so the log window is clean for this capture.
docker rm -f "$FALCO_CTR" >/dev/null 2>&1 || true
docker run -d --rm --name "$FALCO_CTR" --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /proc:/host/proc:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$REPO_ROOT/detectors/falco/baseline_rules.yaml:/etc/falco/rules.d/baseline_rules.yaml:ro" \
  "$FALCO_IMAGE" \
  falco -o engine.kind=modern_ebpf -o json_output=true -o stdout_output.enabled=true \
        -o buffered_outputs=false >/dev/null 2>&1

# Wait (bounded) for Falco to open the syscall source, then allow the modern-BPF
# probe to attach and begin delivering events before the workload runs.
for _ in $(seq 1 30); do
  docker logs "$FALCO_CTR" 2>&1 | grep -q "Opening 'syscall' source" && break
  sleep 1
done
sleep 6

WL_NAME="lab-workload-${RUN_LABEL}-falco"
docker rm -f "$WL_NAME" >/dev/null 2>&1 || true
echo "[falco] $MODE run: docker run ${IMAGE} ${CMD[*]}" >&2
CID="$(docker run -d --rm --name "$WL_NAME" "$IMAGE" "${CMD[@]}")"
SHORT="${CID:0:12}"
timeout 30 docker wait "$CID" >/dev/null 2>&1 || true
sleep 3

ALERTS_FILE="$(mktemp)"
trap 'rm -f "$ALERTS_FILE"' EXIT
docker logs "$FALCO_CTR" 2>&1 | grep -E '^\{' > "$ALERTS_FILE" || true
docker stop "$FALCO_CTR" >/dev/null 2>&1 || true
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

OUT="$EVID_DIR/${RUN_LABEL}.jsonl"
MANIFEST="$RUNS_DIR/${RUN_LABEL}_falco.json"

python3 -I - "$ALERTS_FILE" "$SHORT" "$OUT" "$MANIFEST" \
  "$RUN_ID" "$STARTED_AT" "$ENDED_AT" "$RUN_LABEL" "$MODE" "$CID" "${CMD[*]}" <<'PY'
import json, sys, os
alerts_file, short, out, manifest, run_id, started, ended, label, mode, cid, cmd = sys.argv[1:12]
CUSTOM_RULE = "EBPF Lab Container Process Execution"
PRIO_RANK = {"Emergency":7,"Alert":6,"Critical":5,"Error":4,"Warning":3,
             "Notice":2,"Informational":1,"Debug":0}
kept = []
for line in open(alerts_file):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        ev = json.loads(line)
    except Exception:
        continue
    cidf = (ev.get("output_fields", {}) or {}).get("container.id", "") or ""
    if cidf and cidf.startswith(short[:12]):
        kept.append(ev)

# Classify each alert; qualifying security detections vs custom telemetry rule.
qualifying, custom_notices = [], []
for ev in kept:
    rule = ev.get("rule", "")
    prio = ev.get("priority", "")
    tags = ev.get("tags", []) or []
    is_custom = rule == CUSTOM_RULE
    mitre = [t for t in tags if t.startswith("T1") or t.startswith("mitre_")]
    qualifies = (not is_custom) and PRIO_RANK.get(prio, 0) >= PRIO_RANK["Warning"]
    rec = {"rule": rule, "priority": prio, "tags": tags, "mitre": mitre,
           "output": ev.get("output", ""),
           "fields": {k: v for k, v in (ev.get("output_fields", {}) or {}).items()
                      if v is not None}}
    (qualifying if qualifies else custom_notices).append(rec)

with open(out, "w") as f:
    for ev in kept:
        f.write(json.dumps(ev) + "\n")

mani = {
    "run_id": run_id, "run_label": label, "tool": "falco", "mode": mode,
    "provenance": "live", "started_at": started, "ended_at": ended,
    "workload_image": "alpine:3.20", "workload_cmd": cmd,
    "container_id": cid, "container_short": short,
    "tool_version": "falcosecurity/falco:0.45.0",
    "driver": "modern_ebpf",
    "total_alerts": len(kept),
    "qualifying_detections": qualifying,
    "custom_rule_notices": custom_notices,
    "evidence_events": f"results/raw/falco_events/{label}.jsonl",
}
with open(manifest, "w") as f:
    f.write(json.dumps(mani, indent=2) + "\n")
print(f"[falco] run_id={run_id} alerts={len(kept)} qualifying={len(qualifying)} "
      f"custom_notices={len(custom_notices)} -> {out}", file=sys.stderr)
PY

echo "$OUT"
