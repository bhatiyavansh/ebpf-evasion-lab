#!/usr/bin/env bash
#
# run_expansion.sh — collect additional INDEPENDENT live trials (4..10) for the
# working live tools (Falco, Tracee) across the A1-A3 scenarios. Each trial is a
# fresh workload execution with a unique run ID; existing trials 1-3 are kept.
# Tetragon is intentionally excluded (verified container-capture regression ->
# COLLECTION_FAILED; re-running would only produce failed captures).
#
# Non-destructive, benign workloads only. ~22 min total.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
TRACEE_EVENTS="execve,openat,security_file_open,security_socket_connect"
log(){ echo "[$(date +%H:%M:%S)] $*"; }

declare -A PAYLOAD=(
  [A1]='cat /etc/shadow >/dev/null'
  [A2]='sh -c "id; uname -a"'
  [A3]='id; uname -a; cat /etc/os-release >/dev/null; hostname'
)

for sc in A1 A2 A3; do
  pl="${PAYLOAD[$sc]}"
  for t in 4 5 6 7 8 9 10; do
    # skip if this trial already exists (never overwrite / never pad)
    if [ ! -f "results/runs/${sc}_falco_t${t}_falco.json" ]; then
      log "${sc} falco t${t}"
      ./scripts/capture_falco.sh "${sc}_falco_t${t}" configured alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  falco ${sc} t${t} FAILED"
    fi
    if [ ! -f "results/runs/${sc}_tracee_t${t}_tracee.json" ]; then
      log "${sc} tracee t${t}"
      ./scripts/capture_tracee.sh "${sc}_tracee_t${t}" baseline "$TRACEE_EVENTS" alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  tracee ${sc} t${t} FAILED"
    fi
  done
done

docker rm -f falco-lab tracee-lab >/dev/null 2>&1 || true
log "=== expansion complete ==="
