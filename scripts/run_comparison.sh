#!/usr/bin/env bash
#
# run_comparison.sh — run the fair detection comparison study with REAL captures.
#
# Scenarios (MITRE-mapped, non-destructive, benign throwaway alpine container):
#   A1 Credential access   (T1552.001/T1555): read /etc/shadow  [alpine shadow holds no real secret]
#   A2 Nested shell exec   (T1059.004):        sh -c "id; uname -a"  (extra shell layer)
#   A3 Discovery           (T1082/T1033):      id; uname -a; cat /etc/os-release; hostname
#
# For each scenario we run 3 trials per tool/config and capture genuine evidence:
#   Falco (security rules on), Tracee (telemetry), Tetragon baseline (telemetry),
#   and for A1 additionally Tetragon CONFIGURED (selective sensitive-file policy).
#
# No synthetic events. If a detector/trial fails, its manifest records the failure.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
TRACEE_EVENTS="execve,openat,security_file_open,security_socket_connect"

log(){ echo "[$(date +%H:%M:%S)] $*"; }

falco_trials(){ local sc="$1" pl="$2"; for t in 1 2 3; do
  log "A${sc} falco t${t}"; ./scripts/capture_falco.sh "A${sc}_falco_t${t}" configured alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  falco t${t} FAILED"
done; }

tracee_trials(){ local sc="$1" pl="$2"; for t in 1 2 3; do
  log "A${sc} tracee t${t}"; ./scripts/capture_tracee.sh "A${sc}_tracee_t${t}" baseline "$TRACEE_EVENTS" alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  tracee t${t} FAILED"
done; }

tetragon_trials(){ local sc="$1" pl="$2" tag="$3"; for t in 1 2 3; do
  log "A${sc} tetragon(${tag}) t${t}"; ./scripts/capture_tetragon.sh "A${sc}_tet${tag}_t${t}" alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  tetragon t${t} FAILED"
done; }

A1='cat /etc/shadow >/dev/null'
A2='sh -c "id; uname -a"'
A3='id; uname -a; cat /etc/os-release >/dev/null; hostname'

log "=== A1 credential access ==="
falco_trials 1 "$A1"
tracee_trials 1 "$A1"
./scripts/lab.sh up-tetragon policies >/dev/null 2>&1;            tetragon_trials 1 "$A1" B; ./scripts/lab.sh down-tetragon >/dev/null 2>&1
./scripts/lab.sh up-tetragon policies-configured >/dev/null 2>&1; tetragon_trials 1 "$A1" C; ./scripts/lab.sh down-tetragon >/dev/null 2>&1

log "=== A2 nested shell ==="
falco_trials 2 "$A2"
tracee_trials 2 "$A2"
./scripts/lab.sh up-tetragon policies >/dev/null 2>&1; tetragon_trials 2 "$A2" B; ./scripts/lab.sh down-tetragon >/dev/null 2>&1

log "=== A3 discovery ==="
falco_trials 3 "$A3"
tracee_trials 3 "$A3"
./scripts/lab.sh up-tetragon policies >/dev/null 2>&1; tetragon_trials 3 "$A3" B; ./scripts/lab.sh down-tetragon >/dev/null 2>&1

# Safety: ensure no detector left running
./scripts/lab.sh down >/dev/null 2>&1
docker rm -f falco-lab tracee-lab >/dev/null 2>&1 || true
log "=== comparison study complete ==="
