#!/usr/bin/env bash
#
# run_campaign2.sh — balanced detection campaign for the NEW diverse scenarios
# (A5 drop-and-execute, A6 sudoers modification, A7 benign control), 10 live
# trials each for the working tools (Falco built-in rules, Tracee signatures).
# Tetragon is excluded (verified container-capture regression).
#
# Each scenario's Tracee signature event-set comes from the catalog. Benign,
# non-destructive workloads in a throwaway alpine container.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
log(){ echo "[$(date +%H:%M:%S)] $*"; }

catval(){ python3 -I -c "import json,sys; c=json.load(open('experiments/comparison_catalog.json')); s=[x for x in c['scenarios'] if x['id']=='$1'][0]; print(s['$2'])"; }

for sc in A5 A6 A7; do
  pl="$(catval $sc payload)"
  tev="$(catval $sc tracee_events)"
  log "=== $sc : $pl ==="
  for t in $(seq 1 10); do
    if [ ! -f "results/runs/${sc}_falco_t${t}_falco.json" ]; then
      log "$sc falco t$t"
      ./scripts/capture_falco.sh "${sc}_falco_t${t}" configured alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  falco $sc t$t FAILED"
    fi
    if [ ! -f "results/runs/${sc}_tracee_t${t}_tracee.json" ]; then
      log "$sc tracee t$t"
      ./scripts/capture_tracee.sh "${sc}_tracee_t${t}" configured "$tev" alpine:3.20 sh -c "$pl" >/dev/null 2>&1 || log "  tracee $sc t$t FAILED"
    fi
  done
done
docker rm -f falco-lab tracee-lab >/dev/null 2>&1 || true
log "=== campaign2 complete ==="
