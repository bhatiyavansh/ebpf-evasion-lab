#!/usr/bin/env bash
# TraceWeaver Phase 1 pipeline — inventory → normalize → validate (deterministic).
# Reads ONLY results/raw/ (never mutates it); writes derived artifacts under
# results/inventory.json and results/normalized/{events/,events_index.json,quarantine.jsonl}.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
echo "[1/3] inventory (read-only, hashes + capture modes)"
python3 -m scripts.traceweaver.inventory
echo "[2/3] normalize raw streams -> canonical events"
python3 -m scripts.traceweaver.pipeline
echo "[3/3] validate evidence provenance + schema + determinism"
python3 -m scripts.traceweaver.validate_evidence
echo "done. Phase 2 input: results/normalized/events/*.jsonl (+ events_index.json)"
