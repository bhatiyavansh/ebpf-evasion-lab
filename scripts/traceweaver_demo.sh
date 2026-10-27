#!/usr/bin/env bash
#
# TraceWeaver end-to-end demonstration (one command). Deterministic; replay-based
# (uses the repository's real eligible historical evidence). NEVER modifies raw
# evidence. Does not start a duplicate dashboard if one is already running.
#
#   ./scripts/traceweaver_demo.sh
#
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
ok(){ echo "  [ok] $*"; }
warn(){ echo "  [!!] $*"; }

echo "== TraceWeaver demo =="

echo "[1/8] verify repository + input artifacts"
[ -d results/raw ] && ok "raw evidence present" || { warn "results/raw missing"; exit 2; }
[ -f results/normalized/events_index.json ] && ok "Phase-1 normalized index present" \
  || warn "normalized index missing (will regenerate)"

echo "[2/8] normalize raw -> canonical events (idempotent; reads results/raw only)"
python3 -m scripts.traceweaver.pipeline >/dev/null && ok "normalized $(python3 -c 'import json;print(json.load(open("results/normalized/events_index.json"))["total_events"])') events"

echo "[3/8] validate provenance + schema + determinism"
python3 -m scripts.traceweaver.validate_evidence >/dev/null && ok "evidence provenance OK" || { warn "provenance validation FAILED"; exit 1; }

echo "[4/8] run the TraceWeaver detection engine"
python3 -m scripts.traceweaver.run >/dev/null && ok "engine scored $(python3 -c 'import json;print(json.load(open("results/engine/summary.json"))["total_streams"])') streams"

echo "[5/8] validate engine output + explanation provenance"
python3 -m scripts.traceweaver.cli validate >/dev/null && ok "every finding cites real evidence; no detection without policy evidence" || { warn "engine validation FAILED"; exit 1; }

echo "[6/8] generate evaluation (eligible trials only)"
python3 -m scripts.traceweaver.evaluate >/dev/null && ok "evaluation written" || warn "evaluation failed"

echo "[7/8] dashboard"
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/lab 2>/dev/null | grep -q 200; then
  ok "dashboard already running at http://localhost:3000/lab (TraceWeaver Engine tab)"
else
  warn "dashboard not running. Start with: (cd dashboard && source ../.toolchain/activate.sh && npm run start)"
fi

echo "[8/8] verify API endpoints respond (if dashboard up)"
for p in "lab" "api/evidence?path=results/engine/summary.json" "api/evidence?path=results/engine/evaluation.json"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/$p" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && ok "/$p -> 200" || warn "/$p -> $code"
done

echo
echo "== RESULT SUMMARY =="
python3 -m scripts.traceweaver.cli run --all --summary 2>/dev/null | sed 's/^/  /' | head -5
echo "  evaluation:"
python3 -c "import json;m=json.load(open('results/engine/evaluation.json'))['methods'];[print(f\"    {k:13} P={v['metrics']['precision']} R={v['metrics']['recall']} F1={v['metrics']['f1']}\") for k,v in m.items()]"
echo
echo "== LIMITATIONS =="
echo "  - Tetragon live container capture is broken post-reboot (COLLECTION_FAILED); Falco/Tracee unaffected."
echo "  - Replay demonstration over real historical evidence; not a fresh live capture."
echo "  - Small exploratory evaluation (see results/engine/evaluation.md); not statistically powered."
echo "  - Raw evidence is NOT modified by this demo."
