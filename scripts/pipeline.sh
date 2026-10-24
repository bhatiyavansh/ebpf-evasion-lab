#!/usr/bin/env bash
# pipeline.sh — regenerate normalized results, analysis, and summary CSV,
# then validate. Single command to make the dataset reproducible.
#   ./scripts/pipeline.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
echo "[1/5] regenerate tetragon raw from captured events (idempotent)"
python3 -I scripts/gen_tetragon_raw.py >/dev/null
[ -f results/runs/E08.json ] && python3 -I scripts/gen_new_experiments.py >/dev/null || \
  echo "       (E06-E08 manifests not present; skipping new-experiment regen)"
echo "[2/5] normalize  (raw -> normalized + summary.csv)"
python3 -I scripts/normalize.py
echo "[3/6] analyze    (normalized -> analysis.json + runs.json)"
python3 -I scripts/analyze.py
echo "[4/6] comparison (A-series run manifests -> comparison.json)"
[ -n "$(ls results/runs/A1_* 2>/dev/null)" ] && python3 -I scripts/build_comparison.py >/dev/null && echo "       comparison rebuilt" || echo "       (no A-series runs; skipping comparison)"
echo "[5/6] validate   (integrity + schema tests)"
python3 -I scripts/validate.py
[ -f results/analysis/comparison.json ] && python3 -I scripts/validate_comparison.py | tail -1
echo "[6/6] done. Dashboard reads normalized + analysis + comparison artifacts"
