# TraceWeaver — Final Audit

Independent verification of Phases 1–5 plus the new interactive Demo tab. No raw
evidence modified; no commit/push/branch.

## Adversarial evaluation audit (Part 2) — PASSED

The reported metrics were **independently reconstructed** from trial-level
`results/engine/results.jsonl` and match `evaluation.json` exactly:

| Method | TP | FP | TN | FN | reconstruction |
|--------|----|----|----|----|----------------|
| rules_only | 20 | 0 | 6 | 26 | MATCH |
| anomaly_only | 33 | 0 | 6 | 13 | MATCH |
| combined (TraceWeaver) | 43 | 0 | 6 | 3 | MATCH |

Verified integrity properties:
- **Same eligible set + rules** for all three methods (52 eligible; reconstructed independently).
- **A7 benign controls are held out** — not in `baseline_fit_on`, used only as the 6 negatives.
- **Thresholds not selected using held-out labels** — weights/thresholds are fixed in
  `engine_config.json`; the anomaly baseline is fit only on A2/A3/E-series.
- **Baseline ≠ combined decision logic** — they differ on 23 eligible streams (non-trivial).
- **Denominators explicit**; undefined metrics render `N/A`; excluded trials carry reasons.
- **Reconstructable** from trial-level results (this audit does exactly that).
- The one FN (Falco/A6 ×3) is an honest **sensor coverage gap** (no sudoers rule), not an engine bug.

New adversarial tests (`tests/test_engine.py::AdversarialTests`): explanation cannot cite a
nonexistent event; summary-derived cannot be DETECTED without real policy evidence; out-of-order +
duplicate events handled; benign shell not detected; high-risk + insufficient visibility not promoted.

## Acceptance checklist — actual results

| # | Check | Result |
|---|-------|--------|
| 13 | All Python tests | **OK** (43: 17 schema/adapter/provenance + 26 engine/eval/adversarial) |
| 14 | Existing validators | validate.py **40/40**, validate_comparison **19/19** |
| 15 | Provenance + explanation | provenance **8/8**, cli validate **OK** |
| 16 | Production build | **compiles** |
| 17 | Routes + engine APIs | `/ /lab /cve-lab /outcome /demo` + engine API **200** |
| 11 | API path guard | traversal + non-allowlisted stream **blocked** |
| 12 | One-command demo | `./scripts/traceweaver_demo.sh` **OK** |
| 18 | `git diff --check` | **clean** |
| 19 | Protected evidence | **145 raw files byte-identical** |
| — | Run-engine action | real server run A6→DETECTED in ~180ms, allowlisted |

## Demo tab verification
Rendered the Demo tab (Lab → ★ Demo): real figures (111 streams, 2068 canonical events, 52 eligible,
20 detected), HISTORICAL REPLAY label, 5 steps navigable (Prev/Next/Reset/Copy), Step 3 "Run engine on
this trial" executed the **real** engine (not simulated) and confirmed "live engine run matches", with
every finding citing the exact raw source (`A1_falco_t1.jsonl:3`). No fabricated values.

## Discrepancies with prior handoff
None material. Prior handoff reported 2,068 events / Falco 156 / Tracee 1,510 / Tetragon 402 and
F1 0.966 — all reproduced exactly this audit. Values are read live from engine output, never hardcoded.
