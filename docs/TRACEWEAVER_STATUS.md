# TraceWeaver — Status

## Completed
- [x] Phase 1 data foundation intact; raw evidence byte-identical.
- [x] Phase 2 engine: behavior graph, A/S/P signals, risk, visibility-aware verdict, explanations.
- [x] Deterministic, configurable (engine_config.json; weights sum to 1.0, enforced).
- [x] CLI: run / validate (explanation+provenance) / eligible.
- [x] Phase 3 dashboard: TraceWeaver Engine tab (overview, evaluation, trial explorer, timeline,
      graph summary, explanation, evidence drill-down). Existing routes still work.
- [x] Phase 4 evaluation: 3 baselines on the same eligible set, metrics with explicit denominators,
      train/eval split (no leakage), benign-control negatives.
- [x] Phase 5 demo: one command, deterministic, non-destructive.
- [x] Tests: 38 Python (17 schema/adapter/provenance + 21 engine/eval), 8 provenance, 40 + 19 legacy.
- [x] Production build compiles; routes + engine APIs 200.
- [x] Final raw-evidence hash comparison: byte-identical.

## Blocked / incomplete
- [ ] Tetragon live container capture (environment blocker; documented, not faked).
- [ ] Graph visualization is a correct **structured/textual** summary (nodes/edges/gaps + process
      timeline), not a force-directed graphic — a deliberate reliability choice for the deadline.
- [ ] Live-mode capture is not wired into the engine view (replay over historical evidence is used);
      the capture harnesses exist (`scripts/capture_*.sh`) and remain usable for Falco/Tracee.

## Not started (future)
- Streaming/online scoring; larger balanced dataset; additional patterns; force-directed graph UI.

## Final audit + Demo tab (added)
- [x] Interactive **Demo tab** in the dashboard (Lab → ★ Demo): 5 guided steps, real engine data,
      HISTORICAL REPLAY label, presenter notes, Prev/Next/Reset/Copy, live "Run engine" action
      (allowlisted server route `/api/traceweaver/run`, traversal-guarded).
- [x] Adversarial evaluation audit passed (metrics independently reconstructed; A7 held out; 23
      streams differ between rules-only and combined).
- [x] Final acceptance: 43 py tests, 40+19 validators, 8 provenance, build, routes, API guards,
      byte-identical evidence — all verified.
