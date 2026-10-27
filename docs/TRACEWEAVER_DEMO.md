# TraceWeaver — 60–90 second demo

## One command (deterministic, replay over real evidence; never modifies raw data)
```bash
cd ~/ebpf-evasion-lab
./scripts/traceweaver_demo.sh
```
It normalizes → validates provenance → runs the engine → validates explanations →
evaluates → checks the dashboard/API → prints a summary + limitations.

## Dashboard walkthrough (90s)
Open **http://localhost:3000/lab** (default tab: **TraceWeaver Engine**).

1. **Overview (15s):** 111 streams scored — 20 DETECTED, 63 TELEMETRY_ONLY, 1 COLLECTION_FAILED.
   "A verdict of DETECTED requires verified policy evidence; a high risk never overrides a collection failure."
2. **Evaluation table (20s):** rules-only F1 0.61 → **TraceWeaver (combined) F1 0.97**, precision 1.0,
   0 false positives on the benign control. One honest FN = Falco/A6 (no sudoers rule).
3. **Trial explorer (30s):** pick an **A1 · tracee** trial → verdict TELEMETRY_ONLY, risk band, the
   `sensitive_file_access` pattern with its MITRE tag and the exact evidence file:line; pick an
   **A6 · tracee** → **DETECTED** with the `sudoers_modification` signature as qualifying evidence.
4. **Visibility (15s):** pick the Tetragon **E04** → **COLLECTION_FAILED**, risk 0 — "missing events are
   not treated as evidence the behavior did not occur."
5. **Drill-down (10s):** expand "Inspect full engine result" → every finding has event IDs + raw_ref.

## Troubleshooting
- Page loads unstyled once → transient browser resource block; reload.
- Dashboard not running → `(cd dashboard && source ../.toolchain/activate.sh && npm run start)`.
- Recompute everything from evidence → `./scripts/traceweaver_demo.sh` (idempotent).

## In-dashboard Demo tab (recommended for faculty)
Open **http://localhost:3000/lab** → click **★ Demo** (first sub-tab). One screen, 5 steps:
1. **The problem** — architecture diagram; collection failure ≠ safety.
2. **Unified evidence** — pick a sensor/trial, load real canonical events with file:line:sha256.
3. **Detection in action** — pick a verified trial (e.g. A1·falco, A6·tracee); click **Run engine on
   this trial** to execute the real engine live; expand "Open full trial details".
4. **Visibility-aware verdict** — the verdict taxonomy + a real COLLECTION_FAILED example (Tetragon E04).
5. **Evaluation & limits** — the 3-method table with denominators + ineligible reasons + caveats.
Controls: Prev/Next, step dots, Reset, Copy summary. Works offline over historical replay.
Start command: `(cd dashboard && source ../.toolchain/activate.sh && npm run start)`.
