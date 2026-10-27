# TraceWeaver — Limitations & unsupported inferences

- **Tetragon live container capture is broken** (environment regression after a host reboot;
  host events captured, container events not). Affected trials are honestly `COLLECTION_FAILED`
  and excluded from supervised metrics. Falco and Tracee are unaffected. See
  `docs/E04_ZERO_EVENT_DIAGNOSIS.md`.
- **Replay, not fresh live capture.** The demo replays the repository's real eligible historical
  evidence; it is labelled replay and never presented as a new live run.
- **Small exploratory evaluation** (52 eligible trials). No claims of statistical significance,
  universal superiority, or production readiness.
- **Scenario-level labels.** Per-sensor detectability differs by configuration; a sensor without a
  relevant rule/signature (e.g. Falco for sudoers) produces an honest coverage-gap FN, not an
  engine failure.
- **Anomaly signal is deliberately conservative** (sensitive/suspicious *actions* only, not novelty),
  which lowers false positives but will miss novel attack shapes it has no pattern for.
- **Field coverage** is bounded by what each sensor emits in this repo: Falco JSON has no numeric pid;
  Tetragon events carry no container name. Missing fields are explicit sentinels, never invented.
- **Not a prevention/response system.** TraceWeaver scores and explains; it does not block.
