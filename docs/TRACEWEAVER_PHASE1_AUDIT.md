# TraceWeaver — Phase 1 Audit & Data Foundation

**Scope:** Phase 1 only (data foundation, canonical event schema, normalization,
evidence provenance, reproducibility). Phase 2 (detection engine) is **not** started.
Nothing was committed, pushed, or branched. No raw evidence was modified.

---

## 1. Repository baseline (as found)

- **Branch:** `main`, clean working tree, last commit `d02ce97 feat:dashboard`
  (the prior dashboard + pipeline work is committed).
- **Environment:** Kali Linux ARM64, kernel `7.1.5+kali-arm64`, `aarch64`, Docker.
- **Sensor versions in evidence:** `falcosecurity/falco:0.45.0`,
  `aquasec/tracee:latest`, `quay.io/cilium/tetragon:v1.6.0`.
- **Empty top-level dirs present** (`analysis/`, `attacks/`, `collectors/`, `runner/`) —
  no files; left untouched. The existing working pipeline lives in `scripts/` +
  `results/` + `dashboard/`, which Phase 1 **extends** (no competing pipeline).
- **Existing evidence (unchanged):** 18 raw result summaries, 111 raw event streams
  (43 Falco + 43 Tracee + 25 Tetragon `.jsonl`), 113 run manifests.
- **Baseline validators:** `scripts/validate.py` 40/40, `scripts/validate_comparison.py`
  19/19 (both still pass after Phase 1).
- **Evidence hash baseline:** 145 raw/config files hashed →
  `docs/traceweaver_phase1_evidence_baseline.sha256`. **Re-hashed after Phase 1: byte-identical.**
- **Known environmental limitation (pre-existing, documented):** Tetragon container-event
  capture regressed after a host reboot; live Tetragon runs are `COLLECTION_FAILED`
  (Falco/Tracee unaffected). See `docs/E04_ZERO_EVENT_DIAGNOSIS.md`. Not re-diagnosed here.

## 2. Files added (all additive; nothing overwritten)

| Path | Purpose |
|------|---------|
| `scripts/traceweaver/schema.py` | Canonical versioned event schema + missing-value sentinels + validator |
| `scripts/traceweaver/adapters.py` | Falco / Tracee / Tetragon normalization adapters |
| `scripts/traceweaver/manifest.py` | Trial-manifest contract + deterministic outcome classifier |
| `scripts/traceweaver/inventory.py` | Read-only historical-evidence inventory (hashes + capture modes) |
| `scripts/traceweaver/pipeline.py` | Deterministic normalize → validate → quarantine → report |
| `scripts/traceweaver/validate_evidence.py` | Standalone provenance validator (P1–P8) |
| `scripts/traceweaver_pipeline.sh` | One-command runner (inventory → normalize → validate) |
| `tests/test_traceweaver.py` | 17 regression tests (schema, adapters, provenance) |
| `tests/fixtures/` | Clearly-labelled **synthetic** fixtures (excluded from the real pipeline) |
| `results/inventory.json` | Generated evidence inventory |
| `results/normalized/events/*.jsonl` | Generated canonical events (111 streams) |
| `results/normalized/events_index.json` | Generated index/report |
| `results/normalized/quarantine.jsonl` | Malformed-record quarantine (currently empty) |
| `dashboard/lib/types.ts`, `dashboard/lib/data.ts`, `dashboard/app/api/traceweaver/` | Minimal dashboard read of canonical data |

## 3. Canonical event schema (`v1.0.0`)

A single schema representing all three sensors (field list in `schema.py:FIELDS`).
Key properties:

- **Versioned:** `SCHEMA_VERSION = "1.0.0"`; readers accept any `1.x` (new optional
  fields may appear); a MAJOR bump signals breaking changes.
- **Explicit missing-value semantics** — four distinct sentinels, never a bare null:
  `<NOT_SUPPLIED>`, `<UNPARSEABLE>`, `<NOT_APPLICABLE>`, `<UNKNOWN_COLLECTION>`.
  An absent container id becomes `<NOT_SUPPLIED>` — **never** a host event.
- **Canonical type vocabulary:** `process_exec, process_exit, file_open, file_write,
  network_connect, security_alert, other`. Trial-level detection significance is **not**
  assigned to individual events.
- **Full traceability:** every event carries `raw_ref = {file, line, sha256}` back to its
  exact source record. `event_id` is a deterministic hash of those source coordinates.
- **Timestamp provenance:** `timestamp_source ∈ {sensor_native, manifest_derived, unknown}`;
  timestamps are preserved (Tracee ns-epoch → ISO-8601, source marked).
- **Secret redaction:** copied command/args are redacted (`password=`, tokens, JWTs, AWS keys).

### Representative normalized events (real, with provenance)

```json
// Falco (security_alert) — raw_ref: results/raw/falco_events/A1_falco_t1.jsonl:1
{"sensor":"falco","canonical_type":"security_alert",
 "sensor_native_event":"Read sensitive file untrusted","file_path":"/etc/shadow",
 "container_id":"20e2fd35a389","timestamp_source":"sensor_native",
 "raw_ref":{"file":"results/raw/falco_events/A1_falco_t1.jsonl","line":1,"sha256":"8a9ce6a0…"}}

// Tracee behavioral signature (security_alert) — A6_tracee_t3.jsonl:8
{"sensor":"tracee","canonical_type":"security_alert",
 "sensor_native_event":"sudoers_modification","container_id":"ea800f39…",
 "raw_ref":{"file":"results/raw/tracee_events/A6_tracee_t3.jsonl","line":8,"sha256":"3f276c05…"}}

// Tetragon process exec — E02.jsonl:1
{"sensor":"tetragon","canonical_type":"process_exec","process_name":"sh",
 "process_args":"-c \"echo EXEC_TEST; id; uname -a\"","pid":53973,"container_id":"4d0f14b47fff…",
 "raw_ref":{"file":"results/raw/tetragon_events/E02.jsonl","line":1,"sha256":"2f579f12…"}}
```

## 4. Normalization coverage (real native output, not just fixtures)

Adapters were validated against the repository's **real** captured streams
(`results/raw/*_events/*.jsonl`), not only synthetic fixtures:

| Sensor | Streams | Canonical events | Native types mapped |
|--------|---------|------------------|---------------------|
| Falco | 43 | 156 | rule alerts → `security_alert` (+ file context) |
| Tracee | 43 | 1510 | `execve`→exec, `openat`/`security_file_open`→file_open, `connect`→network_connect, 27 behavioral signatures→`security_alert` |
| Tetragon | 25 | 402 | `process_exec`/`process_tracepoint`→exec, `process_exit`→exit, `process_kprobe(openat)`→file_open |
| **Total** | **111** | **2068** | 0 quarantined, 0 warnings, all `capture_mode=live` |

## 5. Execution / Collection / Telemetry / Detection are separated

The trial-manifest classifier (`manifest.classify_outcome`) assigns exactly one of
`DETECTED, TELEMETRY_ONLY, NOT_DETECTED, COLLECTION_FAILED, EXECUTION_FAILED,
NOT_EVALUATED, INCONCLUSIVE` from evidence only:

- **DETECTED** — a real qualifying finding exists in the raw manifest (Falco built-in
  non-custom rule, or a Tracee behavioral signature). The lab's custom process-exec
  Notice rule alone → `TELEMETRY_ONLY`, never DETECTED.
- **COLLECTION_FAILED** — verified execution but zero scoped events (Tetragon regression).
  Never demoted to NOT_DETECTED.
- **EXECUTION_FAILED** — non-zero/failed workload exit.
- **INCONCLUSIVE** — evidence insufficient (e.g. aggregate manifests lacking capture fields).

Observed classifier distribution over the 113 historical manifests:
`TELEMETRY_ONLY 89, DETECTED 20, COLLECTION_FAILED 1, EXECUTION_FAILED 1, INCONCLUSIVE 2`.

Notable honest edge cases surfaced (not papered over): `E02.json` is a **failed re-capture**
manifest (`execution_failed`) whose good 22-event stream is preserved separately;
`E06.json`/`E07.json` are **aggregate** manifests lacking capture fields → `INCONCLUSIVE`
(their per-trial sub-manifests carry the real outcomes).

## 6. Provenance validation (the mandatory correction)

`scripts/traceweaver/validate_evidence.py` is the standalone validator enforcing the
same provenance rules the pipeline relies on (all pass, 8/8):

- **P1** a DETECTED manifest must have a real qualifying finding (not a bare flag);
- **P2** summary-derived (no event stream) evidence cannot be DETECTED;
- **P3** synthetic fixtures are excluded from the real inventory;
- **P4** every manifest carries an explicit `capture_mode` (live/historical/…);
- **P5** a failed capture/exec is never NOT_DETECTED;
- **P6** every normalized event validates + `raw_ref` points to a real file;
- **P7** `event_id`s are unique within a stream;
- **P8** the pipeline is deterministic (identical report across runs).

Regression tests in `tests/test_traceweaver.py` pin these rules (17 tests, all pass),
including: *detection requires a real finding*, *custom telemetry rule ≠ detection*,
*collection-failed ≠ not-detected*, *absent container id ≠ host event*, *synthetic ≠ live*.

## 7. How to run (Phase 1)

```bash
cd ~/ebpf-evasion-lab
./scripts/traceweaver_pipeline.sh          # inventory → normalize → validate
python3 -m unittest tests.test_traceweaver # 17 regression tests
```

Individually: `python3 -m scripts.traceweaver.inventory`,
`python3 -m scripts.traceweaver.pipeline`, `python3 -m scripts.traceweaver.validate_evidence`.

## 8. Phase 2 input/output contract

Phase 2 (detection/scoring engine) **consumes**:
- `results/normalized/events/<sensor>__<label>.jsonl` — canonical events (schema `1.x`),
  one JSON object per line, sorted keys, each with `raw_ref` provenance.
- `results/normalized/events_index.json` — per-stream index (sensor, trial_id,
  capture_mode, event counts, canonical-type counts).
- `results/inventory.json` — evidence inventory (hashes, capture modes, derived outcomes).
- `scripts/traceweaver/manifest.classify_outcome(manifest)` — the deterministic
  trial-outcome function (import and reuse; do not re-derive).

Phase 2 must **not** mutate raw evidence or the canonical event files, must keep the
`capture_mode` / provenance distinctions, and must treat `COLLECTION_FAILED` / `summary_derived`
inputs as ineligible for a verified detection.

## 9. Limitations / honest notes

- Falco JSON output here carries no numeric `pid` field → `pid=<NOT_SUPPLIED>` for Falco events.
- Tetragon events carry no container **name** → `container_name=<NOT_SUPPLIED>`.
- Adapter coverage is validated against the native formats **present in this repo**; formats from
  other sensor versions are not claimed as validated.
- Tetragon live container capture remains broken (environment blocker); unaffected by Phase 1.
