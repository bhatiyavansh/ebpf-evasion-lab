"""
TraceWeaver canonical event schema (Phase 1).

One versioned schema that represents the real outputs of Falco, Tracee and
Tetragon as a shared vocabulary, WITHOUT inventing missing fields. Every
normalized record traces back to its exact source record (file + line + hash).

This module is pure stdlib and deterministic. It defines:
  * SCHEMA_VERSION and compatibility notes
  * explicit missing-value sentinels (4 distinct meanings)
  * the canonical event-type vocabulary
  * a builder + validator for canonical events

Missing-value semantics (NEVER collapse these into a bare null):
  NOT_SUPPLIED      the source did not provide this field
  UNPARSEABLE       the source supplied it but it could not be parsed
  NOT_APPLICABLE    the field does not apply to this event type
  UNKNOWN_COLLECTION unknown because collection/attribution failed or is unknown
"""
from __future__ import annotations

SCHEMA_VERSION = "1.0.0"

# Compatibility: readers must treat any SCHEMA_VERSION with the same MAJOR as
# forward-compatible (new optional fields may appear). A MAJOR bump means a
# breaking change to existing field meanings. Phase 2 consumes 1.x only.
SCHEMA_COMPATIBLE_MAJOR = 1

# --- explicit missing-value sentinels (strings so they survive JSON) ---
NOT_SUPPLIED = "<NOT_SUPPLIED>"
UNPARSEABLE = "<UNPARSEABLE>"
NOT_APPLICABLE = "<NOT_APPLICABLE>"
UNKNOWN_COLLECTION = "<UNKNOWN_COLLECTION>"
MISSING_SENTINELS = {NOT_SUPPLIED, UNPARSEABLE, NOT_APPLICABLE, UNKNOWN_COLLECTION}

# --- canonical event-type vocabulary (shared across sensors) ---
CANONICAL_TYPES = {
    "process_exec",     # a process was executed
    "process_exit",     # a process exited
    "file_open",        # a file was opened (NOT proof it was read)
    "file_write",       # a file write/modify was observed
    "network_connect",  # an outbound connection attempt (NOT proof it succeeded)
    "security_alert",   # a sensor raised a qualifying/notice alert (Falco rule, Tracee signature)
    "other",            # a captured event outside the shared vocabulary
}

# --- timestamp provenance ---
TIMESTAMP_SOURCES = {"sensor_native", "manifest_derived", "unknown"}

# --- capture modes (provenance of the whole evidence record) ---
CAPTURE_MODES = {"live", "replay", "historical", "summary_derived", "synthetic"}

# Ordered field list = the canonical record shape. Order is stable for
# deterministic serialization.
FIELDS = [
    "schema_version",
    "event_id",            # deterministic id (see build)
    "trial_id",            # run/trial this event belongs to
    "scenario_id",         # scenario label (A1.., E01..) or NOT_SUPPLIED
    "sensor",              # falco | tracee | tetragon
    "sensor_version",      # exact sensor version or NOT_SUPPLIED
    "policy_mode",         # baseline | configured | NOT_APPLICABLE
    "capture_mode",        # live | replay | historical | summary_derived | synthetic
    "timestamp",           # iso8601 or sentinel
    "timestamp_source",    # sensor_native | manifest_derived | unknown
    "container_id",        # full/short container id or sentinel
    "container_name",      # or sentinel
    "pid",                 # int or sentinel
    "parent_pid",          # int or sentinel
    "process_name",        # or sentinel
    "process_args",        # REDACTED-safe args string or sentinel
    "canonical_type",      # one of CANONICAL_TYPES
    "file_path",           # or NOT_APPLICABLE/sentinel
    "file_operation",      # open|write|read or NOT_APPLICABLE
    "network_dest",        # host/ip or NOT_APPLICABLE
    "network_port",        # int or NOT_APPLICABLE
    "sensor_native_event", # Falco rule / Tracee eventName / Tetragon kind
    "raw_ref",             # {file, line, sha256}
    "collection_status",   # complete | collection_failed_* | unknown
    "normalization_warnings",  # list[str]
]

# Fields that must never be a missing sentinel (always concretely set).
REQUIRED_CONCRETE = {
    "schema_version", "event_id", "trial_id", "sensor", "capture_mode",
    "canonical_type", "sensor_native_event", "raw_ref", "collection_status",
}

# --- secret redaction for copied args / free-text ---
import re as _re

_SECRET_PATTERNS = [
    (_re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|bearer)\s*[=:]\s*\S+"), r"\1=<REDACTED>"),
    (_re.compile(r"(?i)(-p|--password)\s+\S+"), r"\1 <REDACTED>"),
    (_re.compile(r"(?i)AKIA[0-9A-Z]{16}"), "<REDACTED_AWS_KEY>"),
    (_re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "<REDACTED_JWT>"),
]


def redact(text):
    """Redact likely secrets from a copied command/arg string. Returns the
    redacted string, or the sentinel unchanged if text is a sentinel/missing."""
    if text is None:
        return NOT_SUPPLIED
    if text in MISSING_SENTINELS:
        return text
    s = str(text)
    for pat, repl in _SECRET_PATTERNS:
        s = pat.sub(repl, s)
    return s


def _stable_event_id(sensor, trial_id, raw_file, raw_line, native_event, timestamp):
    """Deterministic event id from immutable source coordinates."""
    import hashlib
    basis = f"{sensor}|{trial_id}|{raw_file}|{raw_line}|{native_event}|{timestamp}"
    return "ev_" + hashlib.sha256(basis.encode()).hexdigest()[:20]


def build_event(**kw):
    """Build a canonical event dict with defaults filled as NOT_SUPPLIED.
    Computes event_id deterministically if not provided. Does not invent data."""
    ev = {f: kw.get(f, NOT_SUPPLIED) for f in FIELDS}
    ev["schema_version"] = SCHEMA_VERSION
    if ev.get("normalization_warnings") in (NOT_SUPPLIED, None):
        ev["normalization_warnings"] = []
    raw = ev.get("raw_ref")
    if ev.get("event_id") in (NOT_SUPPLIED, None):
        rf = (raw or {}).get("file", "?") if isinstance(raw, dict) else "?"
        rl = (raw or {}).get("line", "?") if isinstance(raw, dict) else "?"
        ev["event_id"] = _stable_event_id(
            ev.get("sensor"), ev.get("trial_id"), rf, rl,
            ev.get("sensor_native_event"), ev.get("timestamp"))
    return ev


def validate_event(ev):
    """Return a list of schema violations (empty == valid)."""
    errs = []
    missing_fields = [f for f in FIELDS if f not in ev]
    if missing_fields:
        errs.append(f"missing fields: {missing_fields}")
    if ev.get("schema_version", "").split(".")[0:1] != [str(SCHEMA_COMPATIBLE_MAJOR)]:
        errs.append(f"incompatible schema_version {ev.get('schema_version')}")
    if ev.get("canonical_type") not in CANONICAL_TYPES:
        errs.append(f"invalid canonical_type {ev.get('canonical_type')}")
    if ev.get("capture_mode") not in CAPTURE_MODES:
        errs.append(f"invalid capture_mode {ev.get('capture_mode')}")
    ts_src = ev.get("timestamp_source")
    if ts_src not in TIMESTAMP_SOURCES and ts_src not in MISSING_SENTINELS:
        errs.append(f"invalid timestamp_source {ts_src}")
    for f in REQUIRED_CONCRETE:
        v = ev.get(f)
        if isinstance(v, str) and v in MISSING_SENTINELS:
            errs.append(f"required field {f} is a missing sentinel ({v})")
    raw = ev.get("raw_ref")
    if not isinstance(raw, dict) or "file" not in raw:
        errs.append("raw_ref must be a dict with at least a 'file' key")
    return errs
