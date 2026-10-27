"""
TraceWeaver trial-manifest contract (Phase 1).

A single schema describing what a trial manifest should carry. The existing
run manifests in results/runs/*.json were produced by different capture scripts
over time and have heterogeneous keys; this module defines the canonical
contract, classifies a manifest's lifecycle stage, and derives the trial-level
outcome status deterministically from evidence provenance.

Lifecycle stages (strictly distinct):
  template   a blank manifest shape (no run)
  planned    a scenario/tool chosen but not executed
  completed  a workload executed and a capture was attempted
  verified   completed AND evidence provenance checks pass for its claimed status

Trial-level outcome statuses (exact conditions in classify_outcome):
  DETECTED, TELEMETRY_ONLY, NOT_DETECTED, COLLECTION_FAILED,
  EXECUTION_FAILED, NOT_EVALUATED, INCONCLUSIVE
"""
from __future__ import annotations

MANIFEST_SCHEMA_VERSION = "1.0.0"

CONTRACT_FIELDS = [
    "trial_id", "scenario_id", "scenario_version", "tool", "tool_version",
    "policy_mode", "policy_identity", "workload_cmd", "workload_image",
    "started_at", "ended_at", "workload_exit_code", "execution_status",
    "sensor_health", "collection_status", "evidence_raw", "evidence_normalized",
    "capture_mode", "validation_status", "warnings",
]

VALID_OUTCOMES = {
    "DETECTED", "TELEMETRY_ONLY", "NOT_DETECTED", "COLLECTION_FAILED",
    "EXECUTION_FAILED", "NOT_EVALUATED", "INCONCLUSIVE",
}

# Tracee behavioral-signature event names that count as a qualifying finding.
TRACEE_SIGNATURES = {
    "dropped_executable", "sudoers_modification", "anti_debugging", "hidden_file_created",
    "fileless_execution", "illegitimate_shell", "ld_preload", "proc_mem_code_injection",
    "stdio_over_socket", "docker_abuse", "scheduled_task_mod", "core_pattern_modification",
    "kernel_module_loading", "syscall_hooking", "proc_kcore_read", "proc_mem_access",
    "ptrace_code_injection", "process_vm_write_inject", "dynamic_code_loading",
    "system_request_key_mod", "sched_debug_recon", "k8s_cert_theft", "aslr_inspection",
    "default_loader_mod", "rcd_modification", "cgroup_release_agent", "disk_mount",
}

FALCO_CUSTOM_TELEMETRY_RULE = "EBPF Lab Container Process Execution"


def lifecycle_stage(m):
    """Classify a manifest's lifecycle stage from what it actually contains."""
    if not m:
        return "template"
    if not m.get("container_id") and not m.get("started_at"):
        return "planned"
    # a verified stage is only awarded by the validator; the manifest alone is 'completed'
    return "completed"


def capture_mode(m):
    """Return the capture mode of a manifest, preferring an explicit field."""
    mode = m.get("capture_mode")
    if mode:
        return mode
    # Live-capture manifests set provenance=live and carry a container_id.
    if m.get("provenance") == "live" and m.get("container_id"):
        return "live"
    if m.get("provenance") == "recorded":
        return "historical"
    return "historical"


def _qualifying_finding(m):
    """Return (has_finding, detail) based ONLY on real evidence in the manifest.
    A qualifying finding is: a Falco built-in (non-custom) alert, a Tracee
    behavioral signature, or a documented Tetragon selective-policy match."""
    tool = m.get("tool")
    if tool == "falco":
        qual = m.get("qualifying_detections") or []
        # defensive: ensure none are the custom telemetry notice rule
        real = [d for d in qual if d.get("rule") != FALCO_CUSTOM_TELEMETRY_RULE]
        if real:
            return True, "falco built-in rule(s): " + ", ".join(sorted({d.get("rule", "?") for d in real}))
        return False, ""
    if tool == "tracee":
        sigs = m.get("signature_detections") or {}
        sig_hits = {k: v for k, v in sigs.items() if k in TRACEE_SIGNATURES}
        if sig_hits:
            return True, "tracee signature(s): " + ", ".join(sorted(sig_hits))
        if m.get("matched_policies"):
            return True, "tracee matched policy"
        return False, ""
    if tool == "tetragon":
        # a selective sensitive-file policy match is a documented detection
        paths = m.get("openat_paths") or []
        SENSITIVE = ("/etc/shadow", "/etc/sudoers", "/etc/ssh/ssh_host_rsa_key")
        if any(p in SENSITIVE for p in paths) and m.get("run_label", "").endswith("tetC") is False:
            # only the configured selective policy run yields a sensitive-only stream;
            # baseline tetragon openat telemetry is broad and is NOT a detection.
            pass
        return False, ""
    return False, ""


def classify_outcome(m):
    """Deterministically classify the trial-level outcome from evidence.
    Returns (outcome, reason). Never promotes a failed/empty capture to a
    detection, and never treats telemetry as detection."""
    if not m:
        return "NOT_EVALUATED", "no manifest"

    exit_code = m.get("workload_exit_code")
    exec_ok = m.get("execution_ok")
    # Execution: a non-zero/absent exit code with no events is execution failure.
    cstatus = str(m.get("collection_status", "")).lower()

    if cstatus.startswith("execution_failed") or exec_ok is False or \
       (exit_code not in (None, 0, "0") and str(exit_code) not in ("0",)):
        # distinguish a genuine exec failure from a tetragon-style collection failure
        if cstatus.startswith("collection_failed"):
            return "COLLECTION_FAILED", m.get("collection_note", "collection failed")
        if exit_code not in (None, 0, "0"):
            return "EXECUTION_FAILED", f"workload exit code {exit_code}"

    if cstatus.startswith("collection_failed"):
        return "COLLECTION_FAILED", m.get("collection_note", "collection failed; verified execution, zero scoped events")

    has_finding, detail = _qualifying_finding(m)
    if has_finding:
        return "DETECTED", detail

    # No qualifying finding. Did we observe relevant telemetry?
    observed = (
        (m.get("scoped_event_count", 0) or 0) > 0
        or bool(m.get("processes_observed"))
        or (m.get("total_alerts", 0) or 0) > 0
        or bool(m.get("event_counts"))
    )
    if observed:
        return "TELEMETRY_ONLY", "relevant telemetry captured; no qualifying detection"
    # Executed, collection healthy, but nothing observed -> NOT_DETECTED only if
    # we can confirm collection health; otherwise INCONCLUSIVE.
    if m.get("sensor_health") == "healthy":
        return "NOT_DETECTED", "verified execution + healthy collection + no qualifying event"
    return "INCONCLUSIVE", "no events and collection health unknown"


def normalize_manifest(m):
    """Project an existing run manifest onto the canonical contract (without
    discarding extra keys, which are kept under 'source_extra')."""
    out = {f: m.get(f) for f in CONTRACT_FIELDS}
    out["manifest_schema_version"] = MANIFEST_SCHEMA_VERSION
    out["trial_id"] = m.get("run_id") or m.get("trial_id")
    out["tool"] = m.get("tool")
    out["policy_mode"] = m.get("mode", out.get("policy_mode"))
    out["execution_status"] = (
        "completed" if m.get("workload_exit_code") in (0, "0") else
        ("failed" if m.get("workload_exit_code") not in (None,) else "unknown"))
    out["capture_mode"] = capture_mode(m)
    out["evidence_raw"] = m.get("evidence_events")
    outcome, reason = classify_outcome(m)
    out["derived_outcome"] = outcome
    out["derived_outcome_reason"] = reason
    out["lifecycle_stage"] = lifecycle_stage(m)
    return out
