"""
TraceWeaver normalization adapters (Phase 1).

One adapter per sensor. Each takes a single RAW record (already JSON-parsed) plus
source context, and returns a canonical event (schema.build_event) or raises
AdapterQuarantine for a malformed record (the pipeline quarantines it with
diagnostics rather than silently dropping it).

Adapters NEVER invent fields: an absent container id becomes a missing sentinel,
never a host event. The original native event name is always preserved.
"""
from __future__ import annotations
import os

from . import schema as S


class AdapterQuarantine(Exception):
    """Raised when a raw record cannot be normalized; carries a reason."""
    def __init__(self, reason, record_excerpt=""):
        super().__init__(reason)
        self.reason = reason
        self.record_excerpt = record_excerpt


def _ns_to_iso(ns):
    """Convert a nanosecond epoch int to iso8601 UTC, or UNPARSEABLE."""
    try:
        import datetime
        sec = int(ns) / 1_000_000_000
        return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).isoformat()
    except Exception:
        return S.UNPARSEABLE


def _basename(p):
    if not p or p in S.MISSING_SENTINELS:
        return S.NOT_SUPPLIED
    return os.path.basename(p) or p


# --- Falco -------------------------------------------------------------------

def falco_adapter(rec, ctx):
    """Falco JSON alert -> canonical event. A Falco record is fundamentally a
    rule firing (security_alert); file/network context is attached when present.
    Trial-level detection significance is decided elsewhere, not here."""
    if "rule" not in rec or "output_fields" not in rec:
        raise AdapterQuarantine("falco record missing 'rule'/'output_fields'", str(rec)[:200])
    of = rec.get("output_fields") or {}
    warnings = []

    file_path = of.get("fd.name")
    evt_type = of.get("evt.type")
    if file_path:
        canonical = "security_alert"  # the record is an alert; file is context
        file_op = "open" if (evt_type and "open" in evt_type) else S.NOT_APPLICABLE
    else:
        canonical = "security_alert"
        file_path = S.NOT_APPLICABLE
        file_op = S.NOT_APPLICABLE

    cid = of.get("container.id")
    if cid in (None, "", "host"):
        cid = S.NOT_SUPPLIED if cid != "host" else "host"

    ts = rec.get("time") or of.get("evt.time.iso8601") or S.NOT_SUPPLIED
    ts_src = "sensor_native" if ts not in S.MISSING_SENTINELS else "unknown"

    return S.build_event(
        trial_id=ctx["trial_id"], scenario_id=ctx.get("scenario_id", S.NOT_SUPPLIED),
        sensor="falco", sensor_version=ctx.get("sensor_version", S.NOT_SUPPLIED),
        policy_mode=ctx.get("policy_mode", S.NOT_APPLICABLE),
        capture_mode=ctx["capture_mode"],
        timestamp=ts, timestamp_source=ts_src,
        container_id=cid if cid is not None else S.NOT_SUPPLIED,
        container_name=of.get("container.name") or S.NOT_SUPPLIED,
        pid=S.NOT_SUPPLIED,  # Falco JSON output here does not include a numeric pid field
        parent_pid=S.NOT_SUPPLIED,
        process_name=of.get("proc.name") or S.NOT_SUPPLIED,
        process_args=S.redact(of.get("proc.cmdline")),
        canonical_type=canonical,
        file_path=file_path if file_path else S.NOT_APPLICABLE,
        file_operation=file_op,
        network_dest=S.NOT_APPLICABLE, network_port=S.NOT_APPLICABLE,
        sensor_native_event=rec.get("rule"),
        raw_ref=ctx["raw_ref"], collection_status=ctx.get("collection_status", "complete"),
        normalization_warnings=warnings,
    )


# --- Tracee ------------------------------------------------------------------

_TRACEE_SIGNATURES = {
    "dropped_executable", "sudoers_modification", "anti_debugging", "hidden_file_created",
    "fileless_execution", "illegitimate_shell", "ld_preload", "proc_mem_code_injection",
    "stdio_over_socket", "docker_abuse", "scheduled_task_mod", "core_pattern_modification",
    "kernel_module_loading", "syscall_hooking", "proc_kcore_read", "proc_mem_access",
    "ptrace_code_injection", "process_vm_write_inject", "dynamic_code_loading",
    "system_request_key_mod", "sched_debug_recon", "k8s_cert_theft", "aslr_inspection",
    "default_loader_mod", "rcd_modification", "cgroup_release_agent", "disk_mount",
}


def tracee_adapter(rec, ctx):
    """Tracee JSON event -> canonical event."""
    name = rec.get("eventName")
    if not name:
        raise AdapterQuarantine("tracee record missing 'eventName'", str(rec)[:200])
    args = {a.get("name"): a.get("value") for a in (rec.get("args") or []) if isinstance(a, dict)}
    warnings = []

    if name in _TRACEE_SIGNATURES:
        canonical = "security_alert"
    elif name == "execve":
        canonical = "process_exec"
    elif name in ("openat", "security_file_open"):
        canonical = "file_open"
    elif name in ("security_socket_connect", "connect"):
        canonical = "network_connect"
    else:
        canonical = "other"

    file_path = S.NOT_APPLICABLE
    file_op = S.NOT_APPLICABLE
    if canonical == "file_open":
        file_path = args.get("pathname") or args.get("syscall_pathname") or S.NOT_SUPPLIED
        file_op = "open"

    net_dest = S.NOT_APPLICABLE
    net_port = S.NOT_APPLICABLE
    if canonical == "network_connect":
        addr = args.get("remote_addr") or args.get("addr")
        if isinstance(addr, dict):
            net_dest = addr.get("sin_addr") or addr.get("sin6_addr") or S.NOT_SUPPLIED
            try:
                net_port = int(addr.get("sin_port") or addr.get("sin6_port"))
            except Exception:
                net_port = S.UNPARSEABLE
        else:
            net_dest = addr if addr else S.NOT_SUPPLIED

    cont = rec.get("container") or {}
    cid = cont.get("id") or rec.get("containerId") or S.NOT_SUPPLIED
    ts_raw = rec.get("timestamp")
    ts = _ns_to_iso(ts_raw) if ts_raw is not None else S.NOT_SUPPLIED
    ts_src = "sensor_native" if ts not in S.MISSING_SENTINELS else "unknown"

    exe = rec.get("executable") or {}
    args_repr = args.get("argv")
    if args_repr is None and name == "execve":
        args_repr = args.get("pathname")

    return S.build_event(
        trial_id=ctx["trial_id"], scenario_id=ctx.get("scenario_id", S.NOT_SUPPLIED),
        sensor="tracee", sensor_version=ctx.get("sensor_version", S.NOT_SUPPLIED),
        policy_mode=ctx.get("policy_mode", S.NOT_APPLICABLE),
        capture_mode=ctx["capture_mode"],
        timestamp=ts, timestamp_source=ts_src,
        container_id=cid,
        container_name=cont.get("name") or S.NOT_SUPPLIED,
        pid=rec.get("processId", S.NOT_SUPPLIED),
        parent_pid=rec.get("parentProcessId", S.NOT_SUPPLIED),
        process_name=rec.get("processName") or S.NOT_SUPPLIED,
        process_args=S.redact(str(args_repr)) if args_repr is not None else S.NOT_SUPPLIED,
        canonical_type=canonical,
        file_path=file_path, file_operation=file_op,
        network_dest=net_dest, network_port=net_port,
        sensor_native_event=name,
        raw_ref=ctx["raw_ref"], collection_status=ctx.get("collection_status", "complete"),
        normalization_warnings=warnings,
    )


# --- Tetragon ----------------------------------------------------------------

_TETRA_KINDS = ("process_exec", "process_exit", "process_kprobe", "process_tracepoint")


def tetragon_adapter(rec, ctx):
    """Tetragon JSON event -> canonical event."""
    kind = next((k for k in _TETRA_KINDS if k in rec), None)
    if kind is None:
        raise AdapterQuarantine("tetragon record has no known process_* kind", str(rec)[:200])
    node = rec.get(kind) or {}
    proc = node.get("process") or {}
    parent = node.get("parent") or {}
    warnings = []

    file_path = S.NOT_APPLICABLE
    file_op = S.NOT_APPLICABLE
    if kind == "process_exec":
        canonical = "process_exec"
    elif kind == "process_exit":
        canonical = "process_exit"
    elif kind == "process_tracepoint":
        canonical = "process_exec"  # sched_process_exec tracepoint
    elif kind == "process_kprobe":
        fn = node.get("function_name", "") or ""
        if "openat" in fn:
            canonical = "file_open"
            file_op = "open"
            file_path = next((a.get("string_arg") for a in node.get("args", [])
                              if "string_arg" in a), S.NOT_SUPPLIED)
        else:
            canonical = "other"
            warnings.append(f"unmapped kprobe function_name={fn}")
    else:
        canonical = "other"

    cid = proc.get("docker") or S.NOT_SUPPLIED
    ts = rec.get("time") or proc.get("start_time") or S.NOT_SUPPLIED
    ts_src = "sensor_native" if ts not in S.MISSING_SENTINELS else "unknown"

    return S.build_event(
        trial_id=ctx["trial_id"], scenario_id=ctx.get("scenario_id", S.NOT_SUPPLIED),
        sensor="tetragon", sensor_version=ctx.get("sensor_version", S.NOT_SUPPLIED),
        policy_mode=ctx.get("policy_mode", S.NOT_APPLICABLE),
        capture_mode=ctx["capture_mode"],
        timestamp=ts, timestamp_source=ts_src,
        container_id=cid,
        container_name=S.NOT_SUPPLIED,  # tetragon events here carry no container name
        pid=proc.get("pid", S.NOT_SUPPLIED),
        parent_pid=parent.get("pid", S.NOT_SUPPLIED),
        process_name=_basename(proc.get("binary")),
        process_args=S.redact(proc.get("arguments")),
        canonical_type=canonical,
        file_path=file_path, file_operation=file_op,
        network_dest=S.NOT_APPLICABLE, network_port=S.NOT_APPLICABLE,
        sensor_native_event=kind,
        raw_ref=ctx["raw_ref"], collection_status=ctx.get("collection_status", "complete"),
        normalization_warnings=warnings,
    )


ADAPTERS = {"falco": falco_adapter, "tracee": tracee_adapter, "tetragon": tetragon_adapter}
