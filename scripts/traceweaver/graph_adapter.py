"""
TraceWeaver — read-only behavior-graph adapter (visualization support).

This module does NOT detect anything and does NOT re-implement the engine. It
reuses the engine's own BehaviorGraph (the same nodes/edges the detector builds)
and the engine's result for one stream, and serializes them — together with the
ordered canonical events — into a payload the frontend can render and replay.

Every node, edge and event is traceable to a real normalized record
(event_id + raw_ref file:line:sha256). The only relationships emitted are ones
justified by concrete evidence:

  * parent_of / accessed / connected — taken verbatim from the engine graph.
  * in_container — derived from a concrete `container_id` field on an event
    (never a sentinel). This is an explicit membership relationship, not a
    causal one, and is labelled as such.

No temporal-proximity edges are ever created. Missing identities stay explicit.
"""
from __future__ import annotations
import os

from . import engine as E
from . import run as R
from . import schema as S


def _concrete(v):
    return isinstance(v, str) and v not in S.MISSING_SENTINELS


def _find_stream_entry(index, stream):
    base = os.path.basename(stream)
    for st in index["streams"]:
        if st.get("stream") == stream or os.path.basename(st.get("stream", "")) == base:
            return st
    return None


def _event_view(e, order):
    """A flat, UI-friendly projection of one canonical event (no invented fields)."""
    return {
        "order": order,
        "event_id": e.get("event_id"),
        "timestamp": e.get("timestamp"),
        "canonical_type": e.get("canonical_type"),
        "sensor": e.get("sensor"),
        "native_event": e.get("sensor_native_event"),
        "process_name": e.get("process_name"),
        "process_args": e.get("process_args"),
        "pid": e.get("pid"),
        "parent_pid": e.get("parent_pid"),
        "container_id": e.get("container_id"),
        "container_name": e.get("container_name"),
        "file_path": e.get("file_path"),
        "file_operation": e.get("file_operation"),
        "network_dest": e.get("network_dest"),
        "network_port": e.get("network_port"),
        "raw_ref": e.get("raw_ref"),
    }


def build_graph_payload(stream, cfg=None):
    """Return the full, evidence-backed graph + ordered events + engine result
    for ONE stream. Deterministic. Read-only."""
    cfg = cfg or E.load_config()
    index = R.load_index()
    st = _find_stream_entry(index, stream)
    if not st:
        return {"ok": False, "error": "stream not found in index"}

    events = R.load_stream_events(st.get("normalized_events"))
    man = R._manifest_collection_status(st)
    stream_meta = {
        "trial_id": st.get("trial_id"), "stream": st.get("stream"),
        "sensor": st.get("sensor"), "scenario_id": R._scenario(st),
        "capture_mode": st.get("capture_mode"),
        "collection_status": man.get("collection_status", "complete"),
    }

    # Reuse the engine's own correlation + result (no second engine).
    baseline, _ = R.fit_baseline(index, cfg)
    result = E.run_engine(events, stream_meta, baseline, cfg)
    graph = E.BehaviorGraph(events)

    ordered = graph.events  # already sorted (timestamp, event_id) by the engine
    order_of = {e.get("event_id"): i for i, e in enumerate(ordered)}
    event_views = [_event_view(e, i) for i, e in enumerate(ordered)]

    # events that back a finding or a qualifying policy signal → emphasised nodes
    finding_event_ids = set()
    for f in result.get("findings", []):
        finding_event_ids.update(f.get("event_ids", []))
    for q in result.get("qualifying_policy_events", []):
        finding_event_ids.add(q.get("event_id"))

    # canonical_type per event (for node-kind refinement)
    ctype = {e.get("event_id"): e.get("canonical_type") for e in ordered}

    # ---- nodes (from the engine graph), with light, honest refinement -------
    nodes = []
    node_ids = set()
    for key, n in graph.nodes.items():
        kind = n["kind"]
        # refine a process node that only ever appears as a security alert
        if kind == "process":
            cts = {ctype.get(eid) for eid in n["event_ids"]}
            if cts == {"security_alert"}:
                kind = "security_event"
        evids = n["event_ids"]
        first_order = min((order_of.get(eid, 0) for eid in evids), default=0)
        is_finding = any(eid in finding_event_ids for eid in evids)
        nodes.append({
            "id": key,
            "kind": kind,
            "label": (n["label"] if _concrete(n["label"]) else key.split(":", 1)[0]),
            "identifier": key.split(":", 1)[1] if ":" in key else key,
            "event_ids": evids,
            "raw_refs": n["raw_refs"],
            "identity_known": n["identity_known"],
            "is_finding": is_finding,
            "first_order": first_order,
        })
        node_ids.add(key)

    # ---- edges (engine edges) -----------------------------------------------
    # Only emit edges BETWEEN OBSERVED entities. The engine may record a
    # parent_of edge whose parent process was never itself observed (e.g. a
    # parent_pid of an init/kernel process with no event of its own); that
    # endpoint has no node. We drop such dangling edges rather than fabricate an
    # unobserved parent node — missing lineage stays missing, not invented.
    edges = []
    dropped_unobserved_parent = 0
    for i, ed in enumerate(graph.edges):
        if ed["src"] not in node_ids or ed["dst"] not in node_ids:
            if ed["type"] == "parent_of":
                dropped_unobserved_parent += 1
            continue
        edges.append({
            "id": f"e{i}",
            "type": ed["type"],
            "source": ed["src"],
            "target": ed["dst"],
            "event_id": ed.get("event_id"),
            "raw_ref": ed.get("raw_ref"),
            "reveal_order": order_of.get(ed.get("event_id"), 0),
            "derived": False,
        })

    # ---- derived container-membership edges (from concrete container_id) -----
    missing_container = 0
    seen_membership = set()
    for e in ordered:
        cid = e.get("container_id")
        if not _concrete(cid):
            missing_container += 1
            continue
        cnode = f"cont:{cid[:12]}"
        if cnode not in node_ids:
            nodes.append({
                "id": cnode, "kind": "container",
                "label": (e.get("container_name") if _concrete(e.get("container_name")) else cid[:12]),
                "identifier": cid, "event_ids": [], "raw_refs": [],
                "identity_known": True, "is_finding": False,
                "first_order": order_of.get(e.get("event_id"), 0),
            })
            node_ids.add(cnode)
        # the process/alert node for this event
        pkey = graph._proc_key(e)
        if pkey in node_ids:
            mk = (pkey, cnode)
            if mk not in seen_membership:
                seen_membership.add(mk)
                edges.append({
                    "id": f"m{len(seen_membership)}", "type": "in_container",
                    "source": pkey, "target": cnode,
                    "event_id": e.get("event_id"), "raw_ref": e.get("raw_ref"),
                    "reveal_order": order_of.get(e.get("event_id"), 0),
                    "derived": True,
                })

    # ---- why correlation is limited (honest diagnostics) --------------------
    pid_gaps = sum(1 for e in ordered if not isinstance(e.get("pid"), int))
    ppid_gaps = sum(1 for e in ordered if not isinstance(e.get("parent_pid"), int))
    missing = []
    if pid_gaps:
        missing.append({"field": "pid", "events_missing": pid_gaps,
                        "effect": "no process-identity merge; each event is a distinct unknown-process node"})
    if ppid_gaps:
        missing.append({"field": "parent_pid", "events_missing": ppid_gaps,
                        "effect": "no parent/child (lineage) edges can be established"})
    if missing_container:
        missing.append({"field": "container_id", "events_missing": missing_container,
                        "effect": "no container-membership edge for those events"})
    if dropped_unobserved_parent:
        missing.append({"field": "parent process", "events_missing": dropped_unobserved_parent,
                        "effect": "parent/child edge dropped — the parent process was never "
                                  "observed as its own event (not fabricated)"})

    return {
        "ok": True,
        "stream": st.get("stream"),
        "sensor": result.get("sensor"),
        "scenario_id": result.get("scenario_id"),
        "capture_mode": result.get("capture_mode"),
        "visibility_status": result.get("visibility_status"),
        "verdict": result.get("verdict"),
        "verdict_reason": result.get("verdict_reason"),
        "risk_score": result.get("risk_score"),
        "risk_band": result.get("risk_band"),
        "component_scores": result.get("component_scores"),
        "event_count": result.get("event_count"),
        "time_window": result.get("time_window"),
        "events": event_views,
        "nodes": nodes,
        "edges": edges,
        "findings": result.get("findings", []),
        "finding_event_ids": sorted(finding_event_ids),
        "identity_gaps": result.get("graph_summary", {}).get("identity_gaps", 0),
        "correlation_limits": missing,
        "engine_edge_count": len(graph.edges),
        "data_mode": "historical_replay",
        "is_synthetic": bool(st.get("synthetic", False)),
        # full engine result, so one call feeds both the Outcome view and the
        # investigation graph (single engine run, guaranteed consistent).
        "result": result,
    }
