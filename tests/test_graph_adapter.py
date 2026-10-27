"""
TraceWeaver behavior-graph adapter tests.

Run:  python3 -m unittest tests.test_graph_adapter -v

Covers: payload shape, evidence-backed nodes/edges, NO fabricated edges when
identities are missing, container-membership derivation, finding emphasis,
ordered events for replay, collection-failure vs empty-graph distinction, and
determinism. These exercise the REAL recorded evidence in the repo.
"""
import os
import unittest

from scripts.traceweaver import graph_adapter as G

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

A6 = "results/raw/tracee_events/A6_tracee_t1.jsonl"   # correlated: process+file+container edges
A1_FALCO = "results/raw/falco_events/A1_falco_t1.jsonl"  # alerts with no pid -> identity gaps
E04 = "results/raw/tetragon_events/E04.jsonl"          # collection failed, zero events


def _has(path):
    return os.path.exists(os.path.join(REPO, path))


class GraphAdapterShape(unittest.TestCase):
    @unittest.skipUnless(_has(A6), "A6 evidence missing")
    def test_payload_shape(self):
        g = G.build_graph_payload(A6)
        self.assertTrue(g["ok"])
        for k in ("events", "nodes", "edges", "findings", "correlation_limits",
                  "result", "verdict", "risk_score", "component_scores"):
            self.assertIn(k, g)
        # events are ordered by (timestamp, event_id) and carry provenance
        orders = [e["order"] for e in g["events"]]
        self.assertEqual(orders, sorted(orders))
        for e in g["events"]:
            self.assertIsNotNone(e["event_id"])

    @unittest.skipUnless(_has(A6), "A6 evidence missing")
    def test_edges_are_evidence_backed(self):
        g = G.build_graph_payload(A6)
        node_ids = {n["id"] for n in g["nodes"]}
        event_ids = {e["event_id"] for e in g["events"]}
        self.assertTrue(len(g["edges"]) > 0)
        for ed in g["edges"]:
            # both endpoints exist as real nodes
            self.assertIn(ed["source"], node_ids)
            self.assertIn(ed["target"], node_ids)
            # every edge cites a real supporting event
            self.assertIn(ed["event_id"], event_ids)

    @unittest.skipUnless(_has(A6), "A6 evidence missing")
    def test_finding_nodes_marked(self):
        g = G.build_graph_payload(A6)
        self.assertTrue(any(n["is_finding"] for n in g["nodes"]),
                        "A6 should emphasise at least one finding node")
        # finding node event ids intersect the finding event ids
        fset = set(g["finding_event_ids"])
        for n in g["nodes"]:
            if n["is_finding"]:
                self.assertTrue(set(n["event_ids"]) & fset)

    @unittest.skipUnless(_has(A6), "A6 evidence missing")
    def test_determinism(self):
        a = G.build_graph_payload(A6)
        b = G.build_graph_payload(A6)
        self.assertEqual(a, b)


class NoFabricatedEdges(unittest.TestCase):
    @unittest.skipUnless(_has(A1_FALCO), "A1 falco evidence missing")
    def test_missing_pid_no_lineage_edges(self):
        g = G.build_graph_payload(A1_FALCO)
        # Falco alerts here have NO pid/parent_pid -> the engine must not invent
        # parent/child (lineage) edges.
        self.assertEqual(g["engine_edge_count"], 0)
        self.assertFalse(any(ed["type"] == "parent_of" for ed in g["edges"]))
        # the limitation is surfaced honestly
        fields = {c["field"] for c in g["correlation_limits"]}
        self.assertIn("pid", fields)
        self.assertIn("parent_pid", fields)

    @unittest.skipUnless(_has(A1_FALCO), "A1 falco evidence missing")
    def test_container_membership_derived_from_real_field(self):
        g = G.build_graph_payload(A1_FALCO)
        # the three alerts share a real container_id -> connected via in_container
        mem = [ed for ed in g["edges"] if ed["type"] == "in_container"]
        self.assertTrue(len(mem) >= 1)
        for ed in mem:
            self.assertTrue(ed["derived"])
            self.assertIsNotNone(ed["event_id"])
        self.assertTrue(any(n["kind"] == "container" for n in g["nodes"]))


class CollectionFailureDistinct(unittest.TestCase):
    @unittest.skipUnless(_has(E04), "E04 evidence missing")
    def test_collection_failed_is_not_an_empty_graph(self):
        g = G.build_graph_payload(E04)
        self.assertEqual(g["visibility_status"], "COLLECTION_FAILED")
        self.assertEqual(g["verdict"], "COLLECTION_FAILED")
        self.assertEqual(g["event_count"], 0)
        self.assertEqual(len(g["nodes"]), 0)  # nothing to graph -> UI shows failure state


class UnknownStream(unittest.TestCase):
    def test_unknown_stream_rejected(self):
        g = G.build_graph_payload("results/raw/does_not_exist.jsonl")
        self.assertFalse(g["ok"])


if __name__ == "__main__":
    unittest.main()
