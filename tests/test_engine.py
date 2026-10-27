"""
TraceWeaver engine regression tests (Phase 2).

Run:  python3 -m unittest tests.test_engine -v

Covers: config validity, graph construction/ordering/identity-gaps/isolation,
risk boundary values + invalid weights + missing features, patterns
(positive/negative/missing-telemetry), the visibility-aware verdict invariants,
determinism, and resilience to malformed input.
"""
import copy
import unittest

from scripts.traceweaver import engine as E
from scripts.traceweaver import schema as S


def ev(**kw):
    base = dict(schema_version=S.SCHEMA_VERSION, event_id="e" + str(id(kw) % 100000),
                trial_id="t", sensor="tracee", capture_mode="live",
                canonical_type="process_exec", sensor_native_event="execve",
                raw_ref={"file": "f.jsonl", "line": 1, "sha256": "x"},
                collection_status="complete", timestamp="2026-01-01T00:00:00Z",
                container_id="cid123456789", pid=10, parent_pid=1,
                process_name="sh", process_args="-c id",
                file_path=S.NOT_APPLICABLE, network_dest=S.NOT_APPLICABLE,
                normalization_warnings=[])
    base.update(kw)
    return base


CFG = E.load_config()


class ConfigTests(unittest.TestCase):
    def test_weights_sum_to_one(self):
        w = CFG["risk_weights"]
        self.assertAlmostEqual(w["wA"] + w["wS"] + w["wP"], 1.0, places=6)

    def test_invalid_weights_rejected(self):
        import json, tempfile, os
        bad = copy.deepcopy(CFG); bad["risk_weights"] = {"wA": 0.5, "wS": 0.5, "wP": 0.5}
        p = tempfile.mktemp(suffix=".json"); json.dump(bad, open(p, "w"))
        with self.assertRaises(ValueError):
            E.load_config(p)
        os.unlink(p)


class GraphTests(unittest.TestCase):
    def test_parent_child_edge(self):
        events = [ev(event_id="a", pid=1, process_name="sh"),
                  ev(event_id="b", pid=2, parent_pid=1, process_name="id")]
        g = E.BehaviorGraph(events)
        self.assertTrue(any(e["type"] == "parent_of" for e in g.edges))

    def test_identity_gap_not_merged(self):
        # two events with no container id must NOT be merged into one process node
        e1 = ev(event_id="a", container_id=S.NOT_SUPPLIED, pid=5)
        e2 = ev(event_id="b", container_id=S.NOT_SUPPLIED, pid=5)
        g = E.BehaviorGraph([e1, e2])
        unknowns = [n for n in g.nodes.values() if not n["identity_known"]]
        self.assertEqual(len(unknowns), 2)

    def test_ordering_deterministic(self):
        events = [ev(event_id="z", timestamp="2026-01-01T00:00:02Z"),
                  ev(event_id="a", timestamp="2026-01-01T00:00:01Z")]
        g = E.BehaviorGraph(events)
        self.assertEqual([e["event_id"] for e in g.events], ["a", "z"])

    def test_unrelated_not_correlated(self):
        # a file access by an unknown process must not attach to an unrelated process
        e1 = ev(event_id="a", pid=1, canonical_type="process_exec")
        e2 = ev(event_id="b", container_id=S.NOT_SUPPLIED, canonical_type="file_open",
                file_path="/etc/shadow")
        g = E.BehaviorGraph([e1, e2])
        # the file edge's source must be the unknown proc, not proc:cid:1
        acc = [e for e in g.edges if e["type"] == "accessed"]
        self.assertTrue(all("unknown" in e["src"] for e in acc))


class RiskTests(unittest.TestCase):
    def test_anomaly_empty_is_zero(self):
        a, _ = E.score_anomaly([], {"process_names": {}}, CFG)
        self.assertEqual(a, 0.0)  # absence never raises anomaly

    def test_sensitive_path_is_anomalous(self):
        e = ev(canonical_type="file_open", file_path="/etc/shadow")
        a, reasons = E.score_anomaly([e], {"process_names": {"sh": 1}}, CFG)
        self.assertGreater(a, 0.0)

    def test_policy_requires_real_alert(self):
        custom = ev(canonical_type="security_alert", sensor_native_event=E.FALCO_CUSTOM_RULE)
        p, q = E.score_policy([custom])
        self.assertEqual(p, 0.0)  # custom telemetry rule is not a detection
        real = ev(canonical_type="security_alert", sensor_native_event="sudoers_modification")
        p2, q2 = E.score_policy([real])
        self.assertEqual(p2, 1.0)

    def test_risk_bounds(self):
        g = E.BehaviorGraph([])
        r = E.run_engine([ev(canonical_type="security_alert", sensor_native_event="sudoers_modification",
                             file_path="/etc/sudoers")], {"collection_status": "complete"},
                         {"process_names": {}}, CFG)
        self.assertGreaterEqual(r["risk_score"], 0.0)
        self.assertLessEqual(r["risk_score"], 100.0)


class VerdictTests(unittest.TestCase):
    def test_collection_failed_never_not_detected(self):
        r = E.run_engine([], {"collection_status": "collection_failed_container_not_tracked"},
                         {"process_names": {}}, CFG)
        self.assertEqual(r["verdict"], "COLLECTION_FAILED")

    def test_high_risk_does_not_override_collection_failure(self):
        # even with a qualifying alert present, a collection failure dominates
        alert = ev(canonical_type="security_alert", sensor_native_event="sudoers_modification")
        r = E.run_engine([alert], {"collection_status": "collection_failed_container_not_tracked"},
                         {"process_names": {}}, CFG)
        self.assertEqual(r["verdict"], "COLLECTION_FAILED")

    def test_detected_requires_policy(self):
        # a suspicious sequence without a qualifying alert is TELEMETRY_ONLY, not DETECTED
        fe = ev(canonical_type="file_open", file_path="/etc/shadow")
        r = E.run_engine([fe], {"collection_status": "complete"}, {"process_names": {"sh": 1}}, CFG)
        self.assertEqual(r["verdict"], "TELEMETRY_ONLY")
        self.assertEqual(r["component_scores"]["P_policy"], 0.0)

    def test_deterministic(self):
        events = [ev(event_id=f"e{i}") for i in range(5)]
        r1 = E.run_engine(events, {"collection_status": "complete"}, {"process_names": {}}, CFG)
        r2 = E.run_engine(copy.deepcopy(events), {"collection_status": "complete"}, {"process_names": {}}, CFG)
        self.assertEqual(r1["risk_score"], r2["risk_score"])
        self.assertEqual(r1["verdict"], r2["verdict"])


class PatternTests(unittest.TestCase):
    def test_sudoers_pattern(self):
        e = ev(canonical_type="file_open", file_path="/etc/sudoers.d/x")
        g = E.BehaviorGraph([e])
        f = E.detect_patterns([e], g, CFG)
        self.assertTrue(any(x["pattern"] == "sudoers_modification" for x in f))

    def test_no_pattern_on_benign(self):
        e = ev(canonical_type="process_exec", process_name="echo", process_args="hello")
        g = E.BehaviorGraph([e])
        self.assertEqual(E.detect_patterns([e], g, CFG), [])

    def test_filename_substring_does_not_trigger(self):
        # 'shadow' in an arg but not a sensitive file_open must not trigger P1
        e = ev(canonical_type="process_exec", process_name="echo", process_args="echo shadow")
        g = E.BehaviorGraph([e])
        f = E.detect_patterns([e], g, CFG)
        self.assertFalse(any(x["pattern"] == "sensitive_file_access" for x in f))


class ResilienceTests(unittest.TestCase):
    def test_missing_fields(self):
        e = {"schema_version": S.SCHEMA_VERSION, "event_id": "x", "canonical_type": "other",
             "sensor": "tracee", "capture_mode": "live", "sensor_native_event": "?",
             "raw_ref": {"file": "f"}, "collection_status": "complete"}
        r = E.run_engine([e], {"collection_status": "complete"}, {"process_names": {}}, CFG)
        self.assertIn(r["verdict"], E.load_config()["verdict_policy"]["precedence"])

    def test_empty_stream(self):
        r = E.run_engine([], {"collection_status": "complete"}, {"process_names": {}}, CFG)
        self.assertEqual(r["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()


class EvaluationReproducibilityTests(unittest.TestCase):
    def test_evaluation_deterministic(self):
        from scripts.traceweaver import evaluate as EV
        r1 = EV.evaluate(write=False)
        r2 = EV.evaluate(write=False)
        for m in ("rules_only", "anomaly_only", "combined"):
            self.assertEqual(r1["methods"][m]["metrics"], r2["methods"][m]["metrics"])

    def test_no_detection_without_policy_in_full_run(self):
        from scripts.traceweaver import run as RUN
        results, _ = RUN.run_all(write=False)
        for r in results:
            if r["verdict"] == "DETECTED":
                self.assertEqual(r["component_scores"]["P_policy"], 1.0)


class AdversarialTests(unittest.TestCase):
    """Part 2 adversarial cases: invalid evidence must not become verified detection."""

    def test_explanation_cannot_cite_nonexistent_event(self):
        from scripts.traceweaver import cli
        # craft a result whose finding cites an event_id not in any stream
        bogus = {"stream": "results/raw/tracee_events/A6_tracee_t1.jsonl", "sensor": "tracee",
                 "verdict": "TELEMETRY_ONLY", "visibility_status": "FULL",
                 "component_scores": {"P_policy": 0.0, "A_anomaly": 0.0, "S_sequence": 0.8},
                 "findings": [{"pattern": "x", "event_ids": ["ev_DOESNOTEXIST"],
                               "raw_refs": [{"file": "results/raw/tracee_events/A6_tracee_t1.jsonl", "line": 1}]}],
                 "qualifying_policy_events": []}
        problems = cli.validate_results([bogus])
        self.assertTrue(any("unknown event" in p for p in problems))

    def test_summary_derived_cannot_be_detected_without_real_policy(self):
        # even labelled a detection, with P=0 the engine verdict is never DETECTED
        e = ev(canonical_type="file_open", file_path="/etc/shadow", capture_mode="summary_derived")
        r = E.run_engine([e], {"collection_status": "complete", "capture_mode": "summary_derived"},
                         {"process_names": {"sh": 1}}, CFG)
        self.assertNotEqual(r["verdict"], "DETECTED")

    def test_out_of_order_and_duplicate_events(self):
        a = ev(event_id="a", timestamp="2026-01-01T00:00:03Z")
        b = ev(event_id="b", timestamp="2026-01-01T00:00:01Z")
        dup = ev(event_id="a", timestamp="2026-01-01T00:00:03Z")  # duplicate id
        r = E.run_engine([a, b, dup], {"collection_status": "complete"}, {"process_names": {}}, CFG)
        # engine still produces a bounded, valid verdict
        self.assertIn(r["verdict"], CFG["verdict_policy"]["precedence"])
        # timeline is ordered by timestamp
        tl = E.BehaviorGraph([a, b, dup]).events
        self.assertEqual(tl[0]["event_id"], "b")

    def test_benign_shell_not_detected(self):
        # benign shell + echo must not produce a DETECTED or a strong pattern
        es = [ev(event_id="s", process_name="sh", process_args="-c 'echo hi'"),
              ev(event_id="e", process_name="echo", process_args="echo hi", parent_pid=10)]
        r = E.run_engine(es, {"collection_status": "complete"}, {"process_names": {"sh": 9}}, CFG)
        self.assertNotEqual(r["verdict"], "DETECTED")
        self.assertFalse(any(f["severity"] >= 0.6 for f in r["findings"]))

    def test_high_risk_insufficient_visibility_not_promoted(self):
        # a qualifying alert present but execution failed -> EXECUTION_FAILED, not DETECTED
        alert = ev(canonical_type="security_alert", sensor_native_event="sudoers_modification")
        r = E.run_engine([alert], {"collection_status": "execution_failed"},
                         {"process_names": {}}, CFG)
        self.assertEqual(r["verdict"], "EXECUTION_FAILED")
