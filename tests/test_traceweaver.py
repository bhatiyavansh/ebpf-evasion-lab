"""
TraceWeaver Phase 1 regression tests (stdlib unittest).

Run from repo root:  python3 -m unittest tests.test_traceweaver -v

These tests pin the evidence-provenance rules so invalid evidence can never be
promoted to a verified detection, and check the adapters against both real-shape
records and clearly-labelled SYNTHETIC fixtures (tests/fixtures, excluded from
the real pipeline).
"""
import json
import os
import unittest

from scripts.traceweaver import schema as S
from scripts.traceweaver import adapters as A
from scripts.traceweaver import manifest as M

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def ctx(**kw):
    base = {"trial_id": "t_test", "scenario_id": "A1", "sensor_version": "test",
            "policy_mode": "configured", "capture_mode": "synthetic",
            "collection_status": "complete",
            "raw_ref": {"file": "tests/fixtures/x.jsonl", "line": 1, "sha256": "deadbeef"}}
    base.update(kw)
    return base


class SchemaTests(unittest.TestCase):
    def test_event_id_deterministic(self):
        e1 = S.build_event(sensor="falco", trial_id="t", sensor_native_event="R",
                           canonical_type="security_alert", capture_mode="live",
                           collection_status="complete",
                           raw_ref={"file": "f", "line": 3})
        e2 = S.build_event(sensor="falco", trial_id="t", sensor_native_event="R",
                           canonical_type="security_alert", capture_mode="live",
                           collection_status="complete",
                           raw_ref={"file": "f", "line": 3})
        self.assertEqual(e1["event_id"], e2["event_id"])

    def test_missing_sentinels_distinct(self):
        self.assertEqual(len(S.MISSING_SENTINELS), 4)

    def test_redaction(self):
        self.assertIn("<REDACTED>", S.redact("mysql -u root --password hunter2"))
        self.assertIn("REDACTED", S.redact("TOKEN=abcdef12345"))
        # a sentinel passes through unchanged
        self.assertEqual(S.redact(S.NOT_SUPPLIED), S.NOT_SUPPLIED)

    def test_required_concrete_rejects_sentinel(self):
        ev = S.build_event(sensor="falco", trial_id="t", sensor_native_event=S.NOT_SUPPLIED,
                           canonical_type="security_alert", capture_mode="live",
                           collection_status="complete", raw_ref={"file": "f"})
        self.assertTrue(any("sensor_native_event" in e for e in S.validate_event(ev)))


class AdapterTests(unittest.TestCase):
    def test_falco_alert(self):
        rec = {"rule": "Read sensitive file untrusted", "priority": "Warning",
               "time": "2026-01-01T00:00:00Z", "output_fields":
               {"container.id": "abc123", "proc.name": "cat",
                "proc.cmdline": "cat /etc/shadow", "fd.name": "/etc/shadow", "evt.type": "openat"}}
        ev = A.falco_adapter(rec, ctx())
        self.assertEqual(ev["canonical_type"], "security_alert")
        self.assertEqual(ev["sensor_native_event"], "Read sensitive file untrusted")
        self.assertEqual(ev["file_path"], "/etc/shadow")
        self.assertEqual(ev["container_id"], "abc123")

    def test_falco_missing_fields_quarantine(self):
        with self.assertRaises(A.AdapterQuarantine):
            A.falco_adapter({"not": "a falco record"}, ctx())

    def test_tracee_signature_is_alert(self):
        rec = {"eventName": "sudoers_modification", "timestamp": 1735689600000000000,
               "processId": 7, "parentProcessId": 1, "processName": "sh",
               "container": {"id": "c1", "name": "wl"}, "args": []}
        ev = A.tracee_adapter(rec, ctx())
        self.assertEqual(ev["canonical_type"], "security_alert")
        self.assertEqual(ev["sensor_native_event"], "sudoers_modification")

    def test_tracee_openat_is_file_open(self):
        rec = {"eventName": "security_file_open", "timestamp": 1735689600000000000,
               "processId": 7, "container": {"id": "c1"},
               "args": [{"name": "pathname", "value": "/etc/shadow"}]}
        ev = A.tracee_adapter(rec, ctx())
        self.assertEqual(ev["canonical_type"], "file_open")
        self.assertEqual(ev["file_path"], "/etc/shadow")

    def test_tetragon_exec(self):
        rec = {"process_exec": {"process": {"binary": "/bin/sh", "arguments": "-c id",
               "pid": 100, "docker": "d1"}, "parent": {"pid": 1}}, "time": "2026-01-01T00:00:00Z"}
        ev = A.tetragon_adapter(rec, ctx())
        self.assertEqual(ev["canonical_type"], "process_exec")
        self.assertEqual(ev["process_name"], "sh")
        self.assertEqual(ev["parent_pid"], 1)

    def test_tetragon_no_container_is_not_host(self):
        # an absent container id must become a sentinel, never a host event
        rec = {"process_exec": {"process": {"binary": "/usr/bin/id", "pid": 5}}, "time": "t"}
        ev = A.tetragon_adapter(rec, ctx())
        self.assertEqual(ev["container_id"], S.NOT_SUPPLIED)
        self.assertNotEqual(ev["container_id"], "host")


class ProvenanceTests(unittest.TestCase):
    def test_detected_requires_real_finding(self):
        # a manifest that CLAIMS detection but has no qualifying finding must NOT be DETECTED
        m = {"tool": "falco", "run_id": "r", "qualifying_detections": [],
             "total_alerts": 2, "workload_exit_code": 0, "evidence_events": "x.jsonl",
             "sensor_health": "healthy"}
        self.assertNotEqual(M.classify_outcome(m)[0], "DETECTED")

    def test_custom_telemetry_rule_is_not_detection(self):
        m = {"tool": "falco", "run_id": "r",
             "qualifying_detections": [],
             "custom_rule_notices": [{"rule": M.FALCO_CUSTOM_TELEMETRY_RULE}],
             "total_alerts": 1, "workload_exit_code": 0, "evidence_events": "x.jsonl",
             "sensor_health": "healthy"}
        self.assertEqual(M.classify_outcome(m)[0], "TELEMETRY_ONLY")

    def test_tracee_signature_is_detection(self):
        m = {"tool": "tracee", "run_id": "r",
             "signature_detections": {"sudoers_modification": 2},
             "scoped_event_count": 5, "workload_exit_code": 0, "evidence_events": "x.jsonl"}
        self.assertEqual(M.classify_outcome(m)[0], "DETECTED")

    def test_collection_failed_never_not_detected(self):
        m = {"tool": "tetragon", "run_id": "r",
             "collection_status": "collection_failed_container_not_tracked",
             "workload_exit_code": 0, "sensor_health": "healthy",
             "host_events_in_window": 50}
        self.assertEqual(M.classify_outcome(m)[0], "COLLECTION_FAILED")

    def test_execution_failed(self):
        m = {"tool": "falco", "run_id": "r", "workload_exit_code": 1}
        self.assertEqual(M.classify_outcome(m)[0], "EXECUTION_FAILED")

    def test_summary_derived_capture_mode(self):
        # a recorded manifest with no live container id -> historical, not live
        m = {"tool": "falco", "run_id": "r", "provenance": "recorded"}
        self.assertEqual(M.capture_mode(m), "historical")


class SyntheticFixtureTests(unittest.TestCase):
    def test_synthetic_fixture_labelled_and_normalizes(self):
        path = os.path.join(FIX, "synthetic_falco.jsonl")
        self.assertTrue(os.path.exists(path), "synthetic fixture must exist under tests/fixtures")
        rec = json.loads(open(path).readline())
        ev = A.falco_adapter(rec, ctx(capture_mode="synthetic"))
        self.assertEqual(ev["capture_mode"], "synthetic")  # never 'live'


if __name__ == "__main__":
    unittest.main()
