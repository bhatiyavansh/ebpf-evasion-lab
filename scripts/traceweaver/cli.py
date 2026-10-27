"""
TraceWeaver CLI (Phase 2).

  python3 -m scripts.traceweaver.cli run --all            # run engine on all streams
  python3 -m scripts.traceweaver.cli run --trial <id>     # one trial id
  python3 -m scripts.traceweaver.cli run --stream <path>  # one raw stream path
  python3 -m scripts.traceweaver.cli run --all --summary  # human-readable summary
  python3 -m scripts.traceweaver.cli validate             # output + explanation provenance
  python3 -m scripts.traceweaver.cli eligible             # eligibility report

Deterministic output; exit codes: 0 ok, 1 validation failure, 2 usage error,
3 no eligible data.
"""
from __future__ import annotations
import argparse
import json
import os
import sys

from . import engine as E
from . import run as R
from .inventory import REPO


# --- explanation / provenance consistency validator -------------------------
def validate_results(results):
    """Every cited event_id must exist in the stream's normalized events and
    every raw_ref file must exist. No explanation may cite a nonexistent event."""
    problems = []
    for r in results:
        stream = r.get("stream", "")
        # rebuild the normalized path from the index
        norm = _norm_path_for(stream, r.get("sensor"))
        ids = set()
        if norm and os.path.exists(os.path.join(REPO, norm)):
            for line in open(os.path.join(REPO, norm)):
                line = line.strip()
                if line:
                    ids.add(json.loads(line)["event_id"])
        for f in r.get("findings", []):
            for eid in f["event_ids"]:
                if ids and eid not in ids:
                    problems.append(f"{stream}: finding '{f['pattern']}' cites unknown event {eid}")
            for rr in f["raw_refs"]:
                if isinstance(rr, dict) and rr.get("file") and not os.path.exists(os.path.join(REPO, rr["file"])):
                    problems.append(f"{stream}: raw_ref file missing {rr['file']}")
        for q in r.get("qualifying_policy_events", []):
            if ids and q["event_id"] not in ids:
                problems.append(f"{stream}: qualifying event {q['event_id']} not in stream")
        # integrity: no DETECTED without P>0
        if r["verdict"] == "DETECTED" and r["component_scores"]["P_policy"] == 0:
            problems.append(f"{stream}: DETECTED without policy evidence")
        # visibility never overridden by risk
        if r["visibility_status"] in ("COLLECTION_FAILED", "EXECUTION_FAILED") and \
           r["verdict"] not in ("COLLECTION_FAILED", "EXECUTION_FAILED"):
            problems.append(f"{stream}: visibility {r['visibility_status']} but verdict {r['verdict']}")
    return problems


def _norm_path_for(stream_rel, sensor):
    base = os.path.basename(stream_rel)
    return os.path.join("results", "normalized", "events", f"{sensor}__{base}")


def _print_summary(results):
    by = {}
    for r in results:
        by[r["verdict"]] = by.get(r["verdict"], 0) + 1
    print(f"TraceWeaver engine {E.ENGINE_VERSION} — {len(results)} streams")
    print(f"  verdicts: {by}")
    det = [r for r in results if r["verdict"] == "DETECTED"]
    print(f"  {len(det)} DETECTED (all with verified policy evidence):")
    for r in sorted(det, key=lambda x: x["stream"])[:12]:
        q = r["qualifying_policy_events"][0] if r["qualifying_policy_events"] else {}
        print(f"    {r['sensor']:8} {r['scenario_id'] or '?':4} risk={r['risk_score']:<6} "
              f"{q.get('native_event','?')}  [{r['stream']}]")


def cmd_run(args):
    cfg = E.load_config()
    results, _ = R.run_all(write=not args.no_write, cfg=cfg)
    if args.trial:
        results = [r for r in results if r.get("trial_id") == args.trial]
    if args.stream:
        results = [r for r in results if r.get("stream") == args.stream or
                   os.path.basename(r.get("stream", "")) == os.path.basename(args.stream)]
    if not results:
        print("no matching streams", file=sys.stderr)
        return 3
    if args.summary:
        _print_summary(results)
    else:
        print(json.dumps(results if (args.all or len(results) > 1) else results[0],
                         indent=2, sort_keys=True))
    return 0


def cmd_validate(args):
    results, _ = R.run_all(write=False)
    problems = validate_results(results)
    if problems:
        print(f"VALIDATION FAILED ({len(problems)} problems):")
        for p in problems[:50]:
            print("  -", p)
        return 1
    print(f"VALIDATION OK — {len(results)} engine results: explanations cite real events, "
          f"raw_refs exist, no detection without policy evidence, visibility never overridden.")
    return 0


def cmd_graph(args):
    from . import graph_adapter as G
    payload = G.build_graph_payload(args.stream)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") else 3


def cmd_eligible(args):
    results, _ = R.run_all(write=False)
    eligible, ineligible = [], []
    for r in results:
        if r["is_baseline_stream"]:
            ineligible.append((r["stream"], "baseline/training split"))
        elif r["visibility_status"] in ("COLLECTION_FAILED", "EXECUTION_FAILED", "NO_EVENTS"):
            ineligible.append((r["stream"], f"visibility={r['visibility_status']}"))
        elif r["capture_mode"] not in ("live",):
            ineligible.append((r["stream"], f"capture_mode={r['capture_mode']}"))
        else:
            eligible.append(r["stream"])
    print(f"eligible trials: {len(eligible)} | ineligible: {len(ineligible)}")
    reasons = {}
    for _, why in ineligible:
        reasons[why] = reasons.get(why, 0) + 1
    print(f"  ineligibility reasons: {reasons}")
    return 0 if eligible else 3


def main(argv=None):
    ap = argparse.ArgumentParser(prog="traceweaver", description="TraceWeaver detection engine CLI")
    sub = ap.add_subparsers(dest="cmd")
    pr = sub.add_parser("run")
    pr.add_argument("--all", action="store_true")
    pr.add_argument("--trial")
    pr.add_argument("--stream")
    pr.add_argument("--summary", action="store_true")
    pr.add_argument("--no-write", action="store_true")
    sub.add_parser("validate")
    sub.add_parser("eligible")
    pg = sub.add_parser("graph")
    pg.add_argument("--stream", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "eligible":
        return cmd_eligible(args)
    if args.cmd == "graph":
        return cmd_graph(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
