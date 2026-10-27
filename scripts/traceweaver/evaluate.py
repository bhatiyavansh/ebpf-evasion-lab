"""
TraceWeaver evaluation harness (Phase 4).

Honest, reproducible evaluation over the eligible live A-series trials. Compares
three methods on the SAME eligible set and labels:

  rules_only   : flags iff a verified policy alert exists (P>0)   — the sensor's own detections
  anomaly_only : flags iff the statistical anomaly signal A >= ANOM_THRESH
  combined     : TraceWeaver — flags iff any signal present (P>0 OR S>0 OR A>=ANOM_THRESH)

"Flag" here means "surfaced as suspicious", NOT "verified detection". The engine
only ever reports DETECTED when P>0 (verified policy evidence); the suspicious-
flag task measures the multi-signal engine's ability to surface malicious-scenario
behavior that pure rules miss, WITHOUT firing on the benign control.

Ground-truth labels (scenario-level, evidence-justified):
  positive  = A1 (credential access), A5 (drop-and-execute), A6 (sudoers mod)
  negative  = A7 (benign control)
  ambiguous = A2 (nested shell), A3 (discovery)  -> excluded from supervised metrics
  E-series  = original observability baselines     -> excluded (not attack scenarios)

Small-sample caveat is reported; this is an exploratory evaluation, not a powered study.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import datetime

from . import engine as E
from . import run as R
from .inventory import REPO

ANOM_THRESH = 0.2
LABELS = {"A1": "positive", "A5": "positive", "A6": "positive", "A7": "negative",
          "A2": "ambiguous", "A3": "ambiguous"}
OUT = os.path.join(REPO, "results", "engine")


def _git_rev():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO,
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"


def _cfg_hash(cfg):
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:16]


def eligibility(r):
    """Return (eligible: bool, reason)."""
    if r.get("is_baseline_stream"):
        return False, "baseline/training split"
    if r["capture_mode"] != "live":
        return False, f"capture_mode={r['capture_mode']}"
    if r["visibility_status"] in ("COLLECTION_FAILED", "EXECUTION_FAILED", "NO_EVENTS"):
        return False, f"visibility={r['visibility_status']}"
    scn = r.get("scenario_id")
    if scn not in LABELS:
        return False, f"no supervised label for scenario {scn}"
    if LABELS[scn] == "ambiguous":
        return False, f"ambiguous label ({scn})"
    return True, "eligible"


STRONG_SEVERITY = 0.6  # only strong behavioral patterns flag; weak/ambiguous
                       # patterns (nested_shell, discovery) do not flag alone.


def predict(method, r):
    cs = r["component_scores"]
    if method == "rules_only":
        return cs["P_policy"] > 0
    if method == "anomaly_only":
        return cs["A_anomaly"] >= ANOM_THRESH
    if method == "combined":
        strong = any(f["severity"] >= STRONG_SEVERITY for f in r.get("findings", []))
        return cs["P_policy"] > 0 or strong or cs["A_anomaly"] >= ANOM_THRESH
    raise ValueError(method)


def confusion(results, method):
    tp = fp = tn = fn = 0
    per = {}
    for r in results:
        elig, _ = eligibility(r)
        if not elig:
            continue
        label = LABELS[r["scenario_id"]]
        pred = predict(method, r)
        pos = label == "positive"
        key = (r["scenario_id"], r["sensor"])
        d = per.setdefault(key, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        if pos and pred:
            tp += 1; d["tp"] += 1
        elif pos and not pred:
            fn += 1; d["fn"] += 1
        elif (not pos) and pred:
            fp += 1; d["fp"] += 1
        else:
            tn += 1; d["tn"] += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "per_scenario_sensor": {f"{k[0]}/{k[1]}": v for k, v in sorted(per.items())}}


def metrics(cm):
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    def rate(n, d):
        return None if d == 0 else round(n / d, 4)
    prec = rate(tp, tp + fp)
    rec = rate(tp, tp + fn)
    f1 = None
    if prec is not None and rec is not None and (prec + rec) > 0:
        f1 = round(2 * prec * rec / (prec + rec), 4)
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "positives": tp + fn, "negatives": tn + fp, "total_eligible": tp + fp + tn + fn,
        "precision": prec, "precision_denom": tp + fp,
        "recall": rec, "recall_denom": tp + fn,
        "f1": f1,
        "false_positive_rate": rate(fp, fp + tn), "fpr_denom": fp + tn,
    }


def evaluate(write=True):
    cfg = E.load_config()
    results, baseline_used = R.run_all(write=False, cfg=cfg)

    elig_list, inelig = [], {}
    for r in results:
        ok, why = eligibility(r)
        if ok:
            elig_list.append(r["stream"])
        else:
            inelig[why] = inelig.get(why, 0) + 1

    methods = {}
    for m in ("rules_only", "anomaly_only", "combined"):
        cm = confusion(results, m)
        methods[m] = {"confusion": cm, "metrics": metrics(cm)}

    report = {
        "evaluation_version": "1.0.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "git_revision": _git_rev(),
        "engine_version": E.ENGINE_VERSION,
        "schema_version": E.S.SCHEMA_VERSION,
        "config_hash": _cfg_hash(cfg),
        "anomaly_threshold": ANOM_THRESH,
        "labels": LABELS,
        "train_split_streams": baseline_used,
        "eligible_count": len(elig_list),
        "ineligible_reasons": inelig,
        "eligible_streams": sorted(elig_list),
        "methods": methods,
        "caveats": [
            "Small, exploratory sample — not a statistically powered study.",
            "The anomaly baseline is fit only on the train-split streams (benign/baseline), "
            "which are excluded from these metrics to avoid leakage.",
            "'Flag' means surfaced-as-suspicious; a verified DETECTED still requires P>0.",
            "A2/A3 are ambiguous and excluded; E-series are observability baselines and excluded.",
        ],
    }
    if write:
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "evaluation.json"), "w") as f:
            f.write(json.dumps(report, indent=2) + "\n")
        _write_markdown(report)
    return report


def _write_markdown(rep):
    lines = ["# TraceWeaver Evaluation (auto-generated)\n",
             f"- git `{rep['git_revision'][:10]}` · engine `{rep['engine_version']}` · "
             f"schema `{rep['schema_version']}` · config `{rep['config_hash']}` · {rep['generated_at']}",
             f"- Eligible trials: **{rep['eligible_count']}** · ineligible: {rep['ineligible_reasons']}",
             f"- Anomaly threshold: {rep['anomaly_threshold']} · labels: {rep['labels']}\n",
             "| Method | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
             "|--------|----|----|----|----|-----------|--------|----|-----|"]
    for m, d in rep["methods"].items():
        x = d["metrics"]
        def s(v, dn): return "N/A" if v is None else f"{v} ({dn})"
        lines.append(f"| {m} | {x['tp']} | {x['fp']} | {x['tn']} | {x['fn']} | "
                     f"{s(x['precision'], x['precision_denom'])} | {s(x['recall'], x['recall_denom'])} | "
                     f"{x['f1'] if x['f1'] is not None else 'N/A'} | {s(x['false_positive_rate'], x['fpr_denom'])} |")
    lines.append("\n**Caveats:** " + " ".join(rep["caveats"]))
    with open(os.path.join(OUT, "evaluation.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    rep = evaluate(write=True)
    print("wrote results/engine/evaluation.json + evaluation.md")
    print(f"  eligible={rep['eligible_count']} ineligible={rep['ineligible_reasons']}")
    for m, d in rep["methods"].items():
        x = d["metrics"]
        print(f"  {m:13} P={x['precision']} R={x['recall']} F1={x['f1']} "
              f"(TP={x['tp']} FP={x['fp']} TN={x['tn']} FN={x['fn']})")


if __name__ == "__main__":
    main()
