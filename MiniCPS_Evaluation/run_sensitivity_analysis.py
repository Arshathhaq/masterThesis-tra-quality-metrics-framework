#!/usr/bin/env python3
"""
Threshold sensitivity analysis for the TRA quality-metric framework.

The automatic criteria depend on a handful of numeric thresholds (Table
"Calibrated thresholds" in the thesis). This script tests whether the
*conclusions* of the L1 mutation experiment survive reasonable changes to those
thresholds, i.e. whether the comparative ranking

        clean (V0)  >  mildly damaged  >  heavily damaged

is stable when every threshold is moved to a LOW, DEFAULT, and HIGH setting.

It does NOT re-calibrate the tool permanently: each threshold is temporarily
overridden on the imported analyser module, the three representative cases are
re-scored, and the original values are restored.

Representative cases:
  * V0            - the clean reference TRA
  * mild damage   - V4 (a single unattacked interface: small, localised defect)
  * heavy damage  - V2 (system overview and every component description removed)

Output:
  MiniCPS_Evaluation/results/sensitivity_analysis.csv
"""
from __future__ import annotations

import copy
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tra_quality_report as tqr  # noqa: E402
import run_mutation_experiment as rme  # noqa: E402

V0_PATH = os.path.join(HERE, "tra", "minicps_swat_tra.json")
OUT_CSV = os.path.join(HERE, "results", "sensitivity_analysis.csv")

# Thresholds varied, with (low, default, high) settings. The default column
# reproduces the values documented in the thesis.
THRESHOLDS = {
    "KEYWORD_ONLY_MIN_WORDS": (4, 6, 8),
    "OVERVIEW_MIN_WORDS": (15, 20, 30),
    "SCOPE_DESC_MIN_WORDS": (3, 5, 8),
    "JACCARD_DUP_THRESHOLD": (0.5, 0.6, 0.7),
    "SPECIFICITY_PASS_THRESHOLD": (0.55, 0.65, 0.75),
}

SETTINGS = ["low", "default", "high"]


def score(tra):
    return tqr.analyze(tra)["scorecard"]["overall"]


def build_cases():
    with open(V0_PATH, "r", encoding="utf-8") as fh:
        v0 = json.load(fh)
    mild = rme.v4_unused_interfaces(copy.deepcopy(v0))       # small, localised defect
    heavy = rme.v2_remove_overview(copy.deepcopy(v0))        # large, structural defect
    return {"V0_clean": v0, "mild_V4": mild, "heavy_V2": heavy}


def apply_setting(idx):
    """Set every threshold to its low/default/high value (idx 0/1/2)."""
    for name, triple in THRESHOLDS.items():
        setattr(tqr, name, triple[idx])


def restore_defaults():
    apply_setting(1)


def main():
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    cases = build_cases()

    rows = []
    ranking_stable = True
    for i, setting in enumerate(SETTINGS):
        apply_setting(i)
        scores = {name: score(tra) for name, tra in cases.items()}
        ok = scores["V0_clean"] >= scores["mild_V4"] >= scores["heavy_V2"]
        ranking_stable = ranking_stable and ok
        rows.append(dict(setting=setting, **scores, ordering_preserved=ok))
    restore_defaults()

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["threshold_setting", "V0_clean", "mild_V4", "heavy_V2",
                    "ordering_preserved"])
        for r in rows:
            w.writerow([r["setting"], r["V0_clean"], r["mild_V4"], r["heavy_V2"],
                        "yes" if r["ordering_preserved"] else "NO"])

    print("Threshold sensitivity analysis (overall quality score)\n")
    print(f"{'setting':<9}{'V0_clean':>10}{'mild_V4':>10}{'heavy_V2':>10}   ordering")
    for r in rows:
        print(f"{r['setting']:<9}{r['V0_clean']:>10.1f}{r['mild_V4']:>10.1f}"
              f"{r['heavy_V2']:>10.1f}   {'preserved' if r['ordering_preserved'] else 'BROKEN'}")
    print("\nRanking clean > mild > heavy is",
          "STABLE across all threshold settings." if ranking_stable
          else "NOT stable - a threshold changes the conclusion.")
    print("Written:", os.path.relpath(OUT_CSV, ROOT))


if __name__ == "__main__":
    main()
