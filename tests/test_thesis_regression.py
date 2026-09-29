#!/usr/bin/env python3
"""Regression checks for thesis reproducibility evidence.

These tests lock the key Chapter 8 evidence to expected values so future
changes cannot silently drift the published conclusions.
"""

from __future__ import annotations

import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
EVAL = os.path.join(ROOT, "MiniCPS_Evaluation")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if EVAL not in sys.path:
    sys.path.insert(0, EVAL)

import tra_quality_report as tqr  # noqa: E402
import run_mutation_experiment as rme  # noqa: E402

V0_PATH = os.path.join(EVAL, "tra", "minicps_swat_tra.json")
THRESHOLD_KEYS = (
    "KEYWORD_ONLY_MIN_WORDS",
    "OVERVIEW_MIN_WORDS",
    "SCOPE_DESC_MIN_WORDS",
    "JACCARD_DUP_THRESHOLD",
    "SPECIFICITY_PASS_THRESHOLD",
)


def _load_v0():
    with open(V0_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _metric_maps(result):
    values, statuses = {}, {}
    for metric in result["core"]:
        values[metric["id"]] = metric.get("value", 0.0)
        statuses[metric["id"]] = metric.get("status", "na")
    return values, statuses


def test_reference_scorecard_regression():
    """Reference MiniCPS TRA should keep the published baseline scorecard."""
    result = tqr.analyze(_load_v0())
    statuses = {m["id"]: m["status"] for m in result["core"]}

    # Rounded display in the CLI is 90, while the precise score is 89.6.
    assert result["scorecard"]["overall"] == pytest.approx(89.6, abs=0.01)
    assert statuses["CM-17"] == "ok"
    assert statuses["CM-08"] == "bad"
    assert statuses["CM-05"] == "warn"


def test_mutation_detector_regression():
    """Reproduce the detector confusion totals used in the thesis evidence."""
    v0 = _load_v0()
    base = tqr.analyze(v0)
    _, base_status = _metric_maps(base)
    criteria = [m["id"] for m in base["core"]]

    tot_tp = tot_fp = tot_fn = 0
    for label, _defect, mutate in rme.MUTATIONS:
        mutated = mutate(copy.deepcopy(v0))
        result = tqr.analyze(mutated)
        _vals, status = _metric_maps(result)

        detected = set()
        for cid in criteria:
            bw = rme.status_weight(base_status.get(cid))
            vw = rme.status_weight(status.get(cid))
            if bw is not None and vw is not None and (vw - bw) < 0:
                detected.add(cid)

        targets = rme.TARGETS.get(label, set())
        tot_tp += len(targets & detected)
        tot_fn += len(targets - detected)
        tot_fp += len(detected - targets)

    precision = tot_tp / (tot_tp + tot_fp)
    recall = tot_tp / (tot_tp + tot_fn)
    f1 = 2 * precision * recall / (precision + recall)

    assert (tot_tp, tot_fp, tot_fn) == (19, 2, 1)
    assert precision == pytest.approx(0.905, abs=0.001)
    assert recall == pytest.approx(0.950, abs=0.001)
    assert f1 == pytest.approx(0.927, abs=0.001)


def test_threshold_ordering_regression():
    """Clean > mild > heavy ordering must stay stable under threshold sweep."""
    v0 = _load_v0()
    mild = rme.v4_unused_interfaces(copy.deepcopy(v0))
    heavy = rme.v2_remove_overview(copy.deepcopy(v0))

    old = {name: getattr(tqr, name) for name in THRESHOLD_KEYS}
    try:
        settings = [
            {
                "KEYWORD_ONLY_MIN_WORDS": 4,
                "OVERVIEW_MIN_WORDS": 15,
                "SCOPE_DESC_MIN_WORDS": 3,
                "JACCARD_DUP_THRESHOLD": 0.5,
                "SPECIFICITY_PASS_THRESHOLD": 0.55,
            },
            {
                "KEYWORD_ONLY_MIN_WORDS": 6,
                "OVERVIEW_MIN_WORDS": 20,
                "SCOPE_DESC_MIN_WORDS": 5,
                "JACCARD_DUP_THRESHOLD": 0.6,
                "SPECIFICITY_PASS_THRESHOLD": 0.65,
            },
            {
                "KEYWORD_ONLY_MIN_WORDS": 8,
                "OVERVIEW_MIN_WORDS": 30,
                "SCOPE_DESC_MIN_WORDS": 8,
                "JACCARD_DUP_THRESHOLD": 0.7,
                "SPECIFICITY_PASS_THRESHOLD": 0.75,
            },
        ]

        orderings = []
        for cfg in settings:
            for name, val in cfg.items():
                setattr(tqr, name, val)
            s_v0 = tqr.analyze(v0)["scorecard"]["overall"]
            s_mild = tqr.analyze(mild)["scorecard"]["overall"]
            s_heavy = tqr.analyze(heavy)["scorecard"]["overall"]
            orderings.append((s_v0, s_mild, s_heavy))

        assert all(v0s >= milds >= heavys for v0s, milds, heavys in orderings)
        assert orderings[1] == pytest.approx((89.6, 87.8, 77.4), abs=0.01)
    finally:
        for name, val in old.items():
            setattr(tqr, name, val)
