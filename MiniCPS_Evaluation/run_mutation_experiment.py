#!/usr/bin/env python3
"""
L1 controlled mutation experiment for the TRA quality-metric framework.

Starting from the hand-authored MiniCPS/SWaT reference TRA (V0_good), this
script derives twelve degraded variants (V1..V12), each seeding exactly one
defect class that targets a specific quality dimension / criterion. It runs the
analyser (tra_quality_report.analyze) on the reference and on every variant and
produces:

  1. delta_status_matrix.csv  - variant x criterion matrix of status-weight
                                change relative to V0 (negative = degraded).
                                This is the primary H1/H2 artefact.
  2. delta_value_matrix.csv   - variant x criterion matrix of raw metric-value
                                change relative to V0 (audit trail).
  3. overall_scores.csv       - overall + per-dimension score of every variant.
  4. delta_matrix.png         - heat-map of (1), written to the thesis
                                figure folder if matplotlib is available.

The experiment is fully reproducible and uses only the public MiniCPS case, so
the whole package can be published alongside the thesis.

Usage:
    python run_mutation_experiment.py
"""
from __future__ import annotations

import copy
import csv
import json
import os
import shutil
import sys

# --- locate the analyser (packaged under <repo>/src) ------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import tra_quality_report as tqr  # noqa: E402

# --- paths ------------------------------------------------------------------
V0_PATH = os.path.join(HERE, "tra", "minicps_swat_tra.json")
OUT_DIR = os.path.join(HERE, "results")
FIG_DIR = os.path.join(OUT_DIR, "figures")
VARIANT_DIR = os.path.join(OUT_DIR, "variants")
# Optional local thesis figure folder; the heat-map is mirrored here when it
# exists so the private thesis build keeps working, but the repository never
# depends on it.
THESIS_FIG_DIR = os.path.join(ROOT, "Thesis_Drafts", "prism-uploads")

STATUS_WEIGHT = {"ok": 100.0, "warn": 60.0, "bad": 20.0}


# --------------------------------------------------------------------------- #
#  Mutation operators. Each takes a fresh deep copy of V0 and injects ONE
#  defect class. They mutate in place and set a version label.
# --------------------------------------------------------------------------- #
def _threats(tra):
    return tra.get("ThreatScenarios", [])


def _components(tra):
    # components live under whichever key components_of() resolves; mutate the
    # first list-of-dicts field that carries subUnit_id.
    comps, key = tqr.components_of(tra)
    return comps, key


def _iface_field(comp):
    """Return (key, live list) of the component's interface collection.

    component_interfaces() returns a *copy*, so mutations must target the real
    list field (the one whose key contains 'Interface').
    """
    for key, val in comp.items():
        if "Interface" in key and isinstance(val, list):
            return key, val
    return None, None


def v1_placeholders(tra):
    """Placeholder text (TBD / open questions) left in fields -> CM-04."""
    ts = _threats(tra)
    for t in ts[:5]:
        t["attackActionDesc"] = (t.get("attackActionDesc", "") +
                                 " TBD: open question, to be defined later. ???")
    tra["TRAVersionComment"] = "TBD - draft, tbd"
    return tra


def v2_remove_overview(tra):
    """System overview and scope description removed -> CM-13 / CM-15."""
    tra["IntendedOp"] = {"operationalEnvironment": "", "intendedUsers": ""}
    comps, _ = _components(tra)
    for c in comps:
        c["description"] = ""
    return tra


def v3_orphan_components(tra):
    """Components added with no linked threat -> CM-06 coverage.

    To deterministically lower CM-06, add multiple in-scope components with no
    interfaces and no communications. These cannot be reached by any threat via
    interface or communication paths.
    """
    comps, key = _components(tra)
    template = copy.deepcopy(comps[0]) if comps else {}
    for i in range(1, 8):
        c = copy.deepcopy(template)
        c["subUnit_id"] = f"ORPHAN-{i}"
        c["name"] = f"Unlinked auxiliary unit {i}"
        c["scope"] = "In_Scope"
        c["description"] = "In-scope orphan component with no interface or communication path."
        # Strip all interface/communication collections so this component stays
        # unreachable by design (CM-06 fail) without injecting noisy side-effects.
        for k in list(c.keys()):
            if ("Interface" in k or "Communication" in k) and isinstance(c.get(k), list):
                c[k] = []
        comps.append(c)
    tra[key] = comps
    return tra


def v4_unused_interfaces(tra):
    """Network-facing interfaces left unattacked -> attack-surface use."""
    comps, key = _components(tra)
    n = 0
    for c in comps:
        ikey, ilist = _iface_field(c)
        if ikey and ilist:
            extra = copy.deepcopy(ilist[0])
            extra["interface_id"] = f"UNUSED-IF-{n}"
            extra["name"] = "Unattacked network-facing interface"
            ilist.append(extra)      # append to the LIVE list field
            n += 1
    return tra


def v5_orphan_protection_goals(tra):
    """Protection goals never referenced by any threat -> coverage."""
    pgs = tra.get("ProtectionGoals", [])
    template = copy.deepcopy(pgs[0]) if pgs else {}
    for i in range(1, 4):
        p = copy.deepcopy(template)
        p["pg_id"] = f"ORPHAN-PG-{i}"
        p["name"] = f"Unreferenced protection goal {i}"
        p["ThreatScenarios"] = []
        pgs.append(p)
    tra["ProtectionGoals"] = pgs
    return tra


def v6_keyword_threats(tra):
    """Threat descriptions reduced to single keywords -> CM-17 / CM-25."""
    for t in _threats(tra):
        t["attackActionDesc"] = "spoofing"
        t["name"] = "spoofing"
    return tra


def v7_blank_rating_comments(tra):
    """Rating-justification comments blanked -> reconstructability."""
    for t in _threats(tra):
        for k in ("exploitabilityComment", "threatSpecificExposureComment",
                  "threatSpecificImpactComment"):
            if k in t:
                t[k] = ""
        rr = t.get("ReRating")
        if isinstance(rr, dict):
            rr["acceptanceComment"] = ""
            rr["mitigation"] = ""
    return tra


def v8_risk_inconsistency(tra):
    """Risk rating contradicts impact x likelihood -> CM-20."""
    for t in _threats(tra):
        # force an obviously wrong risk cell
        if t.get("CALCAppliedImpactRating") and t.get("CALCLikelihood"):
            t["CALCRiskRating"] = "Low" if t.get("CALCRiskRating") != "Low" else "Critical"
    return tra


def v9_duplicate_threats(tra):
    """Near-identical threats cloned (duplicates) -> CM-19 / CM-24.

    Make cloned pairs near-identical in wording, but assign a conflicting severe
    rating so CM-19 (rating consistency across similar threats) deterministically
    fires in addition to CM-24.
    """
    ts = _threats(tra)
    clones = []
    # Build one coherent (impact, likelihood) pair for each target rating so
    # we can keep CM-20 coherent while still creating CM-19 conflicts.
    coherent_pair = {}
    for imp, row in tqr.RISK_MATRIX.items():
        for lik, risk in row.items():
            coherent_pair.setdefault(str(risk).lower(), (str(imp).title(), str(lik).replace("_", " ").title()))

    for idx, t in enumerate(ts[:8]):
        c = copy.deepcopy(t)
        c["threatscenario_id"] = (t.get("threatscenario_id", "T") or "T") + "-DUP"
        # Split clone ratings between coherent severe classes (Major/Moderate)
        # to maximize inconsistent similar-pair combinations for CM-19 while
        # remaining matrix-coherent (no CM-20 side-effect).
        target = "major" if idx % 2 == 0 else "moderate"
        imp, lik = coherent_pair.get(target, coherent_pair.get("major", ("Critical", "Very Likely")))
        c["CALCAppliedImpactRating"] = imp
        c["CALCLikelihood"] = lik
        c["CALCRiskRating"] = target.title()
        # Keep wording almost identical to preserve CM-24 near-duplicate behavior.
        if idx % 2 == 0:
            c["attackActionDesc"] = (t.get("attackActionDesc") or "") + ""
        clones.append(c)
    ts.extend(clones)
    tra["ThreatScenarios"] = ts
    return tra


def v10_metadata_inconsistency(tra):
    """Inconsistent version and date metadata -> completeness."""
    tra["TRAVersionNumber"] = ""
    tra["createdDate"] = "2025-13-45"       # impossible date
    tra["changedDate"] = "1999-01-01"       # earlier than created
    proj = tra.get("Project", {})
    if isinstance(proj, dict):
        proj["createdDate"] = ""
    return tra


def v11_unvalidated_assumptions(tra):
    """Assumptions marked unvalidated and unlinked -> coverage / consistency."""
    for a in tra.get("Assumptions", []):
        a["validated"] = False
        a["ZoneExposures"] = []
    return tra


def v12_drop_rating_fields(tra):
    """Rating or treatment fields dropped -> completeness / consistency."""
    for t in _threats(tra):
        for k in ("CALCAppliedImpactRating", "CALCLikelihood", "CALCRiskRating",
                  "exploitabilityRating"):
            t.pop(k, None)
        t.pop("ReRating", None)
    return tra


# Low-IDF (common, non-distinctive) good-vocab word pairs. Each pair sums to
# < CONCRETE_STRENGTH_MIN (1.0), so it clears the OLD raw ">=2 term" rule but
# fails the NEW IDF-weighted rule. Used to build the V13 evasion.
_STUFF_PAIRS = [
    ("physical", "unauthorized"), ("manipulate", "disable"),
    ("station", "remote"), ("steal", "plant"),
    ("configuration", "device"), ("unpatched", "operation"),
    ("physical", "remote"),
]


def v13_keyword_stuffing(tra):
    """Evasion: verbose but non-distinctive descriptions engineered to *look*
    specific (they reuse a couple of common good-vocab words and are long
    enough to clear the length gate) while carrying no distinctive technical
    content, and with the component/interface link removed so the specificity
    wording gate is the deciding factor -> CM-17.

    This variant exists to exercise the IDF-weighted specificity check: the old
    raw-overlap rule scored these as "specific" (false pass); the IDF rule flags
    them because the shared terms are collectively non-distinctive. The
    component/interface link is deliberately KEPT so the only degraded signal is
    the wording, isolating CM-17 (no coverage side-effects).
    """
    for i, t in enumerate(_threats(tra)):
        w1, w2 = _STUFF_PAIRS[i % len(_STUFF_PAIRS)]
        t["name"] = f"Entry item {i + 1}"
        t["attackActionDesc"] = (
            f"An attacker gains access and then influences the {w1} "
            f"and {w2} of that asset without further detail in entry "
            f"number {i + 1} as written here today by us.")
    return tra


MUTATIONS = [
    ("V1", "Placeholder text (TBD / open questions) left in fields", v1_placeholders),
    ("V2", "System overview and scope description removed", v2_remove_overview),
    ("V3", "Components added with no linked threat", v3_orphan_components),
    ("V4", "Network-facing interfaces left unattacked", v4_unused_interfaces),
    ("V5", "Protection goals never referenced by any threat", v5_orphan_protection_goals),
    ("V6", "Threat descriptions reduced to single keywords", v6_keyword_threats),
    ("V7", "Rating-justification comments blanked", v7_blank_rating_comments),
    ("V8", "Risk rating contradicts impact x likelihood", v8_risk_inconsistency),
    ("V9", "Near-identical threats cloned (duplicates)", v9_duplicate_threats),
    ("V10", "Inconsistent version and date metadata", v10_metadata_inconsistency),
    ("V11", "Assumptions marked unvalidated and unlinked", v11_unvalidated_assumptions),
    ("V12", "Rating or treatment fields dropped", v12_drop_rating_fields),
    ("V13", "Keyword-stuffed evasion (verbose but non-distinctive wording)", v13_keyword_stuffing),
]

# --------------------------------------------------------------------------- #
#  Design-intent targets: the criterion(s) each defect class is *designed* to
#  degrade. Defined from the mutation operators' intent (Table 8.3), NOT from
#  the observed results, so that precision/recall is a genuine detector metric.
#  A defect is "detected" when a targeted criterion's traffic-light status drops
#  (status-weight delta < 0). On-target drop = TP; targeted-but-no-drop = FN;
#  off-target drop = FP.
# --------------------------------------------------------------------------- #
TARGETS = {
    "V1":  {"CM-04"},
    "V2":  {"CM-03", "CM-13", "CM-14", "CM-15"},
    "V3":  {"CM-06"},
    "V4":  {"CM-07"},
    "V5":  {"CM-10"},
    "V6":  {"CM-17", "CM-25"},
    "V7":  {"CM-20", "CM-21"},
    "V8":  {"CM-20"},
    "V9":  {"CM-19", "CM-24"},
    "V10": {"CM-02"},
    "V11": {"CM-05"},
    "V12": {"CM-21", "CM-25"},
    "V13": {"CM-17"},
}



# --------------------------------------------------------------------------- #
#  Experiment driver
# --------------------------------------------------------------------------- #
def metric_maps(result):
    """id -> (value, status) for every core criterion."""
    vals, stats = {}, {}
    for m in result["core"]:
        vals[m["id"]] = m.get("value", 0.0)
        stats[m["id"]] = m.get("status", "na")
    return vals, stats


def status_weight(status):
    return STATUS_WEIGHT.get(status, None)  # None for 'na'


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(VARIANT_DIR, exist_ok=True)
    os.makedirs(FIG_DIR, exist_ok=True)

    with open(V0_PATH, "r", encoding="utf-8") as fh:
        v0 = json.load(fh)

    base = tqr.analyze(v0)
    base_vals, base_stats = metric_maps(base)
    criteria = [m["id"] for m in base["core"]]          # ordered CM-01..CM-28
    crit_dim = {m["id"]: m["dim"] for m in base["core"]}
    crit_better = {m["id"]: m.get("better", "high") for m in base["core"]}

    variants = []           # (label, defect, value_map, status_map, scorecard)
    for label, defect, fn in MUTATIONS:
        mutated = fn(copy.deepcopy(v0))
        mutated["TRAVersionName"] = f"MiniCPS mutation {label}: {defect}"
        # persist the variant for reproducibility
        with open(os.path.join(VARIANT_DIR, f"{label}.json"), "w", encoding="utf-8") as fh:
            json.dump(mutated, fh, indent=2)
        res = tqr.analyze(mutated)
        vals, stats = metric_maps(res)
        variants.append((label, defect, vals, stats, res["scorecard"]))

    # ---- 1) status-weight delta matrix (primary artefact) ------------------
    status_csv = os.path.join(OUT_DIR, "delta_status_matrix.csv")
    with open(status_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "defect"] + criteria)
        status_matrix = []
        for label, defect, vals, stats, _sc in variants:
            row = []
            for cid in criteria:
                bw = status_weight(base_stats.get(cid))
                vw = status_weight(stats.get(cid))
                row.append("" if (bw is None or vw is None) else round(vw - bw, 1))
            status_matrix.append(row)
            w.writerow([label, defect] + row)

    # ---- 2) raw value delta matrix (audit trail) ---------------------------
    value_csv = os.path.join(OUT_DIR, "delta_value_matrix.csv")
    with open(value_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "defect"] + criteria)
        for label, defect, vals, stats, _sc in variants:
            row = [round(vals.get(cid, 0.0) - base_vals.get(cid, 0.0), 2) for cid in criteria]
            w.writerow([label, defect] + row)

    # ---- 3) overall + per-dimension scores ---------------------------------
    dims = [d["dim"] for d in base["scorecard"]["dimensions"]]
    scores_csv = os.path.join(OUT_DIR, "overall_scores.csv")
    with open(scores_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "overall"] + dims)
        base_dim = {d["dim"]: d["score"] for d in base["scorecard"]["dimensions"]}
        w.writerow(["V0"] + [base["scorecard"]["overall"]] +
                   [base_dim.get(d, "") for d in dims])
        for label, defect, vals, stats, sc in variants:
            dm = {d["dim"]: d["score"] for d in sc["dimensions"]}
            w.writerow([label] + [sc["overall"]] + [dm.get(d, "") for d in dims])

    # ---- 4) heat-map -------------------------------------------------------
    png_path = os.path.join(FIG_DIR, "delta_matrix.png")
    made_png = _render_heatmap(criteria, [v[0] for v in variants], status_matrix, png_path)

    # Mirror the figure into the (optional, private) thesis folder if present.
    if made_png and os.path.isdir(THESIS_FIG_DIR):
        shutil.copyfile(png_path, os.path.join(THESIS_FIG_DIR, "delta_matrix.png"))

    # ---- 5) precision / recall as a defect detector ------------------------
    # Detection = targeted criterion's status weight dropped relative to V0.
    pr_csv = os.path.join(OUT_DIR, "precision_recall.csv")
    tot_tp = tot_fp = tot_fn = 0
    pr_rows = []
    for label, defect, vals, stats, _sc in variants:
        detected = set()
        for cid in criteria:
            bw = status_weight(base_stats.get(cid))
            vw = status_weight(stats.get(cid))
            if bw is not None and vw is not None and (vw - bw) < 0:
                detected.add(cid)
        targets = TARGETS.get(label, set())
        tp = len(targets & detected)
        fn = len(targets - detected)
        fp = len(detected - targets)
        tot_tp += tp; tot_fp += fp; tot_fn += fn
        pr_rows.append((label, sorted(targets), tp, fp, fn,
                        sorted(detected - targets)))
    precision = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 0.0
    recall = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    with open(pr_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "targets", "TP", "FP", "FN", "off_target_flags"])
        for label, targets, tp, fp, fn, offt in pr_rows:
            w.writerow([label, ";".join(targets), tp, fp, fn, ";".join(offt)])
        w.writerow([])
        w.writerow(["TOTAL", "", tot_tp, tot_fp, tot_fn, ""])
        w.writerow(["precision", round(precision, 3)])
        w.writerow(["recall", round(recall, 3)])
        w.writerow(["f1", round(f1, 3)])

    # ---- console summary ---------------------------------------------------
    print("Reference V0 overall quality:", base["scorecard"]["overall"])
    print("\nOverall score per variant (lower = more degraded):")
    for label, defect, vals, stats, sc in variants:
        print(f"  {label:<4} {sc['overall']:>6.1f}   {defect}")
    print(f"\nDetector performance (status-level, over {len(variants)} variants):")
    print(f"  TP={tot_tp}  FP={tot_fp}  FN={tot_fn}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}")
    print("\nArtefacts written:")
    for p in (status_csv, value_csv, scores_csv, pr_csv):
        print("  " + os.path.relpath(p, ROOT))

    if made_png:
        print("  " + os.path.relpath(png_path, ROOT))
    else:
        print("  (delta_matrix.png skipped - matplotlib not installed; "
              "run 'pip install matplotlib' to generate the figure)")


def _render_heatmap(criteria, variant_labels, matrix, png_path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception:
        return False

    data = np.array([[float(c) if c != "" else np.nan for c in row] for row in matrix])
    fig, ax = plt.subplots(figsize=(max(8, len(criteria) * 0.42),
                                    max(4, len(variant_labels) * 0.42)))
    cmap = plt.cm.RdYlGn            # negative (degraded) -> red, ~0 -> yellow/green
    cmap.set_bad(color="0.9")
    im = ax.imshow(data, cmap=cmap, vmin=-80, vmax=80, aspect="auto")
    ax.set_xticks(range(len(criteria)))
    ax.set_xticklabels(criteria, rotation=90, fontsize=7)
    ax.set_yticks(range(len(variant_labels)))
    ax.set_yticklabels(variant_labels, fontsize=8)
    ax.set_xlabel("Quality criterion")
    ax.set_ylabel("Degraded variant")
    ax.set_title("Status-weight change relative to reference V0 "
                 "(negative = criterion degraded)", fontsize=9)
    cbar = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cbar.set_label("Δ status weight", fontsize=8)
    fig.tight_layout()
    fig.savefig(png_path, dpi=200)
    plt.close(fig)
    return True


if __name__ == "__main__":
    main()
