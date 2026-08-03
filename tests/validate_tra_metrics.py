"""
validate_tra_metrics.py -- Validation harness for the TRA quality analyzer (Ch. 8).

Two studies, both importing the production analyzer (no logic is duplicated):

  Study 1 -- Seeded-defect detection.
      A known defect is injected into a clean, complete TRA and the harness
      checks whether the metric that *should* react actually does (true
      positive) or misses it (false negative). Collateral reactions of other
      metrics are listed and inspected for plausibility. The headline number is
      the detection rate (recall) over the seeded defect set.

  Study 2 -- Threshold sensitivity.
      The numeric thresholds (minimum word counts, Jaccard duplicate cut-off)
      are varied within a reasonable range and the overall quality ranking of a
      clean / mildly-damaged / heavily-damaged TRA is recomputed. If the ranking
      is invariant, the thresholds affect absolute scores but not the
      comparative conclusion (robustness).

Usage:
    python validate_tra_metrics.py [clean_tra.json]
"""

import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import tra_quality_report as t  # noqa: E402


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def metric(res, cid):
    """Return the computed metric dict with catalog id ``cid`` (or None)."""
    return next((m for m in res["core"] if m["id"] == cid), None)


def n_fail(m):
    return len((m.get("detail") or {}).get("fail") or [])


def is_worse(base_m, def_m):
    """True if ``def_m`` indicates lower quality than ``base_m``."""
    if base_m is None or def_m is None:
        return False
    if def_m.get("kind") == "count":            # better == 'low': more is worse
        return def_m["num"] > base_m["num"]
    if def_m.get("value", 0) < base_m.get("value", 0) - 0.01:
        return True
    if n_fail(def_m) > n_fail(base_m):
        return True
    order = {"ok": 0, "warn": 1, "bad": 2}
    return order.get(def_m["status"], 0) > order.get(base_m["status"], 0)


# --------------------------------------------------------------------------- #
#  defect generators -- each returns (mutated_tra, [target_ids], description)
# --------------------------------------------------------------------------- #
def d_empty_field(tra):
    """CM-15 -- empty a component description that is currently filled.

    CM-03 is now section-level (presence of populated sections), so clearing a
    single component description no longer flips it; the metric that reacts is
    CM-15 (scope clarity by component descriptions).
    """
    d = copy.deepcopy(tra)
    comps, _ = t.components_of(d)
    target = next((c for c in comps if (c.get("description") or "").strip()), None)
    if target:
        target["description"] = ""
    return d, ["CM-15"], "Empty a filled component description field"


def d_placeholder(tra):
    """CM-04 -- inject an unfinished-entry marker."""
    d = copy.deepcopy(tra)
    ts = d.get("ThreatScenarios") or []
    if ts:
        ts[0]["attackActionDesc"] = (ts[0].get("attackActionDesc") or "") + " TBD"
    return d, ["CM-04"], "Insert a 'TBD' placeholder into a threat"


def d_short_desc(tra):
    """CM-17 -- reduce a currently-adequate description to a bare keyword."""
    d = copy.deepcopy(tra)
    ts = d.get("ThreatScenarios") or []
    target = next((th for th in ts
                   if len((th.get("attackActionDesc") or "").split()) >= t.KEYWORD_ONLY_MIN_WORDS),
                  ts[0] if ts else None)
    if target is not None:
        target["attackActionDesc"] = "SQL injection"
    return d, ["CM-17"], "Reduce a threat description to a keyword"


def d_drop_pg_link(tra):
    """CM-10 -- remove the threat coverage of a currently-covered protection goal.

    The target is chosen deterministically (document order) and must be both
    non-negligible (CM-10 ignores negligible goals) and currently linked to at
    least one threat, so the seed always produces a real coverage drop.
    """
    d = copy.deepcopy(tra)
    linked = set()
    for th in d.get("ThreatScenarios") or []:
        for p in (th.get("ProtectionGoals") or []):
            if p.get("pg_id"):
                linked.add(p["pg_id"])
    for p in (d.get("ProtectionGoals") or []):
        if p.get("ThreatScenarios"):
            linked.add(p.get("pg_id"))
    pid = next((p.get("pg_id") for p in (d.get("ProtectionGoals") or [])
                if p.get("pg_id") in linked
                and str(p.get("impactLevel", "")).strip().lower() != "negligible"), None)
    if pid is not None:
        for p in (d.get("ProtectionGoals") or []):
            if p.get("pg_id") == pid:
                p["ThreatScenarios"] = []
        for th in d.get("ThreatScenarios") or []:
            th["ProtectionGoals"] = [x for x in (th.get("ProtectionGoals") or [])
                                     if x.get("pg_id") != pid]
    return d, ["CM-10"], "Remove all threat links from a protection goal"


def d_duplicate(tra):
    """CM-24 -- introduce a near-duplicate threat scenario."""
    d = copy.deepcopy(tra)
    ts = d.get("ThreatScenarios") or []
    if ts:
        dup = copy.deepcopy(ts[0])
        dup["threatscenario_id"] = (dup.get("threatscenario_id") or "TS") + "-DUP"
        ts.append(dup)
    return d, ["CM-24"], "Duplicate an existing threat scenario"


def d_remove_rationale(tra):
    """CM-20 -- strip the explanatory rating comments from every threat."""
    d = copy.deepcopy(tra)
    for th in (d.get("ThreatScenarios") or []):
        for k in ("exploitabilityComment", "threatSpecificExposureComment",
                  "threatSpecificImpactComment"):
            th[k] = ""
    return d, ["CM-20"], "Remove all rating rationale comments"


def d_uniform_ratings(tra):
    """CM-22 -- collapse every risk rating onto a single value."""
    d = copy.deepcopy(tra)
    for th in (d.get("ThreatScenarios") or []):
        if th.get("CALCRiskRating"):
            th["CALCRiskRating"] = "Moderate"
    return d, ["CM-22"], "Collapse all risk ratings onto one value"


DEFECTS = [d_empty_field, d_placeholder, d_short_desc, d_drop_pg_link,
           d_duplicate, d_remove_rationale, d_uniform_ratings]


# --------------------------------------------------------------------------- #
#  Study 1 -- seeded-defect detection
# --------------------------------------------------------------------------- #
def run_seeded(clean):
    base = t.analyze(clean)
    print("=== Study 1: seeded-defect detection ===")
    print(f"{'Seeded defect':40} {'Target':20} {'Detected':9} Collateral reactions")
    print("-" * 100)
    hits = 0
    for fn in DEFECTS:
        mut, targets, desc = fn(clean)
        res = t.analyze(mut)
        detected = all(is_worse(metric(base, c), metric(res, c)) for c in targets)
        hits += detected
        collat = [m["id"] for m in res["core"]
                  if m["id"] not in targets and is_worse(metric(base, m["id"]), m)]
        print(f"{desc[:40]:40} {','.join(targets):20} "
              f"{'YES' if detected else 'MISS':9} {', '.join(collat) or '-'}")
    print("-" * 100)
    print(f"Detection rate (recall): {hits}/{len(DEFECTS)} = {100 * hits / len(DEFECTS):.0f}%\n")


# --------------------------------------------------------------------------- #
#  Study 2 -- threshold sensitivity
# --------------------------------------------------------------------------- #
SWEEP_KEYS = ("KEYWORD_ONLY_MIN_WORDS", "OVERVIEW_MIN_WORDS",
              "SCOPE_DESC_MIN_WORDS", "JACCARD_DUP_THRESHOLD")


def run_sensitivity(clean):
    print("=== Study 2: threshold sensitivity ===")

    # build a mildly- and a heavily-damaged variant from the clean TRA.
    # mild   = a single-dimension defect (rating rationale stripped);
    # damaged = several dimensions degraded across MANY items at once.
    mild, _, _ = d_remove_rationale(clean)
    dmg = copy.deepcopy(clean)
    for th in dmg.get("ThreatScenarios") or []:
        th["attackActionDesc"] = "SQL injection"          # CM-17 / CM-24
        for k in ("exploitabilityComment", "threatSpecificExposureComment",
                  "threatSpecificImpactComment"):
            th[k] = ""                                     # CM-20
        if th.get("CALCRiskRating"):
            th["CALCRiskRating"] = "Moderate"              # CM-22
        th["ProtectionGoals"] = []                         # CM-10
    for p in dmg.get("ProtectionGoals") or []:
        p["ThreatScenarios"] = []
    variants = {"clean": clean, "mild": mild, "damaged": dmg}

    settings = {
        "low   (kw4/ov15/sd4/j0.50)":
            dict(KEYWORD_ONLY_MIN_WORDS=4, OVERVIEW_MIN_WORDS=15,
                 SCOPE_DESC_MIN_WORDS=4, JACCARD_DUP_THRESHOLD=0.50),
        "def   (kw6/ov20/sd5/j0.60)":
            dict(KEYWORD_ONLY_MIN_WORDS=6, OVERVIEW_MIN_WORDS=20,
                 SCOPE_DESC_MIN_WORDS=5, JACCARD_DUP_THRESHOLD=0.60),
        "high  (kw8/ov25/sd6/j0.70)":
            dict(KEYWORD_ONLY_MIN_WORDS=8, OVERVIEW_MIN_WORDS=25,
                 SCOPE_DESC_MIN_WORDS=6, JACCARD_DUP_THRESHOLD=0.70),
    }

    saved = {k: getattr(t, k) for k in SWEEP_KEYS}
    print(f"{'Threshold setting':34}" + "".join(f"{n:>9}" for n in variants) + "    ranking")
    print("-" * 100)
    try:
        for label, cfg in settings.items():
            for k, v in cfg.items():
                setattr(t, k, v)
            scores = {n: t.analyze(v)["scorecard"]["overall"] for n, v in variants.items()}
            ranking = " > ".join(n for n, _ in sorted(scores.items(), key=lambda kv: -kv[1]))
            print(f"{label:34}" + "".join(f"{scores[n]:9.1f}" for n in variants)
                  + f"    {ranking}")
    finally:
        for k, v in saved.items():
            setattr(t, k, v)
    print("-" * 100)
    print("If the ranking column is identical on every row, the thresholds shift\n"
          "absolute scores but not the comparative quality ordering (robust).\n")


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else t.DEFAULT_JSON
    if not os.path.isfile(path):
        sys.exit(f"Clean TRA not found: {path}")
    clean = load(path)
    print(f"Clean TRA: {os.path.basename(path)} "
          f"({len(clean.get('ThreatScenarios', []))} threats, "
          f"{len(clean.get('ProtectionGoals', []))} protection goals, "
          f"{len(clean.get('Assets', []))} assets)\n")
    run_seeded(clean)
    run_sensitivity(clean)
