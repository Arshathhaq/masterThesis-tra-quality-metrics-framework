#!/usr/bin/env python3
"""
TRA Quality Report Generator
============================

Reads a Threat & Risk Analysis (TRA) export (e.g. ExampleTRA.json),
computes the quality metrics, and writes:
    1) a standalone HTML dashboard report
    2) a JSON metrics output for tooling/integration

Usage:
        python tra_quality_report.py [path-to-tra.json]

No third-party dependencies are required (Python standard library only).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys
import html
from datetime import datetime, timedelta, timezone

# tra_tool.py lives next to this file and already implements the tra-ql
# question-catalog loading + interface crosswalk (used by `suggest`/`questions`).
# Reuse it here instead of duplicating the logic, so catalog-grounded
# suggestions in this report stay in sync with tra_tool.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import tra_tool as _tra_tool
except Exception:
    _tra_tool = None

# Reference corpus of "known-good" threat scenarios (CM-17). Every
# ThreatScenario found in any TRA JSON in this folder contributes to the
# good-threat vocabulary that real, product-specific threats are compared
# against by the rule-based specificity check.
GOOD_THREATS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "Threat_Corpus")
GOOD_THREATS_FILE = os.path.join(GOOD_THREATS_DIR, "SampleThreatScenarios.json")

# Data-driven threshold calibration corpus (idea/item 5): a labeled corpus of
# whole TRA JSON exports, split into <dir>/good/*.json and <dir>/poor/*.json.
# Mirrors the Threat_Corpus convention used for CM-14 vocabulary
# learning, but labels entire TRAs (not individual threats) so text-length
# and specificity thresholds can be calibrated against real quality outcomes
# instead of hand-picked constants.
CALIBRATION_CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "Calibration_Corpus")
CALIBRATION_LABELS = ("good", "poor")

# Optional CM-17 corpus learning gate. Entries are only appended when they
# are high-confidence specific threats and pass additional quality checks.
LEARN_MIN_SPECIFICITY_SCORE = 0.75
LEARN_MIN_WORDS = 8
LEARN_MIN_CHARS = 40

# Words that mark an unfinished / placeholder entry (CM-04). The bare word
# "test" was removed: it collides with legitimate content ("penetration test",
# "test environment", "regression test", ...). Placeholder-specific forms
# ("test entry/data/xxx/ttt") are kept.
PLACEHOLDER_PATTERNS = [
    r"QUESTION", r"\?\?", r"\bTBD\b", r"\bTODO\b", r"\bFIXME\b", r"\bXXX\b",
    r"\bplaceholder\b", r"\blorem\b", r"\bfill[\s_-]?in\b",
    r"\bto\s+be\s+(defined|done|determined|filled|completed|added)\b",
    r"\btest\s*(entry|data|value|text|xxx|ttt)\b", r"\bttt+\b", r"\bxxx+\b",
]

LIST_ITEM_ID_FIELDS = (
    "assumption_id", "threatscenario_id", "pg_id", "asset_id", "subUnit_id",
    "zone_id", "interface_id", "communication_id", "workshopID", "name",
)


def list_item_ref(section_path: str, item, index: int | None = None,
                  preferred_id_fields: tuple[str, ...] | None = None) -> str:
    """Return section-path reference like Assumptions[A_gen-1] with index fallback."""
    fields = preferred_id_fields or LIST_ITEM_ID_FIELDS
    ident = None
    if isinstance(item, dict):
        ident = next((item.get(k) for k in fields if item.get(k)), None)
    token = str(ident).strip() if ident is not None else ""
    if not token:
        token = str(index if index is not None else "?")
    token = token.replace("]", "_")
    return f"{section_path}[{token}]"


def extract_placeholder_hits(obj) -> list[dict]:
    """Find placeholder-pattern hits in every string field of a nested object.

    Returns a list of dicts with path, snippet and matched pattern, so CM-04 can
    show concrete evidence and reviewers can quickly spot false positives.
    """
    hits = []
    compiled = [re.compile(p, flags=re.IGNORECASE) for p in PLACEHOLDER_PATTERNS]

    def _walk(node, path: str):
        if isinstance(node, dict):
            for key, value in node.items():
                next_path = f"{path}.{key}" if path else str(key)
                _walk(value, next_path)
            return
        if isinstance(node, list):
            for idx, value in enumerate(node):
                next_path = list_item_ref(path or "<root-list>", value, idx)
                _walk(value, next_path)
            return
        if not isinstance(node, str):
            return

        # Treat strings that only contain whitespace/newlines as unfinished
        # content (e.g., "\n\n\n").
        if node and not node.strip():
            hits.append({
                "path": path or "<root>",
                "pattern": "WHITESPACE_ONLY",
                "snippet": f"{len(node)} whitespace character(s)",
            })
            return

        for cre in compiled:
            for match in cre.finditer(node):
                start, end = match.start(), match.end()
                left = max(0, start - 35)
                right = min(len(node), end + 35)
                snippet = node[left:right].replace("\r", " ").replace("\n", " ").strip()
                if left > 0:
                    snippet = "..." + snippet
                if right < len(node):
                    snippet = snippet + "..."
                hits.append({
                    "path": path or "<root>",
                    "pattern": cre.pattern,
                    "snippet": snippet,
                })

    _walk(obj, "")
    return hits


def extract_vague_term_hits(obj) -> list[dict]:
    """Find vague/hedging term hits (CM-22) across every string field of a
    nested object, not just a single description field. Only strings with at
    least 3 words are scanned, so IDs, enum values, and single-word labels
    (which are not prose) can't trigger a false hit.

    Returns a list of dicts with path and matched term, so evidence can name
    both which vague words were used and which field(s) they came from.
    """
    hits = []

    def _walk(node, path: str):
        if isinstance(node, dict):
            for key, value in node.items():
                _walk(value, f"{path}.{key}" if path else str(key))
            return
        if isinstance(node, list):
            for idx, value in enumerate(node):
                _walk(value, list_item_ref(path or "<root-list>", value, idx))
            return
        if not isinstance(node, str):
            return
        if len(re.findall(r"\w+", node)) < 3:
            return
        for match in VAGUE_RE.finditer(node):
            hits.append({"path": path or "<root>", "term": match.group(0).lower()})

    _walk(obj, "")
    return hits


# --------------------------------------------------------------------------- #
#  Metric computation
# --------------------------------------------------------------------------- #
def collect_text(obj) -> str:
    """Flatten all string values of a nested object into one blob."""
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.append(collect_text(v))
    elif isinstance(obj, list):
        for v in obj:
            out.append(collect_text(v))
    elif isinstance(obj, str):
        out.append(obj)
    return " ".join(out)


def parse_iso_datetime(value):
    """Parse an ISO-like timestamp string to aware datetime (UTC), else None."""
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_human_datetime(value):
    """Format timestamp value for readable report output."""
    dt = parse_iso_datetime(value)
    return dt.strftime("%Y-%m-%d") if dt else "(missing)"


# A TRA export describes one of two "Target Areas", which use different
# container key names for the same underlying structure:
#   * Software Component development  -> "SWComponents",  "LogicalInterfaces",
#       "HostLevelInterfaces_Zone", "NetworkFacingInterfaces_Zone",
#       "InterSWCommunications"
#   * Design & Deployment of a System -> "SystemComponents", "NetworkFacingInterfaces",
#       "ProximityInterfaces", "NetworkCommunications"
# The inner field names (interface_id, communication_id, SourceComponent,
# TargetInterface, ...) are identical, so we detect the container keys
# structurally instead of hard-coding either variant.
COMPONENT_ARRAY_KEYS = ("SWComponents", "SystemComponents")


def components_of(tra: dict):
    """Return (components list, key) for whichever component array the TRA uses.

    Works for both Target Areas (Software development / System deployment) by
    preferring the known keys, then falling back to any top-level list whose
    key ends in 'Components'.
    """
    for key in COMPONENT_ARRAY_KEYS:
        if isinstance(tra.get(key), list):
            return tra[key], key
    for key, val in tra.items():
        if key.endswith("Components") and isinstance(val, list):
            return val, key
    return [], None


def component_interfaces(comp: dict) -> list:
    """Return all interface objects of a component, regardless of Target Area.

    Any list-valued field whose name contains 'Interface' is treated as an
    interface collection (LogicalInterfaces, NetworkFacingInterfaces,
    ProximityInterfaces, HostLevelInterfaces_Zone, ...). The dict-valued
    'AttackInterface' on threats is naturally excluded by the list check.
    """
    ifaces = []
    for key, val in comp.items():
        if "Interface" in key and isinstance(val, list):
            ifaces.extend(val)
    return ifaces


def component_communications(comp: dict) -> list:
    """Return all communication edges declared on a component, any Target Area.

    A communication is a directed data-flow edge: a SourceComponent reaches a
    TargetInterface hosted by the owning component. Software TRAs name the list
    'InterSWCommunications', System/Deployment TRAs 'NetworkCommunications';
    both are matched by the 'Communication' name fragment.
    """
    comms = []
    for key, val in comp.items():
        if "Communication" in key and isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    row = dict(item)
                    row["_comm_list_type"] = key
                    comms.append(row)
    return comms


GENERIC_COMPONENT_NAMES = {
    "test", "temp", "component", "module", "unknown", "general", "generic",
}


def is_generic_component(comp: dict) -> bool:
    """Return True for placeholder/generic component names that should be
    ignored by coverage-style attack-surface metrics."""
    name = str((comp or {}).get("name") or "").strip().lower()
    return bool(name) and (name in GENERIC_COMPONENT_NAMES or name.startswith("_"))


# --------------------------------------------------------------------------- #
#  Question-list (tra-ql) catalog-grounded suggestions
#
#  Coverage gaps (orphan protection goals, components/interfaces never
#  attacked, ...) are turned into *advisory* pointers into the PSS TRA
#  Question List catalog, so a reviewer gets a concrete starting point
#  ("which catalog question could seed a threat scenario here") instead of a
#  bare "missing" flag. This never invents a threat - it only cites catalog
#  question IDs/titles/CWEs for the human to confirm, reject or refine.
# --------------------------------------------------------------------------- #

# Reverse of the Attack-action -> STRIDE / CIA bridge table in
# create-tra/SKILL.md: which tra-ql attack actions can violate a given CIA
# protection-goal type.
PG_TYPE_TO_TRAQL_ACTIONS = {
    "Confidentiality": ["nc"],
    "Integrity": ["mc", "ac", "mi", "nc"],
    "Availability": ["er"],
}


def _catalog_questions_for_codes(codes: list, actions: list | None = None, limit: int = 3) -> list[str]:
    """Return up to `limit` formatted 'QID Title' strings from the tra-ql
    catalog whose applicability matches any of `codes`, optionally restricted
    to a set of attack actions. Returns [] if the catalog or tra_tool helpers
    are unavailable, or nothing matches."""
    if not codes or _tra_tool is None:
        return []
    catalog = _tra_tool.load_catalog()
    if not catalog:
        return []
    matches = _tra_tool._match_questions(catalog, codes)
    if actions:
        wanted = set(actions)
        matches = [(q, acts) for q, acts in matches if wanted & set(acts)]
    out = []
    for q, acts in matches[:limit]:
        qid = q.get("qid", "?")
        title = q.get("title", "?")
        out.append(f"{qid} ({title})")
    return out


def suggest_for_pg(pg: dict, comps: list) -> str:
    """Advisory catalog suggestion for an orphan ProtectionGoal: which tra-ql
    questions (filtered by the goal's CIA type) could seed a missing threat
    scenario. Uses the union of tra-ql interface codes present anywhere in the
    TRA (no precise Asset->Interface link is required/assumed)."""
    actions = PG_TYPE_TO_TRAQL_ACTIONS.get(pg.get("protectionGoalType") or "", [])
    codes = set()
    for c in comps:
        for it in component_interfaces(c):
            if _tra_tool is not None:
                codes.update(_tra_tool._traql_codes_for_interface(it))
    qs = _catalog_questions_for_codes(sorted(codes), actions)
    if not qs:
        return ""
    return f"consider TRA question-list entries for {pg.get('protectionGoalType')}: {', '.join(qs)}"


def suggest_for_component(comp: dict) -> str:
    """Advisory catalog suggestion for a component never reached by a threat:
    which tra-ql questions apply to its own interfaces."""
    if _tra_tool is None:
        return ""
    codes = set()
    for it in component_interfaces(comp):
        codes.update(_tra_tool._traql_codes_for_interface(it))
    qs = _catalog_questions_for_codes(sorted(codes))
    if not qs:
        return ""
    return f"consider TRA question-list entries: {', '.join(qs)}"


# --------------------------------------------------------------------------- #
#  Workshop free-text comments parsing (CM-01)
#
#  Excel-imported TRAs commonly carry the moderator and participant/role
#  information as free text in the workshop's 'comments' field rather than in
#  the schema's structured Participants/Participations arrays (which only
#  support an AccountGID per participant and have no 'role' field at all - role
#  can only ever live in free text). This is best-effort *advisory* parsing
#  for assessment/reporting purposes only; it does not modify the TRA and does
#  not claim schema compliance.
# --------------------------------------------------------------------------- #

_MODERATOR_RE = re.compile(r"Moderator\s*:\s*([^\n\r]+)", re.IGNORECASE)
_PARTICIPANT_RE = re.compile(
    r"Participant\s*Name\s*:\s*([^\n\r]+?)\s*[\r\n]+\s*Role\s*:\s*([^\n\r]+)", re.IGNORECASE)


def _parse_workshop_comments(comments: str) -> dict:
    """Best-effort extraction of 'Moderator: X' and 'Participant Name: Y /
    Role: Z' pairs from free-text workshop comments. Returns
    {"moderator": str|None, "participants": [{"name": str, "role": str}, ...]}."""
    if not comments:
        return {"moderator": None, "participants": []}
    mod = _MODERATOR_RE.search(comments)
    moderator = mod.group(1).strip() if mod else None
    participants = [{"name": n.strip(), "role": r.strip()}
                    for n, r in _PARTICIPANT_RE.findall(comments)]
    return {"moderator": moderator, "participants": participants}


def analyze(tra: dict) -> dict:
    assets = tra.get("Assets", [])
    pgs = tra.get("ProtectionGoals", [])
    threats = tra.get("ThreatScenarios", [])
    zones = tra.get("SecurityZones", [])
    comps, component_key = components_of(tra)
    assumptions = tra.get("Assumptions", [])

    # ---- interface inventory -------------------------------------------------
    # logical_iface_ids = interfaces owned directly by a component (used for the
    # "attack-surface utilization" metric); all_iface_ids also includes
    # zone-level interfaces. Collected structurally so both Target Areas work.
    logical_iface_ids = set()
    all_iface_ids = set()
    iface_owner = {}  # interface_id -> component subUnit_id
    iface_name = {}   # interface_id -> human-readable interface name
    for c in comps:
        for it in component_interfaces(c):
            iid = it.get("interface_id")
            if not iid:
                continue
            all_iface_ids.add(iid)
            logical_iface_ids.add(iid)
            iface_owner.setdefault(iid, c.get("subUnit_id"))
            iname = str(it.get("name") or "").strip()
            if iname:
                iface_name.setdefault(iid, iname)
    # zone-level interfaces (any list field on a zone whose name contains "Interface")
    for z in zones:
        for key, val in z.items():
            if "Interface" in key and isinstance(val, list):
                for it in val:
                    if it.get("interface_id"):
                        all_iface_ids.add(it["interface_id"])

    in_scope = [c for c in comps if c.get("scope") == "In_Scope"]

    # ---- threat -> interface / pg --------------------------------------------
    threat_iface = {t.get("threatscenario_id"): (t.get("AttackInterface") or {}).get("interface_id")
                    for t in threats if t.get("threatscenario_id")}
    # interfaces actually used as an attack surface
    used_ifaces = {i for i in threat_iface.values() if i}

    # reverse map: interface_id -> sorted [threatscenario_id, ...] that attack
    # it. This is the concrete evidence a reviewer needs to confirm "yes, this
    # interface/component/communication really is covered" instead of a bare
    # pass/fail flag (used by CM-06/07/09).
    iface_to_threats: dict = {}
    for tid, iid in threat_iface.items():
        if iid:
            iface_to_threats.setdefault(iid, []).append(tid)
    for iid in iface_to_threats:
        iface_to_threats[iid].sort()

    # components reached by a threat (through one of their interfaces)
    comp_ifaces = {c.get("subUnit_id"): {it.get("interface_id")
                   for it in component_interfaces(c) if it.get("interface_id")}
                   for c in comps if c.get("subUnit_id")}

    # ---- inter-component communications --------------------------------------
    # Directed data-flow edges (SourceComponent -> TargetInterface, hosted by
    # the owning component). A component also counts as "reached" by a threat
    # when it sits on a communication path whose endpoint interface is attacked.
    communications = []
    for c in comps:
        for cm in component_communications(c):
            tiface = (cm.get("TargetInterface") or {}).get("interface_id")
            communications.append(dict(
                id=cm.get("communication_id"), name=cm.get("name"),
                owner=c.get("subUnit_id"),
                source=(cm.get("SourceComponent") or {}).get("subUnit_id"),
                target_iface=tiface,
                list_type=cm.get("_comm_list_type") or "UnknownCommunicationList"))
            if tiface:
                all_iface_ids.add(tiface)

    comp_comm_reach = {}  # subUnit_id -> ["LC-x (name) -> LI-y", ...]
    for cm in communications:
        if cm["target_iface"] in used_ifaces:
            for sid in (cm["source"], cm["owner"]):
                if sid:
                    comp_comm_reach.setdefault(sid, []).append(
                        f"{cm['id']} ({cm['name']}) -> {cm['target_iface']}")

    comps_with_threat = {sid for sid, ifs in comp_ifaces.items() if ifs & used_ifaces}
    comps_with_threat |= set(comp_comm_reach)

    # per-component reading for CM-05: which in-scope components are NOT
    # reached by any threat, and through which interface / communication path.
    comp_name = {c.get("subUnit_id"): c.get("name") for c in comps if c.get("subUnit_id")}
    m2_linked, m2_missing = [], []
    for c in [c for c in comps if c.get("scope") == "In_Scope" and not is_generic_component(c)]:
        sid = c.get("subUnit_id")
        ifs = comp_ifaces.get(sid, set())
        reached = ifs & used_ifaces
        comm = comp_comm_reach.get(sid, [])
        if reached or comm:
            via = []
            if reached:
                attackers = sorted({tid for i in reached for tid in iface_to_threats.get(i, [])})
                via.append("interface " + ", ".join(sorted(reached))
                          + (f" (attacked by {', '.join(attackers)})" if attackers else ""))
            if comm:
                via.append("communication " + ", ".join(sorted(comm)))
            m2_linked.append(f"{sid} ({comp_name.get(sid)}) - reached via {'; '.join(via)}")
        else:
            if ifs:
                why = (f"none of its interfaces [{', '.join(sorted(ifs))}] and no communication "
                       f"is used as an AttackInterface")
            else:
                why = "component exposes no interfaces and no communications at all"
            m2_missing.append(f"{sid} ({comp_name.get(sid)}) - missing threat linkage: {why}")

    # protection goals linked to a threat (either direction), plus the reverse
    # map pg_id -> sorted [threatscenario_id, ...] so CM-09 can cite exactly
    # which threat(s) satisfy coverage for each protection goal.
    pgs_with_threat = set()
    pg_to_threats: dict = {}
    for t in threats:
        for p in (t.get("ProtectionGoals") or []):
            if p.get("pg_id"):
                pgs_with_threat.add(p["pg_id"])
                pg_to_threats.setdefault(p["pg_id"], set()).add(t.get("threatscenario_id"))
    for p in pgs:
        if p.get("ThreatScenarios"):
            pgs_with_threat.add(p.get("pg_id"))
            for ts in p["ThreatScenarios"]:
                if ts.get("threatscenario_id"):
                    pg_to_threats.setdefault(p.get("pg_id"), set()).add(ts["threatscenario_id"])
    pg_to_threats = {pid: sorted(tids) for pid, tids in pg_to_threats.items()}

    # assets represented by at least one protection goal
    assets_covered = {(p.get("Asset") or {}).get("asset_id") for p in pgs}
    assets_covered.discard(None)

    # zone exposures
    zone_exposures = []
    for z in zones:
        for ze in z.get("ZoneExposures", []) or []:
            zone_exposures.append(ze)

    # placeholder density (CM-04) across all text fields, with per-hit evidence
    placeholder_readings = extract_placeholder_hits(tra)
    placeholder_hits = len(placeholder_readings)

    n_assets, n_pgs, n_threats = len(assets), len(pgs), len(threats)

    # human-readable labels for per-item readings
    clab = lambda c: f"{c.get('subUnit_id')} ({c.get('name')})"
    plab = lambda p: f"{p.get('pg_id')} ({p.get('name')})"
    tlab = lambda t: f"{t.get('threatscenario_id')} ({t.get('name')})"
    alab = lambda a: f"{a.get('assumption_id')} ({a.get('name')})"
    aslab = lambda a: f"{a.get('asset_id')} ({a.get('name')})"

    # ----------------------------------------------------------------------- #
    # Core metrics (CM set, from the metric catalog).
    #  Computed structurally from the same JSON so they work for BOTH target
    #  areas (Software / Deployment).
    # ----------------------------------------------------------------------- #
    core = compute_core_metrics(
        tra,
        assets=assets, pgs=pgs, threats=threats, zones=zones, comps=comps,
        in_scope=in_scope, assumptions=assumptions,
        logical_iface_ids=logical_iface_ids, used_ifaces=used_ifaces,
        comps_with_threat=comps_with_threat, pgs_with_threat=pgs_with_threat,
        assets_covered=assets_covered, iface_owner=iface_owner, iface_name=iface_name,
        communications=communications, iface_to_threats=iface_to_threats,
        pg_to_threats=pg_to_threats,
        m2_linked=m2_linked, m2_missing=m2_missing, placeholder_hits=placeholder_hits,
        placeholder_readings=placeholder_readings,
        clab=clab, tlab=tlab, plab=plab, alab=alab, aslab=aslab)

    findings = build_findings(tra, assets, pgs, threats, assets_covered, pgs_with_threat,
                              comps_with_threat, in_scope, assumptions, core=core)

    selection = str((tra.get("Project", {}).get("Config", {}) or {}).get("selection") or "")
    target_area = {
        "Software": "Software Development Project",
        "Deployment": "Design & Deployment of a System",
    }.get(selection, selection or "Unknown")

    summary = dict(
        assets=n_assets, protection_goals=n_pgs, threats=n_threats,
        zones=len(zones), components=len(comps), in_scope=len(in_scope),
        out_of_scope=len(comps) - len(in_scope), assumptions=len(assumptions),
        interfaces=len(all_iface_ids), zone_exposures=len(zone_exposures),
        target_area=target_area, component_key=component_key,
    )
    return dict(findings=findings, summary=summary, core=core,
                dimension_status=compute_dimension_status(core),
                project=tra.get("Project", {}), status=tra.get("status"))


def status_from_metric(m: dict) -> str:
    """Traffic-light status from metric counts/ratios."""
    def _first_match_status(rules, default="ok"):
        for mapped_status, predicate in rules:
            if predicate():
                return mapped_status
        return default

    if m.get("kind") == "count":
        return _first_match_status([
            ("bad", lambda: m["num"] > 5),
            ("warn", lambda: m["num"] > 0),
        ])

    den = m.get("den") or 0
    num = m.get("num") or 0
    v = ((num / den) * 100) if den else 0.0

    if m["better"] == "low":
        return _first_match_status([
            ("bad", lambda: v > 40),
            ("warn", lambda: v > 10),
        ])

    return _first_match_status([
        ("bad", lambda: v < 60),
        ("warn", lambda: v < 90),
    ])


# --------------------------------------------------------------------------- #
# Core metric set (CM-xx) - computed structurally from the
#  TRA JSON, so it works for BOTH target areas (Software / Deployment).
# --------------------------------------------------------------------------- #
# Risk & Likelihood matrices for the rating-coherence check (final catalog
# CM-20). These reproduce the project's TRA rating matrices exactly, so the
# stored CALCRiskRating / CALCLikelihood can be recomputed and verified cell by
# cell (not approximated). Label keys are lower-cased; unknown labels skip the
# check for that threat.
#
# Risk = f(Impact, Likelihood)   - rows: impact, cols: likelihood
# Authoritative source: the "Risk Level Matrix" table in
# .agents/skills/create-tra/SKILL.md. Keep this in sync with the RISK_MATRIX
# in validate_tra.py - both must agree with that table cell-for-cell.
RISK_MATRIX = {
    "negligible": {"very_unlikely": "minor",    "unlikely": "minor",    "possible": "minor",       "likely": "minor",       "very_likely": "moderate"},
    "moderate":   {"very_unlikely": "minor",    "unlikely": "moderate", "possible": "moderate",    "likely": "moderate",    "very_likely": "significant"},
    "critical":   {"very_unlikely": "minor",    "unlikely": "moderate", "possible": "moderate",    "likely": "significant", "very_likely": "major"},
    "disastrous": {"very_unlikely": "moderate", "unlikely": "moderate", "possible": "significant", "likely": "major",       "very_likely": "major"},
}
# Likelihood = f(Exploitability/Simplicity, Exposure) - rows: exploitability, cols: exposure
LIKELIHOOD_MATRIX = {
    "high":   {"high": "very_likely", "medium": "likely",   "low": "possible"},
    "medium": {"high": "likely",      "medium": "possible", "low": "unlikely"},
    "low":    {"high": "possible",    "medium": "unlikely", "low": "very_unlikely"},
}


def _norm_rating(v):
    """Normalise a rating label to a matrix key (lower-case, spaces->_)."""
    return str(v or "").strip().lower().replace(" ", "_")


# CM-19: severity classes that matter for the rating-consistency check. Per the
# refinement request the focus is on Moderate / Major / Critical / Severe
# ("disastrous") ratings; differences that involve only Negligible/Minor ratings
# are not treated as inconsistencies.
SEVERE_RISK = {"moderate", "major", "critical", "severe", "catastrophic", "disastrous"}

# CM-17: generic / non-distinctive tokens removed when comparing a threat's
# wording against the good-threat vocabulary, so only concrete technical /
# mechanism terms count towards "specificity".
GENERIC_THREAT_TERMS = {
    "attacker", "adversary", "access", "accesses", "gain", "gains", "gets", "data",
    "user", "users", "system", "systems", "network", "could", "would", "cause",
    "vulnerability", "exploit", "exploits", "exploited", "malicious", "information",
    "server", "service", "services", "application", "component", "components",
    "interface", "interfaces", "password", "account", "attack", "attacks",
    "possible", "without", "through", "using", "which", "there", "their", "with",
    "from", "that", "this", "then", "into", "other", "some", "have", "will",
}

# CM-17: common non-technical English words that carry no domain specificity.
# Stripped from the good-threat vocabulary so ordinary prose ("considered",
# "equivalent", ...) cannot be mistaken for concrete, mechanism-specific terms.
STOPWORDS = {
    "considered", "consider", "considers", "equivalent", "equal", "equally",
    "given", "taken", "based", "related", "described", "defined", "provided",
    "required", "needed", "allowed", "enabled", "involved", "associated",
    "respective", "additional", "following", "above", "below", "within",
    "between", "because", "therefore", "however", "whereas", "since", "while",
    "being", "been", "does", "done", "made", "make", "only", "also", "such",
    "each", "every", "more", "most", "less", "than", "when", "where", "what",
    "whose", "they", "them", "thus", "here", "these", "those", "same", "both",
    "either", "neither", "example", "including", "included", "includes", "used",
    "part", "parts", "case", "cases", "type", "types", "kind", "form", "level",
}

_GOOD_VOCAB_CACHE = None

# CM-17: known misspellings in the curated good-threat corpus mapped to their
# canonical form, so a copied typo cannot masquerade as a distinct concrete
# term (and so the IDF of the real term is not diluted). Small and explicit by
# design -- this is a data-hygiene map, NOT a statistical spell-checker.
VOCAB_NORMALISE = {
    "acceess": "access",
    "acess": "access",
    "authetication": "authentication",
    "authentification": "authentication",
    "vulnerabiity": "vulnerability",
    "vulnerabilty": "vulnerability",
    "vulnerabilities": "vulnerability",
    "errir": "error",
    "anlysis": "analysis",
    "malicous": "malicious",
}

# CM-17: short technical tokens that are security-relevant and should be kept
# even when shorter than the generic minimum word length.
SHORT_TECH_TERMS = {
    "api", "ssh", "tls", "vpn", "hmi", "rtu", "plc", "dos", "mitm", "sql",
    "xss", "ids", "ips", "iam", "lan", "wan", "usb", "gui", "cli",
}

# CM-17: entries in the good-threat corpus that document exclusions or review
# notes are filtered out from the vocabulary source to avoid polluting matches.
NON_THREAT_TEXT_RE = re.compile(
    r"\b(not\s+relevant|not\s+rated|not\s+considered|"
    r"threat\s+was\s+not\s+rated|not\s+applicable)\b",
    re.IGNORECASE,
)


def tokenize_security_terms(text: str) -> set[str]:
    """Tokenize text for CM-17 and keep short security acronyms."""
    raw = re.findall(r"[a-z0-9]{3,}", (text or "").lower())
    normalized = {str(VOCAB_NORMALISE.get(w, w) or w) for w in raw}
    return {w for w in normalized if len(w) >= 4 or w in SHORT_TECH_TERMS}


def is_good_threat_entry(threat: dict) -> bool:
    """Return True if a corpus threat entry is usable for CM-17 vocabulary."""
    name = str(threat.get("name") or "").strip()
    attack = str(threat.get("attackActionDesc") or "").strip()
    weakness = str(threat.get("weakness") or "").strip()

    # Numeric-only names and empty descriptions are low-quality placeholders.
    if name and re.fullmatch(r"\d+[a-z]?$", name.lower()):
        return False
    if not (name or attack or weakness):
        return False

    text = f"{name} {attack} {weakness}"
    # Skip entries that explicitly document exclusion/rationale text.
    if NON_THREAT_TEXT_RE.search(text):
        return False
    # Skip obvious placeholder markers already used in CM-04 logic.
    if any(re.search(p, text, flags=re.IGNORECASE) for p in PLACEHOLDER_PATTERNS):
        return False

    return True


def _cm17_evaluate_threat(threat: dict, good_vocab: set[str],
                          good_idf: dict[str, float]) -> dict:
    """Evaluate CM-17 specificity signals for one threat."""
    desc = threat.get("attackActionDesc") or ""
    text = f"{threat.get('name', '')} {desc}".lower()
    toks = tokenize_security_terms(text)
    specific = (toks & good_vocab) if good_vocab else set()
    concrete_strength = sum(good_idf.get(w, 0.0) for w in specific)
    concrete_ok = (len(specific) >= CONCRETE_MIN_TERMS
                   and concrete_strength >= CONCRETE_STRENGTH_MIN)
    has_iface = bool((threat.get("AttackInterface") or {}).get("interface_id"))
    words = len(re.findall(r"\w+", desc))
    long_enough = words >= KEYWORD_ONLY_MIN_WORDS
    has_actor = bool(ACTOR_RE.search(desc))
    vague_hits = len(set(mo.group(0).lower() for mo in VAGUE_RE.finditer(desc)))

    score = 0.0
    if has_iface:
        score += 0.30
    if concrete_ok or (not good_vocab and long_enough and has_actor):
        score += 0.40
    if long_enough and vague_hits < 2:
        score += 0.30

    is_specific = score >= SPECIFICITY_PASS_THRESHOLD and (has_iface or concrete_ok)
    return {
        "score": score,
        "specific_terms": specific,
        "concrete_ok": concrete_ok,
        "has_iface": has_iface,
        "words": words,
        "vague_hits": vague_hits,
        "is_specific": is_specific,
    }


def _threat_text_signature(threat: dict) -> str:
    """Stable normalized text signature for deduplicating good-threat entries."""
    parts = [
        str(threat.get("name") or ""),
        str(threat.get("attackActionDesc") or ""),
        str(threat.get("weakness") or ""),
    ]
    text = " | ".join(parts).lower()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^a-z0-9| ]+", "", text)
    return text.strip()


def _next_gt_id(existing_items: list[dict]) -> str:
    max_id = 0
    for item in existing_items:
        gid = str((item or {}).get("gt_id") or "")
        mo = re.fullmatch(r"GT-(\d+)", gid)
        if mo:
            max_id = max(max_id, int(mo.group(1)))
    return f"GT-{max_id + 1:04d}"


def learn_good_threats(tra: dict) -> tuple[int, int, str]:
    """Append high-confidence threats to the curated CM-17 corpus.

    Returns (added_count, considered_count, output_file).
    """
    threats = [t for t in (tra.get("ThreatScenarios") or []) if isinstance(t, dict)]
    good_vocab, good_idf, _, _ = load_good_threat_vocab()

    os.makedirs(GOOD_THREATS_DIR, exist_ok=True)
    corpus_doc = {
        "description": (
            "Curated good threat scenarios (wording only) used as the reference "
            "vocabulary for the CM-17 threat-specificity check. "
            "Only name, attackActionDesc and weakness are read by the analyzer."
        ),
        "count": 0,
        "ThreatScenarios": [],
    }
    if os.path.isfile(GOOD_THREATS_FILE):
        try:
            with open(GOOD_THREATS_FILE, "r", encoding="utf-8-sig") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                corpus_doc = loaded
        except (OSError, json.JSONDecodeError):
            pass

    existing_items = [x for x in (corpus_doc.get("ThreatScenarios") or []) if isinstance(x, dict)]
    existing_sigs = {_threat_text_signature(x) for x in existing_items if is_good_threat_entry(x)}

    considered = 0
    added = []
    for t in threats:
        if not is_good_threat_entry(t):
            continue
        desc = str(t.get("attackActionDesc") or "")
        words = len(re.findall(r"\w+", desc))
        chars = len(desc.strip())
        eval_res = _cm17_evaluate_threat(t, good_vocab, good_idf)

        considered += 1
        if not eval_res["is_specific"]:
            continue
        if eval_res["score"] < LEARN_MIN_SPECIFICITY_SCORE:
            continue
        if not eval_res["concrete_ok"]:
            continue
        if not eval_res["has_iface"]:
            continue
        if words < LEARN_MIN_WORDS or chars < LEARN_MIN_CHARS:
            continue

        candidate = {
            "name": t.get("name") or "",
            "attackActionDesc": t.get("attackActionDesc") or "",
        }
        if t.get("weakness"):
            candidate["weakness"] = t.get("weakness")

        sig = _threat_text_signature(candidate)
        if not sig or sig in existing_sigs:
            continue
        existing_sigs.add(sig)
        added.append(candidate)

    for item in added:
        item["gt_id"] = _next_gt_id(existing_items)
        existing_items.append(item)

    corpus_doc["ThreatScenarios"] = existing_items
    corpus_doc["count"] = len(existing_items)
    with open(GOOD_THREATS_FILE, "w", encoding="utf-8") as fh:
        json.dump(corpus_doc, fh, indent=2)

    # Invalidate cache so a subsequent run in the same process sees updates.
    global _GOOD_VOCAB_CACHE
    _GOOD_VOCAB_CACHE = None
    return len(added), considered, GOOD_THREATS_FILE


def _iter_labeled_calibration_files(corpus_dir: str):
    """Yield (label, file_path, tra_dict) for every TRA JSON under
    <corpus_dir>/good/*.json and <corpus_dir>/poor/*.json."""
    for label in CALIBRATION_LABELS:
        label_dir = os.path.join(corpus_dir, label)
        if not os.path.isdir(label_dir):
            continue
        for fn in sorted(os.listdir(label_dir)):
            if not fn.lower().endswith(".json"):
                continue
            path = os.path.join(label_dir, fn)
            try:
                with open(path, "r", encoding="utf-8-sig") as fh:
                    tra = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(tra, dict):
                yield label, path, tra


def _best_separating_threshold(good_values: list, poor_values: list, *, higher_is_better: bool):
    """Scan candidate thresholds and return the (threshold, accuracy) that
    best separates 'good' from 'poor' labeled samples.

    Candidates are the sorted unique observed values plus their midpoints.
    This is plain descriptive statistics (a brute-force best-split scan), not
    machine learning -- deterministic and offline, consistent with the rest
    of this tool. Returns (None, None) when there is nothing to compare.
    """
    values = sorted(set(good_values) | set(poor_values))
    if not values:
        return None, None
    candidates = set(values)
    candidates.update((a + b) / 2 for a, b in zip(values, values[1:]))
    n_total = len(good_values) + len(poor_values)
    best_thr, best_acc = None, -1.0
    for thr in sorted(candidates):
        if higher_is_better:
            correct = sum(1 for v in good_values if v >= thr) + sum(1 for v in poor_values if v < thr)
        else:
            correct = sum(1 for v in good_values if v <= thr) + sum(1 for v in poor_values if v > thr)
        acc = correct / n_total if n_total else 0.0
        if acc > best_acc:
            best_acc, best_thr = acc, thr
    return best_thr, best_acc


def calibrate_thresholds(corpus_dir: str) -> tuple[dict, str]:
    """Data-driven threshold calibration (item 5): scans a labeled corpus of
    whole TRA JSON files (<corpus_dir>/good/*.json, <corpus_dir>/poor/*.json)
    and suggests values for the key text-length / duplicate-detection /
    specificity thresholds by finding the value that best separates the
    'good' TRAs from the 'poor' ones on each underlying signal.

    This mirrors the --learn-good-threats workflow (deterministic, offline,
    corpus-driven, nothing auto-applied) but calibrates thresholds instead of
    growing a vocabulary. Results are written to a JSON report for a
    maintainer to review before manually updating the constants in this file
    -- consistent with the existing "reviewer approval before corpus/constant
    changes" posture used elsewhere in this tool.

    Returns (report_dict, report_file_path).
    """
    good_vocab, good_idf, _, _ = load_good_threat_vocab()

    overview_words = {"good": [], "poor": []}
    scope_desc_words = {"good": [], "poor": []}
    specificity_scores = {"good": [], "poor": []}
    dup_jaccard_scores = {"good": [], "poor": []}
    files_scanned = {"good": 0, "poor": 0}

    for label, _path, tra in _iter_labeled_calibration_files(corpus_dir):
        files_scanned[label] += 1
        comps, _ = components_of(tra)

        intended_op = tra.get("IntendedOp") or {}
        ov_text = collect_text(intended_op)
        for key in ("scopeDescription", "highLevelDescription"):
            ov_text += " " + collect_text(tra.get(key))
        overview_words[label].append(len(re.findall(r"\w+", ov_text)))

        for c in comps:
            desc = c.get("description") or ""
            scope_desc_words[label].append(len(re.findall(r"\w+", desc)))

        threats = [t for t in (tra.get("ThreatScenarios") or []) if isinstance(t, dict)]
        threat_terms = []
        for t in threats:
            eval_res = _cm17_evaluate_threat(t, good_vocab, good_idf)
            specificity_scores[label].append(eval_res["score"])
            threat_terms.append(tokenize_security_terms(str(t.get("attackActionDesc") or "")))

        for i in range(len(threat_terms)):
            for j in range(i + 1, len(threat_terms)):
                a, b = threat_terms[i], threat_terms[j]
                if not a or not b:
                    continue
                dup_jaccard_scores[label].append(len(a & b) / len(a | b))

    def _summarize(metric: str, current, higher_is_better: bool, good_vals: list, poor_vals: list) -> dict:
        result = {
            "metric": metric,
            "current_threshold": current,
            "good_sample_n": len(good_vals),
            "poor_sample_n": len(poor_vals),
        }
        if good_vals:
            result["good_mean"] = round(statistics.mean(good_vals), 3)
            result["good_median"] = round(statistics.median(good_vals), 3)
        if poor_vals:
            result["poor_mean"] = round(statistics.mean(poor_vals), 3)
            result["poor_median"] = round(statistics.median(poor_vals), 3)
        thr, acc = (_best_separating_threshold(good_vals, poor_vals, higher_is_better=higher_is_better)
                   if good_vals and poor_vals else (None, None))
        result["suggested_threshold"] = round(thr, 3) if thr is not None else None
        result["separation_accuracy"] = round(acc, 3) if acc is not None else None
        if not (good_vals and poor_vals):
            result["note"] = "insufficient labeled samples in one or both classes (good/poor)"
        return result

    report = {
        "corpus_dir": corpus_dir,
        "files_scanned": files_scanned,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": (
            "Best-separating-threshold scan over sorted unique observed values (plus "
            "midpoints): the candidate maximizing classification accuracy between the "
            "'good' and 'poor' labeled TRA sets is suggested per signal. This is "
            "descriptive statistics, not machine learning. Nothing is applied "
            "automatically -- review the results and manually update the matching "
            "constant in tra_quality_report.py if you agree with the suggestion."
        ),
        "results": [
            _summarize("OVERVIEW_MIN_WORDS (CM-11 system overview word count)",
                       OVERVIEW_MIN_WORDS, True, overview_words["good"], overview_words["poor"]),
            _summarize("SCOPE_DESC_MIN_WORDS (CM-11 component description word count)",
                       SCOPE_DESC_MIN_WORDS, True, scope_desc_words["good"], scope_desc_words["poor"]),
            _summarize("SPECIFICITY_PASS_THRESHOLD (CM-14 threat specificity score)",
                       SPECIFICITY_PASS_THRESHOLD, True, specificity_scores["good"], specificity_scores["poor"]),
            _summarize("JACCARD_DUP_THRESHOLD (CM-16 near-duplicate token-Jaccard)",
                       JACCARD_DUP_THRESHOLD, False, dup_jaccard_scores["good"], dup_jaccard_scores["poor"]),
        ],
    }
    os.makedirs(corpus_dir, exist_ok=True)
    out_path = os.path.join(corpus_dir, "calibration_report.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report, out_path


def load_good_threat_vocab():
    """Build the good-threat vocabulary (CM-17) from every TRA JSON in
    GOOD_THREATS_DIR.

    Returns (vocab_set, idf_map, n_good_threats, meta); cached after first call.
    ``idf_map`` gives each surviving term an inverse-document-frequency weight
    normalised to (0, 1], where 1.0 marks a term that occurs in a single good
    threat (maximally distinctive) and values near 0 mark near-ubiquitous
    terms. This lets CM-17 reward genuinely distinctive technical language and
    resist keyword-stuffing with common words. Degrades gracefully (empty
    vocab, empty idf) when the folder is absent.
    """
    global _GOOD_VOCAB_CACHE
    if _GOOD_VOCAB_CACHE is not None:
        return _GOOD_VOCAB_CACHE
    doc_freq = {}          # term -> number of good threats containing it
    n_good = 0
    source_files = 0
    total_entries = 0
    accepted_entries = 0
    rejected_placeholder = 0
    rejected_non_threat = 0
    rejected_empty = 0
    if os.path.isdir(GOOD_THREATS_DIR):
        for fn in sorted(os.listdir(GOOD_THREATS_DIR)):
            if not fn.lower().endswith(".json"):
                continue
            source_files += 1
            try:
                with open(os.path.join(GOOD_THREATS_DIR, fn), "r", encoding="utf-8-sig") as fh:
                    doc = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(doc, dict):
                continue
            for t in (doc.get("ThreatScenarios") or []):
                if not isinstance(t, dict):
                    continue
                total_entries += 1
                name = str(t.get("name") or "").strip()
                attack = str(t.get("attackActionDesc") or "").strip()
                weakness = str(t.get("weakness") or "").strip()
                text = f"{name} {attack} {weakness}"
                if not (name or attack or weakness):
                    rejected_empty += 1
                    continue
                if NON_THREAT_TEXT_RE.search(text):
                    rejected_non_threat += 1
                    continue
                if any(re.search(p, text, flags=re.IGNORECASE) for p in PLACEHOLDER_PATTERNS):
                    rejected_placeholder += 1
                    continue
                if not is_good_threat_entry(t):
                    continue
                n_good += 1
                accepted_entries += 1
                text = (f"{t.get('name', '')} {t.get('attackActionDesc', '')} "
                        f"{t.get('weakness', '')}").lower()
                terms = tokenize_security_terms(text)
                for w in terms:
                    doc_freq[w] = doc_freq.get(w, 0) + 1
    vocab = set(doc_freq)
    vocab -= GENERIC_THREAT_TERMS
    vocab -= STOPWORDS
    vocab = {w for w in vocab if not VAGUE_RE.fullmatch(w)}
    # Normalised IDF: log(N / df) scaled so a df==1 term maps to 1.0.
    idf = {}
    if n_good > 1:
        max_idf = math.log(n_good)          # attained at df == 1
        for w in vocab:
            idf[w] = math.log(n_good / doc_freq[w]) / max_idf if max_idf else 0.0
    else:
        idf = {w: 1.0 for w in vocab}
    meta = {
        "source_dir": GOOD_THREATS_DIR,
        "source_files": source_files,
        "entries_seen": total_entries,
        "entries_accepted": accepted_entries,
        "entries_rejected_placeholder": rejected_placeholder,
        "entries_rejected_non_threat": rejected_non_threat,
        "entries_rejected_empty": rejected_empty,
        "vocab_terms": len(vocab),
        "idf_scheme": "normalized-log-idf",
    }
    _GOOD_VOCAB_CACHE = (vocab, idf, n_good, meta)
    return _GOOD_VOCAB_CACHE

KEYWORD_ONLY_MIN_WORDS = 6   # CM-17/CM-25: a real description has >= this many words
ACTOR_RE = re.compile(r"attacker|adversary|insider|malicious|threat actor|user", re.IGNORECASE)

OVERVIEW_MIN_WORDS = 150       # CM-11: a usable system overview has >= this many words
SCOPE_DESC_MIN_WORDS = 5      # CM-13: a real component description has >= this many words
# CM-11/CM-13: a description or overview that carries no prose but does link
# to an arc42 section, an external doc/diagram, or an embedded image/diagram
# file is still usable evidence (the reader can follow the reference), so it
# should not be penalised purely for having few words.
SCOPE_DESC_REF_RE = re.compile(
    r"(https?://\S+|www\.\S+|arc[-_ ]?42\b|\barc42\S*|\.(?:png|jpe?g|svg|gif|bmp|drawio|vsdx|pdf)\b)",
    re.IGNORECASE,
)
JACCARD_DUP_THRESHOLD = 0.6   # CM-19: token-Jaccard above which two threats are near-duplicates
SPECIFICITY_PASS_THRESHOLD = 0.65  # CM-17: aggregate specificity score at/above which a threat is specific
# CM-17: minimum IDF-weighted concrete-term strength for a threat to count as
# "using distinctive technical language". Because good-vocab terms are weighted
# by rarity (normalised IDF in (0,1]), one highly distinctive term (e.g.
# "modbus", idf~1.0) or two moderately distinctive terms clear the bar, while
# stuffing common vocab words (low IDF) does not -- this is the robustness gain
# over the previous raw >=2-term overlap count.
CONCRETE_STRENGTH_MIN = 1.0
CONCRETE_MIN_TERMS = 2        # CM-17: also require at least this many distinct matches
# CM-26: hedging / generic wording that signals an imprecise threat description.
VAGUE_RE = re.compile(
    r"\b(etc|and so on|somehow|some|various|several|appropriate|adequate|properly|"
    r"as needed|as applicable|where necessary|if necessary|generally|might|may|could|"
    r"possibly|relevant|certain|sufficient|unknown|unclear|roughly|approximately|"
    r"to be confirmed|tbc|tbd|misc|general)\b", re.IGNORECASE)
# External-evidence artifact references for the Known-Deficiencies block.
EVIDENCE_RE = re.compile(r"\bSRS\b|static[\s_-]?code[\s_-]?analysis|\bSCA\b|"
                         r"secure[\s_-]?code[\s_-]?review|penetration[\s_-]?test|pen[\s_-]?test|"
                         r"vulnerability[\s_-]?test|\bSVM\b|\bVTS\b|end[\s_-]?of[\s_-]?life|"
                         r"\bEOL\b|CVE-\d{4}-\d+", re.IGNORECASE)


def _external_interface_ids(comps, zones):
    """All externally exposed (network-facing) interface ids, both target areas."""
    ext = set()
    for container in list(comps) + list(zones):
        if not isinstance(container, dict):
            continue
        for key, val in container.items():
            if "NetworkFacing" in key and isinstance(val, list):
                for it in val:
                    if isinstance(it, dict) and it.get("interface_id"):
                        ext.add(it["interface_id"])
    return ext


# Catalog id for each computed metric, keyed by metric name. The four Expert
# catalog-only metrics (not computed here) live in the Excel catalog as CM-30..CM-33.
V3_ID = {
    "Workshop participation": "CM-01",
    "Living-document maintenance (updated since creation)": "CM-02",
    "Mandatory field and section completion": "CM-03",
    "Placeholder / unfinished-entry detection": "CM-04",
    "Assumption validation ratio": "CM-05",
    "Interface-Threat Coverages": "CM-06",
    "High-exposure communication-specific threat coverage": "CM-07",
    "Asset-Protection-goal mapping": "CM-08",
    "Protection-goal-Threat Coverage": "CM-09",
    "Asset mapping to components / communications": "CM-10",
    "Documentation clarity (system overview & component descriptions)": "CM-11",
    "Out-of-scope boundaries": "CM-12",
    "No-threat / empty-analysis red flag": "CM-13",
    "Threat specificity vs good-threat list (rule-based NLP)": "CM-14",
    "Protection-goal C/I/A balance": "CM-15",
    "Rating consistency across similar threats": "CM-16",
    "Rating coherence & justification": "CM-17",
    "Risk-treatment status workflow alignment": "CM-18",
    "Rating-distribution / rubber-stamping detector": "CM-19",
    "Assumption usage / linkage by type": "CM-20",
    "Threat-structure completeness (semantic)": "CM-21",
    "Vagueness / imprecision reduction": "CM-22",
}


def compute_core_metrics(tra, *, assets, pgs, threats, zones, comps,
                         in_scope, assumptions, logical_iface_ids, used_ifaces,
                         comps_with_threat, pgs_with_threat, assets_covered,
                         iface_owner, iface_name, communications,
                         iface_to_threats, pg_to_threats,
                         m2_linked, m2_missing, placeholder_hits,
                         placeholder_readings,
                         clab, tlab, plab, alab, aslab):
    n_threats = len(threats)

    core = []

    # ---- Formal completeness ------------------------------------------------
    # CM-03 mandatory section + field validator. Focuses on content sections
    # (not metadata) and reports exactly where each missing/empty field occurs.
    def _is_present(v):
        if v is None:
            return False
        if isinstance(v, str):
            return bool(v.strip())
        if isinstance(v, list):
            return len(v) > 0
        if isinstance(v, dict):
            return len(v) > 0
        return True  # booleans / numbers count as provided

    def _resolve_path(obj, path: str):
        cur = obj
        for key in path.split("."):
            if not isinstance(cur, dict) or key not in cur:
                return None, False
            cur = cur.get(key)
        return cur, True

    def _item_label(section_key: str, idx: int, item: dict, id_fields: tuple[str, ...]) -> str:
        return list_item_ref(section_key, item, idx, preferred_id_fields=id_fields)

    def _validate_single_object(section_name: str, section_key: str, obj: dict,
                                required_fields: list[tuple[str, str]]):
        passed = 0
        total = len(required_fields)
        sec_pass = []
        sec_fail = []
        for field_path, field_label in required_fields:
            value, exists = _resolve_path(obj, field_path)
            if exists and _is_present(value):
                passed += 1
            else:
                sec_fail.append(
                    f"{section_key}.{field_path} ({field_label}) is missing or empty.")
        if not sec_fail:
            sec_pass.append(f"{section_name}: all mandatory fields are filled.")
        status = "ok" if not sec_fail else "bad"
        return {
            "name": section_name,
            "status": status,
            "num": passed,
            "den": total,
            "pass": sec_pass,
            "fail": sec_fail,
        }

    def _validate_list_section(section_name: str, section_key: str, items: list,
                               required_fields: list[tuple[str, str]],
                               id_fields: tuple[str, ...],
                               extra_check=None):
        sec_pass = []
        sec_fail = []
        passed = 0
        total = 1  # section presence check

        if isinstance(items, list) and items:
            passed += 1
            sec_pass.append(f"{section_key}: section exists with {len(items)} item(s).")
        else:
            sec_fail.append(f"{section_key}: section is missing or empty.")
            return {
                "name": section_name,
                "status": "bad",
                "num": passed,
                "den": total,
                "pass": sec_pass,
                "fail": sec_fail,
            }

        for idx, item in enumerate(items):
            label = _item_label(section_key, idx, item if isinstance(item, dict) else {}, id_fields)
            if not isinstance(item, dict):
                total += 1
                sec_fail.append(f"{label}: expected an object but found a non-object entry.")
                continue

            missing = []
            for field_path, field_label in required_fields:
                total += 1
                value, exists = _resolve_path(item, field_path)
                if exists and _is_present(value):
                    passed += 1
                else:
                    missing.append(f"{field_label} ({field_path})")

            if callable(extra_check):
                extra_result = extra_check(item)
                if isinstance(extra_result, tuple) and len(extra_result) == 2:
                    ok, msg = extra_result
                else:
                    ok, msg = (False, "section-specific validation rule returned an invalid result")
                total += 1
                if ok:
                    passed += 1
                else:
                    missing.append(msg)

            if missing:
                sec_fail.append(f"{label}: missing/empty -> " + "; ".join(missing))
            else:
                sec_pass.append(f"{label}: all mandatory fields are filled.")

        status = "ok" if not sec_fail else "bad"
        return {
            "name": section_name,
            "status": status,
            "num": passed,
            "den": total,
            "pass": sec_pass,
            "fail": sec_fail,
        }

    def _component_extra_check(comp: dict):
        if comp.get("scope") != "In_Scope":
            return True, ""
        if is_generic_component(comp):
            return True, ""
        # In-scope components should model at least one explicit attack-surface
        # or data-flow element.
        if component_interfaces(comp) or component_communications(comp):
            return True, ""
        return False, "at least one interface or communication entry for in-scope components"

    component_section_key = "SystemComponents" if isinstance(tra.get("SystemComponents"), list) else "SWComponents"

    cm03_project_fields = [
        ("JSON_VERSION", "json version"),
        ("TRAVersionName", "tra version name"),
        ("TRAVersionNumber", "tra version number"),
        ("status", "status"),
        ("createdDate", "created date"),
        ("changedDate", "changed date"),
        ("Project.TRAProjectName", "project name"),
        ("Project.responsibleOrg", "responsible organization"),
    ]
    cm03_list_specs = [
        ("Assets", "Assets", assets,
         [("asset_id", "asset id"), ("name", "asset name"), ("assetType", "asset type")],
         ("asset_id", "name"), None),
        ("Assumptions", "Assumptions", assumptions,
         [("assumption_id", "assumption id"), ("name", "assumption name"),
          ("validated", "validated flag"), ("assumptionType", "assumption type")],
         ("assumption_id", "name"), None),
        ("Protection Goals", "ProtectionGoals", pgs,
         [("pg_id", "protection goal id"), ("name", "protection goal name"),
          ("impactLevel", "impact level"), ("protectionGoalType", "protection goal type")],
         ("pg_id", "name"), None),
        ("Security Zones", "SecurityZones", zones,
         [("zone_id", "security zone id"), ("name", "security zone name"),
          ("external", "external flag"), ("isNetworkZone", "network zone flag"),
          ("isProximityZone", "proximity zone flag"), ("isHostZone", "host zone flag"),
          ("isStructuringBox", "structuring box flag"), ("isVisible", "visible flag"),
          ("isTopSecurityZone", "top security zone flag")],
         ("zone_id", "name"), None),
        ("Components", component_section_key, comps,
         [("name", "component name"), ("scope", "scope"),
          ("subUnit_id", "component id"), ("SecurityZone.zone_id", "linked security zone id")],
         ("subUnit_id", "name"), _component_extra_check),
        ("Threat Scenarios", "ThreatScenarios", threats,
         [("threatscenario_id", "threat scenario id"), ("name", "threat name"),
          ("exploitabilityRating", "exploitability rating"),
          ("CALCLikelihood", "likelihood"), ("CALCRiskRating", "risk rating")],
         ("threatscenario_id", "name"), None),
    ]

    cm03_sections = [
        _validate_single_object("Project", "Project", tra, cm03_project_fields)
    ]
    for sec_name, sec_key, sec_items, req_fields, id_fields, extra_check in cm03_list_specs:
        cm03_sections.append(_validate_list_section(
            sec_name, sec_key, sec_items, req_fields, id_fields, extra_check=extra_check
        ))

    cm03_num = sum(sec["num"] for sec in cm03_sections)
    cm03_den = sum(sec["den"] for sec in cm03_sections)
    sec_pass = [f"{sec['name']}: all mandatory checks passed ({sec['num']}/{sec['den']})."
                for sec in cm03_sections if not sec.get("fail")]
    sec_fail = [f"{sec['name']}: {len(sec.get('fail') or [])} issue(s) found "
                f"({sec['num']}/{sec['den']} checks passed). Expand section details for exact fields."
                for sec in cm03_sections if sec.get("fail")]

    core.append(dict(id="CM-03", name="Mandatory section and field completion",
                     dim="Formal Completeness", auto="Auto",
                                     note=("schema-aligned validator for required fields; present declared fields must be "
                                             "non-empty, and in-scope components must define at least one interface or "
                                             "communication unless the component name is a placeholder/generic entry"),
                     num=cm03_num, den=cm03_den, better="high",
                     detail={"pass": sec_pass, "fail": sec_fail, "sections": cm03_sections}))

    # CM-04 placeholder / unfinished-entry detection
    ph_fail = [
        f"{h['path']} - matched /{h['pattern']}/ - snippet: {h['snippet']}"
        for h in placeholder_readings
    ]
    core.append(dict(id="CM-04", name="Placeholder / unfinished-entry detection",
                     dim="Formal Completeness", auto="Auto",
                   note=("detects placeholder patterns (QUESTION, ??, TBD, TODO, FIXME, placeholder, "
                       "etc.) across all text fields; each hit includes JSON path + snippet "
                       "for quick false-positive review "),
                     kind="count", num=placeholder_hits, den=None, better="low",
                     detail={"pass": [], "fail": ph_fail}))

    # CM-05 assumption validation ratio (structural granularity split out of CM-03)
    val_pass, val_fail = [], []
    for a in assumptions:
        if a.get("validated"):
            val_pass.append(alab(a))
        else:
            val_fail.append(f"{alab(a)} - not validated")
    core.append(dict(id="CM-05", name="Assumption validation ratio",
                     dim="Formal Completeness", auto="Auto",
                   note=("Detects Assumptions with validated=true; flags each assumption with "
                       "validated=false (N/A when no assumptions exist)"),
                     num=len(val_pass), den=len(assumptions), better="high",
                     status=("na" if not assumptions else None),
                     detail={"pass": (["no assumptions to assess"] if not assumptions else val_pass),
                                                         "fail": ([] if not assumptions else
                                                                            ([_bulleted(f"{len(val_fail)} assumption(s) are not validated:", val_fail)]
                                                                             if val_fail else []))}))

    # ---- Coverage -----------------------------------------------------------
    # CM-06 combined coverage metric (CM-06/07/08 merged): checks whether
    # in-scope zones, their assigned components, and declared interfaces are
    # covered by at least one threat scenario, with explicit checks for
    # high-exposure zone types and high-exposure interfaces.
    def _norm_rating_value(v: str) -> str:
        return str(v or "").strip().lower().replace(" ", "_")

    def _rank_value(v: str) -> int:
        rank_map = {
            "major": 5, "disastrous": 5, "very_likely": 5,
            "significant": 4, "critical": 4, "likely": 4,
            "moderate": 3, "possible": 3, "high": 3,
            "minor": 2, "unlikely": 2, "medium": 2,
            "negligible": 1, "very_unlikely": 1, "low": 1,
            "norating": 0, "incomplete": 0,
        }
        return rank_map.get(_norm_rating_value(v), 0)

    def _interface_exposure_info(obj: dict) -> tuple[int, list[str]]:
        best = 0
        evidence = []
        for key, val in (obj or {}).items():
            key_s = str(key)
            if "specificExposureRating" not in key_s and "CALCzoneDerivedExposure" not in key_s:
                continue
            rank = _rank_value(val)
            best = max(best, rank)
            if rank >= HIGH_EXPOSURE_MIN_RANK:
                evidence.append(f"{key}={val}")
        return best, evidence

    def _zone_exposure_entries(z: dict) -> list[dict]:
        entries = []
        for ze in (z.get("ZoneExposures") or []):
            rating = ze.get("rating")
            entries.append({
                "type": ze.get("zoneExposureType") or "Unknown",
                "rating": rating,
                "rank": _rank_value(rating),
            })
        return entries

    def _norm_exposure_type(v: str) -> str:
        return str(v or "").strip().lower()

    def _iface_kind_from_record(rec: dict) -> str:
        t = str(rec.get("type") or "").lower()
        if "network" in t:
            return "network"
        if "proximity" in t or "physical" in t:
            return "proximity"
        if "host" in t:
            return "host"
        return "unknown"

    HIGH_EXPOSURE_MIN_RANK = 3

    coverage_in_scope = [c for c in in_scope if not is_generic_component(c)]
    in_scope_component_ids = {c.get("subUnit_id") for c in coverage_in_scope if c.get("subUnit_id")}

    interface_records = []
    for c in comps:
        cid = c.get("subUnit_id")
        cname = c.get("name")
        czone = (c.get("SecurityZone") or {}).get("zone_id")
        if cid not in in_scope_component_ids:
            continue
        for key, val in c.items():
            if "Interface" not in str(key) or not isinstance(val, list):
                continue
            for it in val:
                if not isinstance(it, dict):
                    continue
                iid = it.get("interface_id")
                if not iid:
                    continue
                exposure_rank, exposure_evidence = _interface_exposure_info(it)
                interface_records.append({
                    "id": iid,
                    "type": key,
                    "owner_kind": "component",
                    "owner_id": cid,
                    "owner_name": cname,
                    "zone_id": czone,
                    "exposure_rank": exposure_rank,
                    "exposure_evidence": exposure_evidence,
                })
    for z in zones:
        zid = z.get("zone_id")
        zname = z.get("name")
        for key, val in z.items():
            if "Interface" not in str(key) or not isinstance(val, list):
                continue
            for it in val:
                if not isinstance(it, dict):
                    continue
                iid = it.get("interface_id")
                if not iid:
                    continue
                exposure_rank, exposure_evidence = _interface_exposure_info(it)
                interface_records.append({
                    "id": iid,
                    "type": key,
                    "owner_kind": "zone",
                    "owner_id": zid,
                    "owner_name": zname,
                    "zone_id": zid,
                    "exposure_rank": exposure_rank,
                    "exposure_evidence": exposure_evidence,
                })

    by_iid = {}
    for rec in interface_records:
        iid = rec["id"]
        old = by_iid.get(iid)
        if old is None or rec["exposure_rank"] > old["exposure_rank"]:
            by_iid[iid] = rec
    interface_records = list(by_iid.values())

    comp_by_zone = {}
    for c in coverage_in_scope:
        zid = (c.get("SecurityZone") or {}).get("zone_id")
        if zid:
            comp_by_zone.setdefault(zid, []).append(c)

    children_by_top = {}
    for z in zones:
        zid = z.get("zone_id")
        top = (z.get("SecurityZone_Top") or {}).get("zone_id")
        if zid and top and zid != top:
            children_by_top.setdefault(top, []).append(z)

    zone_checks = []
    zone_fail_msgs = []
    ranked_zones = sorted(
        zones,
        key=lambda z: (-max((e["rank"] for e in _zone_exposure_entries(z)), default=0), z.get("zone_id") or "")
    )
    for z in ranked_zones:
        zid = z.get("zone_id")
        zname = z.get("name")
        descendants = sorted(children_by_top.get(zid, []), key=lambda x: x.get("zone_id") or "")
        zone_scope_ids = {zid, *[d.get("zone_id") for d in descendants if d.get("zone_id")]}
        relevant_interfaces = [r for r in interface_records if r.get("zone_id") in zone_scope_ids]
        relevant_components = []
        for zone_id in sorted(zone_scope_ids):
            relevant_components.extend(sorted(comp_by_zone.get(zone_id, []), key=lambda x: x.get("subUnit_id") or ""))

        high_zone_exposure_types = [
            exp["type"] for exp in sorted(_zone_exposure_entries(z), key=lambda e: -e["rank"])
            if exp["rank"] >= HIGH_EXPOSURE_MIN_RANK
        ]
        if not high_zone_exposure_types:
            continue

        exposure_label = ", ".join(dict.fromkeys(high_zone_exposure_types))
        if not relevant_interfaces:
            zone_fail_msgs.append(
                f"Zone {zid} ({zname}) is rated high for {exposure_label} exposure, but no interface is declared in the zone, its sub-zones, or their assigned components.")
            zone_checks.extend([False] * len(high_zone_exposure_types))
            continue

        # Only evaluate zone-exposure types for which the examined path has
        # matching interface kinds. This avoids false wording like "Host"
        # when no host-interface representation exists in the model path.
        iface_kinds_here = {_iface_kind_from_record(r) for r in relevant_interfaces}
        evaluable_exposure_types = [
            t for t in high_zone_exposure_types
            if _norm_exposure_type(t) in iface_kinds_here
        ]
        if not evaluable_exposure_types:
            continue
        exposure_label = ", ".join(dict.fromkeys(evaluable_exposure_types))

        covered_here = False
        zone_owned = [r for r in relevant_interfaces if r["owner_kind"] == "zone"]
        for r in sorted(zone_owned, key=lambda x: (-x["exposure_rank"], x["id"])):
            threats_here = iface_to_threats.get(r["id"], [])
            if threats_here:
                covered_here = True
        for c in relevant_components:
            for it in sorted(component_interfaces(c), key=lambda x: str(x.get("interface_id") or "")):
                iid = it.get("interface_id")
                if not iid or iid not in {r["id"] for r in relevant_interfaces}:
                    continue
                tids = iface_to_threats.get(iid, [])
                if tids:
                    covered_here = True

        if not covered_here:
            unmapped_here = [
                r for r in sorted(relevant_interfaces, key=lambda x: (-x["exposure_rank"], x["id"]))
                if r["id"] not in used_ifaces
            ]
            high_unmapped_here = [
                r for r in unmapped_here
                if r["exposure_rank"] >= HIGH_EXPOSURE_MIN_RANK and r["id"] not in used_ifaces
            ]
            high_suffix = ""
            if high_unmapped_here:
                high_suffix = (
                    " High-exposure interfaces not mapped in this path: "
                    + ", ".join(
                        f"{r['id']} ({r['owner_kind']} {r['owner_id']})"
                        for r in high_unmapped_here
                    )
                    + "."
                )
            elif unmapped_here:
                high_suffix = (
                    " Declared interfaces not mapped in this path (none of them high-exposure): "
                    + ", ".join(
                        f"{r['id']} ({r['owner_kind']} {r['owner_id']})"
                        for r in unmapped_here
                    )
                    + "."
                )
            zone_fail_msgs.append(
                f"Zone {zid} ({zname}) is rated high for {exposure_label} exposure, and interfaces are declared in the zone scope (zone + sub-zones + assigned in-scope components), but none of them are mapped to a threat scenario.{high_suffix}")
        zone_checks.extend([covered_here] * len(evaluable_exposure_types))

    comp_pass = sum(1 for c in coverage_in_scope if c.get("subUnit_id") in comps_with_threat)
    iface_pass = sum(1 for r in interface_records if r["id"] in used_ifaces)
    zone_pass = sum(1 for ok in zone_checks if ok)
    cov_num = comp_pass + iface_pass + zone_pass
    cov_den = len(coverage_in_scope) + len(interface_records) + len(zone_checks)

    cm06_pass = []

    cm06_fail = []
    if m2_missing:
        missing_comp_ids = []
        for row in m2_missing:
            missing_comp_ids.append(row.split(" ", 1)[0].strip())
        ids_part = f" Components: {', '.join(missing_comp_ids)}." if missing_comp_ids else ""
        cm06_fail.append(
            f"{len(m2_missing)} in-scope component(s) are not covered by a single threat scenario through its interfaces.{ids_part} See grouped interface readings for details.")
    missing_ifaces = [r for r in interface_records if r["id"] not in used_ifaces]
    if missing_ifaces:
        cm06_fail.append(
            f"{len(missing_ifaces)} declared interface(s) are not mapped to any threat scenario. See grouped interface readings for details.")
    if zone_checks and zone_pass != len(zone_checks):
        cm06_fail.extend(zone_fail_msgs)
    high_unmapped_ifaces = sorted(
        [r for r in interface_records if r["id"] not in used_ifaces and r["exposure_rank"] >= HIGH_EXPOSURE_MIN_RANK],
        key=lambda x: (-x["exposure_rank"], x["id"])
    )
    if high_unmapped_ifaces:
        cm06_fail.append(
            "High-exposure interfaces not mapped: "
            + ", ".join(f"{r['id']} ({r['owner_kind']} {r['owner_id']})" for r in high_unmapped_ifaces)
            + "."
        )

    groups = []
    by_type = {}
    for r in interface_records:
        by_type.setdefault(r["type"], []).append(r)
    for tname in sorted(by_type):
        items = sorted(by_type[tname], key=lambda r: (-r["exposure_rank"], r["id"]))
        gpass, gfail = [], []
        for r in items:
            threats_here = iface_to_threats.get(r["id"], [])
            owner = f"{r['owner_kind']} {r['owner_id']} ({r['owner_name']})"
            high_exposure_suffix = ""
            if r["exposure_rank"] >= HIGH_EXPOSURE_MIN_RANK and r.get("exposure_evidence"):
                high_exposure_suffix = (
                    f" - HIGH exposure ({', '.join(r['exposure_evidence'])})"
                )
            if threats_here:
                gpass.append(
                    f"Interface {r['id']} ({owner}) -> {', '.join(threats_here)}{high_exposure_suffix}.")
            else:
                gfail.append(
                    f"Interface {r['id']} ({owner}) - not mapped{high_exposure_suffix}.")
        groups.append({
            "title": f"Interfaces grouped by type: {tname}",
            "pass": gpass,
            "fail": gfail,
        })

    iface_rank = {r["id"]: int(r.get("exposure_rank") or 0) for r in interface_records}
    iface_exposure_evidence = {r["id"]: r.get("exposure_evidence") or [] for r in interface_records}

    core.append(dict(id="CM-06", name="Interface-Threat Coverages", dim="Coverage", auto="Auto",
                     note=("Checks whether each in-scope zone, its assigned in-scope components, and declared interfaces are covered by at least one threat scenario. "
                       "It also checks whether each high-exposure zone type has declared interfaces and at least one threat-mapped interface in the zone scope (zone + sub-zones + assigned in-scope components). "
                           "Interfaces are grouped by interface list type, and high-exposure interfaces are marked in the readings."),
                   interface_num=iface_pass, interface_den=len(interface_records),
                   bar_num=iface_pass, bar_den=len(interface_records), bar_label="Interfaces mapped",
                     num=cov_num, den=cov_den, better="high",
                     status=("na" if cov_den == 0 else None),
                     detail={"pass": cm06_pass, "fail": cm06_fail, "groups": groups}))

    # CM-07 high-exposure communication threat specificity
    comm_edges = [cm for cm in communications if cm.get("target_iface")]
    if comm_edges:
        comm_sorted = sorted(
            comm_edges,
            key=lambda x: (int(re.sub(r"\D", "", str(x.get("id") or "")) or 0), str(x.get("id") or ""))
        )
        comp_name_by_id = {c.get("subUnit_id"): c.get("name") for c in comps if c.get("subUnit_id")}
        threat_by_id = {t.get("threatscenario_id"): t for t in threats if t.get("threatscenario_id")}

        def _norm_blob(text):
            return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()

        def _edge_anchor_matches(threat_obj, cm):
            raw = ((threat_obj.get("name") or "") + " " + (threat_obj.get("attackActionDesc") or "")).strip()
            blob = _norm_blob(raw)
            anchors = []
            seen = set()
            for token in (
                cm.get("id"),
                cm.get("name"),
                cm.get("source"),
                comp_name_by_id.get(cm.get("source")),
                cm.get("owner"),
                comp_name_by_id.get(cm.get("owner")),
            ):
                value = str(token or "").strip()
                if not value:
                    continue
                norm = _norm_blob(value)
                if not norm or norm not in blob:
                    continue
                match = re.search(re.escape(value), raw, flags=re.IGNORECASE)
                snippet = value
                if match:
                    start = max(0, match.start() - 40)
                    end = min(len(raw), match.end() + 80)
                    candidate = re.sub(r"\s+", " ", raw[start:end]).strip(" ,;:-")
                    if len(candidate) > len(value):
                        snippet = candidate
                key = snippet.lower().strip()
                if key and key not in seen:
                    seen.add(key)
                    anchors.append(snippet)
            return anchors

        def _generic_only_reason(threat_obj, cm, target_iface):
            tid = threat_obj.get("threatscenario_id") or "<no-id>"
            tname = threat_obj.get("name") or "<unnamed>"
            owner_id = cm.get("owner") or "<unknown>"
            owner_name = comp_name_by_id.get(cm.get("owner")) or owner_id
            source_id = cm.get("source") or owner_id
            source_name = comp_name_by_id.get(cm.get("source")) or source_id
            checked = [
                str(token) for token in (
                    cm.get("id"),
                    cm.get("name"),
                    source_id,
                    source_name,
                    owner_id,
                    owner_name,
                ) if token
            ]
            checked_text = ", ".join(checked)
            return (
                f"{tid} ({tname}) -> interface {target_iface} is mapped, but the threat name/description does not reference "
                f"this specific communication ({checked_text})"
            )

        assessed_edges = [cm for cm in comm_sorted if iface_rank.get(cm.get("target_iface"), 0) >= HIGH_EXPOSURE_MIN_RANK]
        cc = {"pass": [], "fail": [], "groups": []}
        if not assessed_edges:
            core.append(dict(id="CM-07", name="High-exposure communication-specific threat coverage", dim="Coverage",
                         auto="Semi-auto",
                         note=("Checks whether each high-exposure communication flow is explicitly addressed by a threat scenario, "
                             "not only by a generic threat on its target interface."),
                             better="high", status="na",
                             detail={"pass": ["no high-exposure communications to assess"], "fail": []}))
        else:
            pass_count = 0
            fail_count = 0
            by_list_type = {}
            for cm in assessed_edges:
                by_list_type.setdefault(cm.get("list_type") or "UnknownCommunicationList", []).append(cm)

            for list_type in sorted(by_list_type):
                rows = by_list_type[list_type]
                group_pass, group_fail = [], []
                for cm in rows:
                    target_iface = cm.get("target_iface")
                    comm_id = cm.get("id") or "<no-id>"
                    comm_name = cm.get("name") or "<unnamed>"
                    owner_id = cm.get("owner") or "<unknown>"
                    owner_name = comp_name_by_id.get(owner_id) or "<unknown>"
                    source_id = cm.get("source") or owner_id
                    source_name = comp_name_by_id.get(source_id) or source_id or "<unknown>"
                    ev = iface_exposure_evidence.get(target_iface) or []
                    high_suffix = f" - HIGH exposure ({', '.join(ev)})" if ev else " - HIGH exposure"
                    line = f"{comm_id} ({comm_name}) from {source_id} ({source_name}) to {target_iface} on component {owner_id} ({owner_name})"

                    mapped_tids = iface_to_threats.get(target_iface, [])
                    if not mapped_tids:
                        fail_count += 1
                        group_fail.append(
                            f"{line} - no threat scenario is mapped to the target interface{high_suffix}.")
                        continue

                    specific_hits = []
                    generic_only = []
                    for tid in mapped_tids:
                        threat_obj = threat_by_id.get(tid)
                        if not threat_obj:
                            continue
                        anchors = _edge_anchor_matches(threat_obj, cm)
                        if anchors:
                            specific_hits.append((tid, anchors))
                        else:
                            generic_only.append(tid)

                    if specific_hits:
                        pass_count += 1
                        hit_desc = ", ".join(
                            f"{tid} via matched communication wording {', '.join(f'\'{a}\'' for a in anchors[:2])}"
                            for tid, anchors in specific_hits
                        )
                        group_pass.append(
                            f"{line} - communication-specific threat found: {hit_desc}{high_suffix}.")
                    else:
                        fail_count += 1
                        generic_part = ""
                        if generic_only:
                            generic_reasons = []
                            for tid in generic_only:
                                threat_obj = threat_by_id.get(tid)
                                if threat_obj:
                                    generic_reasons.append(_generic_only_reason(threat_obj, cm, target_iface))
                                else:
                                    generic_reasons.append(f"{tid} -> mapped to interface {target_iface}, but no communication-specific reference was found")
                            generic_part = "\n" + _bulleted("Generic-only threats:", generic_reasons)
                        group_fail.append(
                            f"{line} - only generic interface threat coverage found; no communication-specific threat.{generic_part}{high_suffix}.")

                total_in_group = len(rows)
                mapped_in_group = len(group_pass)
                cc["groups"].append({
                    "title": f"Component communication list: {list_type}",
                    "pass": group_pass,
                    "fail": group_fail,
                })

            if fail_count:
                cc["fail"].insert(
                    0,
                    f"{fail_count} of {len(assessed_edges)} high-exposure communication(s) lack communication-specific threat coverage."
                )
            if pass_count:
                cc["pass"].insert(
                    0,
                    f"{pass_count} of {len(assessed_edges)} high-exposure communication(s) have communication-specific threat coverage."
                )

            core.append(dict(id="CM-07", name="High-exposure communication-specific threat coverage", dim="Coverage",
                             auto="Semi-auto",
                         note=("Checks whether each high-exposure communication flow is explicitly addressed by a threat scenario, "
                             "not only by a generic threat on its target interface."),
                             bar_num=pass_count, bar_den=len(assessed_edges),
                             bar_label="High-exposure communications with edge-specific threats",
                             num=pass_count,
                             den=len(assessed_edges), better="high", detail=cc))
    else:
          core.append(dict(id="CM-07", name="High-exposure communication-specific threat coverage", dim="Coverage",
                         auto="Semi-auto",
                         note="no inter-component communications declared (n/a)",
                         better="high", status="na",
                         detail={"pass": ["no communications to cover"], "fail": []}))

    # CM-09 protection-goal coverage in threat analysis (non-negligible goals).
    # The pass reading cites the exact ThreatScenario id(s) that satisfy
    # coverage for each protection goal (not just a bare pass flag), so a
    # reviewer can jump straight to the mapped threat(s) for confirmation.
    # Negligible-impact goals are exempt from the denominator (not required by
    # the TRA method), but if one happens to carry real threat links anyway
    # those are still cited - otherwise a goal like "I-4" that actually has
    # 5 threats mapped would misleadingly read as if nothing were linked.
    cov_goal = {"pass": [], "fail": []}
    relevant_pgs = [p for p in pgs
                    if str(p.get("impactLevel", "")).strip().lower() == "critical"]
    for p in relevant_pgs:
        impact = str(p.get("impactLevel") or "NoRating").strip() or "NoRating"
        if p.get("pg_id") in pgs_with_threat:
            tids = pg_to_threats.get(p.get("pg_id"), [])
            cov_goal["pass"].append(
                f"{plab(p)} - impact: {impact} - mapped to {', '.join(tids) if tids else 'a threat scenario'}")
        else:
            cov_goal["fail"].append(f"{plab(p)} - impact: {impact} - no threat scenario references it")
    for p in pgs:
        if p not in relevant_pgs:
            impact = str(p.get("impactLevel") or "NoRating").strip() or "NoRating"
            tids = pg_to_threats.get(p.get("pg_id"), [])
            extra = f" - mapped to {', '.join(tids)}" if tids else ""
            cov_goal["pass"].append(f"{plab(p)} - impact: {impact} - ignored{extra}")
    core.append(dict(id="CM-09", name="Protection-goal-Threat Coverage", dim="Coverage",
                     auto="Auto",
                     note="every Critical protection goal linked to >=1 threat; lower impact goals are shown as ignored",
                     num=sum(1 for p in relevant_pgs if p.get("pg_id") in pgs_with_threat),
                 den=len(relevant_pgs), better="high",
                 status=("na" if not relevant_pgs else None),
                 detail=(cov_goal if relevant_pgs else
                     {"pass": ["no Critical protection goals to assess"], "fail": []})))
    # CM-08 asset coverage / asset-to-protection-goal mapping
    # build asset_id -> [covering protection goals] so the pass reading can name
    # exactly which protection goal(s) represent each asset (not just "covered")
    pgs_covering_asset = {}
    for p in pgs:
        aid = (p.get("Asset") or {}).get("asset_id")
        if aid:
            pgs_covering_asset.setdefault(aid, []).append(p)
    cov_asset = {"pass": [], "fail": []}
    cov_asset_fail_rows = []
    for a in assets:
        aid = a.get("asset_id")
        if aid in assets_covered:
            covering = pgs_covering_asset.get(aid, [])
            names = ", ".join(plab(p) for p in covering) or "unknown protection goal"
            cov_asset["pass"].append(f"{aslab(a)} - covered by {names}")
        else:
            cov_asset_fail_rows.append(f"{aslab(a)} - no protection goal covers it")
    if cov_asset_fail_rows:
        cov_asset["fail"] = [_bulleted(
            f"{len(cov_asset_fail_rows)} asset(s) are not covered by any protection goal:",
            cov_asset_fail_rows,
        )]
    core.append(dict(id="CM-08", name="Asset-Protection-goal mapping", dim="Coverage",
                     auto="Auto",
                     note="every asset represented by >=1 protection goal",
                     num=sum(1 for a in assets if a.get("asset_id") in assets_covered),
                     den=len(assets), better="high", detail=cov_asset))

    # CM-10 asset mapping to components / communications (traceability)
    comm_target_ifaces = {cm["target_iface"] for cm in communications if cm.get("target_iface")}
    threat_by_id = {t.get("threatscenario_id"): t for t in threats}
    pgs_by_asset = {}
    for p in pgs:
        aid = (p.get("Asset") or {}).get("asset_id")
        if aid:
            pgs_by_asset.setdefault(aid, []).append(p)
    am_pass, am_fail = [], []
    for a in assets:
        apgs = pgs_by_asset.get(a.get("asset_id"), [])
        apg_ids = {p.get("pg_id") for p in apgs}
        tids = set()
        for p in apgs:
            for ts in (p.get("ThreatScenarios") or []):
                if ts.get("threatscenario_id"):
                    tids.add(ts["threatscenario_id"])
        for t in threats:
            for tp in (t.get("ProtectionGoals") or []):
                if tp.get("pg_id") in apg_ids:
                    tids.add(t.get("threatscenario_id"))
        ifaces = set()
        for tid in tids:
            t = threat_by_id.get(tid)
            if t:
                iid = (t.get("AttackInterface") or {}).get("interface_id")
                if iid:
                    ifaces.add(iid)
        comp_links = {iface_owner[i] for i in ifaces if i in iface_owner}
        comm_links = ifaces & comm_target_ifaces
        if comp_links or comm_links:
            via = []
            if comp_links:
                via.append("component(s) " + ", ".join(sorted(comp_links)))
            if comm_links:
                via.append("communication target(s) " + ", ".join(sorted(comm_links)))
            am_pass.append(f"{aslab(a)} - mapped via {'; '.join(via)}")
        else:
            if not apgs:
                why = "no protection goal references this asset"
            elif not tids:
                why = "its protection goal(s) have no threat scenario"
            else:
                why = "threats do not attack any component-owned or communication interface"
            am_fail.append(f"{aslab(a)} - not traceable to a component/communication: {why}")
    am_fail_grouped = ([_bulleted(
        f"{len(am_fail)} asset(s) are not traceable to a component/communication:",
        am_fail,
    )] if am_fail else [])
    core.append(dict(id="CM-10", name="Asset mapping to components / communications",
                     dim="Coverage", auto="Auto",
                     note=("Each asset should be traceable to a system component or communication "
                          "through the chain: asset -> protection goal -> threat -> attacked interface."),
                     num=len(am_pass), den=len(assets), better="high",
                     status=("na" if not assets else None),
                     detail={"pass": (["no assets to assess"] if not assets else am_pass),
                            "fail": ([] if not assets else am_fail_grouped)}))

    # CM-11 documentation clarity (system overview & component descriptions).
    # This combines the former "system-overview presence" and "component
    # description clarity" checks into one Comprehensibility metric with two
    # grouped readings, since both were really the same underlying question:
    # "is this part of the TRA described clearly enough for a reader to
    # understand it?". Evidence is qualitative (descriptive vs missing/brief)
    # rather than raw word counts, and a short overview/description that still
    # links to an arc42 section, external doc/diagram URL, or an embedded
    # image/diagram file is accepted as equivalent evidence (the reviewer can
    # follow the reference).
    # The system overview is assembled from exactly these 4 candidate fields.
    # Each field's word count is tracked individually so the evidence can name
    # which of the 4 were actually present vs absent, even though the pass/
    # fail decision itself still uses the combined word count against
    # OVERVIEW_MIN_WORDS (brevity in one field is fine as long as the combined
    # text clears the threshold or a reference is present).
    SYSTEM_OVERVIEW_FIELDS = ("IntendedOp.IOEdescription", "Overview",
                             "scopeDescription", "highLevelDescription")
    intended_op = tra.get("IntendedOp") or {}
    ioe_text = str((intended_op.get("IOEdescription") or "")
                  if isinstance(intended_op, dict) else "")
    ov_field_words = {"IntendedOp.IOEdescription": len(re.findall(r"\w+", ioe_text))}
    ov_text = collect_text(intended_op)
    for key in ("Overview", "scopeDescription", "highLevelDescription"):
        wc = len(re.findall(r"\w+", collect_text(tra.get(key))))
        ov_field_words[key] = wc
        if wc:
            ov_text += " " + collect_text(tra.get(key))
    ov_words = len(re.findall(r"\w+", ov_text))
    ov_ref_match = SCOPE_DESC_REF_RE.search(ov_text)
    ov_ok = ov_words >= OVERVIEW_MIN_WORDS or bool(ov_ref_match)
    ov_fields_present = [f for f in SYSTEM_OVERVIEW_FIELDS if ov_field_words.get(f)]
    ov_fields_absent = [f for f in SYSTEM_OVERVIEW_FIELDS if not ov_field_words.get(f)]

    ov_pass, ov_fail = [], []
    if ov_ok:
        fields_bit = f"fields present: {', '.join(ov_fields_present)}" if ov_fields_present else "no fields present"
        if ov_fields_absent:
            fields_bit += f"; fields absent: {', '.join(ov_fields_absent)}"
        base = f"System overview is descriptively covered ({fields_bit})"
        if ov_ref_match and ov_words < OVERVIEW_MIN_WORDS:
            base += f" - accepted via reference evidence ({ov_ref_match.group(0)!r})"
        ov_pass.append(base + ".")
    else:
        fields_bit = f"fields present: {', '.join(ov_fields_present)}; " if ov_fields_present else ""
        ov_fail.append(
            f"System overview is missing or too brief ({fields_bit}"
            f"fields absent: {', '.join(ov_fields_absent)}), and no "
            "arc42/diagram/image reference was found."
        )

    sd_pass, sd_fail = [], []
    for c in comps:
        desc = c.get("description") or ""
        w = len(re.findall(r"\w+", desc))
        ref_match = SCOPE_DESC_REF_RE.search(desc)
        if w >= SCOPE_DESC_MIN_WORDS:
            sd_pass.append(f"{clab(c)} - description is descriptively covered.")
        elif ref_match:
            sd_pass.append(f"{clab(c)} - accepted via reference evidence ({ref_match.group(0)!r}).")
        else:
            sd_fail.append(f"{clab(c)} - description is missing or too brief, no "
                          "arc42/diagram/image reference found.")

    doc_pass_count = (1 if ov_ok else 0) + len(sd_pass)
    doc_total = 1 + len(comps)
    doc_fail_count = doc_total - doc_pass_count
    top_pass = ([f"{doc_pass_count} of {doc_total} documentation clarity check(s) are descriptively covered."]
               if doc_pass_count else [])
    top_fail = ([f"{doc_fail_count} of {doc_total} documentation clarity check(s) are missing or too brief."]
               if doc_fail_count else [])
    doc_groups = [{"title": "System overview (intended operating environment)",
                  "pass": ov_pass, "fail": ov_fail}]
    doc_groups.append({"title": "Component descriptions",
                       "pass": (sd_pass if comps else ["no components to assess"]),
                       "fail": (sd_fail if comps else [])})

    core.append(dict(id="CM-11", name="Documentation clarity (system overview & component descriptions)",
                     dim="Comprehensibility", auto="Semi-auto",
                     note=("Checks that the system overview (combined from 4 candidate fields: "
                          "IntendedOp.IOEdescription, Overview, scopeDescription, highLevelDescription) "
                          "and each component's description are clear enough for a reader to understand. "
                          "A field being short or absent is not itself a fail as long as the combined "
                          "overview text clears the word-count threshold or a reference is present; "
                          "evidence names which of the 4 fields are present vs absent. A short "
                          "overview/description that links to an arc42 section, external doc/diagram, or "
                          "embedded image/diagram file is accepted as equivalent evidence."),
                     num=doc_pass_count, den=doc_total, better="high",
                     detail={"pass": top_pass, "fail": top_fail, "groups": doc_groups}))

    # CM-12 out-of-scope boundaries (scope-exclusion justification proxy)
    oos = [c for c in comps if c.get("scope") and c.get("scope") != "In_Scope"]
    if oos:
        just_keys = ("scopeComment", "scopeJustification", "outOfScopeReason", "justification",
                     "comment", "description")
        jp, jf = [], []
        for c in oos:
            j = next((c.get(k) for k in just_keys if c.get(k)), None)
            (jp if j else jf).append(clab(c) if j else f"{clab(c)} - out of scope without justification")
        jf_grouped = ([_bulleted(
            f"{len(jf)} out-of-scope component(s) have no explicit justification:",
            jf,
        )] if jf else [])
        core.append(dict(id="CM-12", name="Out-of-scope boundaries", dim="Coverage",
                         auto="Semi-auto",
                         note="Each out-of-scope component should include an explicit scope justification.",
                         num=len(jp), den=len(oos), better="high", detail={"pass": jp, "fail": jf_grouped}))
    else:
        core.append(dict(id="CM-12", name="Out-of-scope boundaries", dim="Coverage",
                         auto="Semi-auto",
                         note="No out-of-scope components are present, so this check is not assessable.", status="na",
                         better="high", detail={"pass": ["nothing excluded"], "fail": []}))

    # CM-13 no-threat / empty-analysis red flag
    core.append(dict(id="CM-13", name="No-threat / empty-analysis red flag", dim="Coverage", auto="Auto", note="A TRA should contain threat scenarios; zero threats indicates an incomplete risk analysis.",
                     num=1 if n_threats else 0, den=1, better="high",
                     detail={"pass": [f"{n_threats} threat scenarios present"] if n_threats else [],
                             "fail": [] if n_threats else ["no threat scenarios defined at all"]}))

    # CM-14 threat specificity vs good-threat list (rule-based NLP).
    # Each threat is compared against the vocabulary of a curated good-threat list
    # (all ThreatScenarios in GOOD_THREATS_DIR). A threat is "specific" when it is
    # tied to a component/interface AND uses the concrete technical language seen
    # in real good threats; generic, interface-less threats are flagged.
    #
    # The "concrete language" signal is IDF-weighted: each shared good-vocab term
    # contributes its normalised inverse-document-frequency (rare, distinctive
    # terms like "modbus"/"firmware" ~1.0; near-ubiquitous terms ~0). A threat
    # clears the concreteness bar when it shares at least CONCRETE_MIN_TERMS
    # distinct terms whose IDF weights sum to >= CONCRETE_STRENGTH_MIN. This
    # rewards genuinely distinctive wording and resists keyword-stuffing with
    # common vocabulary, while a single-keyword description (e.g. "spoofing")
    # still fails because it clears neither the term-count nor the length gate.
    good_vocab, good_idf, n_good, vocab_meta = load_good_threat_vocab()
    p16b, f16b = [], []
    cm17_info = [
        ("Vocabulary source: "
         f"{vocab_meta.get('source_files', 0)} file(s), "
         f"{vocab_meta.get('entries_seen', 0)} entries seen, "
         f"{vocab_meta.get('entries_accepted', 0)} accepted, "
         f"{vocab_meta.get('vocab_terms', 0)} terms after filters."),
        ("Vocabulary filters: generic-threat terms + stopwords removed; "
         "placeholder/non-threat/empty entries rejected; token normalisation + short technical-term keep-list applied."),
        ("Specificity formula: score = 0.30*iface_link + 0.40*concrete_language + 0.30*length_non_vague; "
         f"specific when score >= {SPECIFICITY_PASS_THRESHOLD} and (iface_link or concrete_language)."),
        ("Concrete-language gate: at least "
         f"{CONCRETE_MIN_TERMS} shared vocab terms AND weighted strength >= {CONCRETE_STRENGTH_MIN} "
         "(strength = sum of normalized IDF(term))."),
    ]
    for t in threats:
        desc = t.get("attackActionDesc") or ""
        eval_res = _cm17_evaluate_threat(t, good_vocab, good_idf)
        specific = eval_res["specific_terms"]
        score = eval_res["score"]
        ranked_terms = sorted(specific, key=lambda w: (-good_idf.get(w, 0.0), w))
        trigger_terms = ", ".join(
            f"{w}:{good_idf.get(w, 0.0):.2f}" for w in ranked_terms[:8]
        ) or "none"
        strength = sum(good_idf.get(w, 0.0) for w in specific)
        if eval_res["is_specific"]:
            p16b.append(
                f"{tlab(t)} - specific (score={score:.2f}; iface_link={eval_res['has_iface']}; "
                f"concrete_strength={strength:.2f}; trigger_terms={trigger_terms})"
            )
        else:
            why = []
            if not eval_res["has_iface"]:
                why.append("no component/interface link")
            if not eval_res["concrete_ok"]:
                why.append("weak concrete language vs good-threat list")
            if eval_res["words"] < KEYWORD_ONLY_MIN_WORDS:
                why.append(f"only {eval_res['words']} word(s)")
            if eval_res["vague_hits"] >= 2:
                why.append("vague wording")
            # Extract snippet for narrative evidence (first 70 chars + context)
            desc_snippet = desc[:70] if desc else "(no description)"
            if len(desc) > 70:
                desc_snippet += "..."
            f16b.append(
                f"{tlab(t)} - generic / weakly-specific (score={score:.2f}; {('; '.join(why)) or 'heuristic fail'}; "
                f"concrete_strength={strength:.2f}; trigger_terms={trigger_terms}) | snippet: {desc_snippet}"
            )
    core.append(dict(id="CM-14", name="Threat specificity vs good-threat list (rule-based NLP)",
                     dim="Consistency & Traceability", auto="Semi-auto",
                   note=(f"Each threat is compared against a curated corpus of {n_good} good threats "
                       f"({len(good_vocab)} IDF-weighted vocabulary terms). "
                       "Threats are considered specific when they use concrete language and are linked to a component/interface."),
                   num=len(p16b), den=n_threats, better="high",
                   status=("na" if not n_threats else None),
                   detail={"info": cm17_info,
                         "pass": (["no threats to assess"] if not n_threats else p16b),
                         "fail": ([] if not n_threats else f16b)}))

    # CM-15 protection-goal C/I/A balance
    cia_present = {}
    for p in pgs:
        ptype = str(p.get("protectionGoalType", "")).strip().lower()
        if ptype.startswith("conf"):
            cia_present["Confidentiality"] = cia_present.get("Confidentiality", 0) + 1
        elif ptype.startswith("integ"):
            cia_present["Integrity"] = cia_present.get("Integrity", 0) + 1
        elif ptype.startswith("avail"):
            cia_present["Availability"] = cia_present.get("Availability", 0) + 1
    cia_all = ["Confidentiality", "Integrity", "Availability"]
    cia_ok = [c for c in cia_all if cia_present.get(c)]
    cia_missing = [c for c in cia_all if not cia_present.get(c)]
    core.append(dict(id="CM-15", name="Protection-goal C/I/A balance", dim="Consistency & Traceability",
                     auto="Auto",
                     note="protection goals span Confidentiality, Integrity and Availability",
                     num=len(cia_ok), den=3, better="high",
                     detail={"pass": [f"{c} - {cia_present[c]} protection goal(s)" for c in cia_ok],
                             "fail": [f"{c} - no protection goal of this type" for c in cia_missing]}))

    # ---- Consistency & Traceability ----------------------------------------
    # similar-threat clustering (token-Jaccard proxy) for CM-16
    # Placeholder terms that should not contribute to similarity scores
    PLACEHOLDER_TOKENS = {"xxx", "ttt", "test", "todo", "tbd", "fixme", "placeholder"}

    def _tok(t):
        blob = f"{t.get('name', '')} {t.get('attackActionDesc', '')}".lower()
        tokens = set(re.findall(r"[a-z0-9]{3,}", blob))
        # Filter out placeholder and generic filler tokens to reduce false positives
        return tokens - PLACEHOLDER_TOKENS

    # Helper to create rich threat description for reporting
    def _threat_desc(t):
        """Return threat ID + name + brief description for similarity findings."""
        name = t.get('name', 'unnamed')
        desc = (t.get('attackActionDesc', '') or '').strip()
        # Include first 60 chars of description if available
        if desc:
            desc_short = desc[:60] + '...' if len(desc) > 60 else desc
            return f"{tlab(t)} ({desc_short})"
        return tlab(t)

    toks = [(t, _tok(t)) for t in threats]
    cm19_pairs = 0
    cm19_inconsistent = 0
    f18, p18 = [], []
    for i in range(len(toks)):
        for j in range(i + 1, len(toks)):
            a, ta = toks[i]; b, tb = toks[j]
            if not ta or not tb:
                continue
            jac = len(ta & tb) / len(ta | tb)
            if jac >= JACCARD_DUP_THRESHOLD:
                # CM-17 scoping keys
                ia = (a.get("AttackInterface") or {}).get("interface_id")
                ib = (b.get("AttackInterface") or {}).get("interface_id")
                same_iface = bool(ia and ib and ia == ib)
                ca = iface_owner.get(ia) if ia else None
                cb = iface_owner.get(ib) if ib else None
                same_comp = bool(ca and cb and ca == cb)

                # CM-17 applicability gate: compare only threats that target the
                # same attacked interface or the same owning component.
                if not (same_iface or same_comp):
                    continue

                cm19_pairs += 1
                ra, rb = a.get("CALCRiskRating"), b.get("CALCRiskRating")
                # Missing ratings are not counted as inconsistencies. Only
                # compare rated pairs, and only escalate differences when at
                # least one side is Moderate+.
                if not ra or not rb:
                    rel = []
                    if same_iface and ia:
                        rel.append(f"same interface {ia}")
                    if same_comp and ca:
                        rel.append(f"same component {ca}")
                    p18.append(f"{tlab(a)} [{ra or 'no rating'}] ~ {tlab(b)} [{rb or 'no rating'}] - "
                               f"not assessed for inconsistency ({', '.join(rel)})")
                    continue

                sev = {str(ra).lower(), str(rb).lower()} & SEVERE_RISK
                if ra != rb and sev:
                    cm19_inconsistent += 1
                    f18.append(f"{tlab(a)} [{ra}] ~ {tlab(b)} [{rb}] (similarity {jac:.0%}) - "
                               f"descriptions: {_threat_desc(a)} ... {_threat_desc(b)}")
                else:
                    rel = []
                    if same_iface and ia:
                        rel.append(f"same interface {ia}")
                    if same_comp and ca:
                        rel.append(f"same component {ca}")
                    p18.append(f"{tlab(a)} [{ra or 'no rating'}] ~ {tlab(b)} "
                               f"[{rb or 'no rating'}] - consistent ({', '.join(rel)}; similarity {jac:.0%}) - "
                               f"descriptions: {_threat_desc(a)} ... {_threat_desc(b)}")

    # CM-16 rating consistency across similar threats
    if cm19_pairs:
        core.append(dict(id="CM-16", name="Rating consistency across similar threats",
                         dim="Consistency & Traceability", auto="Semi-auto",
                         note=(f"{cm19_pairs} comparable near-duplicate threat pair(s) "
                               f"(same interface/component, Jaccard>={JACCARD_DUP_THRESHOLD}); "
                               "cross-component pairs are excluded; missing ratings are not counted as inconsistencies"),
                         num=cm19_pairs - cm19_inconsistent, den=cm19_pairs, better="high",
                         detail={"pass": p18, "fail": f18}))
    else:
        core.append(dict(id="CM-16", name="Rating consistency across similar threats",
                         dim="Consistency & Traceability", auto="Semi-auto",
                         note=("no comparable near-duplicate pairs found on the same interface/component (n/a); "
                               "cross-component pairs are intentionally excluded"),
                         status="na", better="high",
                         detail={"pass": ["no similar-threat pairs detected"], "fail": []}))

    # CM-17 rating coherence & justification. This now also embeds the
    # server-style audit taxonomy in fail details:
    # - CALC_MISMATCH / CALC_UNDERIVABLE
    # - EXPOSURE_OVERRIDE_UNDOCUMENTED / EXPOSURE_OVERRIDE_EXCEEDS_ZONE
    # - IMPACT_PG_MISMATCH
    def _rationale_fields(t):
        return [name for name, val in (
            ("exploitabilityComment", t.get("exploitabilityComment")),
            ("threatSpecificExposureComment", t.get("threatSpecificExposureComment")),
            ("threatSpecificImpactComment", t.get("threatSpecificImpactComment")),
        ) if val]

    def _has_text(v):
        return bool(str(v or "").strip())

    def _impact_rank_value(v):
        m = {"negligible": 1, "moderate": 2, "critical": 3, "disastrous": 4}
        return m.get(_norm_rating(v), 0)

    # Attack-surface exposure lookup for semantic checks and calc derivation.
    iface_exposure = {}
    comm_exposure = {}
    for c in comps:
        for it in component_interfaces(c):
            iid = it.get("interface_id")
            if iid and iid not in iface_exposure:
                iface_exposure[iid] = it.get("CALCzoneDerivedExposure_I")
        for cm in component_communications(c):
            cid = cm.get("communication_id")
            if cid and cid not in comm_exposure:
                comm_exposure[cid] = cm.get("CALCzoneDerivedExposure_C")
    for z in zones:
        for key, val in z.items():
            if "Interface" not in str(key) or not isinstance(val, list):
                continue
            for it in val:
                if not isinstance(it, dict):
                    continue
                iid = it.get("interface_id")
                if iid and iid not in iface_exposure:
                    iface_exposure[iid] = it.get("CALCzoneDerivedExposure_I")

    pg_impact_by_id = {
        p.get("pg_id"): p.get("impactLevel")
        for p in pgs if p.get("pg_id")
    }

    def _threat_calc_semantic_issues(t):
        issues = []

        # Determine zone-derived exposure from linked attack surface.
        zone_exposure = None
        atk_iface = (t.get("AttackInterface") or {}).get("interface_id")
        atk_comm = (t.get("AttackCommunication") or {}).get("communication_id")
        if atk_iface:
            zone_exposure = iface_exposure.get(atk_iface)
        elif atk_comm:
            zone_exposure = comm_exposure.get(atk_comm)

        # Semantic: exposure override checks.
        specific_exposure = t.get("threatSpecificExposureRating")
        specific_exposure_norm = _norm_rating(specific_exposure)
        if specific_exposure_norm not in {"norating", "no_rating", ""}:
            if not _has_text(t.get("threatSpecificExposureComment")):
                issues.append(
                    "EXPOSURE_OVERRIDE_UNDOCUMENTED: threatSpecificExposureRating is set "
                    "but threatSpecificExposureComment is empty"
                )
            zone_exposure_norm = _norm_rating(zone_exposure)
            exposure_rank = {"low": 1, "medium": 2, "med": 2, "high": 3}
            if zone_exposure_norm in exposure_rank and specific_exposure_norm in exposure_rank:
                if exposure_rank[specific_exposure_norm] > exposure_rank[zone_exposure_norm]:
                    issues.append(
                        f"EXPOSURE_OVERRIDE_EXCEEDS_ZONE: threatSpecificExposureRating={specific_exposure} "
                        f"is higher than zone-derived exposure={zone_exposure}"
                    )

        # Semantic: impact override vs linked protection goals.
        linked_pg_impacts = []
        for pg_ref in (t.get("ProtectionGoals") or []):
            pg_id = (pg_ref or {}).get("pg_id")
            if pg_id and pg_id in pg_impact_by_id:
                linked_pg_impacts.append(pg_impact_by_id[pg_id])
        max_pg_impact = None
        if linked_pg_impacts:
            max_pg_impact = max(linked_pg_impacts, key=_impact_rank_value)

        specific_impact = t.get("threatSpecificImpactRating")
        specific_impact_norm = _norm_rating(specific_impact)
        if specific_impact_norm not in {"norating", "no_rating", ""} and max_pg_impact:
            if _norm_rating(max_pg_impact) != specific_impact_norm:
                issues.append(
                    f"IMPACT_PG_MISMATCH: threatSpecificImpactRating={specific_impact} "
                    f"differs from max linked ProtectionGoal impact={max_pg_impact}"
                )

        # Calc derivation (server-style CALC mismatch taxonomy).
        expected_applied_exposure = None
        if specific_exposure_norm not in {"norating", "no_rating", ""}:
            expected_applied_exposure = specific_exposure
        elif _norm_rating(zone_exposure) not in {"", "norating", "no_rating"}:
            expected_applied_exposure = zone_exposure

        expected_applied_impact = None
        if specific_impact_norm not in {"norating", "no_rating", ""}:
            expected_applied_impact = specific_impact
        elif max_pg_impact:
            expected_applied_impact = max_pg_impact

        expected_calc = {}
        if expected_applied_exposure:
            expected_calc["CALCAppliedExposure"] = expected_applied_exposure
        else:
            issues.append(
                "CALC_UNDERIVABLE: CALCAppliedExposure cannot be derived; "
                f"threatSpecificExposureRating={specific_exposure or 'NoRating'}, "
                f"zoneDerivedExposure={zone_exposure or 'missing'}, "
                f"attackInterface={atk_iface or 'none'}, "
                f"attackCommunication={atk_comm or 'none'}"
            )

        if expected_applied_impact:
            expected_calc["CALCAppliedImpactRating"] = expected_applied_impact
        else:
            issues.append(
                "CALC_UNDERIVABLE: CALCAppliedImpactRating cannot be derived; "
                f"threatSpecificImpactRating={specific_impact or 'NoRating'}, "
                f"linkedProtectionGoals={len(linked_pg_impacts)}, "
                f"maxLinkedPgImpact={max_pg_impact or 'missing'}"
            )

        exp_norm = _norm_rating(expected_applied_exposure)
        xpl_norm = _norm_rating(t.get("exploitabilityRating"))
        expected_lik = LIKELIHOOD_MATRIX.get(xpl_norm, {}).get(exp_norm)
        if expected_lik:
            expected_calc["CALCLikelihood"] = expected_lik
        else:
            issues.append(
                "CALC_UNDERIVABLE: CALCLikelihood cannot be derived from "
                "exploitabilityRating + CALCAppliedExposure; "
                f"exploitabilityRating={t.get('exploitabilityRating') or 'missing'}, "
                f"derivedAppliedExposure={expected_applied_exposure or 'missing'}"
            )

        imp_norm = _norm_rating(expected_applied_impact)
        lik_norm = _norm_rating(expected_lik)
        expected_risk = RISK_MATRIX.get(imp_norm, {}).get(lik_norm)
        if expected_risk:
            expected_calc["CALCRiskRating"] = expected_risk
        else:
            issues.append(
                "CALC_UNDERIVABLE: CALCRiskRating cannot be derived from "
                "CALCAppliedImpactRating + CALCLikelihood; "
                f"derivedAppliedImpact={expected_applied_impact or 'missing'}, "
                f"derivedLikelihood={expected_lik or 'missing'}"
            )

        for field, expected_value in expected_calc.items():
            stored_value = t.get(field)
            if _norm_rating(stored_value) != _norm_rating(expected_value):
                issues.append(
                    f"CALC_MISMATCH: {field} stored={stored_value} expected={expected_value}"
                )

        return issues

    _LIK_LABELS = {"very_unlikely", "unlikely", "possible", "likely", "very_likely"}
    _CM20_GROUP_ORDER = [
        "RISK_MATRIX_MISMATCH",
        "MISSING_RATIONALE",
        "CALC_MISMATCH",
        "CALC_UNDERIVABLE",
        "EXPOSURE_OVERRIDE_UNDOCUMENTED",
        "EXPOSURE_OVERRIDE_EXCEEDS_ZONE",
        "IMPACT_PG_MISMATCH",
        "OTHER",
    ]

    def _cm20_issue_tag(issue_text: str) -> str:
        text = str(issue_text or "").strip()
        if text.startswith("risk matrix=false"):
            return "RISK_MATRIX_MISMATCH"
        if text.startswith("no rating rationale comment"):
            return "MISSING_RATIONALE"
        if text.startswith("CALC_MISMATCH:"):
            return "CALC_MISMATCH"
        if text.startswith("CALC_UNDERIVABLE:"):
            return "CALC_UNDERIVABLE"
        if text.startswith("EXPOSURE_OVERRIDE_UNDOCUMENTED:"):
            return "EXPOSURE_OVERRIDE_UNDOCUMENTED"
        if text.startswith("EXPOSURE_OVERRIDE_EXCEEDS_ZONE:"):
            return "EXPOSURE_OVERRIDE_EXCEEDS_ZONE"
        if text.startswith("IMPACT_PG_MISMATCH:"):
            return "IMPACT_PG_MISMATCH"
        return "OTHER"

    cm20_group_fail: dict[str, list[str]] = {k: [] for k in _CM20_GROUP_ORDER}
    p19, f19 = [], []
    for t in threats:
        audit_issues = _threat_calc_semantic_issues(t)
        imp = _norm_rating(t.get("CALCAppliedImpactRating"))
        lik = _norm_rating(t.get("CALCLikelihood"))
        rsk = _norm_rating(t.get("CALCRiskRating"))
        # derive likelihood from the likelihood matrix when not directly stored
        if lik not in _LIK_LABELS:
            xpl = _norm_rating(t.get("exploitabilityRating"))
            exp = _norm_rating(t.get("threatSpecificExposureRating"))
            lik = LIKELIHOOD_MATRIX.get(xpl, {}).get(exp, lik)
        coherent = True
        expected = None
        if imp in RISK_MATRIX and lik in RISK_MATRIX[imp] and rsk:
            expected = RISK_MATRIX[imp][lik]
            coherent = (rsk == expected)
        rationale_fields = _rationale_fields(t)
        justified = bool(rationale_fields)
        if coherent and justified and not audit_issues:
            p19.append(f"{tlab(t)} - risk={t.get('CALCRiskRating')} matches matrix "
                      f"(impact={t.get('CALCAppliedImpactRating')}, likelihood={t.get('CALCLikelihood') or lik}); "
                      f"rationale: {', '.join(rationale_fields)}")
        else:
            why = []
            if not coherent:
                why.append(f"risk matrix=false (impact={t.get('CALCAppliedImpactRating')}, "
                           f"likelihood={t.get('CALCLikelihood') or lik}, risk={t.get('CALCRiskRating')}; "
                           f"matrix expects {expected})")
            if not justified:
                why.append("no rating rationale comment")
            if not coherent and not justified:
                why.append(f"correction: set CALCRiskRating to {expected} and add a rating rationale comment")
            elif not coherent:
                why.append(f"correction: set CALCRiskRating to {expected}")
            elif not justified:
                why.append("correction: add a rating rationale comment")
            why.extend(audit_issues)
            f19.append(f"{tlab(t)} - {'; '.join(why)}")

            # Grouped readings: classify each issue (ignore correction hints)
            # so reviewers can inspect CM-18 by mismatch type.
            for issue in why:
                if str(issue).startswith("correction:"):
                    continue
                tag = _cm20_issue_tag(issue)
                cm20_group_fail[tag].append(f"{tlab(t)} - {issue}")

    cm20_group_title = {
        "RISK_MATRIX_MISMATCH": "Risk matrix mismatch",
        "MISSING_RATIONALE": "Missing rating rationale",
        "CALC_MISMATCH": "Stored vs derived CALC mismatch",
        "CALC_UNDERIVABLE": "CALC value cannot be derived",
        "EXPOSURE_OVERRIDE_UNDOCUMENTED": "Exposure override lacks justification",
        "EXPOSURE_OVERRIDE_EXCEEDS_ZONE": "Exposure override exceeds zone baseline",
        "IMPACT_PG_MISMATCH": "Impact vs protection-goal mismatch",
        "OTHER": "Other CM-18 issues",
    }

    cm20_groups = []
    for tag in _CM20_GROUP_ORDER:
        fail_items = cm20_group_fail.get(tag) or []
        if not fail_items:
            continue
        title = f"CM-18 grouped by issue type: {cm20_group_title.get(tag, tag)}"
        cm20_groups.append({"title": title, "pass": [], "fail": fail_items})

    core.append(dict(id="CM-17", name="Rating coherence & justification",
                     dim="Consistency & Traceability", auto="Semi-auto",
                     note="stored risk matches the risk matrix value derived from "
                          "impact+likelihood AND rating carries an explanatory comment",
                     num=len(p19), den=n_threats, better="high",
                     status=("na" if not n_threats else None),
                     detail={"pass": (["no threats to assess"] if not n_threats else p19),
                            "fail": ([] if not n_threats else f19),
                            "groups": cm20_groups}))

    # CM-18 risk-treatment status workflow validation
    def _norm_token(v):
        return str(v or "").strip().lower().replace(" ", "_")

    def _has_rating(v):
        return bool(v) and _norm_token(v) not in ("norating", "no_rating", "no_re_rating", "incomplete")

    def _risk_rank(v):
        rank_map = {"minor": 1, "moderate": 2, "significant": 3, "major": 4}
        return rank_map.get(_norm_token(v), 0)

    def _norm_progress_token(progress):
        """Normalize progress values to the UI vocabulary used by reviewers."""
        token = _norm_token(progress)
        if token in {"", "norating", "no_rating"}:
            return "not_started"
        return token

    def _progress_label(progress):
        token = _norm_progress_token(progress)
        labels = {
            "not_started": "Not started",
            "in_work": "In work",
            "on_hold": "On hold",
            "completed": "Completed",
            "deferred": "Deferred",
        }
        return labels.get(token, str(progress or "") or "(empty)")

    def _status_from_progress(progress):
        p = _norm_progress_token(progress)
        if p in {"not_started", "in_work", "in_progress"}:
            return "in_progress", "Open"
        if p == "completed":
            return "passed", "Passed"
        if p in {"on_hold", "deferred"}:
            return "not_passed", "Not passed"
        return None, "unknown"

    def _status_label(v):
        m = {
            "in_progress": "Open",
            "passed": "Passed",
            "not_passed": "Not passed",
        }
        return m.get(_norm_token(v), str(v or "") or "(empty)")

    cm21_pass, cm21_fail = [], []
    cm19_info = [
        "Purpose: verify risk-treatment workflow consistency between re-rating inputs, treatment progress, and CALCstatus.",
        "Flags when Completed treatment still has placeholder residual risk (RR_CALC_STALE).",
        "Flags when CALCrrRiskRating=No_Re_rating but isAcceptedByDefault is false.",
        "Flags when CALCrrRiskRating=No_Re_rating still carries a CALCstatus value.",
        "Flags when non-avoided threats have missing or Incomplete residual risk rating.",
        "Flags when CALCstatus does not match expected status from treatmentProgress or acceptable-range logic.",
        "Status mapping used: Open=[Not started, In work], Passed=[Completed], Not passed=[On hold, Deferred].",
    ]
    for t in threats:
        rerating = t.get("ReRating") or {}
        threat_name = t.get("name") or "(unnamed)"

        base_risk = t.get("CALCRiskRating")
        residual_risk = rerating.get("CALCrrRiskRating")
        status_value = rerating.get("CALCstatus")
        treatment_progress = rerating.get("treatmentProgress")
        has_mitigation = bool(str(rerating.get("mitigation") or "").strip())
        is_avoided = bool(rerating.get("isAvoided"))
        is_accepted_by_default = bool(rerating.get("isAcceptedByDefault"))

        base_rank = _risk_rank(base_risk)
        residual_rank = _risk_rank(residual_risk)
        residual_token = _norm_token(residual_risk)
        status_token = _norm_token(status_value)

        expected_status = None
        expected_desc = ""
        reasons = []

        # Server alignment: completed treatment must not keep placeholder
        # re-rated risk values.
        if _norm_progress_token(treatment_progress) == "completed" and residual_token in {
            "", "norating", "no_rating", "no_re_rating", "incomplete"
        }:
            reasons.append(
                f"RR_CALC_STALE: treatmentProgress=Completed but CALCrrRiskRating={residual_risk or 'NoRating'}"
            )

        # No residual re-rating: accepted-by-default route, no explicit status expected.
        if residual_token == "no_re_rating":
            expected_desc = "Accepted by default (no CALCstatus shown)"
            if not is_accepted_by_default:
                reasons.append("CALCrrRiskRating=No_Re_rating but isAcceptedByDefault=false")
            if status_token:
                reasons.append("CALCrrRiskRating=No_Re_rating should not show CALCstatus")
        else:
            # Explicitly avoided risk follows treatment-progress status.
            if is_avoided:
                expected_status, progress_label = _status_from_progress(treatment_progress)
                expected_desc = f"Avoided risk -> status from treatmentProgress ({progress_label})"
                if expected_status is None:
                    reasons.append(f"unknown treatmentProgress='{treatment_progress}' for avoided risk")
            else:
                # Re-rated risk outside acceptable range (higher than previous risk) must be Not passed.
                if _has_rating(residual_risk) and base_rank and residual_rank > base_rank:
                    expected_status = "not_passed"
                    expected_desc = "Re-rated risk above previous risk -> Not passed"
                else:
                    # Re-rated risk in acceptable range follows treatment-progress status.
                    expected_status, progress_label = _status_from_progress(treatment_progress)
                    expected_desc = f"Re-rated risk in acceptable range -> status from treatmentProgress ({progress_label})"
                    if expected_status is None:
                        reasons.append(f"unknown treatmentProgress='{treatment_progress}'")

            if not is_avoided:
                if residual_token == "incomplete":
                    reasons.append("residual risk rating is 'Incomplete' (CALCrrRiskRating)")
                elif not _has_rating(residual_risk):
                    reasons.append("missing residual risk rating (CALCrrRiskRating)")

            if expected_status is not None and status_token != expected_status:
                reasons.append(f"CALCstatus is '{status_value}' but expected '{expected_status}'")

        evidence = (
            f"{t.get('threatscenario_id') or '?'} ({threat_name}) - mitigation={'yes' if has_mitigation else 'no'}; "
            f"baseRisk={base_risk or 'NoRating'}; rrRisk={residual_risk or 'NoRating'}; "
            f"reratedRiskCalculated={'yes' if _has_rating(residual_risk) else 'no'}; "
            f"avoided={'yes' if is_avoided else 'no'}; acceptedByDefault={'yes' if is_accepted_by_default else 'no'}; "
            f"treatmentProgress={_progress_label(treatment_progress)}; "
            f"status={_status_label(status_value)}"
        )

        if reasons:
            cm21_fail.append(f"{evidence}; expected={expected_desc}; issue=" + "; ".join(reasons))
        else:
            cm21_pass.append(f"{evidence}; expected={expected_desc}")

    core.append(dict(id="CM-18", name="Risk-treatment status workflow alignment",
                     dim="Consistency & Traceability", auto="Auto",
                   note=("Checks when risk-treatment workflow is internally inconsistent: stale residual rating after completion, "
                       "accepted-by-default mismatches, missing residual ratings, or CALCstatus mismatches vs expected progress outcome."),
                    num=len(cm21_pass), den=n_threats, better="high",
                     status=("na" if not n_threats else None),
                    detail={"info": cm19_info,
                        "pass": (["no threats to assess"] if not n_threats else cm21_pass),
                        "fail": ([] if not n_threats else cm21_fail)}))

    # CM-19 rating-distribution / rubber-stamping detector (redesigned).
    # Do NOT assume an even risk distribution: high-coverage TRA portfolios
    # often cluster around Moderate risk. We instead flag suspicious
    # concentration only when concentration is high AND underlying input
    # diversity is low.
    from collections import Counter as _Counter

    def _risk_is_assessable(v):
        return _norm_rating(v) not in {"", "norating", "no_rating", "incomplete"}

    assessable_threats = [t for t in threats if _risk_is_assessable(t.get("CALCRiskRating"))]
    rated_n = len(assessable_threats)
    # Calibrated against the sample TRA portfolio in ./TRA to reduce
    # false positives on valid Moderate-heavy distributions.
    CM22_MIN_RATED = 7
    CM22_BAD_SHARE = 0.90
    CM22_BAD_DIVERSITY = 0.30
    CM22_WARN_SHARE = 0.80
    CM22_WARN_DIVERSITY = 0.40
    CM22_RATIONALE_WARN = 0.60

    cm22_info = [
        "Purpose: detect possible rating rubber-stamping (many threats given the same risk rating without enough input variety).",
        "How it works: combines concentration (dominant_share) with input diversity; concentration alone is not treated as a defect.",
        "Formula: dominant_share = modal_count / assessable_rated_threats",
        "Formula: input_diversity = unique(impact, likelihood, applied exposure, exploitability) / assessable_rated_threats",
        f"Eligibility: assessable threats have CALCRiskRating not in [NoRating, Incomplete]; minimum assessable threats={CM22_MIN_RATED}",
        f"Flag BAD when dominant_share>={int(CM22_BAD_SHARE * 100)}% and input_diversity<{int(CM22_BAD_DIVERSITY * 100)}%",
        f"Flag WARN when dominant_share>={int(CM22_WARN_SHARE * 100)}% and input_diversity<{int(CM22_WARN_DIVERSITY * 100)}%",
        f"Rationale guard: also WARN when >{int(CM22_RATIONALE_WARN * 100)}% of dominant-rating threats lack rating comments",
        "Interpretation: high concentration can be valid in high-coverage portfolios when input diversity stays high.",
    ]
    if rated_n >= CM22_MIN_RATED:
        rating_counts = _Counter(str(t.get("CALCRiskRating")) for t in assessable_threats)
        modal_label, modal_n = rating_counts.most_common(1)[0]
        dominant_share = (modal_n / rated_n)
        dominant_share_pct = round(dominant_share * 100, 1)

        # Diversity signal from input combinations that produce risk ratings.
        # If these combinations are diverse, concentration is likely structural
        # (expected) rather than rubber-stamping.
        combo_counts = _Counter(
            (
                _norm_rating(t.get("CALCAppliedImpactRating")),
                _norm_rating(t.get("CALCLikelihood")),
                _norm_rating(t.get("CALCAppliedExposure")),
                _norm_rating(t.get("exploitabilityRating")),
            )
            for t in assessable_threats
        )
        combo_diversity = (len(combo_counts) / rated_n) if rated_n else 0.0
        combo_diversity_pct = round(combo_diversity * 100, 1)

        # Optional sanity signal: if dominant rating mostly lacks rationale,
        # concentration is more suspicious.
        dominant_rationale_missing = 0
        for t in assessable_threats:
            if str(t.get("CALCRiskRating")) != str(modal_label):
                continue
            has_rationale = bool(
                (t.get("exploitabilityComment") or "").strip()
                or (t.get("threatSpecificExposureComment") or "").strip()
                or (t.get("threatSpecificImpactComment") or "").strip()
            )
            if not has_rationale:
                dominant_rationale_missing += 1
        dominant_missing_ratio = (dominant_rationale_missing / modal_n) if modal_n else 0.0

        status35 = "ok"
        fail_reasons = []
        pass_reasons = []

        dist = ", ".join(f"{k}:{v}" for k, v in rating_counts.most_common())
        pass_reasons.append(f"risk distribution - {dist}")
        pass_reasons.append(
            f"dominant rating '{modal_label}' share={dominant_share_pct}% ({modal_n}/{rated_n}); "
            f"input-combination diversity={combo_diversity_pct}% ({len(combo_counts)}/{rated_n})"
        )

        concentration_rules = [
            (
                "bad",
                lambda share, div: share >= CM22_BAD_SHARE and div < CM22_BAD_DIVERSITY,
                lambda: (
                    f"{modal_n}/{rated_n} threats share '{modal_label}' with low input diversity "
                    f"({len(combo_counts)} unique input combinations) - likely rubber-stamping"
                ),
            ),
            (
                "warn",
                lambda share, div: share >= CM22_WARN_SHARE and div < CM22_WARN_DIVERSITY,
                lambda: (
                    f"concentration warning: {modal_n}/{rated_n} threats share '{modal_label}' and "
                    f"input diversity is limited ({len(combo_counts)} unique combinations)"
                ),
            ),
            (
                "ok",
                lambda share, div: share >= CM22_WARN_SHARE,
                lambda: (
                    "high concentration observed but supported by diverse "
                    "impact/likelihood/exposure/exploitability combinations "
                    "(expected in high-coverage TRA datasets)"
                ),
            ),
        ]

        for mapped_status, predicate, message_builder in concentration_rules:
            if not predicate(dominant_share, combo_diversity):
                continue
            status35 = mapped_status
            if mapped_status == "ok":
                pass_reasons.append(message_builder())
            else:
                fail_reasons.append(message_builder())
            break

        if dominant_missing_ratio > CM22_RATIONALE_WARN:
            if status35 == "ok":
                status35 = "warn"
            fail_reasons.append(
                f"{dominant_rationale_missing}/{modal_n} dominant-rating threats lack rating rationale comments"
            )

        core.append(dict(id="CM-19", name="Rating-distribution / rubber-stamping detector",
                         dim="Consistency & Traceability", auto="Auto",
                     note=("Checks whether repeated risk ratings appear evidence-driven or rubber-stamped. "
                         "Flags only when high rating concentration is paired with low input diversity, "
                         "so valid Moderate-heavy portfolios are not penalized."),
                         value=dominant_share_pct, better="low", status=status35,
                         detail={"info": cm22_info,
                             "pass": pass_reasons,
                                 "fail": fail_reasons}))
    else:
        core.append(dict(id="CM-19", name="Rating-distribution / rubber-stamping detector",
                         dim="Consistency & Traceability", auto="Auto",
                         note=("Not assessable: too few rated threats to judge whether rating concentration is "
                               "evidence-driven or rubber-stamped."),
                         better="low", status="na",
                         detail={"info": cm22_info,
                             "pass": ["not enough assessable risk ratings to evaluate concentration"],
                                 "fail": []}))

    # CM-20 assumption usage / linkage by type. Only General assumptions are
    # assessed: each must actually be referenced somewhere (otherwise it is
    # "declared and ignored"). ZoneSpecific / ThreatSpecific assumptions are
    # excluded from this check.
    referenced = set()

    def _walk_refs(o):
        if isinstance(o, dict):
            aid = o.get("assumption_id")
            if aid and not o.get("assumptionType"):  # reference stub, not a definition
                referenced.add(aid)
            for v in o.values():
                _walk_refs(v)
        elif isinstance(o, list):
            for x in o:
                _walk_refs(x)
    _walk_refs(tra)

    p37, f37 = [], []
    general = [a for a in assumptions
               if (str(a.get("assumptionType", "")).strip() or "General").lower() == "general"]
    for a in general:
        aid = a.get("assumption_id")
        if aid in referenced:
            p37.append(f"{alab(a)} [General] - linked to a threat / element")
        else:
            f37.append(f"{alab(a)} [General] - declared but not linked to a threat / element")
    core.append(dict(id="CM-20", name="Assumption usage / linkage by type",
                     dim="Consistency & Traceability", auto="Auto",
                     note="each General assumption is actually referenced "
                          "(not declared and ignored)",
                     num=len(p37), den=len(general), better="high",
                     status=("na" if not general else None),
                     detail={"pass": (["no General assumptions to assess"] if not general else p37),
                             "fail": f37}))

    # ---- Comprehensibility --------------------------------------------------
    # CM-21 threat-structure completeness (actor/action/target/weakness/interface/impact slots).
    # Pass entries now cite exactly which slots are present per threat (not
    # just an empty list), so re-running after a fix shows what was actually
    # added (e.g. "6/6 slots present (..., weakness, ...)") instead of the
    # threat silently vanishing from view.
    slot_filled = slot_total = 0
    p24, f24 = [], []
    for t in threats:
        desc = t.get("attackActionDesc") or ""
        slots = {
            "action": len(re.findall(r"\w+", desc)) >= KEYWORD_ONLY_MIN_WORDS,
            "actor": bool(ACTOR_RE.search(desc)),
            "interface": bool((t.get("AttackInterface") or {}).get("interface_id")),
            "weakness": bool(t.get("weakness")),
            "impact": bool(t.get("CALCAppliedImpactRating")),
            "protection_goal": bool(t.get("ProtectionGoals")),
        }
        present = sum(slots.values())
        slot_filled += present; slot_total += len(slots)
        present_names = [k for k, v in slots.items() if v]
        missing = [k for k, v in slots.items() if not v]
        if present < len(slots):
            f24.append(f"{tlab(t)} - {present}/{len(slots)} slots; missing {', '.join(missing)}")
        else:
            p24.append(f"{tlab(t)} - {present}/{len(slots)} slots present ({', '.join(present_names)})")
    cm21_info = [
        "Slot definitions and detection logic (each slot is a boolean presence check on the threat):",
        f"  - action: attackActionDesc has >= {KEYWORD_ONLY_MIN_WORDS} words (a real description, not a keyword-only stub).",
        "  - actor: attackActionDesc matches an actor keyword (attacker, adversary, insider, malicious, threat actor, user).",
        "  - interface: AttackInterface.interface_id is set (attack has a named target interface).",
        "  - weakness: the weakness field is non-empty.",
        "  - impact: CALCAppliedImpactRating is set.",
        "  - protection_goal: at least one ProtectionGoals entry is linked.",
        "Example: a threat with a >=6-word attackActionDesc naming an attacker, a linked "
        "AttackInterface, a filled weakness, CALCAppliedImpactRating, and >=1 ProtectionGoals "
        "link scores 6/6 (all slots present). If ProtectionGoals is empty, the same threat "
        "scores 5/6 and is flagged as 'missing protection_goal'.",
        "Caveat: this is a heuristic structural/keyword check, not semantic understanding of the "
        "threat text -- a well-written threat can still score low if it phrases things unusually "
        "(e.g. no actor keyword match), and a poorly-written one can score high by including the "
        "right keywords. Treat the result as a completeness prompt for reviewer judgement, not a "
        "final verdict; the current pass/fail result is disputed and should be manually reviewed.",
    ]
    core.append(dict(id="CM-21", name="Threat-structure completeness (semantic)",
                     dim="Comprehensibility", auto="Semi-auto",
                     note="actor / action / target-interface / weakness / impact / protection-goal slots "
                          "(heuristic keyword/structure check; see info for slot definitions and caveats)",
                     num=slot_filled, den=slot_total, better="high",
                     status=("na" if not n_threats else None),
                     detail={"info": cm21_info,
                             "pass": (["no threats to assess"] if not n_threats else p24),
                             "fail": ([] if not n_threats else f24)}))


    # CM-22 vagueness / imprecision reduction. Scans every string field of the
    # threat (not just attackActionDesc) so vague wording hiding in weakness,
    # name, or rating-rationale comments is also caught.
    vg_pass, vg_fail = [], []
    for t in threats:
        hits = extract_vague_term_hits(t)
        terms = sorted(set(h["term"] for h in hits))
        if len(terms) >= 2:
            paths = sorted(set(h["path"] for h in hits))
            vg_fail.append(f"{tlab(t)} - vague terms: {', '.join(terms)} (fields: {', '.join(paths)})")
        else:
            vg_pass.append(tlab(t))
    core.append(dict(id="CM-22", name="Vagueness / imprecision reduction", dim="Comprehensibility",
                     auto="Semi-auto", informational=True,
                     note="threat text (all fields, not just attackActionDesc) is not dominated by "
                          "vague / generic wording (< 2 vague terms). Reclassified as optional/"
                          "informational: this is a coarse keyword signal of limited practical value "
                          "on its own, so it no longer counts toward the Comprehensibility dimension "
                          "status rollup.",
                     num=len(vg_pass), den=n_threats, better="high",
                     status=("na" if not n_threats else None),
                     detail={"pass": (["no threats to assess"] if not n_threats else vg_pass),
                             "fail": ([] if not n_threats else vg_fail)}))

    # ---- Process & Governance (presence checks for maturity-model rows) ------
    # CM-01 relevant-role / workshop participation (presence + count). The
    # schema's structured Participants/Participations fields carry only an
    # AccountGID per participant (no role field at all - a role such as
    # Product Owner, Architect, Security Officer can only ever be free text). Many
    # Excel-imported TRAs put the moderator and participant/role list as free
    # text in the workshop's 'comments' field instead; when the structured
    # fields are empty this falls back to parsing 'comments' so a real
    # workshop isn't reported as missing just because it wasn't re-entered
    # into the structured fields.
    workshops = tra.get("Workshops") or []
    MIN_PARTICIPANTS = 3
    p01, f01 = [], []

    def _participant_label(p: dict) -> str:
        name = str((p or {}).get("displayName") or (p or {}).get("name") or "?").strip()
        role = str((p or {}).get("role") or (p or {}).get("accessRights") or "").strip()
        ta = (p or {}).get("ToolAccount") or {}
        gid = str(ta.get("accountGID") or ta.get("userGID") or ta.get("accountID") or ta.get("gid") or "").strip()
        bits = [name]
        meta = []
        if role:
            meta.append(role)
        if gid:
            meta.append(gid)
        if meta:
            bits.append(f"[{', '.join(meta)}]")
        return " ".join(bits)

    def _moderator_label(m) -> str:
        if isinstance(m, dict):
            name = str(m.get("displayName") or m.get("name") or "?").strip()
            ta = m.get("ToolAccount") or {}
            gid = str(ta.get("accountGID") or ta.get("userGID") or ta.get("accountID") or ta.get("gid") or "").strip()
            return f"{name}" + (f" [{gid}]" if gid else "")
        return str(m or "?").strip()

    if not workshops:
        f01.append("no workshops recorded at all")
    for wi, w in enumerate(workshops):
        wid = w.get("workshopID") or w.get("name") or "workshop"
        loc = list_item_ref("Workshops", w, wi, preferred_id_fields=("workshopID", "name"))
        parts = w.get("Participants") or []
        mod = w.get("Moderator")
        parsed = _parse_workshop_comments(w.get("comments") or "")
        from_comments = False
        if not parts and parsed["participants"]:
            parts = parsed["participants"]
            from_comments = True
        if not mod and parsed["moderator"]:
            mod = parsed["moderator"]
            from_comments = True
        issues = []
        moderator_data = _moderator_label(mod) if mod else "?"
        if not parts:
            issues.append("no participants list")
        elif len(parts) < MIN_PARTICIPANTS:
            issues.append("participant threshold not met")
            issues.append(f"minimum required participants: {MIN_PARTICIPANTS}")
            issues.append(f"present participants: {len(parts)}")
            participants_list = [_participant_label(p) for p in parts if isinstance(p, dict)]
            if participants_list:
                issues.extend(participants_list)
            else:
                issues.append("(no participant details available)")
            if moderator_data != "?":
                issues.append(f"moderator: {moderator_data}")
            if from_comments:
                issues.append("participant/moderator data source: parsed from free-text comments")
        if not mod:
            issues.append("no moderator")
        if issues:
            f01.append(_bulleted(f"{wid} ({loc})", issues))
        else:
            names = ", ".join(_participant_label(p) for p in parts if isinstance(p, dict))
            source = (" [parsed from free-text 'comments'] " if from_comments else "")
            p01.append(f"{wid} ({loc}) - moderator: {moderator_data}; {len(parts)} participants: {names}{source}")
    core.append(dict(id="CM-01", name="Workshop participation",
                     dim="Process & Governance", auto="Semi-auto",
                     note=("workshop present with a non-empty participant list, a moderator and "
                           f">= {MIN_PARTICIPANTS} participants; schema data used here are Participants.displayName, "
                           "Participants.ToolAccount.accountGID, Participants.accessRights (when present), Moderator.displayName, "
                           "and Moderator.ToolAccount.accountGID; falls back to parsing the free-text 'comments' field when the "
                           "structured fields are empty"),
                   num=len(p01), den=len(workshops), better="high",
                     status=("na" if not workshops else None),
                     detail={"pass": (["no workshop data in this TRA schema (not assessable)"]
                                      if not workshops else p01),
                             "fail": ([] if not workshops else f01)}))

    # CM-02 living-document maintenance / update responsiveness.
    # Automated timeline + version-identity checks for a quick maintenance signal.
    project_created = (tra.get("Project") or {}).get("createdDate")
    version_created = tra.get("createdDate")
    version_changed = tra.get("changedDate")

    dt_project_created = parse_iso_datetime(project_created)
    dt_version_created = parse_iso_datetime(version_created)
    dt_version_changed = parse_iso_datetime(version_changed)

    now_utc = datetime.now(timezone.utc)
    fresh_within_1y = ((now_utc - dt_version_changed) <= timedelta(days=365)
                       if dt_version_changed else None)
    age_days = (now_utc - dt_version_changed).days if dt_version_changed else None
    gap_project_to_changed_delta = ((dt_version_changed - dt_project_created)
                                    if dt_version_changed and dt_project_created else None)
    gap_project_to_changed_days = (gap_project_to_changed_delta.days
                                   if gap_project_to_changed_delta is not None else None)
    gap_project_to_changed_seconds = (gap_project_to_changed_delta.total_seconds()
                                      if gap_project_to_changed_delta is not None else None)

    version_name = str(tra.get("TRAVersionName") or "").strip()
    version_number = str(tra.get("TRAVersionNumber") or "").strip()

    def _is_initial_version_number(v: str) -> bool:
        normalized = str(v or "").strip().lower().lstrip("v")
        return normalized in {"1", "1.0", "1.0.0"}

    cm02_pass, cm02_fail = [], []
    cm02_info = [
        f"Project creation date: {fmt_human_datetime(project_created)}",
        f"Version: {version_name or '(missing name)'} (number: {version_number or '(missing number)'})",
        f"Version creation date: {fmt_human_datetime(version_created)}",
        f"Version changed date: {fmt_human_datetime(version_changed)}",
    ]
    missing_fields = []
    if dt_project_created is None:
        missing_fields.append("project creation date")
    if dt_version_changed is None:
        missing_fields.append("version changed date")
    if not version_number:
        missing_fields.append("TRA version number")

    if missing_fields:
        cm02_status = "na"
        cm02_num = 0
        cm02_den = 0
        cm02_fail.append(
            "Not assessed: required CM-02 field(s) missing/invalid - " + ", ".join(missing_fields) + ".")
    else:
        gap_days = gap_project_to_changed_days if gap_project_to_changed_days is not None else 0
        gap_seconds = gap_project_to_changed_seconds if gap_project_to_changed_seconds is not None else 0
        age_days_local = age_days if age_days is not None else 0
        is_initial_version = _is_initial_version_number(version_number)
        # A non-initial version number is itself evidence that at least one
        # real revision has happened. Any measurable elapsed time (even a
        # few days/hours) between project creation and the version-changed
        # date counts as active maintenance - rapid version bumps (e.g.
        # v1 -> v3 within days) show responsive editing, not staleness.
        # Only a zero/negative gap (changed date at or before creation,
        # i.e. no real elapsed time) is flagged as suspicious/unverifiable.
        maintenance_gap_ok = (gap_seconds > 0) if not is_initial_version else None
        recency_ok = (fresh_within_1y is True)

        if is_initial_version:
            cm02_info.append("Maintenance gap check: skipped for initial version 1.0.")
        elif maintenance_gap_ok:
            cm02_pass.append(
                f"Maintenance gap check: Passed. Version {version_number} shows real elapsed time ({gap_days} day(s)) since project creation, evidencing active revision (rapid version progression counts as active maintenance, not staleness).")
        else:
            cm02_fail.append(
                f"Maintenance gap check: Flagged. Version changed date shows no real elapsed time since project creation ({gap_days} day(s)), so this version bump cannot be verified as a genuine revision.")

        if recency_ok:
            cm02_pass.append(
                f"Recency check: Passed. Latest version update is within 1 year as of today ({age_days_local} days ago).")
        else:
            cm02_fail.append(
                f"Recency check: Flagged. Latest version update is older than 1 year as of today ({age_days_local} days ago).")

        evaluated_checks = [recency_ok] if is_initial_version else [maintenance_gap_ok, recency_ok]
        failed_checks = sum(1 for chk in evaluated_checks if not chk)
        cm02_den = len(evaluated_checks)
        cm02_num = sum(1 for chk in evaluated_checks if chk)
        cm02_status = "ok"
        for mapped_status, predicate in [
            ("bad", lambda: failed_checks >= 2),
            ("warn", lambda: failed_checks == 1),
        ]:
            if predicate():
                cm02_status = mapped_status
                break

    core.append(dict(id="CM-02", name="Living-document maintenance (updated since creation)",
                     dim="Process & Governance", auto="Auto",
                     note=("Checks maintenance using two signals: maintenance gap (a non-initial version number plus any measurable elapsed time since project creation evidences a genuine revision; rapid version bumps count as active maintenance, not staleness -- only a zero/negative gap is flagged) and recency (latest change within 1 year)."),
                     num=cm02_num, den=cm02_den, better="high", status=cm02_status,
                     detail={"info": cm02_info, "pass": cm02_pass, "fail": cm02_fail}))

    # Canonicalise each id from the v3 catalog by metric name (V3_ID is the
    # single source of truth; inline ids above are kept in sync with it), then
    # order by catalog number.
    for m in core:
        m["id"] = V3_ID.get(m["name"], m["id"])
    core.sort(key=lambda m: int(re.sub(r"\D", "", m["id"]) or 0))
    # Finalize evidence strings and resolve status for metrics that rely on
    # default ratio/count thresholds.
    for m in core:
        if m.get("status") == "na":
            m["evidence"] = "not assessable"
            m["assessment_explanation"] = _metric_assessment_explanation(m)
            continue

        if m.get("kind") == "count":
            m["evidence"] = f"{m['num']} flagged"
        elif "num" in m and "den" in m:
            m["evidence"] = f"{m['num']} checked, {m['den']} assessed"
        elif m.get("name") == "Rating-distribution / rubber-stamping detector":
            detail = m.get("detail") or {}
            dist_info = ((detail.get("pass") or [""])[0]).strip()
            fail_info = ((detail.get("fail") or [""])[0]).strip()
            concentration = m.get("value")
            if concentration is None:
                m["evidence"] = dist_info or fail_info or "rating distribution rule"
            elif m.get("status") in {"warn", "bad"}:
                m["evidence"] = f"dominant-share={concentration}%; {fail_info or dist_info}"
            else:
                m["evidence"] = f"dominant-share={concentration}%; {dist_info or fail_info}"
        else:
            m["evidence"] = "derived from rule output"
        m["status"] = m.get("status") or status_from_metric(m)
        m["assessment_explanation"] = _metric_assessment_explanation(m)
    return core


DIMENSION_ORDER = ["Process & Governance", "Formal Completeness", "Coverage",
                   "Consistency & Traceability", "Comprehensibility"
                   ]


def compute_dimension_status(core: list) -> list:
    """Return color-only status per dimension (no numeric rollup).

    Metrics flagged 'informational' (e.g. CM-22) are still computed and shown
    in the report, but are excluded here so they don't drive the dimension's
    OK/WARN/BAD rollup -- they are reclassified as optional/lower-value
    signals rather than authoritative status contributors.
    """
    out = []
    for dim in DIMENSION_ORDER:
        members = [m for m in core if m.get("dim") == dim and not m.get("informational")]
        if not members:
            continue
        statuses = [m.get("status") for m in members]
        assessed = [s for s in statuses if s in {"ok", "warn", "bad"}]
        if not assessed:
            status = "na"
        elif "bad" in assessed:
            status = "bad"
        elif "warn" in assessed:
            status = "warn"
        else:
            status = "ok"
        out.append({
            "dim": dim,
            "status": status,
            "assessed": len(assessed),
            "total": len(members),
            "bad": sum(1 for s in assessed if s == "bad"),
            "warn": sum(1 for s in assessed if s == "warn"),
        })
    return out


def _bulleted(intro: str, items: list) -> str:
    """Format a finding as a short intro line followed by one bullet per item
    (joined with '\\n'), instead of one dense semicolon-joined paragraph.
    HTML rendering turns '\\n' into a line break so each item reads as its own
    line; plain-text/JSON consumers still get a perfectly valid single string."""
    if not items:
        return intro
    return intro + "\n" + "\n".join(f"  - {it}" for it in items)


def _clip_text(text, max_len: int = 160) -> str:
    """Return a compact one-line text snippet for inline evidence."""
    s = " ".join(str(text or "").split())
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _inline_field(path: str, value) -> str:
    """Render deterministic path=value evidence used in findings."""
    return f"{path}={_clip_text(value)!r}"


def _metric_assessment_explanation(m: dict) -> str:
    """Explain how this metric result was assessed for reviewers."""
    if m.get("status") == "na":
        return "Not assessed because required source data is missing in this TRA export."
    if m.get("kind") == "count":
        return "Count-based check: fewer flagged occurrences indicates better quality."
    if "num" in m and "den" in m:
        return "Ratio-based check: status depends on how many assessed items satisfy the criterion."
    return "Rule-derived check: status comes from metric-specific decision logic."


def build_findings(tra, assets, pgs, threats, assets_covered, pgs_with_threat,
                   comps_with_threat, in_scope, assumptions, core=None):
    findings = []

    # Extract components (works for both Software and System deployment schemas)
    comps, comp_key = components_of(tra)
    comp_key = comp_key or "Components"

    # ID-based JSON-location hints: prefer domain IDs (e.g. Assumptions[A_gen-1])
    # with index fallback when an ID is missing.
    asset_loc = {a.get("asset_id"): list_item_ref("Assets", a, i, ("asset_id", "name"))
                 for i, a in enumerate(assets)}
    pg_loc = {p.get("pg_id"): list_item_ref("ProtectionGoals", p, i, ("pg_id", "name"))
              for i, p in enumerate(pgs)}
    threat_loc = {t.get("threatscenario_id"): list_item_ref("ThreatScenarios", t, i, ("threatscenario_id", "name"))
                  for i, t in enumerate(threats)}
    assumption_loc = {a.get("assumption_id"): list_item_ref("Assumptions", a, i, ("assumption_id", "name"))
                      for i, a in enumerate(assumptions)}
    comp_loc = {c.get("subUnit_id"): list_item_ref(comp_key, c, i, ("subUnit_id", "name"))
                for i, c in enumerate(comps)}

    # Severity is data-driven: a rule starts at a base level and is *escalated*
    # to HIGH when a measurable threshold shows the problem is systemic rather
    # than a one-off slip. HIGH_FRACTION is the share of a population that, once
    # affected, turns a WARN into a HIGH.
    HIGH_FRACTION = 0.5

    def _sev(base, affected, total, force_high=False):
        """Return 'high' when force_high, or when >= HIGH_FRACTION of the
        population is affected; otherwise the base level."""
        if force_high:
            return "high"
        if total and (affected / total) >= HIGH_FRACTION:
            return "high"
        return base

    # 1) protection goal whose name matches a different asset than the one it
    #    links to (structural name/link mismatch - derived purely from the data,
    #    no hard-coded ids). A multi-word asset name appearing inside a
    #    protection-goal name that links to a *different* asset is suspicious.
    def _norm(s):
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

    def _threat_desc_snippet(t: dict) -> str:
        tid = t.get("threatscenario_id")
        loc = threat_loc.get(tid, "?")
        return _inline_field(f"{loc}.attackActionDesc", t.get("attackActionDesc") or "")

    asset_name = {a.get("asset_id"): a.get("name") for a in assets}
    asset_kw = {a.get("asset_id"): _norm(a.get("name")) for a in assets}
    for p in pgs:
        linked = (p.get("Asset") or {}).get("asset_id")
        pname = _norm(p.get("name"))
        # if the linked asset's own name already appears in the protection-goal
        # name, the link is corroborated - do not flag a same-named twin asset
        # (this TRA carries parallel Data-*/Func-* asset lists with identical
        # names, so an uncorroborated match would be a false positive).
        linked_kw = asset_kw.get(linked, "")
        if linked_kw and linked_kw in pname:
            continue
        for aid, kw in asset_kw.items():
            if aid and aid != linked and kw and " " in kw and kw in pname:
                # a wrong asset link is a data-integrity error - always HIGH
                ploc = pg_loc.get(p.get('pg_id'), '?')
                findings.append(("high", f"{p.get('pg_id')} \"{p.get('name')}\" name matches asset "
                                         f"{aid} \"{asset_name.get(aid)}\" but links {linked or '<none>'} "
                                         f"({ploc}); {_inline_field(ploc + '.name', p.get('name'))}."))
                break

    # 2) uncovered assets (an asset with no protection goal is a real coverage
    #    gap - HIGH; escalation is implicit since any uncovered asset is HIGH)
    uncovered = [a for a in assets if a.get("asset_id") not in assets_covered]
    if uncovered:
        details = [
            f"Asset {a.get('asset_id')} \"{a.get('name')}\" has no protection goal "
            f"({asset_loc.get(a.get('asset_id'), '?')})."
            for a in uncovered
        ]
        findings.append(("high", _bulleted(
            f"{len(uncovered)} asset(s) have no protection goal:", details)))

    # 3) orphan Critical protection goals - WARN, escalated to HIGH when the
    #    majority of Critical protection goals have no threat scenario.
    #    Lower-impact goals are not required by CM-09 and should not inflate
    #    this finding. Each orphan gets a catalog-grounded suggestion plus its
    #    JSON location and impact for clear reviewer action.
    critical_pgs = [p for p in pgs if str(p.get("impactLevel", "")).strip().lower() == "critical"]
    orphans = [p for p in critical_pgs if p.get("pg_id") not in pgs_with_threat]
    if orphans:
        lvl = _sev("warn", len(orphans), len(critical_pgs))
        detail_ids = []
        for p in orphans:
            loc = pg_loc.get(p.get("pg_id"), "?")
            hint = suggest_for_pg(p, comps)
            impact = str(p.get("impactLevel") or "NoRating").strip() or "NoRating"
            detail_ids.append(f"{p.get('pg_id')} ({loc}) - impact: {impact}" + (f" - {hint}" if hint else ""))
        findings.append((lvl, _bulleted(
            f"{len(orphans)}/{len(critical_pgs)} Critical protection goals have no threat scenario:", detail_ids)))

    # 4) in-scope components with no threat - WARN, escalated to HIGH when the
    #    majority of in-scope components are never attacked. Each gets a
    #    catalog-grounded suggestion from its own interfaces plus its location.
    reportable_in_scope = [c for c in in_scope if not is_generic_component(c)]
    noth = [c for c in reportable_in_scope if c.get("subUnit_id") not in comps_with_threat]
    if noth:
        lvl = _sev("warn", len(noth), len(reportable_in_scope))
        detail_ids = []
        for c in noth:
            loc = comp_loc.get(c.get("subUnit_id"), "?")
            hint = suggest_for_component(c)
            detail_ids.append(f"{c.get('subUnit_id')} ({c.get('name')}, {loc})"
                              + (f" - {hint}" if hint else ""))
        findings.append((lvl, _bulleted(
            f"{len(noth)}/{len(reportable_in_scope)} in-scope components are never attacked:", detail_ids)))

    # 5) unvalidated assumptions - WARN, escalated to HIGH when every assumption
    #    is unvalidated (nothing has been confirmed at all)
    notval = [a for a in assumptions if not a.get("validated")]
    if notval:
        lvl = _sev("warn", len(notval), len(assumptions),
                   force_high=(len(notval) == len(assumptions) and len(assumptions) > 0))
        ids = [f"{a.get('assumption_id')} ({assumption_loc.get(a.get('assumption_id'), '?')})"
              for a in notval]
        findings.append((lvl, _bulleted(
            f"{len(notval)}/{len(assumptions)} assumptions are not validated:", ids)))

    # 6) placeholder objects
    for a in assumptions:
        if (a.get("name") or "").strip().lower() == "test":
            aloc = assumption_loc.get(a.get('assumption_id'), '?')
            findings.append(("info", f"Assumption {a.get('assumption_id')} is a 'test' placeholder "
                                     f"({aloc}); {_inline_field(aloc + '.name', a.get('name'))}."))
    for c in comps:
        if (c.get("name") or "").strip().lower() == "test":
            cloc = comp_loc.get(c.get('subUnit_id'), '?')
            findings.append(("info", f"Component {c.get('subUnit_id')} is a 'test' placeholder "
                                     f"({cloc}); {_inline_field(cloc + '.name', c.get('name'))}."))

    # 7) re-rating anomalies and incomplete risk ratings
    def _norm_findings_token(v):
        return str(v or "").strip().lower().replace(" ", "_")

    for t in threats:
        rr = t.get("ReRating") or {}
        if rr.get("CALCrrRiskRating") == "No_Re_rating" and not rr.get("isAcceptedByDefault") \
                and not rr.get("acceptanceComment"):
            tloc = threat_loc.get(t.get('threatscenario_id'), '?')
            findings.append(("warn", f"{t.get('threatscenario_id')} has no re-rating, is not "
                                     f"accepted-by-default and carries no acceptance comment "
                                     f"({tloc}); {_inline_field(tloc + '.ReRating.CALCrrRiskRating', rr.get('CALCrrRiskRating'))}."))

        base_risk_token = _norm_findings_token(t.get("CALCRiskRating"))
        if base_risk_token == "incomplete":
            tloc = threat_loc.get(t.get('threatscenario_id'), '?')
            findings.append(("warn", f"{t.get('threatscenario_id')} has incomplete base risk rating "
                                     f"({tloc}); {_inline_field(tloc + '.CALCRiskRating', t.get('CALCRiskRating'))}."))

        residual_risk_token = _norm_findings_token(rr.get("CALCrrRiskRating"))
        if residual_risk_token == "incomplete" and not rr.get("isAvoided"):
            tloc = threat_loc.get(t.get('threatscenario_id'), '?')
            findings.append(("warn", f"{t.get('threatscenario_id')} has incomplete re-rated risk "
                                     f"({tloc}); {_inline_field(tloc + '.ReRating.CALCrrRiskRating', rr.get('CALCrrRiskRating'))}."))

    # 8) threats missing rationale - WARN, escalated to HIGH when the majority
    #    of threats carry no rating rationale at all
    norat = [t for t in threats
             if not (t.get("exploitabilityComment") or t.get("threatSpecificExposureComment")
                     or t.get("threatSpecificImpactComment"))]
    if norat:
        lvl = _sev("warn", len(norat), len(threats))
        ids = [f"{t.get('threatscenario_id') or '?'} "
              f"({threat_loc.get(t.get('threatscenario_id'), '?')}) - {_threat_desc_snippet(t)}" for t in norat]
        findings.append((lvl, _bulleted("Threats without any rating rationale:", ids)))

    # 8b) CM-17 risk-matrix coherence surfaced as a top-level finding so
    #     matrix=false and correction guidance are visible in the Findings
    #     panel (not only inside metric details).
    if core:
        cm18_id = V3_ID.get("Rating coherence & justification", "CM-17")
        cm20 = next((m for m in core if m.get("id") == cm18_id
                     or m.get("name") == "Rating coherence & justification"), None)
        cm20_fails = ((cm20 or {}).get("detail") or {}).get("fail") or []
        if cm20_fails:
            cm20_status = (cm20 or {}).get("status")
            lvl = "high" if cm20_status == "bad" else "warn"
            cm20_id = (cm20 or {}).get("id") or V3_ID.get("Rating coherence & justification", "CM-17")
            findings.append((lvl, _bulleted(
                f"{cm20_id} Rating coherence & justification: {len(cm20_fails)} flagged "
                f"(risk matrix/rationale/calc-semantic mismatches):", cm20_fails)))

    # 8c) CM-02 decision-rule finding surfaced explicitly so outcome wording is
    #     unambiguous in Findings: missing fields -> N/A, both failed -> HIGH,
    #     one failed -> WARN.
    if core:
        cm02 = next((m for m in core if m.get("id") == "CM-02"
                     or m.get("name") == "Living-document maintenance (updated since creation)"), None)
        cm02_fails = ((cm02 or {}).get("detail") or {}).get("fail") or []
        cm02_status = (cm02 or {}).get("status")
        if cm02_status == "bad" and cm02_fails:
            findings.append(("high", _bulleted(
                "CM-02 Living-document maintenance: both checks failed -> Urgently review.",
                cm02_fails)))
        elif cm02_status == "warn" and cm02_fails:
            findings.append(("warn", _bulleted(
                "CM-02 Living-document maintenance: one check failed -> Review.",
                cm02_fails)))
        elif cm02_status == "na" and cm02_fails:
            findings.append(("warn", _bulleted(
                "CM-02 Living-document maintenance: not assessed (N/A) because required field(s) are missing/invalid.",
                cm02_fails)))

    # 9) empty analysis is always the most serious red flag (mirrors CM-17)
    if not threats:
        findings.append(("high", "No threat scenarios are defined at all - the risk "
                                 "analysis is empty."))

    # 10) component naming quality - placeholder / generic patterns. This is
    #     advisory only: the finding suggests a rename to the reviewer, it does
    #     not pick or apply a name itself.
    placeholder_comps = []
    generic_names = {'default', 'test', 'temp', 'component', 'module', 'unknown'}
    for c in comps:
        cname = (c.get('name') or '').lower().strip()
        cid = c.get('subUnit_id') or '?'
        # Catch _-prefixed (private/placeholder) and generic single-word names
        if cname.startswith('_') or cname in generic_names:
            loc = comp_loc.get(c.get('subUnit_id'), '?')
            placeholder_comps.append(f"{cid} ({cname}, {loc})")

    if placeholder_comps:
        findings.append(("info", _bulleted(
            f"Components with placeholder/generic names ({len(placeholder_comps)}) - "
            "consider a more descriptive name for traceability (reviewer to choose; "
            "not auto-renamed):", placeholder_comps)))

    # 11) interface naming distinctiveness - repeated generic names
    iface_names = {}
    for c in comps:
        for it in component_interfaces(c):
            iname = it.get('name', 'default_interface')
            iface_names.setdefault(iname, []).append(it.get('interface_id'))

    # Flag if many interfaces share identical names (especially 'default_interface')
    repeated = {name: ids for name, ids in iface_names.items()
                if name and len(ids) >= 3 and name.lower() == 'default_interface'}
    if repeated:
        for name, ids in repeated.items():
            findings.append(("warn", f"Interface naming weakness: {len(ids)} interfaces all named "
                                    f"'{name}' (weakens attack-surface documentation: {', '.join(ids[:3])}...)."))

    # ---- CM metric-status alignment -----------------------------------------
    # Guarantee the findings never disagree with the metric status view: every
    # failing Core metric (status bad -> HIGH, warn -> WARN) that is not already
    # surfaced by a curated rule above is turned into a finding, using the
    # metric's own fail readings as the message. This keeps the two views in
    # sync and makes each finding traceable to a catalog id. Coverage is matched
    # by metric *name* (stable) rather than catalog id (which is renumbered).
    COVERED_NAMES = {
        "Placeholder / unfinished-entry detection",         # rule 6  placeholders
        "Assumption validation ratio",                      # rule 5  unvalidated assumptions
        "Component coverage by threats",                    # rule 4  components never attacked
        "Protection-goal-Threat Coverage",                  # rule 3  orphan protection goals
        "Asset-Protection-goal mapping",                    # rule 2  uncovered assets
        "No-threat / empty-analysis red flag",              # rule 9  empty analysis
        "Rating coherence & justification",                 # rule 8  rating rationale
        "Risk-treatment / handling decision coverage",      # rule 7  re-rating / treatment
        "Living-document maintenance (updated since creation)",  # rule 8c CM-02 explicit outcome
    }
    for m in (core or []):
        if m.get("name") in COVERED_NAMES:
            continue
        status = m.get("status")
        if status not in ("bad", "warn"):
            continue
        fails = (m.get("detail") or {}).get("fail") or []
        if not fails:
            continue
        lvl = "high" if status == "bad" else "warn"
        findings.append((lvl, _bulleted(f"{m['id']} {m['name']}: {len(fails)} flagged:", fails)))

    # Initial-stage review gate: if early checks fail, surface that first so
    # reviewers resolve foundational data quality issues before interpreting
    # downstream coverage/consistency findings.
    initial_gate_ids = {"CM-01", "CM-02", "CM-03", "CM-04", "CM-05"}
    initial_issues = []
    initial_has_bad = False
    for m in (core or []):
        if m.get("id") not in initial_gate_ids:
            continue
        st = m.get("status")
        if st not in ("bad", "warn"):
            continue
        label = "URGENTLY REVIEW" if st == "bad" else "REVIEW"
        initial_issues.append(f"{m.get('id')} {m.get('name')} -> {label}")
        initial_has_bad = initial_has_bad or (st == "bad")
    if initial_issues:
        gate_level = "high" if initial_has_bad else "warn"
        gate_msg = _bulleted(
            "Initial-stage gate failed: review these first before acting on later-stage findings:",
            initial_issues + [
                "Recommended action: complete or correct initial data quality/workshop/completeness items first, then reassess coverage and consistency metrics.",
            ],
        )
        findings.insert(0, (gate_level, gate_msg))

    # sort by severity so all HIGH findings appear before WARN (order within a
    # severity is preserved = rule order)
    order = {"high": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f[0], 3))
    return findings


# --------------------------------------------------------------------------- #
#  HTML rendering
# --------------------------------------------------------------------------- #
def render_html(data: dict, source_path: str, show_download: bool = True) -> str:
    proj = data["project"]
    s = data["summary"]
    findings = data["findings"]

    esc = html.escape  # escape all TRA-derived text before HTML injection

    def esc_multiline(v) -> str:
        """Escape text and preserve newline formatting in HTML output."""
        return esc(str(v)).replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")

    def _render_detail_entries(entries: list, css_class: str, icon: str) -> str:
        """Render metric detail entries.

        If an entry uses '\n  - ' bullet lines (from _bulleted), render those
        as separate list items for cleaner dropdown readability.
        """

        def _is_semicolon_issue_chain(text: str) -> bool:
            markers = (
                "CALC_UNDERIVABLE:",
                "CALC_MISMATCH:",
                "EXPOSURE_OVERRIDE_",
                "IMPACT_PG_MISMATCH:",
                "RR_CALC_STALE:",
                "issue=",
            )
            return ";" in text and any(m in text for m in markers)

        out = []
        for raw in entries:
            text = str(raw or "")
            lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            intro = []
            bullets = []
            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                if s.startswith("- "):
                    bullets.append(s[2:].strip())
                else:
                    intro.append(s)

            if bullets:
                intro_text = " ".join(intro)
                inner_bullets = "".join(
                    f"<li class='{css_class}'>• {esc_multiline(b)}</li>" for b in bullets
                )
                if intro_text:
                    out.append(
                        f"<li class='{css_class}'>{icon} {esc_multiline(intro_text)}"
                        f"<ul class='dlist sublist'>{inner_bullets}</ul></li>"
                    )
                else:
                    out.append(f"<ul class='dlist sublist'>{inner_bullets}</ul>")
            elif _is_semicolon_issue_chain(text):
                parts = [p.strip() for p in text.split(";") if p.strip()]
                if parts:
                    out.append(f"<li class='{css_class}'>{icon} {esc_multiline(parts[0])}</li>")
                    out.extend(f"<li class='{css_class}'>• {esc_multiline(p)}</li>" for p in parts[1:])
                else:
                    out.append(f"<li class='{css_class}'>{icon} {esc_multiline(text)}</li>")
            else:
                out.append(f"<li class='{css_class}'>{icon} {esc_multiline(text)}</li>")
        return "".join(out)

    colors = {"ok": "#1a7f37", "warn": "#bf8700", "bad": "#cf222e", "na": "#6e7681"}
    badges = {"ok": "GOOD", "warn": "REVIEW", "bad": "URGENTLY REVIEW", "na": "N/A"}
    finding_labels = {"high": "PRIO 1", "warn": "PRIO 2", "info": "INFO"}
    dims = data.get("dimension_status", [])

    # KPI cards
    cards = "".join(
        f"<div class='card'><div class='kpi'>{v}</div><div class='lbl'>{k}</div></div>"
        for k, v in [
            ("Assets", s["assets"]), ("Protection Goals", s["protection_goals"]),
            ("Threat Scenarios", s["threats"]), ("Security Zones", s["zones"]),
            ("Components", s["components"]), ("In / Out of scope", f"{s['in_scope']} / {s['out_of_scope']}"),
            ("Assumptions", s["assumptions"]), ("Interfaces", s["interfaces"]),
        ]
    )

    def _overall_from_dimensions(items: list[dict]) -> str:
        assessed_any = any(d.get("assessed", 0) > 0 for d in items)
        if not assessed_any:
            return "na"
        if any(d.get("status") == "bad" for d in items):
            return "bad"
        if any(d.get("status") == "warn" for d in items):
            return "warn"
        return "ok"

    overall_status = _overall_from_dimensions(dims)
    overall_assessed = sum(d.get("assessed", 0) for d in dims)
    overall_total = sum(d.get("total", 0) for d in dims)
    overall_bad = sum(d.get("bad", 0) for d in dims)
    overall_warn = sum(d.get("warn", 0) for d in dims)
    overall_color = colors.get(overall_status, colors["na"])

    dim_cards = "".join(
        f"<div class='dimcard' style='border-top-color:{colors[d['status']]}'>"
        f"<div class='dimname'>{esc(d['dim'])}</div>"
        f"<span class='badge' style='background:{colors[d['status']]}'>{badges[d['status']]}</span>"
        f"<div class='dimmeta'>{d['assessed']}/{d['total']} assessed</div>"
        f"<div class='dimmeta'>Urgently review: {d['bad']} &middot; Review: {d['warn']}</div>"
        f"</div>"
        for d in dims
    ) or "<div class='dimcard'><div class='dimname'>No dimension data available</div></div>"

    def _render_finding_message(msg: str) -> str:
        """Render finding text with metric-style bullet visuals when lines use '- '."""
        lines = str(msg or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        intro_lines = []
        bullet_lines = []
        for ln in lines:
            s = ln.strip()
            if not s:
                continue
            if s.startswith("- "):
                bullet_lines.append(s[2:].strip())
            else:
                intro_lines.append(s)

        if not bullet_lines:
            return f"<span class='fmsg'>{esc_multiline(msg)}</span>"

        intro_html = "<br>".join(esc_multiline(x) for x in intro_lines)
        bullets_html = "".join(
            f"<li class='d-info'>&#9432; {esc_multiline(x)}</li>" for x in bullet_lines
        )
        return (
            f"<span class='fmsg'>"
            f"<div class='fmsg-intro'>{intro_html}</div>"
            f"<ul class='dlist f-dlist'>{bullets_html}</ul>"
            f"</span>"
        )

    def _metric_decision_table_html(metric_id: str) -> str:
        """Render compact rule tables for high-review consistency metrics."""
        table_specs = {
            "CM-17": {
                "title": "CM-17 decision table (when it flags)",
                "rows": [
                    (
                        "Risk matrix coherence check",
                        "CALCRiskRating must match matrix value from impact + likelihood",
                        "risk matrix=false mismatch",
                    ),
                    (
                        "Rating rationale evidence",
                        "At least one rating rationale comment is present",
                        "no rating rationale comment",
                    ),
                    (
                        "Stored vs derived CALC fields",
                        "Stored CALC values equal recomputed values",
                        "CALC_MISMATCH",
                    ),
                    (
                        "Derivability of calculated values",
                        "Inputs are sufficient to derive dependent CALC values",
                        "CALC_UNDERIVABLE",
                    ),
                    (
                        "Exposure override quality",
                        "Override has justification and stays within zone baseline constraints",
                        "EXPOSURE_OVERRIDE_UNDOCUMENTED or EXPOSURE_OVERRIDE_EXCEEDS_ZONE",
                    ),
                ],
            },
            "CM-18": {
                "title": "CM-18 decision table (when it flags)",
                "rows": [
                    (
                        "Completed treatment + placeholder residual risk",
                        "Provide concrete residual risk (not No_Re_rating/NoRating/Incomplete)",
                        "RR_CALC_STALE and workflow inconsistency",
                    ),
                    (
                        "CALCrrRiskRating = No_Re_rating",
                        "isAcceptedByDefault = true and CALCstatus empty",
                        "accepted-by-default mismatch",
                    ),
                    (
                        "Residual risk present and threat not avoided",
                        "CALCrrRiskRating must be concrete (not empty/Incomplete)",
                        "missing residual rating",
                    ),
                    (
                        "Status-bearing path (avoided or re-rated)",
                        "CALCstatus follows treatmentProgress: Open=[Not started, In work], Passed=[Completed], Not passed=[On hold, Deferred]",
                        "CALCstatus mismatch",
                    ),
                    (
                        "Residual risk worsens vs base risk",
                        "Force expected CALCstatus to Not passed",
                        "acceptable-range violation",
                    ),
                ],
            },
            "CM-19": {
                "title": "CM-19 decision table (when it flags)",
                "rows": [
                    (
                        "Assessable sample size",
                        "At least 7 threats with CALCRiskRating not in NoRating/Incomplete",
                        "Not flagged; metric becomes not assessable when below threshold",
                    ),
                    (
                        "Severe concentration pattern",
                        "Dominant risk share stays below 90% or input diversity stays >=30%",
                        "BAD: concentration likely rubber-stamping",
                    ),
                    (
                        "Moderate concentration pattern",
                        "Dominant risk share stays below 80% or input diversity stays >=40%",
                        "WARN: suspicious concentration",
                    ),
                    (
                        "Rationale quality on dominant rating",
                        "No more than 60% of dominant-rating threats without rationale comments",
                        "WARN: dominant-rating rationale gap",
                    ),
                    (
                        "High concentration with high diversity",
                        "Treat as structurally plausible when diverse input combinations exist",
                        "No concentration flag from this condition",
                    ),
                ],
            },
        }
        spec = table_specs.get(metric_id)
        if not spec:
            return ""
        body = "".join(
            f"<tr><td>{esc(cond)}</td><td>{esc(expected)}</td><td>{esc(flag)}</td></tr>"
            for cond, expected, flag in spec["rows"]
        )
        return (
            "<div class='decision-wrap'>"
            f"<div class='decision-title'>{esc(spec['title'])}</div>"
            "<table class='decision-table'>"
            "<thead><tr><th>Condition</th><th>Expected</th><th>Flags if mismatch</th></tr></thead>"
            f"<tbody>{body}</tbody></table></div>"
        )

    finds = "".join(
        f"<li class='f-{lvl}'><span class='tag tag-{lvl}'>{finding_labels.get(lvl, lvl.upper())}</span> "
        f"{_render_finding_message(msg)}</li>"
        for lvl, msg in findings
    ) or "<li>No findings.</li>"

    dl_html = ('<a class="dlbtn" href="/download" download>&#8681; Download report (HTML)</a>'
               if show_download else "")

    # Core metrics (CM set), grouped by quality dimension.
    # Order rows by dimension (per DIMENSION_ORDER) then CM number so each
    # dimension forms one contiguous section (metrics are stored sorted by CM id,
    # which would otherwise interleave dimensions and repeat the section headers).
    core = data.get("core", [])
    _dim_rank = {d: i for i, d in enumerate(DIMENSION_ORDER)}
    core_grouped = sorted(core, key=lambda m: (_dim_rank.get(m["dim"], len(DIMENSION_ORDER)),
                                               int(re.sub(r"\D", "", m["id"]) or 0)))
    auto_color = {"Auto": "#1f6feb", "Semi-auto": "#8957e5"}
    core_rows = ""
    last_dim = None
    for m in core_grouped:
        c = colors[m["status"]]
        if m["dim"] != last_dim:
            core_rows += (f"<tr class='dimrow'><td colspan='3'>{m['dim']}</td></tr>")
            last_dim = m["dim"]
        det = m.get("detail")
        detail_html = ""
        if det and (det.get("fail") or det.get("pass") or det.get("sections") or det.get("groups")):
            fail = det.get("fail") or []
            ok_items = det.get("pass") or []
            info_items = det.get("info") or []
            items = _render_detail_entries(info_items, "d-info", "&#9432;")
            items += _render_detail_entries(fail, "d-miss", "&#10007;")
            items += _render_detail_entries(ok_items, "d-ok", "&#10003;")
            detail_summary = f"{len(fail)} flagged &middot; {len(ok_items)} ok &mdash; show readings"
            if m.get("name") == "Rating coherence & justification" and fail:
                detail_summary += " (risk matrix=false + correction guidance)"
            section_html = ""
            if m.get("id") == "CM-03" and det.get("sections"):
                section_blocks = []
                for sec in det.get("sections") or []:
                    sec_fail = sec.get("fail") or []
                    if not sec_fail:
                        continue
                    sec_ok = sec.get("pass") or []
                    sec_status = sec.get("status") or "na"
                    sec_color = colors.get(sec_status, colors["na"])
                    sec_items = _render_detail_entries(sec_fail, "d-miss", "&#10007;")
                    sec_summary = (
                        f"{esc(str(sec.get('name', 'Section')))} &middot; "
                        f"{len(sec_fail)} flagged &middot; "
                        f"{sec.get('num', 0)}/{sec.get('den', 0)} checks passed"
                    )
                    section_blocks.append(
                        f"<details class='detail subdetail'>"
                        f"<summary><span style='color:{sec_color};font-weight:700'>{sec_summary}</span></summary>"
                        f"<ul class='dlist'>{sec_items}</ul>"
                        f"</details>"
                    )
                section_html = "".join(section_blocks)
            group_html = ""
            if det.get("groups"):
                group_blocks = []
                for grp in det.get("groups") or []:
                    gfail = grp.get("fail") or []
                    gok = grp.get("pass") or []
                    ginfo = grp.get("info") or []
                    g_items = _render_detail_entries(ginfo, "d-info", "&#9432;")
                    g_items += _render_detail_entries(gfail, "d-miss", "&#10007;")
                    g_items += _render_detail_entries(gok, "d-ok", "&#10003;")
                    if ginfo and not gfail and not gok:
                        g_summary = (f"{esc(str(grp.get('title') or 'Group'))} &middot; "
                                     f"{len(ginfo)} entries")
                    else:
                        g_summary = (f"{esc(str(grp.get('title') or 'Group'))} &middot; "
                                     f"{len(gfail)} flagged &middot; {len(gok)} ok")
                    group_blocks.append(
                        f"<details class='detail subdetail'>"
                        f"<summary>{g_summary}</summary>"
                        f"<ul class='dlist'>{g_items}</ul>"
                        f"</details>"
                    )
                group_html = "".join(group_blocks)
            decision_html = _metric_decision_table_html(m.get("id"))
            detail_html = (
                f"<details class='detail'><summary>"
                f"{detail_summary}"
                f"</summary><ul class='dlist'>{items}</ul>{decision_html}{section_html}{group_html}</details>")
        ac = auto_color.get(m["auto"], "#6e7681")
        status_extra = ""
        bar_den = m.get("bar_den")
        bar_num = m.get("bar_num")
        bar_label = m.get("bar_label")
        if bar_den is None and m.get("status") != "na" and m.get("kind") != "count" and m.get("den") is not None:
            bar_den = m.get("den")
            bar_num = m.get("num")
            bar_label = bar_label or "Checked"
        if bar_den is not None:
            bar_num = int(bar_num or 0)
            bar_den = int(bar_den or 0)
            pct = int(round((bar_num / bar_den) * 100)) if bar_den else 0
            bar_label = str(bar_label or "Coverage")
            status_extra = (
                f"<div class='metricbar-wrap'>"
                f"<div class='metricbar-label'>{esc(bar_label)}: {bar_num} / {bar_den}</div>"
                f"<div class='metricbar'><span style='width:{pct}%;background:{c}'></span></div>"
                f"</div>"
            )
        core_rows += (
            f"<tr>"
            f"<td class='mid'>{m['id']}</td>"
            f"<td>{m['name']}"
            f"<span class='abadge' style='background:{ac}'>{m['auto']}</span>"
            + (f"<span class='abadge' style='background:#6e7681' title=\"Does not count toward "
               f"the dimension status rollup\">Informational</span>" if m.get("informational") else "")
            + f"<div class='note'>{esc(str(m.get('note', '-')))}</div>"
            f"{detail_html}</td>"
            f"<td><span class='badge' style='background:{c}'>{badges[m['status']]}</span>{status_extra}</td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TRA Quality Report</title>
<style>
 :root{{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#8b949e}}
 *{{box-sizing:border-box}}
 body{{margin:0;font-family:Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--txt)}}
 header{{padding:24px 32px;border-bottom:1px solid var(--line);background:var(--panel)}}
 h1{{margin:0;font-size:22px}}
 .subgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px 18px;margin-top:10px}}
 .subitem{{display:flex;gap:6px;align-items:baseline;min-width:0}}
 .subk{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.35px;white-space:nowrap}}
 .subv{{color:var(--txt);font-size:13px;overflow-wrap:anywhere}}
 main{{padding:24px 32px;max-width:1200px;margin:auto}}
 .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}}
 .card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center}}
 .kpi{{font-size:26px;font-weight:700}} .lbl{{color:var(--mut);font-size:12px;margin-top:4px}}
.summaryline{{font-size:13px;color:var(--txt);margin:2px 0 10px}}
.summaryline b{{color:var(--txt)}}
.summarygrid{{display:grid;grid-template-columns:1.2fr 2fr;gap:14px;margin:8px 0 14px}}
.overallcard{{background:#0d1117;border:1px solid var(--line);border-left:5px solid #6e7681;border-radius:10px;padding:14px}}
.overalltitle{{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}}
.overallstatus{{font-size:22px;font-weight:800;margin-top:4px}}
.overallmeta{{font-size:12px;color:var(--mut);margin-top:8px;line-height:1.5}}
.dimgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}}
.dimcard{{background:#0d1117;border:1px solid var(--line);border-top:4px solid #6e7681;border-radius:10px;padding:10px}}
.dimname{{font-size:13px;font-weight:700;margin-bottom:6px}}
.dimmeta{{font-size:11px;color:var(--mut);margin-top:6px}}
 .panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}}
 h2{{font-size:15px;margin:0 0 14px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
 th{{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
 .mid{{font-family:Consolas,monospace;color:#79c0ff;white-space:nowrap}}
 .note{{color:var(--mut);font-size:11px;margin-top:3px}}
 .abadge{{color:#fff;padding:1px 7px;border-radius:20px;font-size:9px;font-weight:700;
   margin-left:8px;vertical-align:middle}}
 .dimrow td{{background:#0d1117;color:#79c0ff;font-weight:700;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line)}}
 .detail{{margin-top:6px;font-size:12px}}
 .detail summary{{cursor:pointer;color:#79c0ff;font-size:11px}}
 .subdetail{{margin-top:6px;margin-left:8px}}
 .dlist{{margin:6px 0 0;padding:0}}
 .dlist li{{padding:5px 8px;border:0;border-left:3px solid var(--line);border-radius:4px;
   margin:4px 0;font-size:12px;background:#0d1117}}
 .dlist.sublist{{margin:8px 0 0 18px}}
 .dlist.sublist li{{margin-left:0;background:#111827;border-left-color:#6e7681}}
 .d-info{{border-left-color:#6e7681!important;color:#c9d1d9}}
 .d-miss{{border-left-color:#cf222e!important;color:#ffb3ba}}
 .d-ok{{border-left-color:#1a7f37!important;color:#8ddf9e}}
 .val{{white-space:nowrap;font-variant-numeric:tabular-nums}}
 .badge{{color:#fff;padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}}
 .metricbar-wrap{{margin-top:8px;min-width:120px}}
 .metricbar-label{{font-size:11px;color:var(--mut);margin-bottom:4px}}
 .metricbar{{height:7px;background:#0d1117;border:1px solid var(--line);border-radius:999px;overflow:hidden}}
 .metricbar span{{display:block;height:100%;border-radius:999px}}
 .decision-wrap{{margin-top:8px;border:1px solid var(--line);border-radius:8px;background:#0d1117;padding:8px}}
 .decision-title{{font-size:11px;color:#79c0ff;font-weight:700;margin:0 0 6px}}
 .decision-table{{width:100%;border-collapse:collapse;font-size:11px}}
 .decision-table th,.decision-table td{{padding:6px 7px;border-bottom:1px solid #21262d;vertical-align:top}}
 .decision-table th{{color:var(--mut);font-size:10px;letter-spacing:.35px;text-transform:uppercase}}
 ul{{list-style:none;padding:0;margin:0}}
 li{{padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:8px;font-size:13px}}
 .tag{{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;margin-right:8px}}
 .tag-high{{background:#cf222e;color:#fff}} .tag-warn{{background:#bf8700;color:#fff}}
 .f-high{{border-left:3px solid #cf222e}} .f-warn{{border-left:3px solid #bf8700}}
 .fmsg{{line-height:1.7}}
 .fmsg-intro{{margin-top:2px}}
 .f-dlist{{margin-top:8px}}
 .fmsg br + br{{display:none}}
 footer{{color:var(--mut);font-size:12px;padding:18px 32px;border-top:1px solid var(--line)}}
 .dlbtn{{position:absolute;top:24px;right:32px;background:#1f6feb;color:#fff;text-decoration:none;
   padding:9px 16px;border-radius:8px;font-size:13px;font-weight:600}}
 .dlbtn:hover{{background:#388bfd}}
 header{{position:relative}}
</style></head><body>
<header>
 <h1>TRA Quality Report &mdash; {esc(str(proj.get('TRAProjectName','(unknown project)')))}</h1>
 <div class="subgrid">
  <div class="subitem"><span class="subk">Target Area</span><span class="subv">{esc(str(s.get('target_area','-')))}</span></div>
  <div class="subitem"><span class="subk">Target</span><span class="subv">{esc(str(proj.get('targetOfAnalysis','-')))}</span></div>
  <div class="subitem"><span class="subk">Status</span><span class="subv">{esc(str(data.get('status','-')))}</span></div>
  <div class="subitem"><span class="subk">Source</span><span class="subv">{esc(os.path.basename(source_path))}</span></div>
 </div>
 {dl_html}
</header>
<main>
 <div class="panel" style="margin-bottom:24px">
     <h2>Assessment Summary</h2>
        <div class="summarygrid">
             <div class="overallcard" style="border-left-color:{overall_color}">
                 <div class="overalltitle">Overall</div>
                 <div class="overallstatus" style="color:{overall_color}">{badges[overall_status]}</div>
                 <div class="overallmeta">Assessed criteria: {overall_assessed}/{overall_total}<br>Urgently review: {overall_bad}<br>Review: {overall_warn}</div>
             </div>
             <div class="dimgrid">{dim_cards}</div>
         </div>
 </div>

 <div class="cards">{cards}</div>

 <div class="panel" style="margin-bottom:24px">
     <h2>Findings &amp; recommended actions</h2>
     <ul>{finds}</ul>
 </div>

 <div class="panel" style="margin-bottom:24px">
    <h2>Core metric assessment &mdash; grouped by quality dimension</h2>
    <div class="note" style="margin-bottom:8px"><b>Auto</b> = computable directly from the TRA JSON schema and values.
     <b>Semi-auto</b> = schema-based detection plus expert confirmation/interpretation before final judgement.</div>
        <div class="note" style="margin-bottom:12px"><b>How to read this:</b> each metric includes the check description and expandable readings.</div>
        <div class="note" style="margin-bottom:12px"><b>Caveat:</b> metrics that rely on text length (word counts) or keyword/regex
         matching (e.g. CM-11, CM-21, CM-22) are proxies for reviewability, not guarantees of content quality &mdash;
         a long or keyword-matching field is not automatically well-written, and a short one is not automatically
         wrong. Treat these results as prompts for reviewer judgement, not final verdicts.</div>
             <table><thead><tr><th>ID</th><th>Metric</th><th>Status</th></tr></thead>
  <tbody>{core_rows}</tbody></table>
 </div>
</main>
<footer>Generated by tra_quality_report.py &middot; refresh the page to recompute after editing the JSON.</footer>
</body></html>"""


def analyze_tra_quality(tra: dict) -> dict:
    """Compatibility entrypoint used by tra_tool.py."""
    return analyze(tra)


def cli_usage_help() -> str:
    return (
        "Examples:\n"
        "  python tra_quality_report.py <path-to-tra.json>\n"
        "  python tra_quality_report.py <path-to-tra.json> --html-out report.html\n"
        "  python tra_quality_report.py <path-to-tra.json> --metrics-out metrics.json\n"
        "  python tra_quality_report.py <path-to-tra.json> --metrics-out .\\reports\\\n"
        "  python tra_quality_report.py <path-to-tra.json> --learn-good-threats\n"
        "  python tra_quality_report.py --calibrate-thresholds\n"
        "  python tra_quality_report.py --calibrate-thresholds .\\Calibration_Corpus\\"
    )


def resolve_output_path(user_path: str | None, input_json: str, suffix: str) -> str:
    """Resolve output file path from user input.

    - None: use '<input-json-dir>/TRA-Quality report/<input-json-filename>/<input_basename><suffix>'.
    - Existing directory: place default file name inside that directory.
    - Path ending with a slash/backslash: treat as directory and create it.
    - Otherwise: treat as a file path.
    """
    default_name = os.path.splitext(os.path.basename(input_json))[0] + suffix
    default_dir = os.path.join(
        os.path.dirname(os.path.abspath(input_json)),
        "TRA-Quality report",
        os.path.basename(input_json),
    )
    if not user_path:
        return os.path.join(default_dir, default_name)

    candidate = os.path.normpath(user_path)
    if os.path.isdir(candidate):
        return os.path.join(candidate, default_name)

    if user_path.endswith(("/", "\\")):
        os.makedirs(candidate, exist_ok=True)
        return os.path.join(candidate, default_name)

    return candidate


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generate a TRA quality report (HTML + JSON metrics) for any TRA JSON "
                    "(Software-component or System-deployment schema).",
        epilog=cli_usage_help(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("json", nargs="?",
                    help="Path to a TRA JSON export (required unless --calibrate-thresholds is used "
                        "on its own; either schema variant).")
    ap.add_argument("--html-out", metavar="PATH",
                    help="Write HTML report to PATH. PATH may be a file path or a directory "
                        "(default location: <input-dir>/TRA-Quality report/<input-json-filename>/"
                        "<input>_quality_report.html).")
    ap.add_argument("--metrics-out", metavar="PATH",
                    help="Write JSON metrics to PATH. PATH may be a file path or a directory "
                        "(default location: <input-dir>/TRA-Quality report/<input-json-filename>/"
                        "<input>_quality_metrics.json).")
    ap.add_argument("--learn-good-threats", action="store_true",
                    help="Heuristic CM-14 learning mode: append high-confidence specific threats "
                         "from this TRA run to Threat_Corpus/SampleThreatScenarios.json "
                         "(deduplicated by wording).")
    ap.add_argument("--calibrate-thresholds", metavar="DIR", nargs="?",
                    const=CALIBRATION_CORPUS_DIR, default=None,
                    help="Data-driven threshold calibration: scan a labeled corpus of whole TRA "
                        "JSON files (DIR/good/*.json, DIR/poor/*.json; default DIR is "
                        "Calibration_Corpus/ next to this script) and write suggested values for "
                        "OVERVIEW_MIN_WORDS, SCOPE_DESC_MIN_WORDS, SPECIFICITY_PASS_THRESHOLD and "
                        "JACCARD_DUP_THRESHOLD to DIR/calibration_report.json. Can be used without "
                        "the positional 'json' argument. Nothing is applied automatically.")
    args = ap.parse_args(argv)

    if args.calibrate_thresholds is not None and args.json is None:
        try:
            report, out_path = calibrate_thresholds(args.calibrate_thresholds)
        except OSError as exc:
            sys.exit(f"Failed to write calibration report to {args.calibrate_thresholds}\n  {exc}")
        print(f"Threshold calibration: scanned {report['files_scanned']['good']} good / "
              f"{report['files_scanned']['poor']} poor labeled TRA file(s) under "
              f"{report['corpus_dir']}")
        for r in report["results"]:
            note = f" ({r['note']})" if r.get("note") else ""
            print(f"  {r['metric']}: current={r['current_threshold']} "
                  f"suggested={r['suggested_threshold']}{note}")
        print(f"\nCalibration report written to {out_path}")
        return

    if args.json is None:
        ap.error("the following arguments are required: json (unless --calibrate-thresholds is "
                 "used on its own)")

    if not os.path.isfile(args.json):
        sys.exit(f"TRA JSON not found: {args.json}")

    # validate + print a console summary on startup
    try:
        with open(args.json, "r", encoding="utf-8") as fh:
            tra = json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"Not a valid JSON file: {args.json}\n  {exc}")
    if not isinstance(tra, dict):
        sys.exit(f"Unexpected JSON structure in {args.json}: top level is not an object.")
    comps, _ = components_of(tra)
    if not any(k in tra for k in ("Assets", "ProtectionGoals", "ThreatScenarios")) and not comps:
        print(f"WARNING: {os.path.basename(args.json)} does not look like a TRA export "
              "(no Assets / ProtectionGoals / ThreatScenarios / components). "
              "Computing on whatever is present.")
    data = analyze(tra)
    print(f"Loaded {os.path.basename(args.json)} | "
          f"target area: {data['summary'].get('target_area', '-')} | "
          f"{data['summary']['threats']} threats, "
          f"{data['summary']['protection_goals']} protection goals, "
          f"{data['summary']['assets']} assets")

    print("\nCore metrics (CM set):")
    last_dim = None
    for m in data.get("core", []):
        if m["dim"] != last_dim:
            print(f"  -- {m['dim']} --")
            last_dim = m["dim"]
        print(f"  {m['id']:6} {m.get('evidence','-'):<22} [{m['status'].upper()}]  "
              f"{m['name']} ({m['auto']})")

    out_html = resolve_output_path(args.html_out, args.json, "_quality_report.html")
    out_metrics = resolve_output_path(args.metrics_out, args.json, "_quality_metrics.json")

    os.makedirs(os.path.dirname(out_html) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(out_metrics) or ".", exist_ok=True)

    try:
        with open(out_html, "w", encoding="utf-8") as fh:
            fh.write(render_html(data, args.json, show_download=False))
    except OSError as exc:
        sys.exit(f"Invalid --html-out path: {out_html}\n  {exc}")

    try:
        with open(out_metrics, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError as exc:
        sys.exit(f"Invalid --metrics-out path: {out_metrics}\n  {exc}")

    if args.learn_good_threats:
        try:
            added, considered, corpus_file = learn_good_threats(tra)
            print(f"Heuristic good-threat learning: added {added} of {considered} "
                  f"considered candidate(s) to {corpus_file}")
        except OSError as exc:
            sys.exit(f"Failed to update good-threat corpus: {GOOD_THREATS_FILE}\n  {exc}")

    if args.calibrate_thresholds is not None:
        try:
            report, out_path = calibrate_thresholds(args.calibrate_thresholds)
            print(f"Threshold calibration: scanned {report['files_scanned']['good']} good / "
                  f"{report['files_scanned']['poor']} poor labeled TRA file(s) under "
                  f"{report['corpus_dir']}; report written to {out_path}")
        except OSError as exc:
            sys.exit(f"Failed to write calibration report to {args.calibrate_thresholds}\n  {exc}")

    print(f"\nHTML report written to {out_html}")
    print(f"Metrics JSON written to {out_metrics}")


if __name__ == "__main__":
    main()

