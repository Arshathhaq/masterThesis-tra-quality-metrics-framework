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
import sys
import html

DEFAULT_JSON = ''
# Reference corpus of "known-good" threat scenarios (CM-17). Every
# ThreatScenario found in any TRA JSON in this folder contributes to the
# good-threat vocabulary that real, product-specific threats are compared
# against by the rule-based specificity check.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_good_threats_dir():
    """Locate the good-threat reference corpus.

    Supports both the packaged repository layout (``<repo>/data/
    Good_TRA_Threat_List`` while this script lives in ``<repo>/src``) and a
    flat layout where the corpus sits next to this script.
    """
    candidates = [
        os.path.join(os.path.dirname(_SCRIPT_DIR), "data", "Good_TRA_Threat_List"),
        os.path.join(_SCRIPT_DIR, "Good_TRA_Threat_List"),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


GOOD_THREATS_DIR = _find_good_threats_dir()

# Words that mark an unfinished / placeholder entry (CM-04). The bare word
# "test" was removed: it collides with legitimate content ("penetration test"
# is a positive evidence signal for CM-28, plus "test environment", "regression
# test", ...). Placeholder-specific forms ("test entry/data/xxx/ttt") are kept.
PLACEHOLDER_PATTERNS = [
    r"QUESTION", r"\?\?", r"\bTBD\b", r"\bTODO\b", r"\bFIXME\b", r"\bXXX\b",
    r"\bplaceholder\b", r"\blorem\b", r"\bfill[\s_-]?in\b",
    r"\bto\s+be\s+(defined|done|determined|filled|completed|added)\b",
    r"\btest\s*(entry|data|value|text|xxx|ttt)\b", r"\bttt+\b", r"\bxxx+\b",
]


# --------------------------------------------------------------------------- #
#  Metric computation
# --------------------------------------------------------------------------- #
def pct(num: int, den: int) -> float:
    return round((num / den) * 100, 1) if den else 0.0


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
            comms.extend(val)
    return comms


def analyze(tra: dict) -> dict:
    assets = tra.get("Assets", [])
    pgs = tra.get("ProtectionGoals", [])
    threats = tra.get("ThreatScenarios", [])
    zones = tra.get("SecurityZones", [])
    comps, component_key = components_of(tra)
    assumptions = tra.get("Assumptions", [])

    asset_ids = {a.get("asset_id") for a in assets}
    pg_ids = {p.get("pg_id") for p in pgs}
    zone_ids = {z.get("zone_id") for z in zones}
    assumption_ids = {a.get("assumption_id") for a in assumptions}

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
    threat_pgs = {t.get("threatscenario_id"): [p.get("pg_id") for p in (t.get("ProtectionGoals") or [])]
                  for t in threats if t.get("threatscenario_id")}

    # interfaces actually used as an attack surface
    used_ifaces = {i for i in threat_iface.values() if i}

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
                target_iface=tiface))
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
    for c in [c for c in comps if c.get("scope") == "In_Scope"]:
        sid = c.get("subUnit_id")
        ifs = comp_ifaces.get(sid, set())
        reached = ifs & used_ifaces
        comm = comp_comm_reach.get(sid, [])
        if reached or comm:
            via = []
            if reached:
                via.append("interface " + ", ".join(sorted(reached)))
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

    # protection goals linked to a threat (either direction)
    pgs_with_threat = set()
    for t in threats:
        for p in (t.get("ProtectionGoals") or []):
            if p.get("pg_id"):
                pgs_with_threat.add(p["pg_id"])
    for p in pgs:
        if p.get("ThreatScenarios"):
            pgs_with_threat.add(p.get("pg_id"))

    # assets represented by at least one protection goal
    assets_covered = {(p.get("Asset") or {}).get("asset_id") for p in pgs}
    assets_covered.discard(None)

    # zone exposures
    zone_exposures = []
    for z in zones:
        for ze in z.get("ZoneExposures", []) or []:
            zone_exposures.append(ze)

    # placeholder density (CM-04) - also track which patterns matched for better diagnostics
    blob = collect_text(tra)
    placeholder_hits = sum(len(re.findall(p, blob, flags=re.IGNORECASE)) for p in PLACEHOLDER_PATTERNS)
    # Track which patterns were found (for enhanced reporting)
    placeholder_matches = {}
    for pattern in PLACEHOLDER_PATTERNS:
        matches = re.findall(pattern, blob, flags=re.IGNORECASE)
        if matches:
            placeholder_matches[pattern] = len(matches)

    n_assets, n_pgs, n_threats = len(assets), len(pgs), len(threats)

    # human-readable labels for per-item readings
    clab = lambda c: f"{c.get('subUnit_id')} ({c.get('name')})"
    plab = lambda p: f"{p.get('pg_id')} ({p.get('name')})"
    tlab = lambda t: f"{t.get('threatscenario_id')} ({t.get('name')})"
    alab = lambda a: f"{a.get('assumption_id')} ({a.get('name')})"
    aslab = lambda a: f"{a.get('asset_id')} ({a.get('name')})"

    # ----------------------------------------------------------------------- #
    #  Interview-derived Core metrics (CM set, from the metric catalog).
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
        communications=communications,
        m2_linked=m2_linked, m2_missing=m2_missing, placeholder_hits=placeholder_hits,
        clab=clab, tlab=tlab, plab=plab, alab=alab, aslab=aslab)

    findings = build_findings(tra, assets, pgs, threats, assets_covered, pgs_with_threat,
                              comps_with_threat, in_scope, assumptions, core=core)

    selection = str((tra.get("Project", {}).get("Config", {}) or {}).get("selection") or "")
    target_area = {
        "Software": "Software Component development",
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
                scorecard=compute_scorecard(core),
                project=tra.get("Project", {}), status=tra.get("status"))


def grade(m: dict) -> str:
    """Traffic-light status for a metric."""
    if m.get("kind") == "count":
        return "ok" if m["num"] == 0 else ("warn" if m["num"] <= 5 else "bad")
    v = m["value"]
    if m["better"] == "low":
        return "ok" if v <= 10 else ("warn" if v <= 40 else "bad")
    return "ok" if v >= 90 else ("warn" if v >= 60 else "bad")


# --------------------------------------------------------------------------- #
#  Interview-derived Core metric set (CM-xx) - computed structurally from the
#  TRA JSON, so it works for BOTH target areas (Software / Deployment).
# --------------------------------------------------------------------------- #
# Risk & Likelihood matrices for the rating-coherence check (final catalog
# CM-20). These reproduce the project's TRA rating matrices exactly, so the
# stored CALCRiskRating / CALCLikelihood can be recomputed and verified cell by
# cell (not approximated). Label keys are lower-cased; unknown labels skip the
# check for that threat.
#
# Risk = f(Impact, Likelihood)   - rows: impact, cols: likelihood
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


def load_good_threat_vocab():
    """Build the good-threat vocabulary (CM-17) from every TRA JSON in
    GOOD_THREATS_DIR.

    Returns (vocab_set, idf_map, n_good_threats); cached after first call.
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
    if os.path.isdir(GOOD_THREATS_DIR):
        for fn in sorted(os.listdir(GOOD_THREATS_DIR)):
            if not fn.lower().endswith(".json"):
                continue
            try:
                with open(os.path.join(GOOD_THREATS_DIR, fn), "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(doc, dict):
                continue
            for t in (doc.get("ThreatScenarios") or []):
                if not isinstance(t, dict):
                    continue
                if not is_good_threat_entry(t):
                    continue
                n_good += 1
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
    _GOOD_VOCAB_CACHE = (vocab, idf, n_good)
    return _GOOD_VOCAB_CACHE

KEYWORD_ONLY_MIN_WORDS = 6   # CM-17/CM-25: a real description has >= this many words
ACTOR_RE = re.compile(r"attacker|adversary|insider|malicious|threat actor|user", re.IGNORECASE)

OVERVIEW_MIN_WORDS = 20       # CM-13: a usable system overview has >= this many words
SCOPE_DESC_MIN_WORDS = 5      # CM-15: a real component description has >= this many words
JACCARD_DUP_THRESHOLD = 0.6   # CM-19/CM-24: token-Jaccard above which two threats are near-duplicates
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
# CM-27: authority-approval / sign-off field-name markers.
APPROVAL_RE = re.compile(r"approv|sign[\s_-]?off|signed[\s_-]?off|reviewed[\s_-]?by|"
                         r"authoriz|released[\s_-]?by", re.IGNORECASE)
# CM-28: external-evidence artifact references for the Known-Deficiencies block.
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
    "Relevant-role / workshop participation": "CM-01",
    "Living-document maintenance (updated since creation)": "CM-02",
    "Mandatory field/section completion": "CM-03",
    "Placeholder / unfinished-entry detection": "CM-04",
    "Assumption validation ratio": "CM-05",
    "Component coverage by threats": "CM-06",
    "Interface coverage by threats": "CM-07",
    "External / network-facing interface coverage": "CM-08",
    "Communication coverage by threats": "CM-09",
    "Protection-goal coverage in threat analysis": "CM-10",
    "Asset coverage / asset-to-protection-goal mapping": "CM-11",
    "Asset mapping to components / communications": "CM-12",
    "System-overview / description presence": "CM-13",
    "Out-of-scope boundaries": "CM-14",
    "Scope clarity by descriptions": "CM-15",
    "No-threat / empty-analysis red flag": "CM-16",
    "Threat specificity vs good-threat list (rule-based NLP)": "CM-17",
    "Protection-goal C/I/A balance": "CM-18",
    "Rating consistency across similar threats": "CM-19",
    "Rating coherence & justification": "CM-20",
    "Risk-treatment / handling decision coverage": "CM-21",
    "Rating-distribution / rubber-stamping detector": "CM-22",
    "Assumption usage / linkage by type": "CM-23",
    "Duplicate / similar-threat detection": "CM-24",
    "Threat-structure completeness (semantic)": "CM-25",
    "Vagueness / imprecision reduction": "CM-26",
    "Authority-approval presence": "CM-27",
    "Known-deficiency evidence references": "CM-28",
}


def compute_core_metrics(tra, *, assets, pgs, threats, zones, comps,
                         in_scope, assumptions, logical_iface_ids, used_ifaces,
                         comps_with_threat, pgs_with_threat, assets_covered,
                         iface_owner, iface_name, communications,
                         m2_linked, m2_missing, placeholder_hits,
                         clab, tlab, plab, alab, aslab):
    n_threats = len(threats)

    def _ph(obj):
        b = collect_text(obj)
        return sum(len(re.findall(p, b, flags=re.IGNORECASE)) for p in PLACEHOLDER_PATTERNS)

    core = []

    # ---- Formal completeness ------------------------------------------------
    # CM-03 mandatory section presence. Each required section must exist AND
    # carry actual content (e.g. ThreatScenarios has >= 1 threat, IntendedOp
    # carries descriptive text) - a section-level gate, not a per-field ratio.
    def _has_content(v):
        if v is None:
            return False
        if isinstance(v, str):
            return bool(v.strip())
        if isinstance(v, list):
            return len(v) > 0
        if isinstance(v, dict):
            return any(_has_content(x) for x in v.values())
        return True  # booleans / numbers count as provided

    req_sections = [("Assets", assets), ("ProtectionGoals", pgs), ("ThreatScenarios", threats),
                    ("SecurityZones", zones), ("Components", comps), ("Assumptions", assumptions),
                    ("Project", tra.get("Project")), ("IntendedOp", tra.get("IntendedOp"))]
    sec_pass, sec_fail = [], []
    for label, val in req_sections:
        if _has_content(val):
            sec_pass.append(label)
        else:
            sec_fail.append(f"{label} - section missing or empty")
    core.append(dict(id="CM-03", name="Mandatory field/section completion",
                     dim="Formal Completeness", auto="Auto",
                     refs="I1-Q6,Q20; I2-Q10,Q21",
                     note="every required section present and carrying content "
                          "(e.g. >=1 threat scenario, non-empty system overview)",
                     num=len(sec_pass), den=len(req_sections), better="high",
                     detail={"pass": sec_pass, "fail": sec_fail}))

    # CM-04 placeholder / unfinished-entry detection
    ph_fail = []
    for t in threats:
        h = _ph(t)
        if h:
            ph_fail.append(f"{tlab(t)} - {h} placeholder occurrence(s)")
    for a in assumptions:
        h = _ph(a)
        if h:
            ph_fail.append(f"{alab(a)} - {h} placeholder occurrence(s)")
    core.append(dict(id="CM-04", name="Placeholder / unfinished-entry detection",
                     dim="Formal Completeness", auto="Auto", refs="I1-Q6",
                     note="QUESTION / ?? / TBD / TODO / FIXME / placeholder occurrences (lower is better)",
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
                     refs="Maturity model (Assumptions / Validation)",
                     note="assumption explicitly flagged as validated",
                     num=len(val_pass), den=max(len(assumptions), 1), better="high",
                     detail={"pass": val_pass, "fail": val_fail}))

    # ---- Coverage -----------------------------------------------------------
    # CM-06 component coverage by threats
    core.append(dict(id="CM-06", name="Component coverage by threats", dim="Coverage", auto="Auto",
                     refs="I1-Q10,Q17; I3-Q11,Q12; I5-Q8",
                     note="in-scope component reached by >=1 threat (interface or communication)",
                     num=sum(1 for c in in_scope if c.get("subUnit_id") in comps_with_threat),
                     den=len(in_scope), better="high",
                     detail={"pass": m2_linked, "fail": m2_missing}))
    # CM-07 interface coverage by threats
    cov6 = {"pass": [], "fail": []}
    for i in sorted(logical_iface_ids):
        iname = iface_name.get(i)
        if iname:
            lbl = f"{i} ({iname}; owner {iface_owner.get(i)})"
        else:
            lbl = f"{i} (owner {iface_owner.get(i)})"
        if i in used_ifaces:
            cov6["pass"].append(lbl)
        else:
            cov6["fail"].append(f"{lbl} - never used as an AttackInterface")
    core.append(dict(id="CM-07", name="Interface coverage by threats", dim="Coverage", auto="Auto",
                     refs="I1-Q9; I3-Q11,Q12; I5-Q8",
                     note="Logical interfaces used as an attack surface",
                     num=len(logical_iface_ids & used_ifaces), den=len(logical_iface_ids),
                     better="high", detail=cov6))

    # CM-08 external / network-facing interface coverage
    ext = _external_interface_ids(comps, zones)
    if ext:
        used_ext = ext & used_ifaces
        ed = {"pass": [f"{i} - covered" for i in sorted(used_ext)],
              "fail": [f"{i} - external interface never attacked" for i in sorted(ext - used_ifaces)]}
        core.append(dict(id="CM-08", name="External / network-facing interface coverage",
                         dim="Coverage", auto="Auto", refs="I1-Q9,Q19",
                         note="network-facing interfaces used as an attack surface",
                         num=len(used_ext), den=len(ext), better="high", detail=ed))
    else:
        core.append(dict(id="CM-08", name="External / network-facing interface coverage",
                         dim="Coverage", auto="Auto", refs="I1-Q9,Q19",
                         note="no network-facing interfaces declared (n/a)",
                         better="high", status="na",
                         detail={"pass": ["no external interfaces to cover"], "fail": []}))

    # CM-09 communication coverage by threats
    comm_edges = [cm for cm in communications if cm.get("target_iface")]
    if comm_edges:
        cc = {"pass": [], "fail": []}
        for cm in comm_edges:
            lbl = f"{cm.get('id')} ({cm.get('name')}) -> {cm.get('target_iface')}"
            if cm["target_iface"] in used_ifaces:
                cc["pass"].append(lbl)
            else:
                cc["fail"].append(f"{lbl} - target interface never attacked")
        core.append(dict(id="CM-09", name="Communication coverage by threats", dim="Coverage",
                         auto="Auto", refs="I1-Q9,Q20; I3-Q11,Q12; I5-Q8",
                         note="each inter-component communication whose target interface "
                              "is used as an attack surface",
                         num=sum(1 for cm in comm_edges if cm["target_iface"] in used_ifaces),
                         den=len(comm_edges), better="high", detail=cc))
    else:
        core.append(dict(id="CM-09", name="Communication coverage by threats", dim="Coverage",
                         auto="Auto", refs="I1-Q9,Q20; I3-Q11,Q12; I5-Q8",
                         note="no inter-component communications declared (n/a)",
                         better="high", status="na",
                         detail={"pass": ["no communications to cover"], "fail": []}))

    # CM-10 protection-goal coverage in threat analysis (non-negligible goals)
    cov8 = {"pass": [], "fail": []}
    relevant_pgs = [p for p in pgs
                    if str(p.get("impactLevel", "")).strip().lower() != "negligible"]
    for p in relevant_pgs:
        if p.get("pg_id") in pgs_with_threat:
            cov8["pass"].append(plab(p))
        else:
            cov8["fail"].append(f"{plab(p)} - no threat scenario references it")
    for p in pgs:
        if p not in relevant_pgs:
            cov8["pass"].append(f"{plab(p)} - negligible impact (not required)")
    core.append(dict(id="CM-10", name="Protection-goal coverage in threat analysis", dim="Coverage",
                     auto="Auto", refs="I1-Q9,Q10; I3-Q11",
                     note="every non-negligible protection goal linked to >=1 threat",
                     num=sum(1 for p in relevant_pgs if p.get("pg_id") in pgs_with_threat),
                     den=max(len(relevant_pgs), 1), better="high", detail=cov8))
    # CM-11 asset coverage / asset-to-protection-goal mapping
    # build asset_id -> [covering protection goals] so the pass reading can name
    # exactly which protection goal(s) represent each asset (not just "covered")
    pgs_covering_asset = {}
    for p in pgs:
        aid = (p.get("Asset") or {}).get("asset_id")
        if aid:
            pgs_covering_asset.setdefault(aid, []).append(p)
    cov9 = {"pass": [], "fail": []}
    for a in assets:
        aid = a.get("asset_id")
        if aid in assets_covered:
            covering = pgs_covering_asset.get(aid, [])
            names = ", ".join(plab(p) for p in covering) or "unknown protection goal"
            cov9["pass"].append(f"{aslab(a)} - covered by {names}")
        else:
            cov9["fail"].append(f"{aslab(a)} - no protection goal covers it")
    core.append(dict(id="CM-11", name="Asset coverage / asset-to-protection-goal mapping", dim="Coverage",
                     auto="Auto", refs="I3-Q5,Q11",
                     note="every asset represented by >=1 protection goal",
                     num=sum(1 for a in assets if a.get("asset_id") in assets_covered),
                     den=len(assets), better="high", detail=cov9))

    # CM-12 asset mapping to components / communications (traceability)
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
    core.append(dict(id="CM-12", name="Asset mapping to components / communications",
                     dim="Coverage", auto="Auto", refs="I3-Q5,Q12",
                     note="each asset traceable to a system component or communication "
                          "(asset -> protection goal -> threat -> attacked interface)",
                     num=len(am_pass), den=max(len(assets), 1), better="high",
                     detail={"pass": am_pass, "fail": am_fail}))

    # CM-13 system-overview / description presence
    ov_text = collect_text(tra.get("IntendedOp"))
    for key, val in tra.items():
        if "Overview" in key:
            ov_text += " " + collect_text(val)
    ov_words = len(re.findall(r"\w+", ov_text))
    ov_ok = ov_words >= OVERVIEW_MIN_WORDS
    core.append(dict(id="CM-13", name="System-overview / description presence", dim="Comprehensibility",
                     auto="Semi-auto", refs="I2-Q3,Q5,Q18; I3-Q5",
                     note=f"intended-operation / system-overview text has >= {OVERVIEW_MIN_WORDS} words",
                     num=1 if ov_ok else 0, den=1, better="high",
                     detail={"pass": [f"system overview has {ov_words} word(s)"] if ov_ok else [],
                             "fail": [] if ov_ok else
                                     [f"system overview empty or too short ({ov_words} word(s))"]}))

    # CM-14 out-of-scope boundaries (scope-exclusion justification proxy)
    oos = [c for c in comps if c.get("scope") and c.get("scope") != "In_Scope"]
    if oos:
        just_keys = ("scopeComment", "scopeJustification", "outOfScopeReason", "justification",
                     "comment", "description")
        jp, jf = [], []
        for c in oos:
            j = next((c.get(k) for k in just_keys if c.get(k)), None)
            (jp if j else jf).append(clab(c) if j else f"{clab(c)} - out of scope without justification")
        core.append(dict(id="CM-14", name="Out-of-scope boundaries", dim="Coverage",
                         auto="Semi-auto", refs="I1-Q3; I2-Q4; I4-Q5,Q10",
                         note="out-of-scope components carry an explicit justification",
                         num=len(jp), den=len(oos), better="high", detail={"pass": jp, "fail": jf}))
    else:
        core.append(dict(id="CM-14", name="Out-of-scope boundaries", dim="Coverage",
                         auto="Semi-auto", refs="I1-Q3; I2-Q4; I4-Q5,Q10",
                         note="no out-of-scope components to justify (n/a)", status="na",
                         better="high", detail={"pass": ["nothing excluded"], "fail": []}))

    # CM-15 scope clarity by descriptions (component descriptive adequacy)
    sd_pass, sd_fail = [], []
    for c in comps:
        desc = c.get("description") or ""
        w = len(re.findall(r"\w+", desc))
        if w >= SCOPE_DESC_MIN_WORDS:
            sd_pass.append(f"{clab(c)} - {w} word(s)")
        else:
            sd_fail.append(f"{clab(c)} - description missing or too short ({w} word(s))")
    core.append(dict(id="CM-15", name="Scope clarity by descriptions", dim="Comprehensibility",
                     auto="Semi-auto", refs="I1-Q3; I2-Q4; I4-Q5,Q11",
                     note=f"each component carries a descriptive scope text (>= {SCOPE_DESC_MIN_WORDS} words)",
                     num=len(sd_pass), den=max(len(comps), 1), better="high",
                     detail={"pass": sd_pass, "fail": sd_fail}))

    # CM-16 no-threat / empty-analysis red flag
    core.append(dict(id="CM-16", name="No-threat / empty-analysis red flag", dim="Coverage", auto="Auto",
                     refs="I4-Q10", note="a TRA with zero threats is a serious red flag",
                     num=1 if n_threats else 0, den=1, better="high",
                     detail={"pass": [f"{n_threats} threat scenarios present"] if n_threats else [],
                             "fail": [] if n_threats else ["no threat scenarios defined at all"]}))

    # CM-17 threat specificity vs good-threat list (rule-based NLP).
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
    good_vocab, good_idf, n_good = load_good_threat_vocab()
    p16b, f16b = [], []
    for t in threats:
        desc = t.get("attackActionDesc") or ""
        text = f"{t.get('name', '')} {desc}".lower()
        toks = tokenize_security_terms(text)
        specific = (toks & good_vocab) if good_vocab else set()
        concrete_strength = sum(good_idf.get(w, 0.0) for w in specific)
        concrete_ok = (len(specific) >= CONCRETE_MIN_TERMS
                       and concrete_strength >= CONCRETE_STRENGTH_MIN)
        has_iface = bool((t.get("AttackInterface") or {}).get("interface_id"))
        words = len(re.findall(r"\w+", desc))
        long_enough = words >= KEYWORD_ONLY_MIN_WORDS
        has_actor = bool(ACTOR_RE.search(desc))
        vague_hits = len(set(mo.group(0).lower() for mo in VAGUE_RE.finditer(desc)))
        # heuristic specificity score (0..1). Weights make distinctive wording a
        # necessary ingredient: a component/interface link plus mere length
        # (0.30 + 0.30 = 0.60) no longer clears SPECIFICITY_PASS_THRESHOLD on its
        # own, so a verbose-but-generic (keyword-stuffed) threat is flagged even
        # when it is structurally linked.
        score = 0.0
        if has_iface:
            score += 0.30
        if concrete_ok or (not good_vocab and long_enough and has_actor):
            score += 0.40
        if long_enough and vague_hits < 2:
            score += 0.30
        if score >= SPECIFICITY_PASS_THRESHOLD and (has_iface or concrete_ok):
            shown = ", ".join(sorted(specific, key=lambda w: -good_idf.get(w, 0.0))[:6]) or "structural"
            p16b.append(f"{tlab(t)} - specific ({score:.0%}; concrete terms: {shown})")
        else:
            why = []
            if not has_iface:
                why.append("no component/interface link")
            if not concrete_ok:
                why.append("weak concrete language vs good-threat list")
            if not long_enough:
                why.append(f"only {words} word(s)")
            if vague_hits >= 2:
                why.append("vague wording")
            # Extract snippet for narrative evidence (first 70 chars + context)
            desc_snippet = desc[:70] if desc else "(no description)"
            if len(desc) > 70:
                desc_snippet += "..."
            f16b.append(f"{tlab(t)} - generic / weakly-specific ({'; '.join(why)}) | snippet: {desc_snippet}")
    core.append(dict(id="CM-17", name="Threat specificity vs good-threat list (rule-based NLP)",
                     dim="Consistency & Traceability", auto="Semi-auto", refs="I3-Q6,Q9,Q13; I4-Q6,Q13; I5-Q14",
                     note=(f"each threat compared against {n_good} good threats "
                           f"({len(good_vocab)}-term IDF-weighted vocabulary); specific AND component/interface-linked"),
                     num=len(p16b), den=max(n_threats, 1), better="high",
                     detail={"pass": p16b, "fail": f16b}))

    # CM-18 protection-goal C/I/A balance
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
    core.append(dict(id="CM-18", name="Protection-goal C/I/A balance", dim="Consistency & Traceability",
                     auto="Auto", refs="I1-Q9",
                     note="protection goals span Confidentiality, Integrity and Availability",
                     num=len(cia_ok), den=3, better="high",
                     detail={"pass": [f"{c} - {cia_present[c]} protection goal(s)" for c in cia_ok],
                             "fail": [f"{c} - no protection goal of this type" for c in cia_missing]}))

    # ---- Consistency & Traceability ----------------------------------------
    # similar-threat clustering (token-Jaccard proxy) - shared by CM-19 and CM-24
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
    similar_pairs = inconsistent = 0
    f18, p18, dup_pairs = [], [], []
    for i in range(len(toks)):
        for j in range(i + 1, len(toks)):
            a, ta = toks[i]; b, tb = toks[j]
            if not ta or not tb:
                continue
            jac = len(ta & tb) / len(ta | tb)
            if jac >= JACCARD_DUP_THRESHOLD:
                similar_pairs += 1
                # Include threat descriptions to help users understand the similarity
                rich_desc = f"{_threat_desc(a)} ~ {_threat_desc(b)} (similarity {jac:.0%})"
                dup_pairs.append(rich_desc)
                ra, rb = a.get("CALCRiskRating"), b.get("CALCRiskRating")
                # Focus on high-severity ratings (Moderate+); ignore differences
                # that only involve Negligible/Minor ratings (refinement request).
                sev = {str(ra).lower(), str(rb).lower()} & SEVERE_RISK
                if ra and rb and ra != rb and sev:
                    inconsistent += 1
                    f18.append(f"{tlab(a)} [{ra}] ~ {tlab(b)} [{rb}] (similarity {jac:.0%}) - "
                               f"descriptions: {_threat_desc(a)} ... {_threat_desc(b)}")
                else:
                    p18.append(f"{tlab(a)} [{ra or 'no rating'}] ~ {tlab(b)} "
                               f"[{rb or 'no rating'}] - consistent (similarity {jac:.0%}) - "
                               f"descriptions: {_threat_desc(a)} ... {_threat_desc(b)}")

    # CM-19 rating consistency across similar threats
    if similar_pairs:
        core.append(dict(id="CM-19", name="Rating consistency across similar threats",
                         dim="Consistency & Traceability", auto="Semi-auto",
                         refs="I1-Q11; I2-Q11; I4-Q11,Q12; I5-Q11,Q20",
                         note=f"{similar_pairs} near-duplicate threat pair(s) (Jaccard>={JACCARD_DUP_THRESHOLD}); "
                              "consistent risk ratings (high-severity ratings only)",
                         num=similar_pairs - inconsistent, den=similar_pairs, better="high",
                         detail={"pass": p18, "fail": f18}))
    else:
        core.append(dict(id="CM-19", name="Rating consistency across similar threats",
                         dim="Consistency & Traceability", auto="Semi-auto",
                         refs="I1-Q11; I2-Q11; I4-Q11,Q12; I5-Q11,Q20",
                         note="no near-duplicate threat pairs found (n/a)", status="na", better="high",
                         detail={"pass": ["no similar-threat pairs detected"], "fail": []}))

    # CM-20 rating coherence & justification. A threat passes only if its stored
    # risk equals the value the project's risk matrix derives from impact+likelihood
    # (exact cell lookup) AND it carries an explanatory rating comment. When
    # likelihood is absent it is first recomputed from exploitability+exposure via
    # the likelihood matrix.
    def _rationale(t):
        return bool(t.get("exploitabilityComment") or t.get("threatSpecificExposureComment")
                    or t.get("threatSpecificImpactComment"))
    _LIK_LABELS = {"very_unlikely", "unlikely", "possible", "likely", "very_likely"}
    p19, f19 = [], []
    for t in threats:
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
        justified = _rationale(t)
        if coherent and justified:
            p19.append(tlab(t))
        else:
            why = []
            if not coherent:
                why.append(f"risk mismatch (impact={t.get('CALCAppliedImpactRating')}, "
                           f"likelihood={t.get('CALCLikelihood')}, risk={t.get('CALCRiskRating')}; "
                           f"matrix expects {expected})")
            if not justified:
                why.append("no rating rationale comment")
            f19.append(f"{tlab(t)} - {'; '.join(why)}")
    core.append(dict(id="CM-20", name="Rating coherence & justification",
                     dim="Consistency & Traceability", auto="Semi-auto",
                     refs="I1-Q12,Q16; I2-Q13,Q17",
                     note="stored risk matches the risk matrix value derived from "
                          "impact+likelihood AND rating carries an explanatory comment",
                     num=len(p19), den=max(n_threats, 1), better="high",
                     detail={"pass": p19, "fail": f19}))

    # CM-24 duplicate / similar-threat detection (count of near-duplicate pairs, lower is better)
    core.append(dict(id="CM-24", name="Duplicate / similar-threat detection",
                     dim="Consistency & Traceability", auto="Semi-auto", refs="I5-Q11,Q12,Q20",
                     note="near-duplicate threat pairs (Jaccard>=" + str(JACCARD_DUP_THRESHOLD) + "); lower is better", kind="count",
                     num=similar_pairs, den=None, better="low",
                     detail={"pass": [] if dup_pairs else ["no near-duplicate threat pairs"],
                             "fail": dup_pairs}))

    # CM-21 risk-treatment / handling decision coverage
    def _has_rating(v):
        return bool(v) and str(v).lower() not in ("norating", "no_rating", "no_re_rating")

    p34, f34 = [], []
    for t in threats:
        rr = t.get("ReRating") or {}
        decided = (_has_rating(rr.get("CALCrrRiskRating")) or rr.get("isAcceptedByDefault")
                   or rr.get("isAvoided") or bool(rr.get("mitigation"))
                   or bool(rr.get("acceptanceComment")))
        if decided:
            how = []
            if rr.get("mitigation"):
                how.append("mitigation")
            if rr.get("isAvoided"):
                how.append("avoided")
            if rr.get("isAcceptedByDefault") or rr.get("acceptanceComment"):
                how.append("accepted")
            if _has_rating(rr.get("CALCrrRiskRating")):
                how.append(f"residual={rr.get('CALCrrRiskRating')}")
            p34.append(f"{tlab(t)} - {', '.join(how) or 'decision recorded'}")
        else:
            f34.append(f"{tlab(t)} - no treatment decision (no re-rating, mitigation, "
                       "avoidance or acceptance)")
    core.append(dict(id="CM-21", name="Risk-treatment / handling decision coverage",
                     dim="Consistency & Traceability", auto="Auto",
                     refs="I5-Q11",
                     note="every threat has a documented treatment decision "
                          "(mitigate / avoid / accept / re-rate)",
                     num=len(p34), den=max(n_threats, 1), better="high",
                     detail={"pass": p34, "fail": f34}))

    # CM-22 rating-distribution / rubber-stamping detector
    from collections import Counter as _Counter
    rating_counts = _Counter(str(t.get("CALCRiskRating")) for t in threats if t.get("CALCRiskRating"))
    rated_n = sum(rating_counts.values())
    if rated_n >= 3:
        modal_label, modal_n = rating_counts.most_common(1)[0]
        discrimination = round((1 - modal_n / rated_n) * 100, 1)
        dist = ", ".join(f"{k}:{v}" for k, v in rating_counts.most_common())
        status35 = "ok" if discrimination >= 50 else ("warn" if discrimination >= 25 else "bad")
        core.append(dict(id="CM-22", name="Rating-distribution / rubber-stamping detector",
                         dim="Consistency & Traceability", auto="Auto",
                         refs="I1-Q11; I2-Q11; I4-Q11,Q12; I5-Q11,Q20",
                         note="risk ratings are discriminated (not all collapsed onto one value)",
                         value=discrimination, better="high", status=status35,
                         detail={"pass": [f"rating distribution - {dist}"],
                                 "fail": ([f"{modal_n}/{rated_n} threats share the same rating "
                                           f"'{modal_label}' - possible rubber-stamping"]
                                          if status35 != "ok" else [])}))
    else:
        core.append(dict(id="CM-22", name="Rating-distribution / rubber-stamping detector",
                         dim="Consistency & Traceability", auto="Auto",
                         refs="I1-Q11; I2-Q11; I4-Q11,Q12; I5-Q11,Q20",
                         note="too few rated threats to assess rating distribution (n/a)",
                         better="high", status="na",
                         detail={"pass": ["not enough rated threats to judge distribution"], "fail": []}))

    # CM-23 assumption usage / linkage by type. Only General assumptions are
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
    core.append(dict(id="CM-23", name="Assumption usage / linkage by type",
                     dim="Consistency & Traceability", auto="Auto",
                     refs="Maturity model (Assumptions)",
                     note="each General assumption is actually referenced "
                          "(not declared and ignored)",
                     num=len(p37), den=max(len(general), 1), better="high",
                     status=("na" if not general else None),
                     detail={"pass": (p37 or ["no General assumptions to assess"]),
                             "fail": f37}))

    # ---- Comprehensibility --------------------------------------------------
    # CM-25 threat-structure completeness (actor/action/target/weakness/interface/impact slots)
    slot_filled = slot_total = 0
    f24 = []
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
        missing = [k for k, v in slots.items() if not v]
        if present < len(slots):
            f24.append(f"{tlab(t)} - {present}/{len(slots)} slots; missing {', '.join(missing)}")
    core.append(dict(id="CM-25", name="Threat-structure completeness (semantic)",
                     dim="Comprehensibility", auto="Semi-auto",
                     refs="I1-Q13; I3-Q13; I4-Q13; I5-Q13",
                     note="actor / action / target-interface / weakness / impact / protection-goal slots",
                     num=slot_filled, den=max(slot_total, 1), better="high",
                     detail={"pass": [], "fail": f24}))

    # CM-26 vagueness / imprecision reduction
    vg_pass, vg_fail = [], []
    for t in threats:
        desc = t.get("attackActionDesc") or ""
        hits = sorted(set(mo.group(0).lower() for mo in VAGUE_RE.finditer(desc)))
        if len(hits) >= 2:
            vg_fail.append(f"{tlab(t)} - vague terms: {', '.join(hits)}")
        else:
            vg_pass.append(tlab(t))
    core.append(dict(id="CM-26", name="Vagueness / imprecision reduction", dim="Comprehensibility",
                     auto="Semi-auto", refs="I1-Q14; I2-Q14; I3-Q14; I4-Q14,Q15",
                     note="threat description not dominated by vague / generic wording (< 2 vague terms)",
                     num=len(vg_pass), den=max(n_threats, 1), better="high",
                     detail={"pass": vg_pass, "fail": vg_fail}))

    # ---- Process & Governance (presence checks for maturity-model rows) ------
    # CM-01 relevant-role / workshop participation (presence + count). The 
    # schema has no participant role field, so this scores on presence and counts
    # only (roles such as Product Owner, Architect, PSO/PSC are documented in the
    # catalog but cannot be auto-detected).
    workshops = tra.get("Workshops") or []
    MIN_PARTICIPANTS = 3
    p01, f01 = [], []
    if not workshops:
        f01.append("no workshops recorded at all")
    for w in workshops:
        wid = w.get("workshopID") or w.get("name") or "workshop"
        parts = w.get("Participants") or []
        mod = w.get("Moderator")
        issues = []
        if not parts:
            issues.append("no participants list")
        elif len(parts) < MIN_PARTICIPANTS:
            issues.append(f"only {len(parts)} participant(s) (< {MIN_PARTICIPANTS})")
        if not mod:
            issues.append("no moderator")
        if issues:
            f01.append(f"{wid} - {'; '.join(issues)}")
        else:
            p01.append(f"{wid} - {len(parts)} participants + moderator")
    core.append(dict(id="CM-01", name="Relevant-role / workshop participation",
                     dim="Process & Governance", auto="Semi-auto", refs="I2-Q3,Q21; I4-Q3; I5-Q5",
                     note=("workshop present with a non-empty participant list, a moderator and "
                           f">= {MIN_PARTICIPANTS} participants (roles cannot be read from the schema - "
                           "presence/count only)"),
                     num=len(p01), den=max(len(workshops), 1), better="high",
                     status=("na" if not workshops else None),
                     detail={"pass": (["no workshop data in this TRA schema (not assessable)"]
                                      if not workshops else p01),
                             "fail": ([] if not workshops else f01)}))

    # CM-02 living-document maintenance / update responsiveness. Automated via
    # dates only: a changedDate later than the createdDate means the TRA was
    # updated rather than written once and abandoned.
    created = tra.get("createdDate") or (tra.get("Project") or {}).get("createdDate")
    changed = tra.get("changedDate")
    updated = bool(created and changed and str(changed) > str(created))
    core.append(dict(id="CM-02", name="Living-document maintenance (updated since creation)",
                     dim="Process & Governance", auto="Auto", refs="I2-Q3,Q5",
                     note="changedDate is later than createdDate (document was updated, not write-once)",
                     num=1 if updated else 0, den=1, better="high",
                     detail={"pass": ([f"updated: created {created} -> changed {changed}"] if updated else []),
                             "fail": ([] if updated else
                                      [f"never updated after creation (created {created}, changed {changed})"])}))

    # CM-27 authority-approval presence (System overview / IOE / Assumptions / Assets / PGs)
    def _approval_keys(obj):
        found = []

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if v and APPROVAL_RE.search(str(k)):
                        found.append(k)
                    walk(v)
            elif isinstance(o, list):
                for x in o:
                    walk(x)
        walk(obj)
        return sorted(set(found))
    approval_rows = [
        ("System overview", tra.get("IntendedOp")),
        ("Intended operational environment", tra.get("IntendedOp")),
        ("Assumptions", assumptions),
        ("Data & functionality assets", assets),
        ("Protection goals", pgs),
    ]
    ap_pass, ap_fail = [], []
    for label, obj in approval_rows:
        keys = _approval_keys(obj) if obj else []
        if keys:
            ap_pass.append(f"{label} - approval field(s): {', '.join(keys)}")
        else:
            ap_fail.append(f"{label} - no authority-approval / sign-off field")
    core.append(dict(id="CM-27", name="Authority-approval presence", dim="Process & Governance",
                     auto="Auto", refs="Maturity model (Authority Approval); IEC 62443-4-1 SM-1(e)",
                     note="section carries an explicit approval / sign-off marker",
                     num=len(ap_pass), den=len(approval_rows), better="high",
                     status=("na" if not ap_pass else None),
                     detail={"pass": (ap_pass or ["no approval / sign-off field exists in this TRA "
                                                  "schema (not assessable)"]),
                             "fail": ([] if not ap_pass else ap_fail)}))

    # CM-28 known-deficiency evidence references (single presence gate covering the 12 rows)
    blob_all = collect_text(tra)
    ev_hits = sorted(set(mo.group(0).upper() for mo in EVIDENCE_RE.finditer(blob_all)))
    ev_present = bool(ev_hits)
    core.append(dict(id="CM-28", name="Known-deficiency evidence references", dim="Process & Governance",
                     auto="Semi-auto", refs="Maturity model (Known Deficiencies)",
                     note="TRA references external evidence artifacts (SRS, SCA, pen-test, SVM, EOL, CVE)",
                     num=1 if ev_present else 0, den=1, better="high",
                     status=(None if ev_present else "na"),
                     detail={"pass": [f"evidence references found: {', '.join(ev_hits)}"] if ev_present else
                                     ["no deficiency-evidence field exists in this TRA schema "
                                      "(not assessable)"],
                             "fail": []}))

    # Canonicalise each id from the v3 catalog by metric name (V3_ID is the
    # single source of truth; inline ids above are kept in sync with it), then
    # order the scorecard by catalog number.
    for m in core:
        m["id"] = V3_ID.get(m["name"], m["id"])
    core.sort(key=lambda m: int(re.sub(r"\D", "", m["id"]) or 0))
    # finalize: value / display / status
    for m in core:
        if m.get("status") == "na":          # not assessable - excluded from scores
            m["value"] = m.get("value", 0.0)
            m["display"] = "n/a"
            continue
        if "value" in m:                       # precomputed (composite)
            m["display"] = f"{m['value']}%"
        elif m.get("kind") == "count":
            m["value"] = m["num"]
            m["display"] = str(m["num"])
        else:
            m["value"] = pct(m["num"], m["den"])
            m["display"] = f"{m['num']}/{m['den']} = {m['value']}%"
        m["status"] = m.get("status") or grade(m)
    return core


# Status weights for the combined score (mirrors the traffic-light grading).
STATUS_WEIGHT = {"ok": 100.0, "warn": 60.0, "bad": 20.0}
DIMENSION_ORDER = ["Process & Governance", "Formal Completeness", "Coverage",
                   "Consistency & Traceability", "Comprehensibility"
                   ]


def compute_scorecard(core: list) -> dict:
    """Combined overall quality score + per-dimension sub-scores (Core set,
    status-weighted: ok=100, warn=60, bad=20). Metrics with status 'na'
    (not assessable in this TRA) are excluded from every mean."""
    def avg(items):
        scored = [m for m in items if m["status"] in STATUS_WEIGHT]
        return round(sum(STATUS_WEIGHT[m["status"]] for m in scored) / len(scored), 1) if scored else 0.0

    def stat(items, score):
        if not any(m["status"] in STATUS_WEIGHT for m in items):
            return "na"
        return "ok" if score >= 80 else ("warn" if score >= 50 else "bad")

    dims = []
    for d in DIMENSION_ORDER:
        members = [m for m in core if m["dim"] == d]
        if members:
            score = avg(members)
            scored_n = sum(1 for m in members if m["status"] in STATUS_WEIGHT)
            dims.append(dict(dim=d, score=score, n=scored_n, status=stat(members, score)))
    overall = avg(core)
    return dict(overall=overall, overall_status=stat(core, overall), dimensions=dims)


def build_findings(tra, assets, pgs, threats, assets_covered, pgs_with_threat,
                   comps_with_threat, in_scope, assumptions, core=None):
    findings = []

    # Extract components (works for both Software and System deployment schemas)
    comps, _ = components_of(tra)

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
                findings.append(("high", f"{p.get('pg_id')} \"{p.get('name')}\" name matches asset "
                                         f"{aid} \"{asset_name.get(aid)}\" but links {linked or '∅'}."))
                break

    # 2) uncovered assets (an asset with no protection goal is a real coverage
    #    gap - HIGH; escalation is implicit since any uncovered asset is HIGH)
    uncovered = [a for a in assets if a.get("asset_id") not in assets_covered]
    for a in uncovered:
        findings.append(("high", f"Asset {a.get('asset_id')} \"{a.get('name')}\" "
                                 f"has no protection goal."))

    # 3) orphan protection goals - WARN, escalated to HIGH when the majority of
    #    protection goals have no threat scenario (systemic analysis gap)
    orphans = [p for p in pgs if p.get("pg_id") not in pgs_with_threat]
    if orphans:
        ids = ", ".join(p.get("pg_id") for p in orphans)
        lvl = _sev("warn", len(orphans), len(pgs))
        findings.append((lvl, f"{len(orphans)}/{len(pgs)} protection goals have no "
                              f"threat scenario: {ids}."))

    # 4) in-scope components with no threat - WARN, escalated to HIGH when the
    #    majority of in-scope components are never attacked
    noth = [c for c in in_scope if c.get("subUnit_id") not in comps_with_threat]
    if noth:
        ids = ", ".join(f"{c.get('subUnit_id')} ({c.get('name')})" for c in noth)
        lvl = _sev("warn", len(noth), len(in_scope))
        findings.append((lvl, f"{len(noth)}/{len(in_scope)} in-scope components are "
                              f"never attacked: {ids}."))

    # 5) unvalidated assumptions - WARN, escalated to HIGH when every assumption
    #    is unvalidated (nothing has been confirmed at all)
    notval = [a for a in assumptions if not a.get("validated")]
    if notval:
        lvl = _sev("warn", len(notval), len(assumptions),
                   force_high=(len(notval) == len(assumptions) and len(assumptions) > 0))
        findings.append((lvl, f"{len(notval)}/{len(assumptions)} assumptions are not validated."))

    # 6) placeholder objects
    for a in assumptions:
        if (a.get("name") or "").strip().lower() == "test":
            findings.append(("warn", f"Assumption {a.get('assumption_id')} is a 'test' placeholder."))
    for c in tra.get("SWComponents", []):
        if (c.get("name") or "").strip().lower() == "test":
            findings.append(("warn", f"Component {c.get('subUnit_id')} is a 'test' placeholder."))

    # 7) re-rating anomaly
    for t in threats:
        rr = t.get("ReRating") or {}
        if rr.get("CALCrrRiskRating") == "No_Re_rating" and not rr.get("isAcceptedByDefault") \
                and not rr.get("acceptanceComment"):
            findings.append(("warn", f"{t.get('threatscenario_id')} has no re-rating, is not "
                                     f"accepted-by-default and carries no acceptance comment."))

    # 8) threats missing rationale - WARN, escalated to HIGH when the majority
    #    of threats carry no rating rationale at all
    norat = [str(t.get("threatscenario_id") or "?") for t in threats
             if not (t.get("exploitabilityComment") or t.get("threatSpecificExposureComment")
                     or t.get("threatSpecificImpactComment"))]
    if norat:
        lvl = _sev("warn", len(norat), len(threats))
        findings.append((lvl, f"Threats without any rating rationale: {', '.join(norat)}."))

    # 9) empty analysis is always the most serious red flag (mirrors CM-19)
    if not threats:
        findings.append(("high", "No threat scenarios are defined at all - the risk "
                                 "analysis is empty."))

    # 10) component naming quality - placeholder / generic patterns
    placeholder_comps = []
    generic_names = {'default', 'test', 'temp', 'component', 'module', 'unknown'}
    for c in comps:
        cname = (c.get('name') or '').lower().strip()
        cid = c.get('subUnit_id') or '?'
        # Catch _-prefixed (private/placeholder) and generic single-word names
        if cname.startswith('_') or cname in generic_names:
            placeholder_comps.append(f"{cid} ({cname})")
    
    if placeholder_comps:
        ids = ", ".join(placeholder_comps)
        findings.append(("warn", f"Components with placeholder/generic names ({len(placeholder_comps)}): {ids} "
                                "(meaningful naming improves traceability)."))
    
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

    # ---- CM-scorecard alignment ---------------------------------------------
    # Guarantee the findings never disagree with the metric scorecard: every
    # failing Core metric (status bad -> HIGH, warn -> WARN) that is not already
    # surfaced by a curated rule above is turned into a finding, using the
    # metric's own fail readings as the message. This keeps the two views in
    # sync and makes each finding traceable to a catalog id. Coverage is matched
    # by metric *name* (stable) rather than catalog id (which is renumbered).
    COVERED_NAMES = {
        "Placeholder / unfinished-entry detection",         # rule 6  placeholders
        "Assumption validation ratio",                      # rule 5  unvalidated assumptions
        "Component coverage by threats",                    # rule 4  components never attacked
        "Protection-goal coverage in threat analysis",      # rule 3  orphan protection goals
        "Asset coverage / asset-to-protection-goal mapping",  # rule 2  uncovered assets
        "No-threat / empty-analysis red flag",              # rule 9  empty analysis
        "Rating coherence & justification",                 # rule 8  rating rationale
        "Risk-treatment / handling decision coverage",      # rule 7  re-rating / treatment
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
        shown = "; ".join(fails[:3])
        more = f" (+{len(fails) - 3} more)" if len(fails) > 3 else ""
        lvl = "high" if status == "bad" else "warn"
        findings.append((lvl, f"{m['id']} {m['name']}: {len(fails)} flagged - {shown}{more}."))

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

    colors = {"ok": "#1a7f37", "warn": "#bf8700", "bad": "#cf222e", "na": "#6e7681"}
    badges = {"ok": "GOOD", "warn": "REVIEW", "bad": "CRITICAL", "na": "N/A"}

    # combined overall score + per-dimension sub-scores (Core set)
    sc = data.get("scorecard", {"overall": 0.0, "overall_status": "bad", "dimensions": []})
    oc = colors[sc["overall_status"]]
    dim_cards = "".join(
        f"<div class='dcard'>"
        f"<div class='dscore' style='color:{colors[d['status']]}'>{d['score']:.0f}%</div>"
        f"<div class='dlbl'>{d['dim']}</div>"
        f"<div class='dbar'><span style='width:{min(d['score'],100)}%;"
        f"background:{colors[d['status']]}'></span></div>"
        f"<div class='dn'>{d['n']} metrics</div></div>"
        for d in sc["dimensions"]
    )
    score_hero = (
        f"<div class='panel hero'>"
        f"<div class='heroleft'>"
        f"<div class='herobig' style='color:{oc}'>{sc['overall']:.0f}<span>%</span></div>"
        f"<div class='herolbl'>Overall TRA Quality<br><span>Core-set, status-weighted</span></div>"
        f"<span class='badge' style='background:{oc};margin-top:8px'>{badges[sc['overall_status']]}</span>"
        f"</div>"
        f"<div class='herodims'>{dim_cards}</div>"
        f"</div>"
    )

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

    finds = "".join(
        f"<li class='f-{lvl}'><span class='tag tag-{lvl}'>{lvl.upper()}</span>{esc(str(msg))}</li>"
        for lvl, msg in findings
    ) or "<li>No findings.</li>"

    dl_html = ('<a class="dlbtn" href="/download" download>&#8681; Download report (HTML)</a>'
               if show_download else "")

    # Interview-derived Core metrics (CM set), grouped by quality dimension.
    # Order rows by dimension (per DIMENSION_ORDER) then CM number so each
    # dimension forms one contiguous section (metrics are stored sorted by CM id,
    # which would otherwise interleave dimensions and repeat the section headers).
    core = data.get("core", [])
    _dim_rank = {d: i for i, d in enumerate(DIMENSION_ORDER)}
    core_grouped = sorted(core, key=lambda m: (_dim_rank.get(m["dim"], len(DIMENSION_ORDER)),
                                               int(re.sub(r"\D", "", m["id"]) or 0)))
    auto_color = {"Auto": "#1f6feb", "Semi-auto": "#8957e5", "Expert": "#6e7681"}
    core_rows = ""
    last_dim = None
    for m in core_grouped:
        c = colors[m["status"]]
        if m["dim"] != last_dim:
            core_rows += (f"<tr class='dimrow'><td colspan='5'>{m['dim']}</td></tr>")
            last_dim = m["dim"]
        bar = (f"<div class='bar'><span style='width:{min(m['value'],100)}%;"
               f"background:{c}'></span></div>")
        det = m.get("detail")
        detail_html = ""
        if det and (det.get("fail") or det.get("pass")):
            fail = det.get("fail") or []
            ok_items = det.get("pass") or []
            items = "".join(f"<li class='d-miss'>&#10007; {esc(str(x))}</li>" for x in fail)
            items += "".join(f"<li class='d-ok'>&#10003; {esc(str(x))}</li>" for x in ok_items)
            detail_html = (
                f"<details class='detail'><summary>"
                f"{len(fail)} flagged &middot; {len(ok_items)} ok &mdash; show readings"
                f"</summary><ul class='dlist'>{items}</ul></details>")
        ac = auto_color.get(m["auto"], "#6e7681")
        core_rows += (
            f"<tr>"
            f"<td class='mid'>{m['id']}</td>"
            f"<td>{m['name']}"
            f"<span class='abadge' style='background:{ac}'>{m['auto']}</span>"
            f"<div class='note'>{m['note']}</div>"
            f"<div class='trace'>Interview trace: {m['refs']}</div>{detail_html}</td>"
            f"<td class='val'>{m['display']}{bar}</td>"
            f"<td><span class='badge' style='background:{c}'>{badges[m['status']]}</span></td>"
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
 h1{{margin:0;font-size:22px}} .sub{{color:var(--mut);margin-top:6px;font-size:13px}}
 main{{padding:24px 32px;max-width:1200px;margin:auto}}
 .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}}
 .card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;text-align:center}}
 .kpi{{font-size:26px;font-weight:700}} .lbl{{color:var(--mut);font-size:12px;margin-top:4px}}
 .hero{{display:flex;gap:28px;align-items:center;margin-bottom:24px;flex-wrap:wrap}}
 .heroleft{{display:flex;flex-direction:column;align-items:center;min-width:180px}}
 .herobig{{font-size:64px;font-weight:800;line-height:1}}
 .herobig span{{font-size:26px;font-weight:600}}
 .herolbl{{color:var(--txt);font-size:13px;text-align:center;margin-top:6px}}
 .herolbl span{{color:var(--mut);font-size:11px}}
 .herodims{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;flex:1}}
 .dcard{{background:#0d1117;border:1px solid var(--line);border-radius:10px;padding:14px}}
 .dscore{{font-size:24px;font-weight:700}}
 .dlbl{{color:var(--mut);font-size:11px;margin-top:2px;min-height:28px}}
 .dbar{{height:6px;background:#21262d;border-radius:4px;margin-top:8px;overflow:hidden}}
 .dbar span{{display:block;height:100%}}
 .dn{{color:var(--mut);font-size:10px;margin-top:5px}}
 .grid2{{display:grid;grid-template-columns:2fr 1fr;gap:24px;margin-bottom:24px}}
 .panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}}
 h2{{font-size:15px;margin:0 0 14px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
 th{{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
 .mid{{font-family:Consolas,monospace;color:#79c0ff;white-space:nowrap}}
 .note{{color:var(--mut);font-size:11px;margin-top:3px}}
 .trace{{color:#6e7681;font-size:10px;margin-top:2px;font-family:Consolas,monospace}}
 .abadge{{color:#fff;padding:1px 7px;border-radius:20px;font-size:9px;font-weight:700;
   margin-left:8px;vertical-align:middle}}
 .dimrow td{{background:#0d1117;color:#79c0ff;font-weight:700;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line)}}
 .detail{{margin-top:6px;font-size:12px}}
 .detail summary{{cursor:pointer;color:#79c0ff;font-size:11px}}
 .dlist{{margin:6px 0 0;padding:0}}
 .dlist li{{padding:5px 8px;border:0;border-left:3px solid var(--line);border-radius:4px;
   margin:4px 0;font-size:12px;background:#0d1117}}
 .d-miss{{border-left-color:#cf222e!important;color:#ffb3ba}}
 .d-ok{{border-left-color:#1a7f37!important;color:#8ddf9e}}
 .val{{white-space:nowrap;font-variant-numeric:tabular-nums}}
 .bar{{height:6px;background:#21262d;border-radius:4px;margin-top:6px;overflow:hidden}}
 .bar span{{display:block;height:100%}}
 .badge{{color:#fff;padding:3px 8px;border-radius:20px;font-size:10px;font-weight:700}}
 ul{{list-style:none;padding:0;margin:0}}
 li{{padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:8px;font-size:13px}}
 .tag{{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;margin-right:8px}}
 .tag-high{{background:#cf222e;color:#fff}} .tag-warn{{background:#bf8700;color:#fff}}
 .f-high{{border-left:3px solid #cf222e}} .f-warn{{border-left:3px solid #bf8700}}
 footer{{color:var(--mut);font-size:12px;padding:18px 32px;border-top:1px solid var(--line)}}
 .dlbtn{{position:absolute;top:24px;right:32px;background:#1f6feb;color:#fff;text-decoration:none;
   padding:9px 16px;border-radius:8px;font-size:13px;font-weight:600}}
 .dlbtn:hover{{background:#388bfd}}
 header{{position:relative}}
</style></head><body>
<header>
 <h1>TRA Quality Report &mdash; {esc(str(proj.get('TRAProjectName','(unknown project)')))}</h1>
 <div class="sub">Target Area: {esc(str(s.get('target_area','-')))} &middot; Target: {esc(str(proj.get('targetOfAnalysis','-')))}
  &middot; Status: {esc(str(data.get('status','-')))}
  &middot; Source: {esc(os.path.basename(source_path))}</div>
 {dl_html}
</header>
<main>
 {score_hero}
 <div class="cards">{cards}</div>

 <div class="panel" style="margin-bottom:24px">
  <h2>Core metric scorecard &mdash; grouped by quality dimension</h2>
  <div class="note" style="margin-bottom:10px">Curated thesis Core Set derived from the expert
   interviews (catalog IDs CM-xx). Each metric is traceable to the interview question(s) it was
   derived from. <b>Auto</b> = fully computable, <b>Semi-auto</b> = computed flag needing expert
   confirmation, <b>Expert</b> = reviewer judgement. <b>N/A</b> metrics (nothing to measure in
   this TRA) are listed but excluded from the dimension and overall scores.</div>
  <table><thead><tr><th>ID</th><th>Metric</th><th>Score</th><th>Status</th></tr></thead>
  <tbody>{core_rows}</tbody></table>
 </div>

 <div class="panel">
  <h2>Findings &amp; recommended actions</h2>
  <ul>{finds}</ul>
 </div>
</main>
<footer>Generated by tra_quality_report.py &middot; refresh the page to recompute after editing the JSON.</footer>
</body></html>"""


def cli_usage_help() -> str:
    return (
        "Examples:\n"
        "  python tra_quality_report.py <path-to-tra.json>\n"
        "  python tra_quality_report.py <path-to-tra.json> --html-out report.html\n"
        "  python tra_quality_report.py <path-to-tra.json> --metrics-out metrics.json"
    )


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generate a TRA quality report (HTML + JSON metrics) for any TRA JSON "
                    "(Software-component or System-deployment schema).",
        epilog=cli_usage_help(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("json",
                    help="Path to a TRA JSON export (required; either schema variant).")
    ap.add_argument("--html-out", metavar="PATH",
                    help="Write HTML report to PATH (default: <input>_quality_report.html).")
    ap.add_argument("--metrics-out", metavar="PATH",
                    help="Write JSON metrics to PATH (default: <input>_quality_metrics.json).")
    args = ap.parse_args(argv)

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
    comps, ckey = components_of(tra)
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

    print("\nInterview-derived Core metrics (CM set):")
    last_dim = None
    for m in data.get("core", []):
        if m["dim"] != last_dim:
            print(f"  -- {m['dim']} --")
            last_dim = m["dim"]
        print(f"  {m['id']:6} {m['display']:<22} [{m['status'].upper()}]  "
              f"{m['name']} ({m['auto']})")

    sc = data.get("scorecard", {})
    if sc:
        print(f"\nCombined Overall TRA Quality: {sc['overall']:.0f}% "
              f"[{sc['overall_status'].upper()}]  (Core set, status-weighted)")
        for d in sc.get("dimensions", []):
            print(f"  {d['score']:5.0f}%  [{d['status'].upper():8}]  {d['dim']} ({d['n']} metrics)")

    out_html = args.html_out or (os.path.splitext(args.json)[0] + "_quality_report.html")
    out_metrics = args.metrics_out or (os.path.splitext(args.json)[0] + "_quality_metrics.json")

    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(render_html(data, args.json, show_download=False))

    with open(out_metrics, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    print(f"\nHTML report written to {out_html}")
    print(f"Metrics JSON written to {out_metrics}")


if __name__ == "__main__":
    main()
