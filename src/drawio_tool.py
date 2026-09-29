#!/usr/bin/env python3
"""Draw.io helpers for parsing, aligning, and debugging TRA models.

Commands:
    drawio-parse      Parse draw.io XML into units and communications
    drawio-align      Align draw.io units/comms with TRA model coverage
    drawio-debug      Explain draw.io alignment decisions step by step
"""

from __future__ import annotations

import argparse
import base64
import difflib
import html
import json
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from collections import Counter
from pathlib import Path


GENERIC_TOKENS = {
    "app",
    "application",
    "boundary",
    "cluster",
    "server",
    "host",
    "node",
    "vm",
    "zone",
    "segment",
    "network",
    "gateway",
    "interface",
    "endpoint",
    "platform",
    "runtime",
    "engine",
    "component",
    "system",
    "service",
    "module",
    "manager",
    "management",
    "internal",
    "external",
    "public",
    "private",
    "prod",
    "production",
    "stage",
    "staging",
    "dev",
    "development",
    "test",
    "testing",
    "main",
    "core",
    "and",
    "the",
    "of",
    "for",
}


def load_json_file(path: str) -> dict:
    """Load and return a generic JSON file."""
    p = Path(path)
    if not p.exists():
        print(f"Error: file not found: {p}", file=sys.stderr)
        sys.exit(2)
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def load_tra(path: str) -> dict:
    """Load and return a TRA JSON file."""
    return load_json_file(path)


def _strip_html(raw_value: str) -> str:
    if not raw_value:
        return ""
    text = html.unescape(str(raw_value))
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_name(name: str) -> str:
    base = (name or "").lower().strip()
    base = re.sub(r"[^a-z0-9]+", " ", base)
    return re.sub(r"\s+", " ", base).strip()


def _token_set(name: str) -> set[str]:
    return {token for token in _normalize_name(name).split() if len(token) > 1}


def _specific_tokens(name: str) -> set[str]:
    return {token for token in _token_set(name) if token not in GENERIC_TOKENS}


def _confidence_bucket(score: float) -> str:
    if score >= 0.9:
        return "high"
    if score >= 0.78:
        return "medium"
    return "low"


def _is_container_node(label: str, style: str, child_count: int) -> bool:
    style_text = (style or "").lower()

    if "swimlane" in style_text or "group" in style_text or "container=1" in style_text:
        return True
    return child_count > 0


def _guess_kind(style: str, label: str) -> str:
    style_text = (style or "").lower()
    label_text = (label or "").lower()

    if label_text.startswith("zone:"):
        return "zone"
    if label_text.startswith("boundary:"):
        return "boundary"
    if "cloud" in style_text or "cloud" in label_text:
        return "cloud"
    if "database" in style_text or "cylinder" in style_text or "db" in label_text:
        return "database"
    if any(token in label_text for token in ("interface", "access", "api", "request")):
        return "interface"
    if "router" in style_text or "switch" in style_text:
        return "network"
    if "lock" in style_text or "shield" in style_text or "firewall" in label_text:
        return "security"
    if "mobile" in style_text or "phone" in style_text:
        return "device"
    if "server" in style_text or "rack" in style_text:
        return "server"
    if "actor" in style_text or "user" in label_text:
        return "user"
    return "component"


def _decode_drawio_diagram_text(text: str) -> str:
    payload = (text or "").strip()
    if not payload:
        return ""
    if payload.startswith("<"):
        return payload

    try:
        decoded = base64.b64decode(payload)
        inflated = zlib.decompress(decoded, -15)
        return urllib.parse.unquote(inflated.decode("utf-8"))
    except Exception:
        return ""


def parse_drawio_file(path: str) -> dict:
    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"draw.io file not found: {path}")

    raw_xml = input_path.read_text(encoding="utf-8")
    root = ET.fromstring(raw_xml)

    diagrams: list[dict] = []
    nodes: list[dict] = []
    edges: list[dict] = []

    if root.tag == "mxGraphModel":
        diagram_roots = [{"name": "page-1", "root": root}]
    elif root.tag == "mxfile":
        diagram_roots = []
        all_diagrams = root.findall("diagram")
        if not all_diagrams:
            raise ValueError("mxfile has no diagram pages")

        # Single-page mode for now: parse only the first diagram.
        diagram = all_diagrams[0]
        diagram_name = diagram.attrib.get("name", "page-1")
        direct_child = next(iter(diagram), None)
        if direct_child is not None and direct_child.tag == "mxGraphModel":
            diagram_roots.append({"name": diagram_name, "root": direct_child})
        else:
            decoded_xml = _decode_drawio_diagram_text(diagram.text or "")
            if not decoded_xml:
                diagrams.append({"name": diagram_name, "status": "skipped", "reason": "unparseable payload"})
            else:
                inner_root = ET.fromstring(decoded_xml)
                if inner_root.tag == "mxGraphModel":
                    diagram_roots.append({"name": diagram_name, "root": inner_root})
                elif inner_root.tag == "mxfile":
                    nested_diagram = inner_root.find("diagram")
                    if nested_diagram is not None:
                        nested_xml = _decode_drawio_diagram_text(nested_diagram.text or "")
                        if nested_xml:
                            nested_root = ET.fromstring(nested_xml)
                            if nested_root.tag == "mxGraphModel":
                                diagram_roots.append({"name": diagram_name, "root": nested_root})
                        if not diagram_roots:
                            diagrams.append({"name": diagram_name, "status": "skipped", "reason": "nested format unsupported"})
                    else:
                        diagrams.append({"name": diagram_name, "status": "skipped", "reason": "nested format unsupported"})
                else:
                    diagrams.append({"name": diagram_name, "status": "skipped", "reason": f"unexpected root {inner_root.tag}"})

        skipped_pages = max(len(all_diagrams) - 1, 0)
        if skipped_pages:
            diagrams.append(
                {
                    "name": "_additional-pages",
                    "status": "skipped",
                    "reason": f"single-page mode active; skipped {skipped_pages} additional page(s)",
                }
            )
    else:
        raise ValueError(f"Unsupported draw.io root element: {root.tag}")

    for entry in diagram_roots:
        diagram_name = entry["name"]
        diagram_root = entry["root"]
        model_root = diagram_root.find("root")
        if model_root is None:
            diagrams.append({"name": diagram_name, "status": "skipped", "reason": "missing mxGraphModel/root"})
            continue

        page_nodes: dict[str, dict] = {}
        all_cells = model_root.findall("mxCell")
        edge_ids = {
            cell.attrib.get("id", "")
            for cell in all_cells
            if cell.attrib.get("edge") == "1" and cell.attrib.get("id")
        }
        children_by_parent: dict[str, list[ET.Element]] = {}
        for cell in all_cells:
            parent_id = cell.attrib.get("parent", "")
            if parent_id:
                children_by_parent.setdefault(parent_id, []).append(cell)

        child_counts: Counter[str] = Counter()
        for cell in all_cells:
            parent_id = cell.attrib.get("parent", "")
            if parent_id:
                child_counts[parent_id] += 1

        for cell in all_cells:
            if cell.attrib.get("vertex") != "1":
                continue
            cell_id = cell.attrib.get("id", "")
            if cell_id in {"0", "1"}:
                continue

            label = _strip_html(cell.attrib.get("value", ""))
            style = cell.attrib.get("style", "")
            parent_id = cell.attrib.get("parent", "")

            if "edgelabel" in style.lower() or parent_id in edge_ids:
                continue
            if not label and not any(token in style.lower() for token in ("shape=", "icon", "image", "swimlane", "group")):
                continue

            child_count = int(child_counts.get(cell_id, 0))
            node = {
                "id": cell_id,
                "label": label or f"unnamed-{cell_id}",
                "normalized": _normalize_name(label or f"unnamed-{cell_id}"),
                "kind": _guess_kind(style, label),
                "style": style,
                "parent": parent_id,
                "child_count": child_count,
                "is_container": _is_container_node(label or f"unnamed-{cell_id}", style, child_count),
                "diagram": diagram_name,
            }
            page_nodes[cell_id] = node
            nodes.append(node)

        seen_pairs: set[tuple[str, str, str]] = set()
        for cell in all_cells:
            if cell.attrib.get("edge") != "1":
                continue
            source_id = cell.attrib.get("source", "")
            target_id = cell.attrib.get("target", "")
            if source_id not in page_nodes or target_id not in page_nodes:
                continue

            edge_label = _strip_html(cell.attrib.get("value", ""))
            if not edge_label:
                edge_id = cell.attrib.get("id", "")
                child_labels: list[str] = []
                for child in children_by_parent.get(edge_id, []):
                    child_value = _strip_html(child.attrib.get("value", ""))
                    child_style = (child.attrib.get("style", "") or "").lower()
                    if not child_value:
                        continue
                    # Prefer explicit draw.io edge-label nodes, but allow any labeled child fallback.
                    if "edgelabel" in child_style or child.attrib.get("vertex") == "1":
                        child_labels.append(child_value)
                if child_labels:
                    edge_label = " | ".join(dict.fromkeys(child_labels))

            edge_key = (source_id, target_id, edge_label)
            if edge_key in seen_pairs:
                continue
            seen_pairs.add(edge_key)

            edges.append(
                {
                    "id": cell.attrib.get("id", ""),
                    "source_id": source_id,
                    "target_id": target_id,
                    "source_label": page_nodes[source_id]["label"],
                    "target_label": page_nodes[target_id]["label"],
                    "label": edge_label,
                    "diagram": diagram_name,
                }
            )

        diagrams.append({"name": diagram_name, "status": "parsed", "nodes": len(page_nodes), "edges": len(seen_pairs)})

    return {
        "file": str(input_path),
        "diagram_count": len(diagrams),
        "diagrams": diagrams,
        "nodes": nodes,
        "edges": edges,
    }


def _rank_name_candidates(name: str, candidates: list[dict]) -> list[dict]:
    normalized_name = _normalize_name(name)
    if not normalized_name:
        return []

    normalized_tokens = _token_set(normalized_name)
    specific_tokens = _specific_tokens(normalized_name)
    ranked: list[dict] = []

    for candidate in candidates:
        candidate_name = candidate["normalized"]
        candidate_tokens = _token_set(candidate_name)
        candidate_specific_tokens = _specific_tokens(candidate_name)

        if candidate_name == normalized_name:
            ranked.append({"match": candidate, "confidence": 1.0, "method": "exact"})
            continue

        ratio = difflib.SequenceMatcher(None, normalized_name, candidate_name).ratio()
        token_overlap = 0.0
        if normalized_tokens and candidate_tokens:
            token_overlap = len(normalized_tokens & candidate_tokens) / max(len(normalized_tokens | candidate_tokens), 1)

        containment = 0.0
        containment_method = ""
        if specific_tokens and candidate_specific_tokens:
            overlap_count = len(specific_tokens & candidate_specific_tokens)
            if overlap_count > 0:
                subset_ratio = overlap_count / min(len(specific_tokens), len(candidate_specific_tokens))
                if subset_ratio >= 0.8:
                    containment = subset_ratio
                    containment_method = "token-subset"

        best_score = max(ratio, token_overlap, containment)
        if best_score == containment and containment_method:
            method = containment_method
        elif best_score == token_overlap:
            method = "token-overlap"
        else:
            method = "fuzzy-ratio"

        ranked.append(
            {
                "match": candidate,
                "confidence": round(best_score, 3),
                "method": method,
                "ratio": round(ratio, 3),
                "overlap": round(token_overlap, 3),
            }
        )

    ranked.sort(key=lambda item: item["confidence"], reverse=True)
    return ranked


def _best_available_name_match(
    ranked_candidates: list[dict],
    threshold: float = 0.72,
    preferred_tra_kind: str | None = None,
    allowed_tra_kinds: set[str] | None = None,
) -> dict | None:
    viable_candidates = []
    for candidate in ranked_candidates:
        if float(candidate.get("confidence", 0.0)) < threshold:
            continue
        match = candidate.get("match", {})
        if not match.get("id", ""):
            continue
        if allowed_tra_kinds is not None and match.get("kind") not in allowed_tra_kinds:
            continue
        viable_candidates.append(candidate)

    if not viable_candidates:
        return None

    if preferred_tra_kind:
        for candidate in viable_candidates:
            if candidate.get("match", {}).get("kind") == preferred_tra_kind:
                return {
                    "match": candidate["match"],
                    "confidence": candidate["confidence"],
                    "method": candidate["method"],
                }

    best = viable_candidates[0]
    # many-to-one is the default behavior: multiple draw.io nodes may map to one TRA unit
    return {
        "match": best["match"],
        "confidence": best["confidence"],
        "method": best["method"],
    }


def _is_zone_like_node(node: dict) -> bool:
    style_text = (node.get("style", "") or "").lower()
    if node.get("kind") in {"zone", "boundary"}:
        return True
    if bool(node.get("is_container")):
        return True
    if "swimlane" in style_text or "group" in style_text or "container=1" in style_text:
        return True
    return False


def _allowed_tra_kinds_for_drawio_node(node: dict) -> set[str]:
    if _is_zone_like_node(node):
        return {"SecurityZone"}
    return {"SystemComponent", "SWComponent"}


def _filter_ranked_candidates_by_kind(ranked_candidates: list[dict], allowed_tra_kinds: set[str] | None) -> list[dict]:
    if allowed_tra_kinds is None:
        return ranked_candidates
    return [
        candidate
        for candidate in ranked_candidates
        if candidate.get("match", {}).get("kind") in allowed_tra_kinds
    ]


def _is_strict_zone_first_node(node: dict) -> bool:
    label_norm = _normalize_name(node.get("label", ""))
    if "network" not in label_norm:
        return False
    return bool(node.get("is_container"))


def _extract_protocol_hint(label: str) -> str:
    text = (label or "").strip()
    if not text:
        return ""
    match = re.search(r"\(([^()]+)\)\s*$", text)
    if match:
        return match.group(1).strip().upper()
    for token in ("HTTPS", "HTTP", "SSH", "SQL", "FTP", "SFTP", "TLS"):
        if token.lower() in text.lower():
            return token
    return ""


def _extract_intent_tokens(text: str) -> set[str]:
    tokens = _token_set(text)
    intent_words = {
        "https",
        "http",
        "ssh",
        "tls",
        "sql",
        "api",
        "pull",
        "push",
        "update",
        "scan",
        "upload",
        "download",
        "sync",
        "auth",
        "login",
    }
    return {token for token in tokens if token in intent_words}


def _candidate_comms_for_unmatched_edge(
    source_tra_id: str | None,
    target_tra_id: str | None,
    label: str,
    communications: list[dict],
) -> list[dict]:
    protocol_hint = _extract_protocol_hint(label)
    edge_intents = _extract_intent_tokens(label)
    scored: list[dict] = []

    for communication in communications:
        communication_id = communication.get("id", "")
        source_id = communication.get("source", {}).get("id", "")
        target_id = communication.get("target", {}).get("id", "")
        communication_name = communication.get("name", "")

        score = 0.0
        reasons = []
        if source_tra_id and source_id == source_tra_id:
            score += 0.55
            reasons.append("same source")
        if target_tra_id and target_id == target_tra_id:
            score += 0.55
            reasons.append("same target")

        if protocol_hint:
            normalized_name = _normalize_name(communication_name)
            if protocol_hint.lower() in normalized_name:
                score += 0.2
                reasons.append(f"protocol hint {protocol_hint}")

        communication_intents = _extract_intent_tokens(communication_name)
        if edge_intents and communication_intents:
            overlap = edge_intents & communication_intents
            if overlap:
                score += 0.15
                reasons.append(f"intent overlap {','.join(sorted(overlap))}")

        if score <= 0:
            continue

        scored.append(
            {
                "communication_id": communication_id,
                "name": communication_name,
                "path": communication.get("path", ""),
                "source_id": source_id,
                "target_id": target_id,
                "score": round(score, 3),
                "reasons": reasons,
            }
        )

    scored.sort(key=lambda item: item["score"], reverse=True)
    return scored[:5]


def _collect_tra_component_records(data: dict) -> list[dict]:
    components: list[dict] = []

    for zone in data.get("SecurityZones", []):
        zone_name = zone.get("name", "")
        components.append(
            {
                "id": zone.get("zone_id", ""),
                "name": zone_name,
                "kind": "SecurityZone",
                "normalized": _normalize_name(zone_name),
            }
        )

    for component in data.get("SystemComponents", []):
        component_name = component.get("name", "")
        components.append(
            {
                "id": component.get("subUnit_id", ""),
                "name": component_name,
                "kind": "SystemComponent",
                "normalized": _normalize_name(component_name),
            }
        )

    for software_component in data.get("SWComponents", []):
        software_name = software_component.get("name", "")
        components.append(
            {
                "id": software_component.get("subUnit_id", ""),
                "name": software_name,
                "kind": "SWComponent",
                "normalized": _normalize_name(software_name),
            }
        )

    return components


def _collect_tra_communications_with_endpoints(data: dict) -> list[dict]:
    interface_owners: dict[str, dict] = {}
    component_index: dict[str, dict] = {}

    for component in data.get("SystemComponents", []):
        owner = {"id": component.get("subUnit_id", ""), "name": component.get("name", "")}
        if owner["id"]:
            component_index[owner["id"]] = owner
        for interface_collection in ("NetworkFacingInterfaces", "HostLevelInterfaces", "ProximityInterfaces"):
            for interface in component.get(interface_collection, []):
                interface_id = interface.get("interface_id", "")
                if interface_id:
                    interface_owners[interface_id] = owner

    for software_component in data.get("SWComponents", []):
        owner = {"id": software_component.get("subUnit_id", ""), "name": software_component.get("name", "")}
        if owner["id"]:
            component_index[owner["id"]] = owner
        for interface in software_component.get("LogicalInterfaces", []):
            interface_id = interface.get("interface_id", "")
            if interface_id:
                interface_owners[interface_id] = owner

    communications: list[dict] = []

    for component_position, component in enumerate(data.get("SystemComponents", [])):
        owner_source = {"id": component.get("subUnit_id", ""), "name": component.get("name", "")}
        for communication_index, communication in enumerate(component.get("NetworkCommunications", [])):
            source = owner_source
            source_ref = communication.get("SourceComponent") or {}
            source_component_id = source_ref.get("subUnit_id", "")
            if source_component_id:
                source = component_index.get(source_component_id, {"id": source_component_id, "name": ""})

            source_interface_id = (communication.get("SourceInterface") or {}).get("interface_id", "")
            if source_interface_id and source_interface_id in interface_owners:
                source = interface_owners[source_interface_id]

            target_interface_id = (communication.get("TargetInterface") or {}).get("interface_id", "")
            target = interface_owners.get(target_interface_id, {"id": "", "name": ""})
            communications.append(
                {
                    "id": communication.get("communication_id", ""),
                    "name": communication.get("name", ""),
                    "type": "NC",
                    "source": source,
                    "target": target,
                    "path": f"$.SystemComponents[{component_position}].NetworkCommunications[{communication_index}]",
                }
            )

    for software_position, software_component in enumerate(data.get("SWComponents", [])):
        owner_source = {"id": software_component.get("subUnit_id", ""), "name": software_component.get("name", "")}
        for communication_index, communication in enumerate(software_component.get("InterSWCommunications", [])):
            source = owner_source
            source_ref = communication.get("SourceComponent") or {}
            source_component_id = source_ref.get("subUnit_id", "")
            if source_component_id:
                source = component_index.get(source_component_id, {"id": source_component_id, "name": ""})

            source_interface_id = (communication.get("SourceInterface") or {}).get("interface_id", "")
            if source_interface_id and source_interface_id in interface_owners:
                source = interface_owners[source_interface_id]

            target_interface_id = (communication.get("TargetInterface") or {}).get("interface_id", "")
            target = interface_owners.get(target_interface_id, {"id": "", "name": ""})
            communications.append(
                {
                    "id": communication.get("communication_id", ""),
                    "name": communication.get("name", ""),
                    "type": "LC",
                    "source": source,
                    "target": target,
                    "path": f"$.SWComponents[{software_position}].InterSWCommunications[{communication_index}]",
                }
            )

    return communications


def align_drawio_with_tra(
    drawio: dict,
    data: dict,
    *,
    min_confidence: float = 0.72,
) -> dict:
    tra_units = _collect_tra_component_records(data)
    tra_communications = _collect_tra_communications_with_endpoints(data)
    drawio_nodes = drawio["nodes"]

    node_matches: list[dict] = []
    matched_tra_ids: set[str] = set()
    confidence_counts = Counter()
    ranked_candidates_by_node: dict[str, list[dict]] = {}

    for node in drawio_nodes:
        ranked_candidates_by_node[node["id"]] = _rank_name_candidates(node["label"], tra_units)

    for node in drawio_nodes:
        ranked_candidates = ranked_candidates_by_node.get(node["id"], [])
        allowed_kinds = _allowed_tra_kinds_for_drawio_node(node)
        role_candidates = _filter_ranked_candidates_by_kind(ranked_candidates, allowed_kinds)
        preferred_tra_kind = "SecurityZone" if "SecurityZone" in allowed_kinds else None
        best_match = _best_available_name_match(
            ranked_candidates,
            threshold=min_confidence,
            preferred_tra_kind=preferred_tra_kind,
            allowed_tra_kinds=allowed_kinds,
        )

        if best_match is None:
            best_candidate = role_candidates[0] if role_candidates else None
            best_confidence = float(best_candidate.get("confidence", 0.0)) if best_candidate else 0.0
            threshold_gap = max(min_confidence - best_confidence, 0.0)
            expected_kind = "SecurityZone" if "SecurityZone" in allowed_kinds else "SystemComponent/SWComponent"
            rejection_reason = f"no role-compatible candidates (expected {expected_kind})"
            if best_candidate is not None:
                rejection_reason = (
                    f"best candidate below threshold by {threshold_gap:.3f} "
                    f"({best_confidence:.3f} < {min_confidence:.3f})"
                )
            elif ranked_candidates:
                best_overall = ranked_candidates[0]
                rejection_reason = (
                    f"best overall candidate is role-mismatched "
                    f"({_tra_unit_text(best_overall['match'].get('id', ''), best_overall['match'].get('name', ''))})"
                )
            top_ranked = role_candidates if role_candidates else ranked_candidates
            top_candidates = [
                {
                    "tra_id": candidate["match"].get("id", ""),
                    "tra_name": candidate["match"].get("name", ""),
                    "confidence": candidate["confidence"],
                    "method": candidate["method"],
                    "ratio": candidate.get("ratio"),
                    "overlap": candidate.get("overlap"),
                }
                for candidate in top_ranked[:3]
            ]
            node_matches.append(
                {
                    "drawio_label": node["label"],
                    "drawio_id": node["id"],
                    "diagram": node["diagram"],
                    "drawio_kind": node.get("kind", ""),
                    "is_container": bool(node.get("is_container", False)),
                    "matched": False,
                    "threshold": round(min_confidence, 3),
                    "best_confidence": round(best_confidence, 3),
                    "threshold_gap": round(threshold_gap, 3),
                    "rejection_reason": rejection_reason,
                    "top_candidates": top_candidates,
                }
            )
            continue

        matched_tra = best_match["match"]
        matched_tra_ids.add(matched_tra["id"])
        confidence_bucket = _confidence_bucket(float(best_match["confidence"]))
        confidence_counts[confidence_bucket] += 1
        node_matches.append(
            {
                "drawio_label": node["label"],
                "drawio_id": node["id"],
                "diagram": node["diagram"],
                "drawio_kind": node.get("kind", ""),
                "is_container": bool(node.get("is_container", False)),
                "matched": True,
                "tra_id": matched_tra["id"],
                "tra_name": matched_tra["name"],
                "tra_kind": matched_tra["kind"],
                "confidence": best_match["confidence"],
                "confidence_bucket": confidence_bucket,
                "method": best_match["method"],
            }
        )

    unmatched_drawio_nodes = [match for match in node_matches if not match["matched"]]
    matched_node_count = len(node_matches) - len(unmatched_drawio_nodes)
    matched_tra_unique_count = len(matched_tra_ids)
    missing_in_drawio = [unit for unit in tra_units if unit["id"] not in matched_tra_ids]

    tra_zone_ids = {unit["id"] for unit in tra_units if unit.get("kind") == "SecurityZone" and unit.get("id")}
    matched_zone_ids = {tra_id for tra_id in matched_tra_ids if tra_id in tra_zone_ids}
    missing_zone_units = [unit for unit in missing_in_drawio if unit.get("kind") == "SecurityZone"]
    missing_non_zone_units = [unit for unit in missing_in_drawio if unit.get("kind") != "SecurityZone"]

    drawio_to_tra = {match["drawio_id"]: match["tra_id"] for match in node_matches if match.get("matched") and match.get("tra_id")}
    unmatched_nodes_by_id = {match["drawio_id"]: match for match in node_matches if not match.get("matched")}

    tra_pairs: set[tuple[str, str]] = set()
    tra_pair_details: dict[tuple[str, str], list[dict]] = {}
    for communication in tra_communications:
        source_id = communication["source"].get("id", "")
        target_id = communication["target"].get("id", "")
        if not source_id or not target_id:
            continue
        pair = (source_id, target_id)
        tra_pairs.add(pair)
        tra_pair_details.setdefault(pair, []).append(communication)

    edge_results: list[dict] = []
    covered_tra_pairs: set[tuple[str, str]] = set()
    covered_tra_comm_ids: set[str] = set()

    for edge in drawio["edges"]:
        source_drawio_id = edge["source_id"]
        target_drawio_id = edge["target_id"]
        if source_drawio_id not in drawio_to_tra or target_drawio_id not in drawio_to_tra:
            source_has_match = source_drawio_id in drawio_to_tra
            target_has_match = target_drawio_id in drawio_to_tra
            endpoint_status = "both-unmatched"
            if source_has_match and not target_has_match:
                endpoint_status = "target-unmatched"
            elif not source_has_match and target_has_match:
                endpoint_status = "source-unmatched"
            edge_results.append(
                {
                    "drawio_edge_id": edge["id"],
                    "from": edge["source_label"],
                    "to": edge["target_label"],
                    "diagram": edge["diagram"],
                    "matched": False,
                    "reason": "endpoint-unmatched",
                    "root_cause": "endpoint-unmatched",
                    "endpoint_status": endpoint_status,
                }
            )
            continue

        source_tra_id = drawio_to_tra.get(source_drawio_id)
        target_tra_id = drawio_to_tra.get(target_drawio_id)
        if not source_tra_id or not target_tra_id:
            edge_results.append(
                {
                    "drawio_edge_id": edge["id"],
                    "from": edge["source_label"],
                    "to": edge["target_label"],
                    "diagram": edge["diagram"],
                    "matched": False,
                    "reason": "endpoint-unmatched",
                    "root_cause": "endpoint-unmatched",
                    "endpoint_status": "both-unmatched",
                }
            )
            continue

        if (source_tra_id, target_tra_id) in tra_pairs:
            covered_tra_pairs.add((source_tra_id, target_tra_id))
            matched_communications = tra_pair_details[(source_tra_id, target_tra_id)]
            for communication in matched_communications:
                communication_id = communication.get("id", "")
                if communication_id:
                    covered_tra_comm_ids.add(communication_id)
            edge_results.append(
                {
                    "drawio_edge_id": edge["id"],
                    "from": edge["source_label"],
                    "to": edge["target_label"],
                    "diagram": edge["diagram"],
                    "matched": True,
                    "tra_communications": [item["id"] for item in matched_communications if item.get("id")],
                    "tra_locations": [item.get("path", "") for item in matched_communications if item.get("path")],
                }
            )
        else:
            if (target_tra_id, source_tra_id) in tra_pairs:
                edge_root_cause = "direction-mismatch"
            else:
                edge_root_cause = "no-tra-communication"
            candidates = _candidate_comms_for_unmatched_edge(
                source_tra_id,
                target_tra_id,
                edge.get("label", ""),
                tra_communications,
            )
            edge_results.append(
                {
                    "drawio_edge_id": edge["id"],
                    "from": edge["source_label"],
                    "to": edge["target_label"],
                    "diagram": edge["diagram"],
                    "matched": False,
                    "reason": "no-tra-communication",
                    "root_cause": edge_root_cause,
                    "mapped_pair": [source_tra_id, target_tra_id],
                    "possible_tra_locations": candidates,
                }
            )

    for edge_result in edge_results:
        if edge_result.get("matched"):
            continue
        if edge_result.get("reason") not in {"endpoint-unmatched", "endpoint-filtered-or-unmatched"}:
            continue

        source_id = None
        target_id = None
        for raw_edge in drawio["edges"]:
            if raw_edge.get("id") == edge_result.get("drawio_edge_id"):
                source_id = raw_edge.get("source_id")
                target_id = raw_edge.get("target_id")
                break

        source_info = unmatched_nodes_by_id.get(source_id or "", {})
        target_info = unmatched_nodes_by_id.get(target_id or "", {})
        source_top_candidates = source_info.get("top_candidates", [])[:2]
        target_top_candidates = target_info.get("top_candidates", [])[:2]
        edge_result["source_candidate_components"] = source_top_candidates
        edge_result["target_candidate_components"] = target_top_candidates

        source_tra = source_top_candidates[0].get("tra_id") if source_top_candidates else None
        target_tra = target_top_candidates[0].get("tra_id") if target_top_candidates else None
        edge_result["possible_tra_locations"] = _candidate_comms_for_unmatched_edge(
            source_tra,
            target_tra,
            edge_result.get("label", ""),
            tra_communications,
        )

    missing_tra_communications = []
    for pair in sorted(tra_pairs):
        if pair in covered_tra_pairs:
            continue
        pair_communications = tra_pair_details.get(pair, [])
        source_name = ""
        target_name = ""
        if pair_communications:
            source_name = pair_communications[0].get("source", {}).get("name", "")
            target_name = pair_communications[0].get("target", {}).get("name", "")
        missing_tra_communications.append(
            {
                "source_id": pair[0],
                "source_name": source_name,
                "target_id": pair[1],
                "target_name": target_name,
                "communications": [
                    {
                        "id": communication.get("id", ""),
                        "name": communication.get("name", ""),
                        "path": communication.get("path", ""),
                    }
                    for communication in pair_communications
                    if communication.get("id")
                ],
                "communication_ids": [communication.get("id", "") for communication in pair_communications if communication.get("id")],
            }
        )

    total_tra_communication_ids = [communication.get("id", "") for communication in tra_communications if communication.get("id")]
    total_tra_communication_records = len(total_tra_communication_ids)
    matched_tra_communication_records = len(covered_tra_comm_ids)
    missing_tra_communication_records = max(total_tra_communication_records - matched_tra_communication_records, 0)
    unmatched_edge_root_causes = Counter(
        edge.get("root_cause", edge.get("reason", "unknown"))
        for edge in edge_results
        if not edge.get("matched")
    )
    return {
        "summary": {
            "drawio_nodes": len(drawio_nodes),
            "drawio_nodes_total": len(drawio["nodes"]),
            "drawio_containers_filtered": len(drawio["nodes"]) - len(drawio_nodes),
            "drawio_edges": len(drawio["edges"]),
            "tra_units": len(tra_units),
            "tra_components": len(tra_units),
            "tra_communications": len(tra_communications),
            "matched_nodes": matched_node_count,
            "matched_nodes_drawio": matched_node_count,
            "matched_tra_units_unique": matched_tra_unique_count,
            "matched_tra_components_unique": matched_tra_unique_count,
            "unmatched_drawio_nodes": len(unmatched_drawio_nodes),
            "tra_units_missing_in_drawio": len(missing_in_drawio),
            "tra_components_missing_in_drawio": len(missing_in_drawio),
            "tra_zone_total": len(tra_zone_ids),
            "matched_tra_zone_unique": len(matched_zone_ids),
            "tra_zones_missing_in_drawio": len(missing_zone_units),
            "tra_non_zone_units_missing_in_drawio": len(missing_non_zone_units),
            "matched_nodes_high": int(confidence_counts.get("high", 0)),
            "matched_nodes_medium": int(confidence_counts.get("medium", 0)),
            "matched_nodes_low": int(confidence_counts.get("low", 0)),
            "matched_edges": len([edge for edge in edge_results if edge.get("matched")]),
            "unmatched_drawio_edges": len([edge for edge in edge_results if not edge.get("matched")]),
            "tra_communication_pairs": len(tra_pairs),
            "matched_tra_pairs": len(covered_tra_pairs),
            "tra_pairs_missing_in_drawio": len(missing_tra_communications),
            "tra_communication_records": total_tra_communication_records,
            "matched_tra_communication_records": matched_tra_communication_records,
            "tra_communication_records_missing_in_drawio": missing_tra_communication_records,
            "tra_comms_missing_in_drawio": len(missing_tra_communications),
            "unmatched_edge_root_causes": dict(unmatched_edge_root_causes),
        },
        "node_alignment": node_matches,
        "unmatched_drawio_nodes": unmatched_drawio_nodes,
        "missing_tra_units": missing_in_drawio,
        "missing_tra_components": missing_in_drawio,
        "missing_tra_zones": missing_zone_units,
        "missing_tra_non_zone_units": missing_non_zone_units,
        "edge_alignment": edge_results,
        "missing_tra_communications": missing_tra_communications,
    }


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    if not rows:
        print("  (none)")
        return

    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(str(cell)))

    formatter = "  ".join(f"{{:<{width}}}" for width in widths)
    print(formatter.format(*headers))
    print(formatter.format(*["-" * width for width in widths]))
    for row in rows:
        padded_row = list(row) + [""] * (len(headers) - len(row))
        print(formatter.format(*[str(cell) for cell in padded_row]))


def _drawio_unit_text(label: str, diagram: str) -> str:
    label_text = (label or "").strip() or "(unnamed)"
    diagram_text = (diagram or "").strip() or "unknown-page"
    return f"{label_text} [{diagram_text}]"


def _drawio_link_text(source: str, target: str, diagram: str) -> str:
    return f"{_drawio_unit_text(source, diagram)} -> {_drawio_unit_text(target, diagram)}"


def _tra_unit_text(unit_id: str, unit_name: str) -> str:
    if unit_name and unit_id:
        return f"{unit_name} ({unit_id})"
    if unit_name:
        return unit_name
    if unit_id:
        return unit_id
    return "(unknown TRA unit)"


def _friendly_root_cause(root_cause: str) -> str:
    mapping = {
        "endpoint-unmatched": "Endpoint not mapped",
        "direction-mismatch": "Direction mismatch",
        "no-tra-communication": "No TRA communication",
    }
    return mapping.get(root_cause, root_cause)


def cmd_drawio_parse(args: argparse.Namespace) -> int:
    try:
        parsed = parse_drawio_file(args.file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"draw.io file: {parsed['file']}")
    print(f"Diagrams:    {parsed['diagram_count']}")
    print(f"Nodes:       {len(parsed['nodes'])}")
    print(f"Edges:       {len(parsed['edges'])}")
    print()

    if parsed["diagrams"]:
        print("Pages:")
        rows = []
        for diagram in parsed["diagrams"]:
            notes = diagram.get("reason", "") if diagram.get("status") != "parsed" else ""
            rows.append([
                diagram.get("name", ""),
                diagram.get("status", ""),
                str(diagram.get("nodes", "")),
                str(diagram.get("edges", "")),
                notes,
            ])
        print_table(["Name", "Status", "Nodes", "Edges", "Notes"], rows)
        print()

    zones = [node for node in parsed["nodes"] if _is_zone_like_node(node)]
    components = [node for node in parsed["nodes"] if not _is_zone_like_node(node)]
    zones_sorted = sorted(
        zones,
        key=lambda node: (_normalize_name(node.get("diagram", "")), _normalize_name(node.get("label", ""))),
    )
    components_sorted = sorted(
        components,
        key=lambda node: (_normalize_name(node.get("diagram", "")), _normalize_name(node.get("label", ""))),
    )

    print(f"Zones discovered ({len(zones_sorted)}):")
    zone_rows = [
        [
            str(index),
            (node.get("label", "").strip() or "(unnamed)"),
            (node.get("diagram", "").strip() or "unknown-page"),
        ]
        for index, node in enumerate(zones_sorted, start=1)
    ]
    print_table(["#", "Zone name", "Page"], zone_rows)
    print()

    print(f"Components discovered ({len(components_sorted)}):")
    component_rows = [
        [
            str(index),
            (node.get("label", "").strip() or "(unnamed)"),
            (node.get("diagram", "").strip() or "unknown-page"),
        ]
        for index, node in enumerate(components_sorted, start=1)
    ]
    print_table(["#", "Component name", "Page"], component_rows)
    print()

    print("Communications discovered:")
    print("  Communication text = label written on the draw.io arrow.")
    comm_rows = [
        [
            str(index),
            (edge.get("source_label", "").strip() or "(unnamed)"),
            (edge.get("target_label", "").strip() or "(unnamed)"),
            (edge.get("diagram", "").strip() or "unknown-page"),
            edge.get("label", "") or "(none)",
        ]
        for index, edge in enumerate(parsed["edges"], start=1)
    ]
    print_table(["#", "Source", "Target", "Page", "Comm text"], comm_rows)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as output_file:
            json.dump(parsed, output_file, indent=4)
        print(f"\nWritten parse JSON to {args.json_out}")

    return 0


def cmd_drawio_align(args: argparse.Namespace) -> int:
    try:
        parsed = parse_drawio_file(args.drawio_file)
        data = load_tra(args.tra_file)
        report = align_drawio_with_tra(
            parsed,
            data,
            min_confidence=args.min_confidence,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]

    def _classify_drawio_node(node: dict) -> str:
        normalized_node = {
            "label": node.get("drawio_label", node.get("label", "")),
            "kind": node.get("drawio_kind", node.get("kind", "")),
            "is_container": bool(node.get("is_container", False)),
        }
        if _is_zone_like_node(normalized_node):
            return "zone"
        return "component"

    def _align_unit_text(label: str) -> str:
        return (label or "").strip() or "(unnamed)"

    print("DRAW.IO <-> TRA ALIGNMENT")
    print("================================================================================")
    print("draw.io units used/total          : " f"{summary['drawio_nodes']}/{summary['drawio_nodes_total']}")
    print(f"TRA units (components+zones)      : {summary['tra_units']}")
    print(f"draw.io units matched to TRA      : {summary['matched_nodes_drawio']}/{summary['drawio_nodes']}")
    print(f"unique TRA units hit by draw.io   : {summary['matched_tra_units_unique']}/{summary['tra_units']}")
    print(f"TRA zones matched                 : {summary['matched_tra_zone_unique']}/{summary['tra_zone_total']}")
    print(f"unmatched draw.io units           : {summary['unmatched_drawio_nodes']}")
    print("matching mode                     : many-to-one (default)")
    print()
    print(f"draw.io links                     : {summary['drawio_edges']}")
    print(f"TRA communication records         : {summary['tra_communication_records']}")
    print(f"matched draw.io links in TRA      : {summary['matched_edges']}/{summary['drawio_edges']}")
    print(f"draw.io links missing in TRA      : {summary['unmatched_drawio_edges']}")
    print("================================================================================")

    if summary.get("unmatched_edge_root_causes"):
        print("\nUnmatched draw.io link root causes:")
        rows = [[_friendly_root_cause(cause), str(count)] for cause, count in summary["unmatched_edge_root_causes"].items()]
        print_table(["Root cause", "Count"], rows)

    if report["unmatched_drawio_nodes"]:
        unmatched_zones = []
        unmatched_components = []
        for node in report["unmatched_drawio_nodes"][:25]:
            if _classify_drawio_node(node) == "zone":
                unmatched_zones.append(node)
            else:
                unmatched_components.append(node)

        if unmatched_zones:
            print("\nUnmatched draw.io zones:")
            zone_rows = [[_align_unit_text(node.get("drawio_label", ""))] for node in unmatched_zones]
            print_table(["Zone"], zone_rows)

            print("\nRejected zone match explanations:")
            zone_reason_rows = []
            for node in unmatched_zones:
                top_candidate = (node.get("top_candidates") or [{}])[0]
                candidate_name = top_candidate.get("tra_name", "")
                candidate_id = top_candidate.get("tra_id", "")
                candidate_method = top_candidate.get("method", "")
                candidate_conf = top_candidate.get("confidence", 0)
                zone_reason_rows.append(
                    [
                        _align_unit_text(node.get("drawio_label", "")),
                        _tra_unit_text(candidate_id, candidate_name) if (candidate_id or candidate_name) else "(none)",
                        f"{float(candidate_conf):.3f}" if isinstance(candidate_conf, (int, float)) else str(candidate_conf),
                        str(node.get("threshold", "")),
                        str(node.get("threshold_gap", "")),
                        candidate_method,
                        node.get("rejection_reason", ""),
                    ]
                )
            print_table(["Zone", "Best TRA candidate", "Score", "Threshold", "Gap", "Method", "Explanation"], zone_reason_rows)

        if unmatched_components:
            print("\nUnmatched draw.io components:")
            component_rows = [[_align_unit_text(node.get("drawio_label", ""))] for node in unmatched_components]
            print_table(["Component"], component_rows)

            print("\nRejected component match explanations:")
            component_reason_rows = []
            for node in unmatched_components:
                top_candidate = (node.get("top_candidates") or [{}])[0]
                candidate_name = top_candidate.get("tra_name", "")
                candidate_id = top_candidate.get("tra_id", "")
                candidate_method = top_candidate.get("method", "")
                candidate_conf = top_candidate.get("confidence", 0)
                component_reason_rows.append(
                    [
                        _align_unit_text(node.get("drawio_label", "")),
                        _tra_unit_text(candidate_id, candidate_name) if (candidate_id or candidate_name) else "(none)",
                        f"{float(candidate_conf):.3f}" if isinstance(candidate_conf, (int, float)) else str(candidate_conf),
                        str(node.get("threshold", "")),
                        str(node.get("threshold_gap", "")),
                        candidate_method,
                        node.get("rejection_reason", ""),
                    ]
                )
            print_table(["Component", "Best TRA candidate", "Score", "Threshold", "Gap", "Method", "Explanation"], component_reason_rows)

    unmatched_edges = [edge for edge in report.get("edge_alignment", []) if not edge.get("matched")]
    if unmatched_edges:
        print("\nCommunication mapping gaps:")
        print("  Comm text = label written on the draw.io arrow.")
        rows = []
        for index, edge in enumerate(unmatched_edges[:30], start=1):
            possible_locations = edge.get("possible_tra_locations", [])
            best_hint = ""
            if possible_locations:
                best_location = possible_locations[0]
                best_hint = (
                    f"{best_location.get('name', '')} ({best_location.get('communication_id', '')}, "
                    f"score {best_location.get('score', 0):.2f})"
                )
            root_cause = edge.get("root_cause", edge.get("reason", ""))
            rows.append([
                str(index),
                _align_unit_text(edge.get("from", "")),
                _align_unit_text(edge.get("to", "")),
                (edge.get("diagram", "").strip() or "unknown-page"),
                edge.get("label", "") or "(none)",
                _friendly_root_cause(root_cause),
                best_hint,
            ])
        print_table(["#", "Source", "Target", "Page", "Comm text", "Reason", "Best TRA hint"], rows)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as output_file:
            json.dump(report, output_file, indent=4)
        print(f"\nWritten alignment JSON to {args.json_out}")

    return 0


def cmd_drawio_debug(args: argparse.Namespace) -> int:
    try:
        parsed = parse_drawio_file(args.drawio_file)
        data = load_tra(args.tra_file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    tra_units = _collect_tra_component_records(data)
    tra_communications = _collect_tra_communications_with_endpoints(data)
    tra_by_id = {unit.get("id", ""): unit for unit in tra_units if unit.get("id")}

    drawio_nodes = parsed["nodes"]
    used_tra_ids: set[str] = set()
    drawio_to_tra: dict[str, str] = {}
    zone_rows: list[list[str]] = []
    component_rows: list[list[str]] = []
    unmatched_zone_rows: list[list[str]] = []
    unmatched_component_rows: list[list[str]] = []

    def _debug_unit_text(label: str) -> str:
        return (label or "").strip() or "(unnamed)"

    def _classify_drawio_node(node: dict) -> str:
        if _is_zone_like_node(node):
            return "zone"
        return "component"

    for node in drawio_nodes:
        ranked_candidates = _rank_name_candidates(node["label"], tra_units)
        allowed_kinds = _allowed_tra_kinds_for_drawio_node(node)
        role_candidates = _filter_ranked_candidates_by_kind(ranked_candidates, allowed_kinds)
        preferred_tra_kind = "SecurityZone" if "SecurityZone" in allowed_kinds else None
        best_match = _best_available_name_match(
            ranked_candidates,
            threshold=args.min_confidence,
            preferred_tra_kind=preferred_tra_kind,
            allowed_tra_kinds=allowed_kinds,
        )
        if best_match is None:
            expected_kind = "SecurityZone" if "SecurityZone" in allowed_kinds else "SystemComponent/SWComponent"
            candidate_text = " | ".join(
                _tra_unit_text(candidate["match"].get("id", ""), candidate["match"].get("name", ""))
                for candidate in (role_candidates[:3] if role_candidates else ranked_candidates[:3])
            )
            if not role_candidates and ranked_candidates:
                candidate_text = f"(role-mismatch) {candidate_text}"
            if not candidate_text:
                candidate_text = f"(no role-compatible candidates; expected {expected_kind})"
            row = [
                _debug_unit_text(node.get("label", "")),
                "unmatched",
                "",
                "",
                "",
            ]
            unmatched_row = [
                _debug_unit_text(node.get("label", "")),
                candidate_text,
            ]
            if _classify_drawio_node(node) == "zone":
                zone_rows.append(row)
                unmatched_zone_rows.append(unmatched_row)
            else:
                component_rows.append(row)
                unmatched_component_rows.append(unmatched_row)
            continue

        matched_unit = best_match["match"]
        used_tra_ids.add(matched_unit["id"])
        drawio_to_tra[node["id"]] = matched_unit["id"]
        row = [
            _debug_unit_text(node.get("label", "")),
            "matched",
            _tra_unit_text(matched_unit.get("id", ""), matched_unit.get("name", "")),
            f"{best_match['confidence']:.3f}",
            best_match.get("method", ""),
        ]
        if matched_unit.get("kind") == "SecurityZone":
            zone_rows.append(row)
        else:
            component_rows.append(row)

    tra_pairs: set[tuple[str, str]] = set()
    tra_pair_to_ids: dict[tuple[str, str], list[str]] = {}
    for communication in tra_communications:
        source_id = communication.get("source", {}).get("id", "")
        target_id = communication.get("target", {}).get("id", "")
        if not source_id or not target_id:
            continue
        pair = (source_id, target_id)
        tra_pairs.add(pair)
        tra_pair_to_ids.setdefault(pair, [])
        communication_id = communication.get("id", "")
        if communication_id:
            tra_pair_to_ids[pair].append(communication_id)

    edge_rows: list[list[str]] = []
    for index, edge in enumerate(parsed["edges"], start=1):
        source_drawio_id = edge.get("source_id", "")
        target_drawio_id = edge.get("target_id", "")
        source_tra_id = drawio_to_tra.get(source_drawio_id, "")
        target_tra_id = drawio_to_tra.get(target_drawio_id, "")
        drawio_source = _debug_unit_text(edge.get("source_label", ""))
        drawio_target = _debug_unit_text(edge.get("target_label", ""))
        drawio_page = (edge.get("diagram", "").strip() or "unknown-page")
        comm_text = edge.get("label", "") or "(none)"

        if not source_tra_id or not target_tra_id:
            src_unit = _tra_unit_text(source_tra_id, tra_by_id.get(source_tra_id, {}).get("name", "")) if source_tra_id else "(unmapped)"
            tgt_unit = _tra_unit_text(target_tra_id, tra_by_id.get(target_tra_id, {}).get("name", "")) if target_tra_id else "(unmapped)"
            edge_rows.append([
                str(index),
                drawio_source,
                drawio_target,
                drawio_page,
                src_unit,
                tgt_unit,
                "endpoint-unmatched",
                comm_text,
                "",
            ])
            continue

        mapped_pair = (source_tra_id, target_tra_id)
        if mapped_pair in tra_pairs:
            evidence = ", ".join(tra_pair_to_ids.get(mapped_pair, []))
            src_unit = _tra_unit_text(source_tra_id, tra_by_id.get(source_tra_id, {}).get("name", ""))
            tgt_unit = _tra_unit_text(target_tra_id, tra_by_id.get(target_tra_id, {}).get("name", ""))
            edge_rows.append([
                str(index),
                drawio_source,
                drawio_target,
                drawio_page,
                src_unit,
                tgt_unit,
                "matched",
                comm_text,
                evidence,
            ])
        else:
            evidence = ", ".join(
                f"{candidate.get('communication_id', '')}:{candidate.get('score', 0):.2f}"
                for candidate in _candidate_comms_for_unmatched_edge(source_tra_id, target_tra_id, edge.get("label", ""), tra_communications)
            )
            src_unit = _tra_unit_text(source_tra_id, tra_by_id.get(source_tra_id, {}).get("name", ""))
            tgt_unit = _tra_unit_text(target_tra_id, tra_by_id.get(target_tra_id, {}).get("name", ""))
            edge_rows.append([
                str(index),
                drawio_source,
                drawio_target,
                drawio_page,
                src_unit,
                tgt_unit,
                "no-tra-communication",
                comm_text,
                evidence,
            ])

    print("DRAW.IO ALIGNMENT DEBUG")
    print("================================================================================")
    print(f"threshold(min-confidence)         : {args.min_confidence}")
    print("matching mode                     : many-to-one (default)")
    print(f"draw.io units                     : {len(drawio_nodes)}")
    print(f"TRA units (components+zones)      : {len(tra_units)}")
    print(f"draw.io links                     : {len(parsed['edges'])}")
    print(f"TRA communication records         : {len(tra_communications)}")
    print("================================================================================")
    print("Matching methods:")
    print("  - exact: normalized names are identical")
    print("  - token-subset: key tokens mostly overlap (subset-style match)")
    print("  - fuzzy-ratio: sequence similarity fallback when names are close")

    print("\nZone matching trace:")
    print_table(["Draw.io unit", "Status", "TRA match", "Score", "Method"], zone_rows[:40])

    if unmatched_zone_rows:
        print("\nTop candidates for unmatched zones:")
        print_table(["Draw.io unit", "Top-3 candidates"], unmatched_zone_rows[:40])

    print("\nComponent matching trace:")
    print_table(["Draw.io unit", "Status", "TRA match", "Score", "Method"], component_rows[:40])

    if unmatched_component_rows:
        print("\nTop candidates for unmatched components:")
        print_table(["Draw.io unit", "Top-3 candidates"], unmatched_component_rows[:40])

    print("\nCommunication mapping trace:")
    print("  Comm text = label written on the draw.io arrow.")
    print_table(
        ["#", "Draw.io source", "Draw.io target", "Page", "Mapped source", "Mapped target", "Status", "Comm text", "Evidence"],
        edge_rows[:40],
    )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tra_tool",
        description="Draw.io helpers for parsing, aligning, and debugging TRA models.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    drawio_parse = subparsers.add_parser("drawio-parse", help="Parse draw.io XML into a normalized components/communications view")
    drawio_parse.add_argument("file", help="Path to .drawio or draw.io XML file")
    drawio_parse.add_argument("--json-out", help="Optional path to write parse JSON")

    drawio_align = subparsers.add_parser("drawio-align", help="Cross-check draw.io units/comms against TRA units/comms")
    drawio_align.add_argument("drawio_file", help="Path to .drawio or draw.io XML file")
    drawio_align.add_argument("tra_file", help="Path to TRA JSON file")
    drawio_align.add_argument("--json-out", help="Optional path to write alignment JSON")
    drawio_align.add_argument("--min-confidence", type=float, default=0.72, help="Minimum confidence threshold for node matching (default: 0.72)")

    drawio_debug = subparsers.add_parser("drawio-debug", help="Show step-by-step node and edge matching decisions")
    drawio_debug.add_argument("drawio_file", help="Path to .drawio or draw.io XML file")
    drawio_debug.add_argument("tra_file", help="Path to TRA JSON file")
    drawio_debug.add_argument("--min-confidence", type=float, default=0.72, help="Minimum confidence threshold for node matching (default: 0.72)")

    args = parser.parse_args()

    if args.command == "drawio-parse":
        return cmd_drawio_parse(args)
    if args.command == "drawio-align":
        return cmd_drawio_align(args)
    if args.command == "drawio-debug":
        return cmd_drawio_debug(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())