
# System Architecture LLM Assisted

Date: 2026-09-03

## Why this document exists

This document records the concept, core logic, and current implementation for using architecture diagrams (draw.io XML) to support TRA creation in a hybrid approach:

- Deterministic quality and validation path
- AI or LLM assisted architecture interpretation path

The goal is to improve TRA completeness and discover potential model gaps (missing units and missing communications) while preserving deterministic controls.

Document structure intent:

- First: architecture-assistance idea and rationale.
- Then: implementation process, command behavior, and operational usage details.

## Problem statement

The current TRA flow is strong on schema validation and quality metrics, but architecture understanding is mostly interview driven.

Architecture diagrams often contain useful structure that can be converted into machine-checkable evidence:

- Component inventory
- Component-to-component communication paths
- Page or grouping context

This can be used to cross-check TRA JSON model completeness.

## Two-track approach

## Core acceptance rule (refined)

Primary architecture completeness objective:

- No draw.io architecture information should be missed in TRA.

Asymmetric interpretation:

- Missing draw.io units or links in TRA is a gap and should be reported as actionable.
- Additional TRA units or links that are not present in draw.io are allowed and treated as informational context.

### 1) Deterministic track (existing)

Use strict validation and quality tooling to ensure model consistency and scoring:

- validate_tra.py for schema and consistency
- tra_quality_report.py for quality findings and scorecard
- drawio_tool.py for architecture extraction and alignment diagnostics

This remains the decision authority for pass or fail quality gates.

### 2) LLM-assisted track (new support)

Use draw.io parsing and fuzzy alignment to propose or highlight potential architecture-model gaps:

- Extract nodes and edges from draw.io XML
- Normalize labels and compare against TRA units (components and security zones)
- Compare diagram communications against TRA communications
- Report gaps with confidence levels and match methods

This path is advisory and should not silently rewrite TRA content.

## Is draw.io XML reliable for this purpose?

Yes, with scope boundaries:

Reliable for:

- Node labels and graph edges
- Page partitioning
- Basic structural component extraction

Less reliable for:

- Security semantics not explicitly drawn
- Trust assumptions and intended operating environment details
- Exact protocol semantics when not labeled

Conclusion:

draw.io XML is reliable as structural evidence input. Deterministic TRA quality and workshop review still provide semantic authority.

## What was implemented

A new program capability is implemented in drawio_tool.py:

- New command: drawio-parse
- New command: drawio-align
- New command: drawio-debug

No external dependencies were introduced; only Python standard library modules were used.

## Implemented core logic

### A) drawio-parse command

Purpose:

Parse draw.io content and emit a normalized architecture view.

Behavior:

- Accepts .drawio or draw.io XML input
- Supports mxGraphModel root format
- Supports mxfile in single-page mode (first diagram page only)
- Supports compressed diagram payload decoding
- Extracts architecture units as nodes (components, zones, and boundaries)
- Excludes draw.io edge-label pseudo-nodes from node inventory
- Extracts edges only when source and target map to extracted nodes
- Reads communication text from edge labels, including child edge-label cells when direct edge value is empty
- Deduplicates identical source-target-label edge triples per page

Output:

- Console summary (pages, nodes, edges)
- Separate unit sections for Zones discovered and Components discovered
- Neat tabular listing with row index, unit name, and page name
- Communication listing in separate columns (row index, source, target, page, comm text)
- Optional JSON export via --json-out

### B) drawio-align command

Purpose:

Cross-check draw.io architecture against TRA model content.

Model scope used for alignment:

- TRA units: SecurityZones, SystemComponents, and SWComponents
- TRA communications: NetworkCommunications and InterSWCommunications

Matching strategy:

1. Normalize names (lowercase, non-alphanumeric collapsed)
2. Try exact normalized match
3. Fallback fuzzy scoring:
   - Sequence similarity
   - Token overlap
4. Accept best match above threshold using many-to-one assignment (default behavior)
5. Record confidence and matching method

Brief method meaning:

- exact: normalized draw.io label and TRA name are identical after lowercasing and non-alphanumeric cleanup.
- token-subset: high overlap of key tokens (ignoring common generic words), useful for small wording differences.
- fuzzy-ratio: sequence similarity fallback for near-spelling matches and minor phrasing drift.

Refined matching behavior:

- Many-to-one mapping is the default behavior when multiple draw.io nodes should map to one TRA unit (for aggregated runtime/service modeling)
- Zone distinction is structural-first (container/group/swimlane and boundary characteristics), not primarily name-keyword based.
- Role-safe matching is enforced:
  - zone-like draw.io nodes are matched only against TRA SecurityZones
  - component-like draw.io nodes are matched only against TRA SystemComponents and SWComponents
  - if only role-mismatched high-score candidates exist, the node is left unmatched and explained as role mismatch

Communication alignment strategy:

- Map draw.io edge endpoints through matched unit map
- Compare mapped source-target pair against TRA communication source-target pairs
- Mark edge as matched, endpoint-unmatched, no-tra-communication, or direction-mismatch root cause
- For unmatched links, generate ranked TRA communication hints using endpoint fit and label intent/protocol tokens

Output:

- Compact summary for units and links
- Clear unit coverage split:
  - draw.io units matched to TRA
  - unique TRA units hit by draw.io
- Categorized unresolved sections:
  - Unmatched draw.io zones
  - Unmatched draw.io components
  - Communication mapping gaps
- Communication mapping gaps table uses separate draw.io source/target/page columns with comm text and reason
- Rejected match explanations with best candidate, score, threshold, gap, and method
- Optional JSON report via --json-out

### C) drawio-debug command

Purpose:

Show explainable matching details for review and tuning of threshold behavior.

Behavior:

- Prints a short method legend:
  - exact
  - token-subset
  - fuzzy-ratio
- Splits node mapping trace by category:
  - Zone matching trace
  - Component matching trace
- Prints communication mapping trace separately
- Communication mapping trace uses separate columns for draw.io source/target/page, mapped source/target, status, comm text, and evidence
- Shows top candidates for unmatched zones/components
- Uses readable labels in traces rather than raw node or edge IDs

## Technical implementation details

Implemented in drawio_tool.py with these core functions:

- parse_drawio_file
- align_drawio_with_tra
- cmd_drawio_parse
- cmd_drawio_align
- cmd_drawio_debug

Supporting helpers include:

- HTML label stripping and unescaping
- Name normalization and tokenization
- Draw.io payload decoding for compressed diagrams
- Lightweight node kind inference from style and label hints
- TRA communication endpoint ownership mapping
- Structural zone-like node detection (container/group/swimlane/boundary cues)
- Role-safe candidate filtering between zone and component classes
- Root-cause counters for unmatched communications

## Example usage

Parse a draw.io file:

python drawio_tool.py drawio-parse architecture.drawio --json-out architecture_parse.json

Align a draw.io file with an existing TRA:

python drawio_tool.py drawio-align architecture.drawio TRA/TestProject-Metrics-1.json --json-out architecture_alignment.json

Align with minimal parameters:

python drawio_tool.py drawio-align architecture.drawio TRA/TestProject-Metrics-1.json

Inspect matching decisions:

python drawio_tool.py drawio-debug architecture.drawio TRA/TestProject-Metrics-1.json

## Validation done during implementation

- Python compile check for drawio_tool.py passed
- End-to-end smoke test executed for:
  - drawio-parse
  - drawio-align
  - drawio-debug
- Smoke test used a minimal synthetic draw.io sample and an existing TRA JSON
- architecture edge case validated: a VM management network style container remains zone-classified and is not matched as a component
- No editor diagnostics remained in the updated file

## Current limitations

- Name-based alignment is heuristic and can still miss domain vocabulary drift:
  - close but uncommon synonyms (for example, orchestrator vs pipeline engine) may score below threshold.
  - abbreviations and project-specific shorthand may map to unintended units when token overlap is high.
  - threshold tuning is required per project maturity and naming discipline.
- Communication matching is endpoint-pair based, not intent-complete:
  - communication equivalence is decided mainly by mapped source-target pair presence.
  - protocol intent from labels is only a hint and not a deterministic semantic check.
  - one TRA communication may represent multiple runtime exchanges that appear as separate diagram links.
- Zone/container interpretation remains structural, not policy-aware:
  - container recognition uses shape/style/label heuristics and cannot infer governance boundaries by itself.
  - nested zone semantics and inherited trust constraints are not calculated from diagram geometry.
  - component-in-zone semantics still rely on TRA content as final authority.
- Evidence traceability is optimized for readability in CLI:
  - outputs focus on human-readable names in align/debug views.
  - deep forensic references still require JSON artifacts for machine audit and reproducible pipelines.
- Multi-page draw.io parsing is temporarily disabled:
  - only the first diagram page is processed in current mode.
  - architecture evidence on later pages is ignored in this revision.
  - teams using multi-page diagrams must consolidate relevant content into the first page for now.
- Role-safe zone/component matching can reduce nominal coverage at higher thresholds:
  - zone-like nodes are restricted to SecurityZone candidates and component-like nodes to component candidates.
  - near-match labels may remain unmatched when confidence is below threshold, which is preferred over cross-role misclassification.

## Next steps

### Near-term

1. Strengthen communication scoring beyond endpoint pair checks.
Description: Add a weighted communication evidence score combining endpoint match, direction consistency, and protocol/intent token compatibility from labels.
Outcome: Fewer false negatives for semantically equivalent links and clearer confidence per unmatched communication.

2. Re-enable multi-page parsing with explicit page controls.
Description: Introduce deterministic page handling (first, named page, or explicit page index list) and report exactly which pages were processed/skipped.
Outcome: Predictable behavior for large architecture diagrams without hidden cross-page ambiguity.

3. Add fixture-based regression tests for alignment edge cases.
Description: Create test fixtures for typo drift, abbreviation drift, many-to-one mapping, direction mismatch, and endpoint-unmatched links.
Outcome: Stable behavior across refactors and measurable prevention of regressions in matching outcomes.

4. Add unresolved-only reporting mode for review workflows.
Description: Provide a concise CLI output profile that prints only unmatched zones/components and communication gaps, while keeping full JSON optional.
Outcome: Faster workshop triage and cleaner handoff notes for TRA updates.

### Medium-term

1. Infer interface subtype candidates from labels and model context.
Description: Derive candidate interface classes (network, host, logical/proximity) from communication labels and owning component types.
Outcome: Better guidance on where missing TRA communications should be modeled.

2. Emit structured advisory gaps for quality workflow integration.
Description: Produce a stable machine-readable section for unresolved units/comms with severity, confidence, and recommended action type.
Outcome: Direct integration with quality report pipelines and backlog tooling.

3. Publish deterministic alignment KPIs for dashboards.
Description: Track unit coverage, communication coverage, unresolved root-cause distribution, and threshold sensitivity over time.
Outcome: Trend visibility for architecture-model alignment maturity across iterations.

4. Add pair-vs-record reconciliation diagnostics.
Description: Distinguish missing TRA pair, missing record metadata, and direction-only mismatch with actionable remediation guidance.
Outcome: Faster correction cycles with lower analyst ambiguity during TRA refinement.

### Integration path with TRA workflow

1. Run drawio-parse early after system overview collection
2. Run drawio-align against working TRA draft
3. Feed unmatched items into workshop question prompts
4. Re-run deterministic validation and quality checks
5. Keep deterministic gate as final acceptance criterion

## Recommended governance policy

- Treat draw.io alignment output as advisory evidence
- Never auto-accept low-confidence matches
- Require explicit reviewer confirmation for changes to TRA entities
- Preserve traceability by storing alignment JSON artifacts for review history

## Summary

The project now has a working baseline for architecture-to-unit alignment using draw.io XML. This supports the LLM-assisted track while keeping deterministic TRA quality and validation as the authoritative gate.

## Experiment notes (historical and threshold-dependent)

The sample industrial system architecture runs were used to drive parser and matching refinements. Exact coverage counts are threshold-dependent and can change as matching rules evolve. Use live command outputs as the authoritative numbers for any report.

Stable conclusions from the experiment history:

1. Draw.io ingestion is robust for both direct and compressed diagram payloads.
2. Role-safe matching prevents zone/component cross-classification errors.
3. Communication alignment still benefits from richer semantics beyond endpoint-pair checks.

## Current CLI behavior (code-grounded)

- `drawio-align` uses many-to-one unit matching by default.
- `--min-confidence` is available for `drawio-align` and `drawio-debug`.
- `drawio-align` unresolved output is categorized as:
  - unmatched draw.io zones
  - unmatched draw.io components
  - communication mapping gaps
- communication outputs are table-based with explicit source, target, page, and comm text columns.
- role-safe filtering is enforced between zone-like and component-like candidate classes.
