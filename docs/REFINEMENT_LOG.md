# Refinement Log

Date: 2026-09-03 (updated 2026-09-07)
Workspace: tra-quality-analysis
Primary implementation files: tra_quality_report.py, drawio_tool.py
Reference corpus file: Threat_Corpus/SampleThreatScenarios.json

## 1) Purpose
This refinement log is the implementation and audit record for metric behavior changes, removed logic, formula definitions, and reporting-output improvements.

## 1.1) Current Code Baseline (authoritative)

Source-of-truth snapshot from current `tra_quality_report.py`:

- Active core metric count is 22.
- Active metric IDs are `CM-01..CM-22`.
- IDs were renumbered to a continuous sequence; legacy IDs are documented below.

Assessment rollup model used now:

- Per metric: `ok`, `warn`, `bad`, or `na`.
- Dimension rollup is status-based (color/state aggregation), not a weighted numeric rollup.
- Metric-specific status policies still apply where defined (notably CM-02 and CM-19).

## 1.2) Metric ID Renumbering (Legacy -> Current)

| Legacy ID | Current ID | Metric |
|---|---|---|
| CM-12 | CM-10 | Asset mapping to components / communications |
| CM-13 | CM-11 | System-overview / description presence |
| CM-14 | CM-12 | Out-of-scope boundaries |
| CM-15 | CM-13 | Scope clarity by descriptions |
| CM-16 | CM-14 | No-threat / empty-analysis red flag |
| CM-17 | CM-15 | Threat specificity vs good-threat list (rule-based NLP) |
| CM-18 | CM-16 | Protection-goal C/I/A balance |
| CM-19 | CM-17 | Rating consistency across similar threats |
| CM-20 | CM-18 | Rating coherence & justification |
| CM-21 | CM-19 | Risk-treatment status workflow alignment |
| CM-22 | CM-20 | Rating-distribution / rubber-stamping detector |
| CM-23 | CM-21 | Assumption usage / linkage by type |
| CM-25 | CM-22 | Threat-structure completeness (semantic) |
| CM-26 | CM-23 | Vagueness / imprecision reduction |

## 1.3) Metric ID Renumbering Wave 2 (2026-09-07)

CM-11 (System-overview / description presence) and CM-13 (Scope clarity by descriptions) were merged into a single Comprehensibility metric, since both were really the same underlying question ("is this part of the TRA described clearly enough?"). The merged metric keeps ID `CM-11` under the new name **Documentation clarity (system overview & component descriptions)**, with two grouped readings: "System overview" and "Component descriptions". Evidence is now qualitative (descriptive vs missing/too brief) instead of reporting raw word counts, and a short overview/description that links to an arc42 section, external doc/diagram URL, or embedded image/diagram file is accepted as equivalent evidence.

This removed one active metric (23 -> 22), so every metric from the old CM-14 onward shifted down by one ID:

| Prior ID (wave 1) | Current ID (wave 2) | Metric |
|---|---|---|
| CM-11 + CM-13 | CM-11 | Documentation clarity (system overview & component descriptions) - merged |
| CM-14 | CM-13 | No-threat / empty-analysis red flag |
| CM-15 | CM-14 | Threat specificity vs good-threat list (rule-based NLP) |
| CM-16 | CM-15 | Protection-goal C/I/A balance |
| CM-17 | CM-16 | Rating consistency across similar threats |
| CM-18 | CM-17 | Rating coherence & justification |
| CM-19 | CM-18 | Risk-treatment status workflow alignment |
| CM-20 | CM-19 | Rating-distribution / rubber-stamping detector |
| CM-21 | CM-20 | Assumption usage / linkage by type |
| CM-22 | CM-21 | Threat-structure completeness (semantic) |
| CM-23 | CM-22 | Vagueness / imprecision reduction |

## 2) Baseline vs Current State

### Baseline (before recent refinement wave)
- CM-04 did not flag whitespace-only text such as newline-only strings.
- CM-06 emitted repetitive zone findings and ambiguous wording around path scope.
- CM-06 could mention exposure types not represented by modeled interface kinds in scope.
- Findings could hide failures via +N more not shown truncation.
- CM-22 evidence used generic text derived from rule output, not explicit rationale.
- CM-17 used curated good-threat vocabulary but did not support controlled corpus learning from new runs.

### Current state (after refinement)
- CM-04 flags whitespace-only strings with explicit marker WHITESPACE_ONLY and field path evidence.
- CM-06 zone findings are deduplicated, scope wording is explicit, and exposure-type checks are limited to evaluable interface kinds.
- CM-06 now reports consistent path evidence for both high-exposure and non-high-exposure unmapped interface cases.
- Findings no longer truncate fail lists for CM-aligned findings.
- CM-20 no longer assumes an even rating distribution; it now evaluates suspicious concentration with an input-diversity guard.
- CM-20 thresholds are now calibrated against the sample TRA portfolio (five datasets under TRA/) to harden defaults.
- CM-14 supports opt-in heuristic learning mode via CLI flag to append high-confidence threats to the curated list with deduplication.
- CM-17 now compares only same-interface or same-component near-duplicate threats; cross-component comparisons are excluded.
- CM-17 treats missing ratings as not assessed for inconsistency, not as a defect.
- CM-24 was retired and merged into CM-17 scope; similar-threat checks are now maintained in one metric.
- CM-10, CM-12, CM-14, and CM-15 descriptions were rewritten for cleaner professional wording without changing metric logic.
- CM-19 now validates re-rating status workflow rules (accepted-by-default, acceptable-range, avoided-risk, and treatment-progress-to-status mapping) with per-threat expected vs actual evidence.
- CM-18 findings are now grouped by mismatch type, similar to coverage-style grouped readings, to reduce mixed issue chains.
- CM-11 and CM-13 were merged into one Comprehensibility metric (`CM-11` Documentation clarity); evidence dropped raw word counts in favor of qualitative descriptive/missing wording, grouped into "System overview" and "Component descriptions" sub-readings; short text with an arc42/diagram/image reference is accepted as equivalent evidence. All subsequent metric IDs (former CM-14..CM-23) shifted down by one to CM-13..CM-22.

## 3) Metrics Removed, Renamed, or Re-scoped

| Item | Before | After | Why |
|---|---|---|---|
| CM-06 zone wording | examined path | zone scope (zone + sub-zones + assigned in-scope components) | remove ambiguity and improve reviewer interpretation |
| CM-06 duplicate exposure lines | one line per high exposure type | merged line per zone with combined exposure types | reduce misleading repetition |
| CM-06 exposure type applicability | could mention Host/Proximity without modeled host/proximity interfaces | checks only evaluable interface kinds in scope | prevent false interpretation |
| CM-06 evidence asymmetry | some zones showed high-exposure unmapped suffix, others no suffix | both cases now show path evidence; alternate suffix for none-high cases | consistent reviewer traceability |
| Findings truncation | +N more not shown in key finding lists | full fail list emitted for CM-aligned findings and CM-18 surfaced list | avoid buried checks |
| CM-20 distribution assumption | low discrimination automatically treated as suspect | concentration is only suspicious when coupled with low input diversity | avoid false positives in high-coverage Moderate-heavy portfolios |
| CM-20 evidence text | discrimination percentage only | dominant-share percentage plus input-diversity context | make outcome explainable without assuming even spread |
| CM-04 whitespace handling | whitespace-only strings could pass placeholder checks | whitespace-only strings flagged as unfinished content | catch practical data-quality gap |
| CM-14 corpus update mode | static corpus only | optional heuristic append mode | allow controlled corpus growth over repeated runs |
| CM-17 comparison scope | all near-duplicate pairs could be compared | only same-interface or same-component pairs are compared | avoid false defects from expected cross-component risk differences |
| CM-17 missing rating handling | missing rating could be read as inconsistency context | missing rating is explicitly treated as not assessed for inconsistency | align with reviewer intent and avoid false negatives |
| CM-24 metric lifecycle | standalone duplicate/similarity count metric | retired and merged into CM-17 | keep one similar-threat metric and reduce overlap |
| CM-18 fail presentation | mixed semicolon issue chains in one list | grouped by issue type (matrix mismatch, rationale gap, calc mismatch/underivable, semantic overrides) | improve reviewer triage speed and reduce confusion |
| CM-11/CM-13 metric lifecycle | two separate metrics: system-overview presence and component-description clarity | merged into one `CM-11` Documentation clarity metric with grouped sub-readings | both checked the same underlying question (clear-enough description); reduce overlap and simplify the catalog |
| CM-11/CM-13 evidence style | raw word counts shown per field/component ("15 word(s)") | qualitative descriptive/missing wording, with arc42/diagram/image reference accepted as equivalent evidence | word counts are not meaningful to reviewers on their own; a linked reference is equally valid proof of clarity |

## 4) Formula and Decision Rules by Metric

Legend
- num = number of passed checks or covered items
- den = assessed population
- status is derived from ratio or explicit policy unless noted
- kind=count metrics use low is better semantics

| Metric | Dimension | Formula / Rule | Status basis | Key refinement notes |
|---|---|---|---|---|
| CM-01 Workshop participation | Process & Governance | num = workshops passing participant list + moderator + min participant threshold; den = workshops | ratio (higher better), na when no workshops | structured fields plus fallback parser for comments; participant evidence expanded with names, rights, gid |
| CM-02 Living-document maintenance | Process & Governance | evaluated checks: recency within 1 year and maintenance gap > 30 days, with gap skipped for initial version 1.0 | explicit policy: 2 fails bad, 1 fail warn, 0 fail ok, missing required fields na | outcome wording and evidence lines standardized |
| CM-03 Mandatory field and section completion | Formal Completeness | num = passed required-field checks across required sections; den = total required checks including section presence and component extra check | ratio (higher better) | schema-aligned required fields; in-scope component must define interface or communication unless generic placeholder component |
| CM-04 Placeholder or unfinished-entry detection | Formal Completeness | num = placeholder or unfinished hits; den = none; kind=count, lower better | count thresholds | recursive field scan now includes WHITESPACE_ONLY detection for newline/space-only text |
| CM-05 Assumption validation ratio | Formal Completeness | num = assumptions with validated=true; den = assumptions | ratio (higher better), na when no assumptions | split from CM-03 granularity to isolate validation behavior |
| CM-06 Interface-Threat Coverages | Coverage | num = component coverage pass + interface mapping pass + zone high-exposure coverage pass; den = in-scope components + declared interfaces + evaluable high-exposure zone checks | ratio (higher better), na when den=0 | deduped zone lines, explicit zone scope wording, evaluable exposure-type filtering, consistent path evidence |
| CM-07 High-exposure communication-specific threat coverage | Coverage | num = high-exposure communication edges with communication-specific threat coverage; den = assessed high-exposure communication edges | ratio (higher better), na when no communications/assessed edges | keeps edge-specific coverage distinct from generic interface-only links |
| CM-08 Asset-Protection-goal mapping | Coverage | num = assets covered by at least one protection goal; den = assets | ratio (higher better) | fail details grouped and fully listed |
| CM-09 Protection-goal-Threat Coverage | Coverage | num = Critical protection goals linked to at least one threat; den = Critical protection goals | ratio (higher better), na when no Critical goals | lower-impact goals explicitly listed as ignored with optional mapped context |
| CM-10 Asset mapping to components and communications | Coverage | num = assets traceable via asset -> protection goal -> threat -> attacked interface -> component or communication; den = assets | ratio (higher better), na when no assets | grouped fail evidence with cause-specific reasons |
| CM-11 Documentation clarity (system overview & component descriptions) | Comprehensibility | num = (1 when system overview is descriptively covered) + (components whose description is descriptively covered); den = 1 + component count | ratio (higher better) | merged former CM-11 + CM-13; grouped into "System overview" and "Component descriptions" sub-readings; qualitative evidence (no raw word counts); arc42/diagram/image reference accepted as equivalent evidence for short text |
| CM-12 Out-of-scope boundaries | Coverage | num = out-of-scope components with justification; den = out-of-scope components | ratio (higher better), na when no out-of-scope components | grouped fail evidence |
| CM-13 No-threat or empty-analysis red flag | Coverage | num = 1 when threats exist else 0; den = 1 | binary ratio | hard red-flag behavior unchanged |
| CM-14 Threat specificity vs good-threat list | Consistency & Traceability | num = threats marked specific by composite heuristic; den = threats | ratio (higher better), na when no threats | IDF-weighted concrete term logic; shared evaluator used by optional learning mode |
| CM-15 Protection-goal C, I, A balance | Consistency & Traceability | num = represented CIA types; den = 3 | ratio (higher better) | direct coverage of CIA spread |
| CM-16 Rating consistency across similar threats | Consistency & Traceability | num = comparable similar-pair count minus inconsistent high-severity rated pairs; den = comparable similar-pair count | ratio (higher better), na when no comparable pairs | comparable means same interface or same owning component; cross-component pairs excluded; missing ratings are not counted as inconsistencies |
| CM-17 Rating coherence and justification | Consistency & Traceability | num = threats where risk equals matrix expectation, has rationale, and passes calc/semantic consistency checks; den = threats | ratio (higher better), na when no threats | fail output now carries typed mismatch tags and grouped issue buckets |
| CM-18 Risk-treatment status workflow alignment | Consistency & Traceability | num = threats whose re-rating/status path matches policy; den = threats | ratio (higher better), na when no threats | validates accepted-by-default when no re-rating, no CALCstatus for No_Re_rating, acceptable-range check against previous risk, and treatmentProgress-to-CALCstatus mapping (Open/Passed/Not passed) |
| CM-19 Rating-distribution rubber-stamping detector | Consistency & Traceability | value = dominant-share = modal_count/rated_count; evaluated together with input-combination diversity across impact/likelihood/applied exposure/exploitability | calibrated concentration policy: bad when dominant_share >= 90% and diversity < 30%; warn when dominant_share >= 80% and diversity < 40%; rationale guard warn when >60% dominant-rating threats lack comments; na when rated_count < 7 | mandatory KPI candidate; tuned on sample portfolio to avoid false alarms where high coverage naturally yields many Moderate ratings |
| CM-20 Assumption usage by type | Consistency & Traceability | num = referenced General assumptions; den = General assumptions | ratio (higher better), na when no General assumptions | excludes ZoneSpecific and ThreatSpecific from denominator by design |
| CM-21 Threat-structure completeness | Comprehensibility | num = total filled semantic slots across threats; den = total slots across threats | ratio (higher better), na when no threats | pass entries now include present slot names |
| CM-22 Vagueness or imprecision reduction | Comprehensibility | num = threats with fewer than 2 vague terms in description; den = threats | ratio (higher better), na when no threats | vague-term evidence is explicit per threat |

CM-16 similar-threat policy
- CM-16 is the single active similar-threat metric.
- It evaluates rating consistency only on comparable near-duplicate pairs (same interface or same component).
- CM-24 duplicate counting was retired and merged into this scope.

CM-18 when-it-flags policy
- Flags `RR_CALC_STALE` when `treatmentProgress=Completed` but `CALCrrRiskRating` is still `No_Re_rating`, `NoRating`, `Incomplete`, or empty.
- Flags when `CALCrrRiskRating=No_Re_rating` but `isAcceptedByDefault=false`.
- Flags when `CALCrrRiskRating=No_Re_rating` still carries a `CALCstatus` value.
- Flags when non-avoided threats have missing or `Incomplete` residual risk rating.
- Flags when `CALCstatus` disagrees with expected status from treatment progress or acceptable-range logic.

## 5) CM-14 Heuristic Learning Mode

Feature summary
- New optional flag: --learn-good-threats
- File updated: Threat_Corpus/SampleThreatScenarios.json
- Behavior: append only high-confidence, deduplicated candidates

Append gates
- must pass CM-14 specificity decision
- score must be at least 0.75
- concrete language gate must pass
- AttackInterface link must exist
- attackActionDesc must meet minimum quality length thresholds
- candidate must not be placeholder or excluded commentary text
- candidate must be new under normalized text signature deduplication

Safeguards
- corpus is not auto-updated unless flag is provided
- signature-based dedupe prevents repeated inflation
- id allocation is deterministic and sequential using GT-xxxx format
- cache invalidated after write so same process can see updates

## 5.1) CM-14 Verifiability Evidence (Report Output)

CM-14 now exposes algorithm evidence directly in report output so reviewers can audit why a threat passed or failed specificity.

Per-threat evidence fields in CM-14 detail
- score value from weighted heuristic
- iface_link boolean contribution
- concrete_strength value computed from IDF-weighted matched terms
- trigger_terms list with per-term normalized IDF contribution in the form term:weight

CM-14 method metadata in CM-14 detail.info
- vocabulary source counts: files scanned, entries seen, entries accepted, final vocab size
- filter policy summary: stopwords, generic terms, placeholder exclusion, non-threat exclusion, empty-entry exclusion
- specificity formula statement with thresholds
- concrete-language gate definition

Audit intention
- A reviewer can inspect one CM-14 row and independently understand:
	- which terms triggered the concrete-language signal
	- whether score threshold and gate threshold were met
	- how the vocabulary was constructed from corpus inputs

## 6) Reporting and Readability Refinements

- Findings no longer hide metric failures behind +N more not shown for CM-aligned blocks.
- CM-06 language now states zone scope explicitly and avoids non-evaluable exposure wording.
- CM-06 zone messages now include path evidence in both high-exposure and none-high-exposure suffix cases.
- CM-19 evidence now communicates dominant-share plus diversity context instead of assuming even distribution.
- CM-19 includes explicit formula and threshold explanation lines in metric detail.info for reviewer transparency.
- CM-01 workshop fail details are flattened into clean bullet lines for dropdown readability.
- CM-10, CM-12, CM-13, and CM-14 now use cleaner description text in report output for reviewer readability.
- CM-17 now includes grouped issue sections by mismatch type, similar to grouped coverage readings.
- CM-11 (merged from former CM-11 + CM-13) now groups "System overview" and "Component descriptions" as separate sub-readings and drops raw word-count evidence in favor of qualitative wording.

## 7) Validation Runs Executed

Commands used
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\IndustrialSystem-ExampleTRA-v2.0.json
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\IndustrialSystem-ExampleTRA.json
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\TestProject-Metrics-1.json
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\TestProject-Metrics-2.json
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\IndustrialSystem-ExampleTRA.json --learn-good-threats
- .venv/Scripts/python.exe .\tra_quality_report.py .\TRA\TestProject-Metrics-2.json

Validation result summary
- all runs completed successfully
- metric sets remained consistent across generated reports
- CM-04 whitespace-only IOEdescription now flagged with explicit evidence
- CM-06 zone messaging is deduplicated and scope-clarified
- CM-19 now evaluates concentration with diversity guard and reports dominant-share evidence
- CM-19 threshold calibration validated on five sample TRA datasets with no false-positive concentration flags
- learning mode successfully appended high-confidence entries with deduplication
- CM-16 now scopes consistency checks to same-interface/same-component pairs and excludes cross-component differences
- CM-16 missing-rating pairs are treated as not assessed for inconsistency
- CM-18 now emits per-threat workflow evidence (mitigation yes/no, base risk, re-rated risk, treatment progress, actual status, expected status logic)
- CM-17 fail details are grouped by issue type for clearer reviewer triage
- CM-11 merge/renumbering wave verified end-to-end: regenerated report shows continuous CM-01..CM-22 IDs, grouped "System overview"/"Component descriptions" sub-readings, no raw word-count evidence, and decision tables for CM-17/CM-18/CM-19 render correctly at their shifted positions

## 8) Open Items for Next Refinement Cycle

- Add reviewer approval queue mode for CM-14 learning candidates before corpus append.
- Add multi-run confirmation gate for learned threats to reduce one-off noise.
- Add clickable field-path linking in HTML for direct trace-back navigation.
- Add structured changelog export artifact in JSON for release-note generation.

## 9) Change Governance Notes

- This log is the authoritative refinement documentation for the current code state.
- When metric logic changes, update this file in the same commit with formula deltas and rationale.
- If a metric denominator changes, document impact analysis with at least one cross-TRA before/after run.

## 10) Draw.io Alignment Addendum (2026-09-03)

Scope
- This addendum tracks refinements made in `drawio_tool.py` and documentation updates related to architecture-to-TRA alignment.

Key updates
- Zone classification was generalized to structural cues (container/group/swimlane/boundary) rather than relying on zone-name keywords.
- Role-safe matching was enforced:
	- draw.io zone-like nodes can map only to TRA `SecurityZones`
	- draw.io component-like nodes can map only to TRA `SystemComponents` or `SWComponents`
- Rejection explanations now use role-compatible candidate lists so unmatched reasons are not misleading.
- Communication tables were standardized across all draw.io commands using clear source/target/page/comm-text columns.

Validation snapshot
- IndustrialSystem architecture case verified with `drawio-parse`, `drawio-align`, and `drawio-debug`.
- The prior edge case where a zone-like node could appear as component-matched was resolved.

## 11) Carry-forward Checklist from Prior Sessions

Applied carry-forward items:

- [done] Default report output path now writes under `TRA-Quality report/<input-json-filename>/`.
- [done] CM-03 component rule clarified to accept at least one interface or one communication for in-scope components.
- [done] CM-01 workshop evidence includes participant/moderator detail and improved bulletized readability.
- [done] CM-02 initial-version handling normalized (1, 1.0, 1.0.0, v1.0 patterns).
- [done] CM-04 detects whitespace-only unfinished text.
- [done] CM-17 limited to comparable pairs (same-interface or same-component), excluding cross-component false inconsistencies.
- [done] CM-18 mismatch reporting grouped by issue type for reviewer triage.
- [done] CM-19 workflow alignment checks expanded with expected-vs-actual status evidence.
- [done] CM-07 generic-interface-only case is presented with explicit bulletized detail.
- [done] CM-28 removed from active core metric computation and output path.
- [done, historical] Active core set aligned to 23 metrics (`CM-01..CM-23`) in the prior-session checkpoint.

Verification note:

- Historical checkpoint above recorded 23 active metrics.
- Current runtime baseline (after later renumber/merge wave) is 22 active metrics (`CM-01..CM-22`).

## 12) Refinement Wave 3 (2026-09-07, continued)

Five items requested and implemented in this wave; all validated by running the report against `TRA/IndustrialSystem-ExampleTRA.json` and `TRA/PatientRecordManagemenSystem-ExampleTRA.json`, plus a standalone smoke test of the new CLI flag.

### 12.1) CM-11 — per-field evidence, brevity-is-not-a-fail clarified

- Removed leftover debug `print()` statements from the CM-11 block (external edit artifact found at session start; `OVERVIEW_MIN_WORDS` had also been changed from 20 to 150 externally — left unchanged per this wave's scope).
- System overview is now checked across exactly 4 candidate fields: `IntendedOp.IOEdescription`, `Overview`, `scopeDescription`, `highLevelDescription`.
- Combined word-count threshold logic is **unchanged** (kept per explicit user decision: "keep word-count threshold, just also list field names").
- Evidence now lists which of the 4 fields are present vs absent for both pass and fail cases (e.g. `fields absent: IntendedOp.IOEdescription, Overview, scopeDescription, highLevelDescription`). A short/absent individual field is not itself treated as a failure as long as the combined text clears the threshold or a reference is present.

### 12.2) CM-21 — slot definitions, worked example, disputed-result caveat

- Added an `info` block (`detail.info`, rendered as an expandable "readings" panel) documenting:
  - the exact detection logic for each of the 6 slots (action, actor, interface, weakness, impact, protection_goal);
  - a concrete worked example (6/6 slots present vs. a 5/6 case missing `protection_goal`);
  - an explicit caveat that this is a heuristic structural/keyword check, not semantic understanding, and that the current pass/fail result is disputed and should be manually reviewed.

### 12.3) CM-22 — reclassified as informational, scans all text fields

- Added `extract_vague_term_hits()`, which recursively scans **every** string field (≥3 words) of a threat object for vague/generic terms, replacing the prior `attackActionDesc`-only check.
- Fail evidence now names both the vague terms and the field path(s) where they were found.
- Metric is flagged `informational=True` and its `note` documents the reclassification rationale: "a coarse keyword signal of limited practical value on its own."
- `compute_dimension_status()` now excludes `informational`-flagged metrics from the dimension OK/WARN/BAD rollup (still fully computed and shown in the report). Verified: Comprehensibility dimension `total` dropped from 3 to 2 (CM-11 + CM-21 only) in both validation runs.

### 12.4) Global proxy-metric caveat

- Added a caveat note to the "Core metric assessment" HTML panel and to `README.md` naming `CM-11`, `CM-21`, `CM-22` as text-length/keyword-based proxies: a long or keyword-matching field is not automatically well-written, and a short one is not automatically wrong; treat results as prompts for reviewer judgement, not final verdicts.
- Added an "Informational" HTML badge (gray, with tooltip) shown next to the Auto/Semi-auto badge for any metric flagged `informational=True`.

### 12.5) Data-driven threshold calibration (new feature)

- New CLI flag `--calibrate-thresholds [DIR]` (default `Calibration_Corpus/`), modeled directly on the existing `--learn-good-threats` pattern: corpus-driven, deterministic, nothing auto-applied, human-reviewed.
- Expects a labeled corpus: `<DIR>/good/*.json` and `<DIR>/poor/*.json` (real TRA exports).
- `calibrate_thresholds()` computes, per labeled TRA: system-overview word count, component-description word counts, per-threat specificity scores (reusing `_cm17_evaluate_threat`), and pairwise threat token-Jaccard duplicate scores (reusing `tokenize_security_terms`).
- `_best_separating_threshold()` performs a brute-force best-split scan to find the threshold value maximizing good/poor classification accuracy for each of: `OVERVIEW_MIN_WORDS`, `SCOPE_DESC_MIN_WORDS`, `SPECIFICITY_PASS_THRESHOLD`, `JACCARD_DUP_THRESHOLD`.
- Writes `<DIR>/calibration_report.json`; also prints a console summary. Runs standalone (`json` positional argument is now optional when `--calibrate-thresholds` is used alone) or combined with normal report generation.
- Validated: empty-corpus run (0/0 files) reports `suggested=None` ("insufficient labeled samples") for all 4 metrics without crashing; a smoke test with 1 good + 1 poor sample file produced real suggested values (e.g. `SPECIFICITY_PASS_THRESHOLD: current=0.65 suggested=0.8`). The temporary smoke-test corpus was deleted after validation — no `Calibration_Corpus/` directory is committed.

### 12.6) Minor fix

- Corrected stale CLI help text for `--learn-good-threats` ("Heuristic CM-15 learning mode" → "Heuristic CM-14 learning mode"), a leftover from a prior renumbering wave.

### 12.7) Validation summary

- `get_errors` clean (only the pre-existing, known-harmless `tra_tool` optional-import warning).
- Full report runs completed without exceptions against two sample TRAs; CM-11/CM-21/CM-22 evidence and HTML rendering (info panel, caveat text, Informational badge) all confirmed present in output.
- `--calibrate-thresholds` validated both with an empty corpus and a seeded 1-good/1-poor corpus.

## 13) CM-02 Maintenance-Gap False-Positive Fix (2026-09-07, continued)

Reported finding: `PatientRecordManagemenSystem-ExampleTRA.json` flagged "Maintenance gap check: Flagged. Gap between project creation and version changed dates is only 4 days" despite the TRA already being at version 3 (i.e. two prior revisions had already occurred within those 4 days).

- Root cause: the maintenance-gap check required `gap_days > 30` for any non-initial version, treating a *short* gap as evidence of neglect. This conflated rapid, active early-stage iteration (a good sign) with staleness (the actual risk the check was meant to catch).
- Fix: for non-initial versions, the check now passes as long as there is **any measurable elapsed time** (`gap_seconds > 0`) between project creation and the version-changed date. A non-initial version number is itself already proof that a real revision occurred; requiring an additional 30-day wait penalized fast-moving projects. Only a zero/negative gap (changed date at or before creation — a data anomaly) is now flagged as unverifiable.
- Evidence wording updated to explain the new semantics: passes now read "Version N shows real elapsed time (X day(s)) since project creation, evidencing active revision (rapid version progression counts as active maintenance, not staleness)."; the CM-02 `note` field was updated to match.
- Validated: `PatientRecordManagemenSystem-ExampleTRA.json` CM-02 changed from `1 checked, 2 assessed [WARN]` to `2 checked, 2 assessed [OK]`. Re-ran `IndustrialSystem-ExampleTRA.json` (initial version 1, gap check skipped) to confirm no regression — unchanged at `1 checked, 1 assessed [OK]`.


