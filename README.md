# TRA Quality Analysis Report

**Version 0.1** -- early release. The metric catalog and scoring thresholds are stabilizing, and feedback on real-world TRA exports is actively sought.

A fully deterministic, offline command-line tool that reads a Threat & Risk Analysis (TRA) JSON export and measures its quality against a structured catalog of 28 core metrics. It produces:

- a standalone HTML dashboard
- a machine-readable JSON metrics file

You can open the HTML report directly in any browser or consume the JSON in scripts, pipelines, or further analysis.

> No AI. No internet. No external services.
> Every score is computed from local JSON content using deterministic rules.
> The same input always produces the same output.

---

## What the tool does

A TRA records assets, protection goals, threat scenarios, components, interfaces, assumptions, communications, and security zones for a system under analysis. The quality of that artifact determines how reviewable, explainable, and trustworthy the analysis is.

This tool answers a practical question:

**How complete, consistent, and reviewable is this TRA artifact?**

It reports:

- an overall quality score from 0 to 100
- per-dimension scores across five quality dimensions
- one traffic-light status per metric: `OK`, `WARN`, or `BAD`
- detailed pass/fail evidence naming the concrete elements involved
- a findings panel with `HIGH` and `WARN` review signals

Important boundary:

- a high score does **not** certify substantive domain correctness
- the tool evaluates the structured artifact, not the full expert context behind it

---

## How it works

The tool is fully local and deterministic.

| Does not use | Uses instead |
|---|---|
| LLMs or AI APIs | Hard-coded rules, ratios, regexes, and matrix lookups |
| Internet or cloud services | Local file I/O only |
| External databases | A bundled local reference corpus in `data/Good_TRA_Threat_List/` |
| ML classifiers | Deterministic structural and text-pattern checks |
| Randomness or sampling | Pure Python logic with repeatable outputs |

The only corpus-based metric is **CM-17 (threat specificity)**, which compares threat wording against a curated local good-threat vocabulary loaded from `data/Good_TRA_Threat_List/`. This is still rule-based logic, not a model call.

All other metrics are computed by structural inspection of the supplied JSON: presence checks, counts, ratios, link tracing, similarity thresholds, and exact matrix lookups.

---

## Installation

The tool uses only the Python standard library.

### Option 1: Use an existing Python installation

Requirements:

- Python 3.10 or later
- No third-party packages

Run directly:

```powershell
python src\tra_quality_report.py path\to\your_tra.json
```

### Option 2: Create an isolated environment with `uv`

```powershell
# Install Python 3.12 locally (one time)
uv python install 3.12

# Create a virtual environment
uv venv .venv --python 3.12

# Activate it
.venv\Scripts\Activate.ps1
```

No package installation step is required.

---

## Usage

```powershell
python src\tra_quality_report.py path\to\your_tra.json
```

Optional output paths:

```powershell
python src\tra_quality_report.py path\to\your_tra.json `
    --html-out reports\dashboard.html `
    --metrics-out reports\metrics.json
```

CLI summary:

```text
usage: tra_quality_report.py [-h] [--html-out PATH] [--metrics-out PATH] json

positional arguments:
  json               Path to a TRA JSON export

options:
  --html-out PATH    Write HTML report to PATH
                     (default: <input>_quality_report.html)
  --metrics-out PATH Write JSON metrics to PATH
                     (default: <input>_quality_metrics.json)
```

---

## Outputs

| File | Description |
|---|---|
| `*_quality_report.html` | Self-contained HTML report; open locally in any browser |
| `*_quality_metrics.json` | Full machine-readable analysis result |

The HTML report contains:

- a score hero with the overall score and dimension cards
- a core metric scorecard grouped by quality dimension
- expandable pass/fail evidence for each metric
- a findings panel with recommended actions

---

## Scoring system

### Metric status

Each metric is reduced to a traffic-light status.

#### Standard grading rules

| Metric type | Rule | Status |
|---|---|---|
| Percentage metric (`better = high`) | >= 90 -> `OK`; >= 60 -> `WARN`; < 60 -> `BAD` |
| Percentage metric (`better = low`) | <= 10 -> `OK`; <= 40 -> `WARN`; > 40 -> `BAD` |
| Count metric (`lower is better`) | 0 -> `OK`; <= 5 -> `WARN`; > 5 -> `BAD` |

#### Custom grading rule

`CM-22` uses a dedicated discrimination rule rather than the generic percentage thresholds:

| CM-22 discrimination score | Status |
|---|---|
| >= 50 | `OK` |
| >= 25 and < 50 | `WARN` |
| < 25 | `BAD` |

### Status weights

Scores are aggregated from status weights:

```text
OK   = 100
WARN =  60
BAD  =  20
N/A  = excluded from scoring
```

### Dimension score

Each quality dimension is the unweighted mean of the status weights of its applicable metrics.

### Overall score

The overall score is the unweighted mean of the status weights of all applicable core metrics.

Important:

- this is a **status-weighted** score, not a raw arithmetic mean of the underlying percentages
- `N/A` metrics remain visible in the report but do not affect dimension or overall scores

---

## Quality dimensions and metrics

The tool implements 28 core metrics across five dimensions.

### Process & Governance

| ID | Metric | What it checks |
|---|---|---|
| CM-01 | Relevant-role / workshop participation | Workshop presence, participant count, and moderator presence |
| CM-02 | Living-document maintenance | `changedDate` is later than `createdDate` |
| CM-27 | Authority-approval presence | Approval / sign-off markers exist in key sections |
| CM-28 | Known-deficiency evidence references | The TRA references external evidence such as SRS, SCA, pen-test, CVE, or EOL artifacts |

Notes:

- CM-01 cannot infer true role adequacy from current exports; it checks workshop structure only.
- CM-27 and CM-28 often become `N/A` when the export schema does not carry the needed metadata.

### Formal Completeness

| ID | Metric | What it checks |
|---|---|---|
| CM-03 | Mandatory field / section completion | Required sections exist and are non-empty |
| CM-04 | Placeholder / unfinished-entry detection | Placeholder tokens such as `TBD`, `TODO`, `FIXME`, `QUESTION`, `??` |
| CM-05 | Assumption validation ratio | Share of assumptions marked as validated |

### Coverage

| ID | Metric | What it checks |
|---|---|---|
| CM-06 | Component coverage by threats | In-scope components reached by at least one threat |
| CM-07 | Interface coverage by threats | Declared interfaces used as attack surfaces |
| CM-08 | External / network-facing interface coverage | External interfaces used as attack surfaces |
| CM-09 | Communication coverage by threats | Communication edges whose target interface is attacked |
| CM-10 | Protection-goal coverage in threat analysis | Relevant protection goals linked to threats |
| CM-11 | Asset coverage / asset-to-protection-goal mapping | Assets covered by protection goals |
| CM-12 | Asset mapping to components / communications | Asset traceability through protection goal -> threat -> attacked interface |
| CM-14 | Out-of-scope boundaries | Explicit justification for excluded components |
| CM-16 | No-threat / empty-analysis red flag | At least one threat scenario exists |

### Consistency & Traceability

| ID | Metric | What it checks |
|---|---|---|
| CM-17 | Threat specificity vs good-threat list | Distinctive, technically specific wording using a local reference vocabulary |
| CM-18 | Protection-goal C/I/A balance | Confidentiality, Integrity, and Availability are all represented |
| CM-19 | Rating consistency across similar threats | Near-duplicate threats retain coherent ratings |
| CM-20 | Rating coherence & justification | Stored risk matches the matrix and a rationale comment is present |
| CM-21 | Risk-treatment / handling decision coverage | Threats have a documented treatment decision |
| CM-22 | Rating-distribution / rubber-stamping detector | Ratings are not collapsed onto one repeated label |
| CM-23 | Assumption usage / linkage by type | General assumptions are actually referenced |
| CM-24 | Duplicate / similar-threat detection | Near-duplicate threat pairs above the similarity threshold |

### Comprehensibility

| ID | Metric | What it checks |
|---|---|---|
| CM-13 | System-overview / description presence | Overview text has at least the minimum required substance |
| CM-15 | Scope clarity by descriptions | Component descriptions are informative enough |
| CM-25 | Threat-structure completeness (semantic) | Threats contain the expected semantic slots |
| CM-26 | Vagueness / imprecision reduction | Threat descriptions are not dominated by vague wording |

---

## How key metrics are evaluated

All evaluation is local JSON inspection.

### Generic percentage metrics

Most percentage-style metrics follow:

```text
score = passing_items / total_items * 100
```

Example: `CM-06`

1. Collect all in-scope components.
2. Collect all attacked interfaces from the threat set.
3. Mark a component as covered if one of its interfaces, or a communication path into it, is attacked.
4. Score = covered components / in-scope components * 100.

### Count metrics

- `CM-04`: raw placeholder hit count across flattened text fields
- `CM-24`: number of near-duplicate threat pairs above the Jaccard threshold

### Binary / 1-of-1 metrics

Metrics such as `CM-02`, `CM-13`, and `CM-16` are structurally evaluated as 1/1 pass-fail checks and then converted into a status.

### CM-17: Threat specificity

This is the most detailed rule-based text metric.

For each threat, the tool combines three signals:

- `+0.30` for a concrete interface link
- `+0.40` for distinctive technical language matched against the local corpus
- `+0.30` for sufficient substantive wording without excessive vagueness

A threat passes only if its total score is at least `0.65`.

This prevents a merely verbose but generic description from passing.

### CM-19: Rating consistency across similar threats

1. Build pairwise threat comparisons.
2. Compute token-Jaccard similarity on the threat wording.
3. For pairs above the duplicate threshold, compare risk ratings.
4. Only disagreements involving at least one moderate-or-higher rating count as inconsistencies.

### CM-20: Rating coherence & justification

For each threat:

```text
Likelihood = LIKELIHOOD_MATRIX[exploitabilityRating][exposureRating]
Expected   = RISK_MATRIX[impactRating][Likelihood]
Pass       = stored risk == expected AND rationale comment exists
```

### CM-22: Rubber-stamping detector

```text
discrimination = (1 - modal_rating_count / total_rated_threats) * 100
```

If too many threats share the same risk rating, the TRA is flagged as potentially over-homogeneous.

---

## Findings panel

The findings panel is a second presentation layer built on top of the metrics.

It emits `HIGH` and `WARN` findings after the metric computation stage.

Examples of escalation logic:

- a `WARN` becomes `HIGH` when at least 50% of a relevant population is affected
- uncovered assets are always `HIGH`
- any failing area not already covered by a curated rule still produces a corresponding finding

This keeps the dashboard summary aligned with the underlying scorecard.

---

## Supported TRA schemas

The tool auto-detects the schema variant from the JSON structure.

| Target area | Component key | Interface families | Communication key |
|---|---|---|---|
| Software Component development | `SWComponents` | `LogicalInterfaces`, `HostLevelInterfaces_Zone`, `NetworkFacingInterfaces_Zone` | `InterSWCommunications` |
| Design & Deployment of a System | `SystemComponents` | `NetworkFacingInterfaces`, `ProximityInterfaces` | `NetworkCommunications` |

Inner field names such as `interface_id`, `subUnit_id`, `attackActionDesc`, and `TargetInterface` are shared, so the same metric logic runs on both variants.

---

## Repository structure

```text
.
├── src/
│   └── tra_quality_report.py     # the tool: CLI, metrics, scoring, HTML render
├── data/
│   └── Good_TRA_Threat_List/     # local reference corpus used by CM-17
├── tests/
│   ├── test_improvements.py      # similarity-filter unit check
│   └── validate_tra_metrics.py   # seeded-defect + threshold validation harness
├── examples/
│   ├── README.md
│   └── sample_quality_report.html
├── docs/
│   ├── TRA_Quality_Scoring_Presentation.md
│   └── TRA_Quality_Metrics_Catalog_v3.xlsx
├── scripts/
│   └── generate_maturity_assessment.py
├── MiniCPS_Evaluation/           # reproducible evaluation case study
├── requirements-dev.txt
└── README.md
```

Key files for the tool itself:

- `src/tra_quality_report.py` -- CLI, metric computation, scoring, and HTML rendering
- `data/Good_TRA_Threat_List/` -- local reference corpus used by CM-17

---

## Requirements

- Python 3.10 or later
- No third-party packages
- Windows, macOS, or Linux

Standard-library modules used include `argparse`, `json`, `re`, `math`, `html`, `os`, and `sys`.

The auxiliary evaluation and generator scripts need a few third-party packages, listed in `requirements-dev.txt` (`matplotlib`, `numpy`, `openpyxl`). The core tool never imports them.

---

## Reproducing the evaluation

The thesis evaluation runs entirely on the **public MiniCPS/SWaT reference TRA** in
`MiniCPS_Evaluation/tra/minicps_swat_tra.json`, so every result below can be
regenerated without any confidential data.

### 1. Set up an environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

### 2. Score the reference TRA

```powershell
python src\tra_quality_report.py MiniCPS_Evaluation\tra\minicps_swat_tra.json `
    --html-out examples\sample_quality_report.html `
    --metrics-out examples\sample_quality_metrics.json
```

Expected: overall quality **90%** (status-weighted), with the per-dimension
breakdown printed to the console.

### 3. Controlled mutation experiment (L1)

```powershell
python MiniCPS_Evaluation\run_mutation_experiment.py
```

This derives the 13 single-defect variants (`V1..V13`), scores each against the
reference, and writes:

| Output | Description |
|---|---|
| `MiniCPS_Evaluation/results/delta_status_matrix.csv` | Variant x criterion status-weight change (primary artefact) |
| `MiniCPS_Evaluation/results/delta_value_matrix.csv` | Raw metric-value change (audit trail) |
| `MiniCPS_Evaluation/results/overall_scores.csv` | Overall + per-dimension score per variant |
| `MiniCPS_Evaluation/results/precision_recall.csv` | Detector precision / recall / F1 |
| `MiniCPS_Evaluation/results/variants/V1..V13.json` | Persisted mutated TRAs |
| `MiniCPS_Evaluation/results/figures/delta_matrix.png` | Heat-map of the status-weight matrix |

Expected headline numbers: reference `V0` overall **89.6**; defect detector
**precision 0.905**, **recall 0.950**, **F1 0.927** (TP=19, FP=2, FN=1).

### 4. Threshold sensitivity analysis

```powershell
python MiniCPS_Evaluation\run_sensitivity_analysis.py
```

Re-scores a clean (`V0`), mildly damaged (`V4`), and heavily damaged (`V2`) TRA
under low / default / high settings of five thresholds and writes
`MiniCPS_Evaluation/results/sensitivity_analysis.csv`.

Expected: the ordering **clean > mild > heavy** (89.6 > 87.8 > 77.4) is stable
across all threshold settings.

### 5. Validation harness and unit checks

```powershell
python tests\validate_tra_metrics.py MiniCPS_Evaluation\tra\minicps_swat_tra.json
python tests\test_improvements.py
python -m pytest -q tests\test_thesis_regression.py
```

The pytest suite is the machine-checkable regression gate for thesis evidence:

- reference baseline scorecard (V0)
- mutation-detector totals and precision/recall/F1
- threshold-sensitivity ordering stability

---

## Relationship to the thesis draft

The README and thesis should stay aligned on these points:

- the five dimensions and the placement of CM-13 and CM-15 under **Comprehensibility**
- traffic-light status names: `OK`, `WARN`, `BAD`
- status weights: `100 / 60 / 20`
- the special handling of `N/A` metrics
- the custom grading logic for `CM-22`
- the statement that high scores indicate structural quality signals, not full expert semantic validity

In the thesis draft, the corresponding explanation lives mainly in:

- Chapter 6 scoring scheme and thresholds
- Chapter 7 output/reporting
- Chapter 8 evaluation results
- the appendix with full metric definitions and worked scorecard

---

## Feedback and metric refinement

This is an early release. The 28 metrics and their thresholds were derived from expert interviews and review practice, but broader cross-domain validation is still future work.

Useful feedback includes:

| Topic | Example |
|---|---|
| False positives | A good TRA is flagged as weak by a metric |
| False negatives | A weak TRA passes a metric too easily |
| Threshold calibration | A cut-off is too strict or too lenient for your domain |
| Missing metrics | A practically important review signal is not represented |
| CM-17 vocabulary gaps | Distinctive technical terms are treated as generic |
| Schema variants | A valid TRA export is parsed incorrectly or incompletely |

Current calibration constants are explicit in `src/tra_quality_report.py`, including:

- `KEYWORD_ONLY_MIN_WORDS = 6`
- `OVERVIEW_MIN_WORDS = 20`
- `SCOPE_DESC_MIN_WORDS = 5`
- `JACCARD_DUP_THRESHOLD = 0.6`
- `SPECIFICITY_PASS_THRESHOLD = 0.65`
- `CONCRETE_STRENGTH_MIN = 1.0`
- `CONCRETE_MIN_TERMS = 2`

The most valuable feedback is concrete TRA evidence showing where the current rules help, overfire, or miss important weaknesses.
