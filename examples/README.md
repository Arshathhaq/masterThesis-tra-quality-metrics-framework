# Examples

This folder demonstrates the TRA quality tool on a **public, non-confidential**
system: the MiniCPS / SWaT reference TRA that ships with this repository.

## Sample input

The reference TRA JSON used throughout the thesis evaluation lives at:

```
MiniCPS_Evaluation/tra/minicps_swat_tra.json
```

## Reproduce the sample report

From the repository root:

```powershell
python src/tra_quality_report.py MiniCPS_Evaluation/tra/minicps_swat_tra.json `
    --html-out examples/sample_quality_report.html `
    --metrics-out examples/sample_quality_metrics.json
```

## Sample output

[`sample_quality_report.html`](sample_quality_report.html) is a pre-rendered
copy of that report — open it in any browser to see the scorecard, per-metric
evidence, and findings panel without running anything.
