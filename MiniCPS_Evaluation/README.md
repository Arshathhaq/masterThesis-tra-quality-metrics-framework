# MiniCPS Evaluation — TRA Quality Metrics Case Study

This folder contains the **academic evaluation case study** for the Master-Thesis
TRA (Threat & Risk Analysis) quality-metrics framework. It uses the open-source
**MiniCPS** cyber-physical-system simulation testbed as a neutral, *publicly
citable* system-under-analysis so that the thesis evaluation can be reproduced
and reviewed without relying on internal/confidential TRAs (e.g. SoCoSi).

## Why MiniCPS?

| Property | Relevance to the thesis |
|---|---|
| Open-source (MIT), peer-reviewed (ACM CPS-SPC'15) | Citable, reproducible, no NDA constraints |
| Models the **SWaT** Secure Water Treatment plant (PLCs, sensors, actuators, Modbus/EtherNet-IP network) | Realistic ICS attack surface → meaningful threats, zones, interfaces |
| Built on Mininet (network emulation) + physical-process simulation | Clear components, communications, and trust boundaries to model in a TRA |
| Documented architecture (6 stages, HMI, historian, PLCs) | Lets us author a *reference* TRA of known structure to test the metrics |

> MiniCPS itself is **not** modified. It is used purely as the documented *target
> of analysis* for which we author a TRA in the SoCoSi JSON schema, then run the
> quality metrics on that TRA.

## Reference

- F. Antonioli, N. O. Tippenhauer. *MiniCPS: A Toolkit for Security Research on
  CPS Networks.* ACM CPS-SPC 2015. https://github.com/scy-phy/minicps

```powershell
python src/tra_quality_report.py "MiniCPS_Evaluation/tra/minicps_swat_tra.json"
```

This command directly generates two files next to the input JSON:

- `<input>_quality_report.html` (standalone report for browser viewing)
- `<input>_quality_metrics.json` (machine-readable metrics output)
