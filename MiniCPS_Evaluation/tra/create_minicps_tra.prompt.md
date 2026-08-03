---
mode: agent
description: Generate a complete, schema-valid TRA-X JSON threat and risk analysis for the MiniCPS / SWaT water-treatment testbed.
---

# Agent Prompt — Create a TRA for the MiniCPS / SWaT Testbed

You are a control-systems security analyst. Produce a **single, complete, valid
JSON file** containing a Threat and Risk Analysis (TRA) for the target system
below, conforming exactly to the TRA-X **JSON_VERSION "2"** schema and to the
structure of the reference file
`MiniCPS_Evaluation/tra/minicps_swat_tra.json`.

Write the result to a new file (do **not** overwrite the reference). Output only
the JSON file — no prose, no Markdown fences.

## Target system (scope of analysis)

An open-source **MiniCPS** simulation of the **Secure Water Treatment (SWaT)**
testbed: a six-stage water-treatment process controlled by six PLCs.

- **Stage 1 (PLC1)** raw-water intake and storage — valve MV101, pump P101, level transmitter LIT101.
- **Stage 2 (PLC2)** chemical pre-treatment / dosing — analysers AIT201–AIT203 (pH, ORP, conductivity).
- **Stage 3 (PLC3)** ultrafiltration — feed pump, backwash sequencing.
- **Stage 4 (PLC4)** dechlorination — UV + sodium-bisulphite dosing.
- **Stage 5 (PLC5)** reverse osmosis — high-pressure pumps, permeate quality.
- **Stage 6 (PLC6)** permeate transfer, membrane backwash, chemical cleaning.
- **Supervisory (Level 2):** SCADA/HMI workstation + process historian.
- **Engineering zone:** engineering workstation for controller logic.
- **Field (Level 0):** sensors and actuators.
- **Networks:** Modbus-TCP and EtherNet/IP on a Level-1 control ring; Purdue
  levels 0–3 plus an external/Internet zone for vendor remote support.

Target area = **Software** (`Project.Config.selection = "Software"`), so use
`SWComponents`, `LogicalInterfaces`, and `InterSWCommunications`.

## Required top-level structure (all mandatory)

Emit these keys, in this order, with non-empty values:

1. `JSON_VERSION` = `"2"`
2. `TRAVersionName`, `TRAVersionNumber`, `status`
   (`status` ∈ `Completed | Draft | In_Progress | Under_Review`)
3. `createdBy`, `changedBy`
4. `Project` — with `TRAProjectName`, `responsibleOrg`, `AccessScope`,
   `Config.selection` (`Software` | `Deployment`), `projectID`,
   `targetOfAnalysis`, `overallProjectType`, `createdDate`
5. `TRAVersionComment`, `changedDate`, `createdDate`
6. `IntendedOp` (operational environment + intended users)
7. `Assumptions[]`
8. `Assets[]`
9. `ProtectionGoals[]`
10. `SecurityZones[]` (non-empty)
11. `SWComponents[]`
12. `ThreatScenarios[]`

## Content requirements

**Assumptions** (`assumption_id`, `name`, `description`, `validated`,
`assumptionType`, `ZoneExposures[].SecurityZone.zone_id`): capture at least the
unauthenticated control protocols, field-wiring physical protection, hardened
engineering workstation, and unconfirmed plant-boundary firewall segmentation.
Mark realistic `validated` true/false values.

**Assets** (`asset_id`, `name`, `description`, `assetType` ∈ `Data` |
`Functionality`): sensor measurements, PLC control logic/setpoints, actuator
commands, historian database, HMI configuration, engineering project files, plus
`Functionality` assets for process operation, physical plant safety, and SCADA
monitoring.

**ProtectionGoals** (`pg_id`, `name`, `impactLevel` ∈ `Critical | Moderate |
Negligible`, `impactDescription`, `protectionGoalType` ∈ `Confidentiality |
Integrity | Availability`, `Asset.asset_id`, optional
`ThreatScenarios[].threatscenario_id`, `ImpactCategory.name`): cover integrity
of sensor data, actuator commands, PLC logic, historian and HMI; availability of
the process, SCADA monitoring, and physical plant safety; confidentiality of
design/setpoints. Prefer `Integrity` and `Availability` (safety-driven ICS).
Include at least one `Negligible` goal for realism.

**SecurityZones** — model the Purdue hierarchy: External/Internet, Enterprise
(Level 3), Supervisory (Level 2), Control ring (Level 1), Field bus (Level 0),
and an Engineering zone. For each zone set `zone_id`, `name`, `description`,
`external`, `isNetworkZone`, `isProximityZone`, `isHostZone`,
`isTopSecurityZone`, parent/top links (`SecurityZone_Parent`,
`SecurityZone_Top`), and `ZoneExposures[]` with `rating`
(`High | Medium | Low`), `zoneExposureType` (`Network | Host | Proximity`), and
`description`; link relevant `Assumptions` inside exposures. Give the
enterprise-facing zone a `NetworkFacingInterfaces_Zone` uplink (`NFI-`).

**SWComponents** — one per PLC (PLC1–PLC6) plus the SCADA/HMI workstation,
process historian, engineering workstation, and a Level-0 field-device group.
Each component: `name`, `description`, `scope` (`In_Scope` | `Out_Of_Scope`),
`subUnit_id` (`SW-#`), `SecurityZone.zone_id`, and a `LogicalInterfaces[]` entry
with `interface_id` (`LI-#`), `softwareAttackSurfaceType`,
`abstractInterfaceType`, `ProtocolType.name` (Modbus-TCP / EtherNet/IP),
`ReachableFromSecurityZone.zone_id`, `isManagementInterface`,
`fromUntrustedZones`. Use `InterSWCommunications[]` (`LC-#`, with
`TargetInterface.interface_id`, `SourceComponent.subUnit_id`, `ProtocolType`) to
model data flows (e.g. field sensors → PLC, PLC → SCADA).

**ThreatScenarios** — at least 12–14 scenarios. Each: `threatscenario_id`
(`T-#`), `name`, a **specific, concrete** `attackActionDesc` naming the exact
component, interface, protocol and physical consequence; a `weakness` sentence;
`exploitabilityRating` + `exploitabilityComment`; impact fields
(`threatSpecificImpactRating`, `CALCAppliedImpactRating`), `CALCLikelihood`,
`CALCRiskRating`; `ProtectionGoals[].pg_id`; an `AttackInterface.interface_id`
pointing at a real `LI-`/`NFI-`; and a `ReRating` block containing a concrete
`mitigation`. Cover: false sensor injection, actuator command tampering, PLC
logic modification, control-network DoS, HMI/SCADA compromise, historian
falsification, engineering-workstation malware download, setpoint disclosure,
and a coordinated multi-actuator safety attack.

## Consistency and validity rules

- Every `zone_id`, `asset_id`, `pg_id`, `subUnit_id`, `interface_id`,
  `communication_id`, and `threatscenario_id` referenced anywhere must be
  defined somewhere. No dangling references.
- IDs are unique and use consistent prefixes (`SZ-`, `Data-`/`Func-`, `C-`/`I-`/`A-`,
  `SW-`, `LI-`/`NFI-`, `LC-`, `T-`).
- Every `ThreatScenario.AttackInterface.interface_id` must exist on a component
  or zone; every threat must reference at least one existing protection goal.
- Descriptions must be **concrete** (name the stage, device tag, protocol and
  physical effect) — avoid vague filler like "the system may be attacked".
- Emit strictly valid JSON (double quotes, no trailing commas, no comments).

## Self-check before finishing

1. All 12 top-level mandatory keys present and non-empty; `JSON_VERSION` == "2".
2. `status` and `Config.selection` use allowed enum values.
3. `SecurityZones` non-empty; Purdue hierarchy links resolve.
4. No dangling ID references across assets, goals, zones, components, interfaces
   and threats.
5. The JSON parses. Then, if available, run
   `python tra_quality_report.py <yourfile>.json` and confirm it produces a
   scorecard without crashing.
