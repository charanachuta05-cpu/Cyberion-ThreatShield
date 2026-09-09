# ThreatShield Dataset Sources

## DS-001 - EVTX-ATTACK-SAMPLES

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Telemetry:** Microsoft-Windows-Sysmon
**Selected sample:** `Execution/exec_sysmon_1_ftp.evtx`
**Local identifier:** DS-001
**Format:** Windows EVTX
**Observed records:** 4
**Observed Event ID:** Sysmon Event ID 1 - Process Creation

## Purpose

DS-001 is used as recorded defensive telemetry for detection engineering
and rule-validation exercises.

ThreatShield does not execute or reproduce the activity represented by
the sample. Analysis is performed against the pre-recorded event log.

## Provenance

The original sample remains attributable to its upstream public dataset.
Raw EVTX files are excluded from the ThreatShield Git repository.

Derived evidence, field observations, validation results, and detection
content are version controlled within ThreatShield.
