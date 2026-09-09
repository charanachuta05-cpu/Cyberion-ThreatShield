# ThreatShield Detection Validation

This directory contains reproducible evidence supporting ThreatShield
detection rules.

## Validation Standard

A detection is considered validated only when:

1. The Sigma rule passes Sigma validation.
2. The rule is mapped to an appropriate ATT&CK technique.
3. Its required fields exist in the selected telemetry.
4. Equivalent detection logic is evaluated against actual telemetry.
5. At least one expected match is demonstrated when positive evidence
   is available.
6. Machine-readable validation results are preserved.
7. False-positive considerations and severity rationale are documented.

## Validation Status

| Detection | Dataset | Sigma | Telemetry | Matches | Status |
|---|---|---|---|---:|---|
| DET-001 | DS-001 | PASS | PASS | 1 | VALIDATED |
