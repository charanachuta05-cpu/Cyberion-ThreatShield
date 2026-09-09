# ThreatShield Detection Validation

ThreatShield validates detection content against recorded security
telemetry rather than relying only on rule syntax.

## Validation Standard

A detection is marked VALIDATED only when:

1. The Sigma rule passes structural validation.
2. The underlying dataset is identified and documented.
3. The detection logic is evaluated against actual event records.
4. At least one expected matching event is observed.
5. Matching evidence is recorded.
6. False-positive considerations are documented.

Correlation rules additionally require the aggregation condition to be
reproduced against the recorded matching events.

## Current Validation Matrix

| Detection | Dataset | Sigma | Telemetry | Matches | Status |
|---|---|---|---|---:|---|
| DET-001 | DS-001 | PASS | PASS | 1 | VALIDATED |
| DET-002 | DS-002 | PASS | PASS | 3 | VALIDATED |
| DET-003 | DS-003 | PASS | PASS | 2 | VALIDATED |
| DET-004 | DS-004 | PASS | PASS | 9 | VALIDATED |
| DET-005 | DS-005 | PASS | PASS | 3 | VALIDATED |

## Correlation Validation

| Correlation | Base Rule | Dataset | Threshold | Observed | Status |
|---|---|---|---|---|---|
| CORR-001 | DET-004 | DS-004 | >=5 distinct accounts/source | 9 | VALIDATED |

Machine-readable results are stored under `validation/results/`.
Analyst validation evidence is stored under `validation/evidence/`.
