# ThreatShield Detection Engineering Methodology

## 1. Objective

Develop reproducible detection content and threat-hunting findings
using real or publicly documented security telemetry.

## 2. Evidence Standard

A detection is considered validated only when supported by actual
telemetry evidence.

Each submitted detection must document:

1. Detection ID
2. Source dataset
3. Telemetry source
4. MITRE ATT&CK technique
5. Detection hypothesis
6. Detection logic
7. Matching evidence
8. Validation result
9. False-positive considerations
10. Severity rationale

## 3. Telemetry Categories

ThreatShield's validated baseline uses pre-recorded Windows EVTX telemetry
across several security-observation categories.

### Windows Sysmon Process and System Telemetry

Sysmon telemetry supports analysis of process creation, process ancestry,
registry activity, named-pipe activity, and other endpoint behaviors used by
the validated detection baseline.

### Windows Security Authentication Telemetry

Windows Security events support analysis of Kerberos authentication failures,
successful network logons, account activity, and source-based authentication
correlation.

### Windows Security Administrative Telemetry

Windows Security and related Windows event channels support analysis of
scheduled tasks, account and group changes, audit-log clearing, service
installation, and other administrative security events.

### Network Context Within Windows Events

The project uses network-related fields embedded in Windows telemetry, such as
source IP addresses associated with authentication events. It does not claim validation against a separate packet, NetFlow, Zeek, or live network-telemetry dataset.

## 4. Detection Engineering Workflow

For each target behavior:

1. Select a candidate ATT&CK technique.
2. Identify the telemetry required to observe the behavior.
3. Locate supporting events in the selected dataset.
4. Verify the relevant fields.
5. Develop Sigma detection logic.
6. Validate Sigma syntax.
7. Test the logic against telemetry.
8. Preserve validation evidence.
9. Analyze potential false positives.
10. Assign severity with justification.
11. Update ATT&CK coverage.

## 5. Threat Hunting Method

Every threat hunt follows:

Hypothesis -> Required Evidence -> Analysis -> Findings -> Conclusion

Valid conclusions are:

- Confirmed
- Inconclusive
- Ruled Out

Negative results are retained and documented.

## 6. Incident Escalation

Confirmed findings may be escalated into incident investigations.

Each investigation should reconstruct:

- observable activity
- chronological attack timeline
- affected assets or accounts
- ATT&CK techniques
- root cause
- potential impact
- recommended containment and response
- closure classification

## 7. Closure Classification

Incident findings are classified as:

- True Positive
- False Positive
- Benign Positive

Every classification requires supporting evidence and justification.

## 8. Quality Principles

ThreatShield detection content prioritizes:

- reproducibility
- precision
- evidence traceability
- explainability
- accurate ATT&CK mapping
- realistic false-positive analysis
- operational usefulness
