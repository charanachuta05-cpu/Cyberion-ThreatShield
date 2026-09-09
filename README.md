# Cyberion ThreatShield

## Detection Engineering & Threat Hunting Engagement

Cyberion ThreatShield is an evidence-driven Detection Engineering and
Threat Hunting project developed for the Cyberion Defense Labs
Security Engineering Program.

The engagement analyzes real/publicly documented security telemetry,
develops portable Sigma detection content, maps detection coverage to
MITRE ATT&CK, performs hypothesis-driven threat hunts, investigates
confirmed findings, and develops practical incident-response playbooks.

## Objectives

- Analyze at least three security telemetry source types
- Build 15+ Sigma detection rules
- Develop at least 3 correlation-style detections
- Assess 20+ MITRE ATT&CK techniques
- Conduct 2+ structured threat hunts
- Complete 2+ incident investigations
- Develop 3+ incident-response playbooks
- Research and operationalize relevant IOCs
- Document rule validation and false-positive considerations
- Produce an executive security assessment

## Detection Workflow

Telemetry
    |
    v
Detection Engineering
    |
    v
Sigma Validation
    |
    v
MITRE ATT&CK Mapping
    |
    v
Threat Hunting
    |
    v
Incident Investigation
    |
    v
Response Playbooks
    |
    v
Coverage Improvement

## Repository Structure

- `datasets/` - source and normalized telemetry
- `methodology/` - methodology and data dictionaries
- `detections/` - Sigma detection library
- `validation/` - rule validation results and evidence
- `threat-hunts/` - hypothesis-driven hunt reports
- `incidents/` - investigation case reports
- `playbooks/` - incident-response procedures
- `ioc-research/` - IOC research and operationalization
- `mitre/` - ATT&CK coverage artifacts
- `reports/` - technical and executive reports
- `presentation/` - final project presentation
- `scripts/` - local analysis and validation utilities

## Evidence Standard

A detection is not considered validated merely because its Sigma syntax
is valid.

Every submitted detection must be traceable to actual telemetry,
documented test evidence, an ATT&CK technique, severity rationale, and
false-positive considerations.

## Status

Phase 1 - Telemetry Familiarization and Detection Engineering Setup
