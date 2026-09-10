# IOC-001 — Observed Indicators and Threat Context

## Document Metadata

- **Document ID:** IOC-001
- **Project:** Cyberion ThreatShield
- **Type:** IOC and Behavioral Indicator Research
- **Date:** 2026-09-10
- **Classification:** Defensive Security Research
- **Status:** Complete

---

## 1. Purpose

This document records indicators and behavioral artifacts observed during the
Cyberion ThreatShield detection-engineering and threat-hunting engagement.

The objective is to distinguish evidence observed in project telemetry from
externally confirmed malicious indicators.

An observed value is not automatically a malicious IOC.

---

## 2. Indicator Classification Model

ThreatShield classifies investigative indicators into three categories.

### Dataset-Observed Artifact

A value directly observed in project telemetry, such as an IP address,
username, hostname, task name, event identifier, or authentication context.

This classification establishes observation only.

### Behavioral Indicator

A sequence or combination of events that may indicate suspicious activity,
such as rapid authentication failures across multiple accounts or a network
logon followed by scheduled-task modification.

Behavioral indicators generally provide stronger investigative context than
isolated values.

### Confirmed Threat IOC

An indicator supported by reliable external threat intelligence or confirmed
incident evidence as malicious.

No project-observed value is promoted to this category without supporting
evidence.

---

## 3. Observed Indicator Inventory

| Indicator | Type | Context | Classification | Malicious Status |
|---|---|---|---|---|
| `172.16.66.1` | Private IPv4 | Kerberos failures across multiple accounts | Dataset-observed artifact | Unconfirmed |
| `172.16.66.142` | Private IPv4 | Source of successful network logon preceding task modification | Dataset-observed artifact | Unconfirmed |
| `a-jbrown` | Username | Account associated with network logon and task modification | Dataset-observed artifact | Unconfirmed |
| `\LMST` | Scheduled task | Task modified after correlated network authentication | Dataset-observed artifact | Unconfirmed |
| `PC01.example.corp` | Hostname | Host associated with validated Event ID 1102 | Dataset-observed artifact | Unconfirmed |
| `0x00000000021a8c68` | Windows Logon ID | Links authentication and scheduled-task activity | Correlation artifact | Not independently malicious |

---

## 4. Indicator Analysis — 172.16.66.1

### Observation

`172.16.66.1` was observed as the common source of nine qualifying Kerberos
authentication failures involving nine distinct target accounts.

### Related ThreatShield Content

- DET-004
- CORR-001
- TH-001
- INC-001
- PB-001

### Behavioral Context

The value becomes relevant because of its relationship to a concentrated
multi-account authentication-failure pattern.

The behavioral pattern is consistent with password-spraying activity.

### Classification

**Dataset-observed artifact**

### Threat Status

**UNCONFIRMED**

`172.16.66.1` belongs to RFC1918 private address space.

It should not be treated as a globally attributable malicious IOC. Its meaning is limited to the dataset/environment where it was observed.

---

## 5. Indicator Analysis — 172.16.66.142

### Observation

`172.16.66.142` was observed as the source address of a successful Windows
network logon associated with account `a-jbrown`.

A scheduled-task modification followed approximately `0.389267 seconds`
later.

### Related ThreatShield Content

- CORR-003
- TH-002
- INC-002
- PB-002

### Behavioral Context

The relevant investigative relationship is not the IP address alone.

The important sequence is:

1. successful network authentication;
2. scheduled-task modification;
3. matching authentication context;
4. very short temporal separation.

### Classification

**Dataset-observed artifact**

### Threat Status

**UNCONFIRMED**

The project evidence does not establish whether the source system was an
authorized administrative host.

---

## 6. Indicator Analysis — a-jbrown

### Observation

The username `a-jbrown` appears in the correlated authentication and
scheduled-task activity.

### Context

The account is associated with:

- the successful network logon;
- the scheduled-task modification;
- matching logon context between the correlated events.

### Classification

**Dataset-observed identity artifact**

### Threat Status

**UNCONFIRMED**

A username should not be classified as malicious merely because it appears in
suspicious telemetry.

The appropriate investigative questions are whether the account was
authorized, whether its credentials were compromised, and whether the
associated actions were expected.

---

## 7. Indicator Analysis — \LMST

### Observation

`\LMST` was the scheduled task associated with the correlated Event ID 4702
activity.

### Classification

**Dataset-observed scheduled-task artifact**

### Threat Status

**UNCONFIRMED**

The task name alone is insufficient to establish malicious persistence.

Analysts should review the task definition, action, execution account,
triggers, history, change records, and associated process telemetry.

---

## 8. Indicator Analysis — PC01.example.corp

### Observation

`PC01.example.corp` was associated with the validated Windows Security
Event ID 1102 detection.

### Related ThreatShield Content

- DET-011
- PB-003

### Behavioral Context

Event ID 1102 indicates that the Windows Security audit log was cleared.

The event is security relevant because log clearing reduces local historical
visibility, but legitimate administrative procedures can also produce it.

### Classification

**Dataset-observed hostname**

### Threat Status

**UNCONFIRMED**

The hostname itself is not a malicious IOC.

---

## 9. Behavioral Indicator — Multi-Account Kerberos Failures

### Pattern

A common source generated qualifying Kerberos authentication failures against
multiple distinct accounts in a concentrated period.

### ATT&CK Mapping

**T1110.003 — Brute Force: Password Spraying**

### Detection Strategy

Correlate authentication failures by source address and count distinct target
accounts within a defined time window.

### ThreatShield Implementation

CORR-001 uses a threshold of at least five distinct target accounts within ten
minutes.

The validation dataset produced nine distinct target accounts.

Thresholds should be tuned to each production environment.

---

## 10. Behavioral Indicator — Network Logon Followed by Task Modification

### Pattern

A successful Windows network logon was followed by scheduled-task
modification on the same system.

ThreatShield additionally verified the relationship:

`4624.TargetLogonId == 4702.SubjectLogonId`

### ATT&CK Mapping

**T1053.005 — Scheduled Task/Job: Scheduled Task**

### Detection Strategy

Correlate remote/network authentication context with subsequent scheduled-task
changes and validate the relationship using available logon identifiers.

The correlation should be treated as an investigation trigger rather than
automatic proof of compromise.

---

## 11. Behavioral Indicator — Security Audit Log Clearing

### Pattern

Windows Security Event ID 1102 indicates that the Security audit log was
cleared.

### ATT&CK Mapping

**T1070.001 — Indicator Removal: Clear Windows Event Logs**

### ThreatShield Implementation

DET-011 identifies Event ID 1102.

### Investigative Context

Analysts should determine:

- who initiated the action;
- whether it was authorized;
- what occurred immediately before the event;
- whether centralized copies of the logs remain available;
- whether similar activity occurred on other systems.

---

## 12. IOC Operationalization

Indicators should be operationalized according to context rather than blindly
blocklisted.

### Private IP Addresses

Private addresses should be enriched using internal information such as:

- asset inventory;
- DHCP history;
- endpoint ownership;
- network segment;
- administrative-system designation.

### User Accounts

Identity indicators should be enriched using:

- account ownership;
- privilege level;
- authentication history;
- MFA events;
- expected administrative responsibilities.

### Scheduled Tasks

Task artifacts should be enriched using:

- task definition;
- configured action;
- execution account;
- triggers;
- creation/modification history;
- related process telemetry.

### Hostnames

Host indicators should be enriched using:

- asset role;
- owner;
- endpoint telemetry;
- security alerts;
- administrative history.

---

## 13. Detection Versus IOC Blocking

ThreatShield prioritizes behavioral detection over static blocking for the
observed project artifacts.

This is appropriate because:

- the observed IP addresses are private;
- usernames are environment-specific;
- scheduled-task names can be changed;
- individual artifacts can have legitimate explanations;
- behavior provides additional context.

Static blocking without context could produce operational disruption and does
not establish malicious intent.

---

## 14. Confidence Model

### Low Confidence

Single artifact without supporting behavioral evidence.

### Medium Confidence

Artifact associated with suspicious behavior but lacking sufficient
corroboration.

### High Behavioral Confidence

Multiple linked events establish that the suspicious behavior occurred.

### Confirmed Malicious

Independent evidence establishes unauthorized or malicious activity.

High behavioral confidence does not automatically mean confirmed compromise.

---

## 15. False-Positive Considerations

Potential benign explanations include:

- administrative activity;
- automation;
- configuration management;
- stale credentials;
- service-account failures;
- maintenance;
- approved security testing;
- approved log-management procedures.

Each alert should be evaluated using environmental context.

---

## 16. Analyst Enrichment Workflow

When an indicator is identified:

1. preserve the original evidence;
2. classify the indicator type;
3. identify related events;
4. determine asset or identity ownership;
5. review historical activity;
6. compare against expected behavior;
7. correlate with other security telemetry;
8. consult reliable threat intelligence when externally routable indicators
   are present;
9. assign confidence;
10. document the final disposition.

---

## 17. Key Findings

The ThreatShield engagement demonstrates that isolated indicators should not
be treated as proof of malicious activity.

The strongest investigative findings came from behavioral relationships:

- one source targeting multiple accounts;
- authentication followed by scheduled-task modification;
- cross-event authentication-context linkage;
- audit-log clearing requiring contextual investigation.

The project therefore prioritizes evidence-backed behavioral detection,
correlation, and analyst validation over unsupported IOC attribution.

---

## 18. Final Assessment

The observed indicators provide useful investigative pivots but do not, by
themselves, establish malicious attribution.

**Overall IOC Assessment:** CONTEXT-DEPENDENT

**Observed Artifact Confidence:** HIGH

**Behavioral Detection Confidence:** HIGH for validated project behaviors

**Confirmed Malicious Attribution:** NOT ESTABLISHED

This distinction preserves analytical integrity and prevents dataset artifacts
from being incorrectly represented as real-world malicious infrastructure.
