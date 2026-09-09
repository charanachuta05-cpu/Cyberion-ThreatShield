# PB-003 — Windows Security Audit Log Clearing Incident Response Playbook

## Playbook Metadata

- **Playbook ID:** PB-003
- **Title:** Windows Security Audit Log Clearing Incident Response
- **Owner:** Cyberion ThreatShield
- **Version:** 1.0
- **Date:** 2026-09-09
- **Severity Guidance:** High
- **ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs
- **Related Detection:** DET-011

---

## 1. Purpose

Provide a repeatable defensive process for investigating Windows Security
Event ID 1102 indicating that the Security audit log was cleared.

Security-log clearing can occur during legitimate administration, but it also
reduces local forensic visibility and therefore requires timely review.

---

## 2. Trigger Conditions

Initiate this playbook when:

- DET-011 detects Event ID 1102;
- monitoring identifies unexpected Security-log clearing;
- forensic review discovers a loss of expected Security-log history.

---

## 3. ThreatShield Reference Evidence

DET-011 was behaviorally validated against pre-recorded EVTX telemetry.

Validation sample:

- total records: **112**;
- Event ID 1102 records: **1**;
- Event ID 5156 records: **1**;
- Event ID 4663 records: **110**;
- DET-011 matches: **1**;
- observed host: `PC01.example.corp`;
- Event ID: `1102`;
- observed timestamp: `2019-03-19 23:35:07.524200+00:00`;
- validation status: **PASS**.

---

## 4. Identification

Collect and preserve:

- Event ID 1102;
- hostname;
- timestamp;
- account/context associated with the clearing event where available;
- centralized copies of Windows logs;
- endpoint telemetry;
- authentication history;
- surrounding administrative activity;
- change-management records;
- alerts occurring before and after the clearing event.

Preservation should occur before unnecessary changes are made to the affected
endpoint.

---

## 5. Initial Triage

Determine:

1. Was log clearing authorized?
2. Was there an approved maintenance or troubleshooting activity?
3. Which account or process initiated the action, if available?
4. What security events occurred before the log was cleared?
5. Are centralized or forwarded copies available?
6. Did other systems experience similar log clearing?
7. Is there evidence of suspicious authentication or administrative activity?

---

## 6. Evidence Preservation

Where available, preserve:

- forwarded Windows event logs;
- EDR telemetry;
- identity/authentication logs;
- relevant endpoint artifacts;
- security alerts;
- administrative audit records;
- change-management records.

Record timestamps and evidence sources so the investigation remains
reproducible.

Do not assume the absence of local historical events means no prior activity
occurred.

---

## 7. ATT&CK Mapping

| Tactic | Technique | ATT&CK ID |
|---|---|---|
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |

Event ID 1102 directly identifies Security audit-log clearing.

ATT&CK classification does not by itself prove malicious intent.

---

## 8. Severity Decision

### Medium

Consider only when log clearing is immediately verified as an approved
administrative action with adequate centralized evidence retained.

### High

Use when:

- authorization is unknown;
- clearing is unexpected;
- forensic visibility has been reduced;
- suspicious activity exists around the event.

### Critical

Escalate when log clearing is corroborated by evidence of:

- confirmed compromise;
- unauthorized privileged activity;
- malicious persistence;
- destructive activity;
- coordinated evidence removal across systems.

---

## 9. False-Positive Review

Known benign scenarios include:

- authorized administrative troubleshooting;
- approved maintenance;
- approved log-management procedures.

Analysts should verify authorization rather than automatically suppressing
Event ID 1102.

---

## 10. Containment

If activity is unauthorized or associated with other suspicious evidence:

- preserve available centralized evidence;
- isolate affected systems when justified by incident scope;
- restrict confirmed unauthorized administrative access;
- protect implicated credentials;
- increase monitoring on related systems;
- preserve additional forensic data.

Containment decisions should consider business impact and available evidence.

---

## 11. Eradication

If compromise is confirmed:

- remediate the underlying cause of unauthorized access;
- remove discovered malicious persistence;
- secure affected administrative credentials;
- correct unauthorized system changes;
- verify logging and forwarding configuration.

---

## 12. Recovery

- restore required audit policies;
- verify Security logging is operational;
- verify centralized forwarding;
- confirm expected log retention;
- monitor for repeated Event ID 1102 activity;
- document any visibility gaps created by the clearing event.

---

## 13. Escalation Criteria

Escalate when:

- the clearing action is unauthorized;
- privileged accounts are implicated;
- additional suspicious telemetry precedes or follows Event ID 1102;
- multiple endpoints experience similar clearing;
- centralized evidence suggests broader compromise.

---

## 14. Evidence Checklist

Record:

- [ ] hostname
- [ ] Event ID 1102 timestamp
- [ ] responsible account/context where available
- [ ] authorization/change record
- [ ] centralized log availability
- [ ] surrounding authentication events
- [ ] endpoint alerts
- [ ] related systems
- [ ] evidence-preservation actions
- [ ] containment actions
- [ ] analyst disposition

---

## 15. Closure Criteria

Close as **Benign / Authorized** when the log clearing is verified as an
approved activity and no contradictory evidence exists.

Close as **Suspicious / Unconfirmed** when authorization cannot be established
but no corroborating compromise evidence is available.

Close as **Confirmed Incident** when evidence establishes unauthorized log
clearing associated with malicious activity.

---

## 16. Post-Incident Actions

- review audit-log retention;
- verify centralized log forwarding;
- improve Event ID 1102 alerting;
- review administrative privileges;
- document visibility gaps;
- update response procedures based on lessons learned.
