# PB-002 — Suspicious Remote Scheduled Task Incident Response Playbook

## Playbook Metadata

- **Playbook ID:** PB-002
- **Title:** Suspicious Remote Scheduled Task Incident Response
- **Owner:** Cyberion ThreatShield
- **Version:** 1.0
- **Date:** 2026-09-09
- **Severity Guidance:** Medium to Critical depending on authorization and task behavior
- **ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Related Detection:** CORR-003
- **Related Hunt:** TH-002
- **Related Case:** INC-002

---

## 1. Purpose

Provide a structured defensive procedure for investigating a successful
Windows network logon followed shortly by scheduled-task modification.

---

## 2. Trigger Conditions

Initiate when:

- CORR-003 identifies a network logon followed by task modification;
- Event ID 4702 occurs shortly after remote authentication;
- an analyst identifies suspicious scheduled-task modification associated with
  a remote administrative session.

The sequence requires authorization and endpoint context before being
classified as malicious.

---

## 3. ThreatShield Reference Evidence

The validated ThreatShield case observed:

- source IP: `172.16.66.142`;
- account: `a-jbrown`;
- network logon Event ID: `4624`;
- Logon Type: `3`;
- TargetLogonId: `0x00000000021a8c68`;
- scheduled-task Event ID: `4702`;
- task: `\LMST`;
- SubjectLogonId: `0x00000000021a8c68`;
- observed delta: `0.389267 seconds`;
- CORR-003: **PASS**;
- INC-002 compromise status: **UNCONFIRMED**.

Cross-event relationship:

`4624.TargetLogonId == 4702.SubjectLogonId`

---

## 4. Identification

Collect:

- source address and source asset;
- destination endpoint;
- username;
- Event ID 4624 details;
- Event ID 4702 details;
- Logon Type;
- TargetLogonId and SubjectLogonId;
- scheduled-task name;
- current and previous task definition where available;
- related process telemetry;
- surrounding authentication activity;
- change-management records.

---

## 5. Authentication Validation

Determine:

- whether the source is an approved administrative system;
- whether the user is authorized for remote administration;
- whether authentication occurred during an expected window;
- whether the LogonId relationship is valid;
- whether other systems were accessed by the same account/source.

Do not infer a specific remote protocol solely from a generic Logon Type 3
event.

---

## 6. Scheduled Task Analysis

Review:

- task name;
- creation/modification timestamp;
- task owner;
- configured action;
- execution account;
- trigger;
- execution history;
- associated processes;
- whether the configuration matches an approved baseline.

A task modification alone does not establish malicious persistence.

---

## 7. Severity Decision

### Medium

Use when the task is known and activity appears administrative but requires
verification.

### High

Use when:

- source authorization is unknown;
- task modification immediately follows remote authentication;
- authentication context is strongly linked;
- task purpose is unexpected.

### Critical

Escalate when corroborating evidence establishes:

- unauthorized privileged access;
- malicious task execution;
- confirmed persistence;
- malicious activity across additional systems.

---

## 8. False-Positive Review

Consider:

- approved remote administration;
- software deployment;
- configuration-management tools;
- administrator automation;
- approved task maintenance;
- documented change windows.

Validate against asset ownership and change records.

---

## 9. Containment

When evidence supports unauthorized activity:

- isolate affected endpoints according to policy;
- restrict confirmed unauthorized access paths;
- preserve task configuration and relevant event logs;
- protect affected credentials;
- terminate confirmed unauthorized sessions where supported;
- prevent recurrence of confirmed malicious task execution.

Do not delete evidence before it is preserved.

---

## 10. Eradication

If malicious activity is confirmed:

- remove unauthorized task modifications;
- remove associated persistence;
- remediate the originating system;
- secure compromised credentials;
- review related task changes across affected systems;
- validate administrative access configuration.

---

## 11. Recovery

- restore approved scheduled-task configuration;
- restore authorized administrative access;
- verify system functionality;
- monitor task and authentication telemetry;
- confirm no unauthorized task changes recur.

---

## 12. Escalation Criteria

Escalate when:

- task action is confirmed malicious;
- privileged credentials are implicated;
- unauthorized execution follows the modification;
- multiple endpoints show related activity;
- additional persistence is discovered.

---

## 13. Evidence Checklist

Record:

- [ ] source and destination systems
- [ ] username
- [ ] Event ID 4624
- [ ] Event ID 4702
- [ ] Logon Type
- [ ] TargetLogonId
- [ ] SubjectLogonId
- [ ] task name
- [ ] task configuration
- [ ] event timestamps
- [ ] observed time delta
- [ ] authorization findings
- [ ] related process activity
- [ ] analyst disposition

---

## 14. Closure Criteria

Close as **Benign / Authorized** when administrative activity and task changes
are verified.

Close as **Suspicious / Unconfirmed** when the relationship is verified but
authorization or malicious intent remains unresolved.

Close as **Confirmed Incident** when corroborating evidence establishes
unauthorized task modification or malicious execution.

---

## 15. Post-Incident Actions

- tune approved administrative sources;
- improve scheduled-task monitoring;
- maintain authentication-to-action correlations;
- review administrative account controls;
- document detection gaps;
- update the playbook from lessons learned.
