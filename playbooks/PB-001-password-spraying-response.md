# PB-001 — Password Spraying Incident Response Playbook

## Playbook Metadata

- **Playbook ID:** PB-001
- **Title:** Password Spraying Incident Response
- **Owner:** Cyberion ThreatShield
- **Version:** 1.0
- **Date:** 2026-09-09
- **Severity Guidance:** Medium to Critical depending on successful access and account privilege
- **ATT&CK:** T1110.003 — Brute Force: Password Spraying
- **Related Detection:** DET-004
- **Related Correlation:** CORR-001
- **Related Hunt:** TH-001
- **Related Case:** INC-001

---

## 1. Purpose

Provide a repeatable defensive procedure for investigating and responding to
suspected password-spraying activity involving authentication failures across
multiple accounts from a common source.

---

## 2. Trigger Conditions

Initiate this playbook when one or more of the following occur:

- DET-004 identifies qualifying Kerberos authentication failures;
- CORR-001 identifies at least five distinct target accounts from a common
  source within ten minutes;
- identity monitoring reports abnormal multi-account authentication failures;
- an analyst identifies behavior consistent with password spraying.

A detection is an investigation trigger and is not automatically proof of
account compromise.

---

## 3. ThreatShield Reference Evidence

The validated ThreatShield case observed:

- source IP: `172.16.66.1`;
- qualifying failures: **9**;
- distinct accounts: **9**;
- configured threshold: **>= 5**;
- configured window: **10 minutes**;
- observed span: approximately `0.011011 seconds`;
- DET-004: **PASS**;
- CORR-001: **PASS**;
- INC-001 compromise status: **UNCONFIRMED**.

This evidence is a project validation reference, not a universal production
threshold.

---

## 4. Identification

Collect:

- source IP address;
- authentication timestamps;
- target usernames;
- authentication result;
- event IDs and status codes;
- identity-provider telemetry;
- account privilege level;
- source asset identity;
- successful authentications near the failure window;
- MFA and account-lockout events.

Preserve original logs before making investigative changes where practical.

---

## 5. Initial Triage

Determine:

1. How many accounts were targeted?
2. Did failures originate from one or multiple sources?
3. Did any targeted account subsequently authenticate successfully?
4. Are privileged or service accounts affected?
5. Is the source an approved identity, administrative, or automation system?
6. Is the activity expected during the observed period?
7. Are similar failures occurring elsewhere?

Prioritize investigation when multiple unrelated accounts are affected in a
short interval.

---

## 6. Severity Decision

### Medium

Use when:

- failures are limited;
- no privileged accounts are involved;
- no successful authentication is observed;
- a plausible benign explanation exists.

### High

Use when:

- multiple accounts are targeted;
- correlation thresholds are exceeded;
- privileged or service accounts are included;
- source authorization is unknown.

### Critical

Escalate when corroborating evidence shows:

- successful unauthorized authentication;
- privileged-account compromise;
- widespread account impact;
- malicious follow-on endpoint activity.

---

## 7. False-Positive Review

Consider:

- stale stored credentials;
- password changes;
- service-account misconfiguration;
- authentication infrastructure problems;
- approved security testing;
- administrative automation.

Document why each relevant explanation was accepted or rejected.

---

## 8. Containment

When unauthorized activity is sufficiently supported:

- restrict the suspicious source according to organizational policy;
- protect confirmed affected accounts;
- terminate confirmed unauthorized sessions where supported;
- apply additional authentication controls where appropriate;
- preserve authentication and endpoint evidence.

Avoid mass account disabling solely from an uncorroborated detection.

---

## 9. Eradication

If compromise is confirmed:

- remediate the originating system;
- rotate confirmed exposed credentials according to policy;
- remove unauthorized persistence;
- correct insecure authentication configurations;
- review privileged and service-account exposure.

---

## 10. Recovery

- restore account access according to approved procedures;
- verify expected authentication behavior;
- monitor affected identities for recurrence;
- verify service-account functionality;
- maintain enhanced monitoring during the recovery period.

---

## 11. Escalation Criteria

Escalate to incident response when:

- successful authentication follows the suspicious failures;
- privileged accounts are affected;
- endpoint telemetry indicates malicious follow-on activity;
- activity continues after containment;
- multiple systems or identity sources are involved.

---

## 12. Evidence Checklist

Record:

- [ ] alert/detection identifier
- [ ] first and last observed timestamps
- [ ] source IP/address
- [ ] affected usernames
- [ ] event IDs/status codes
- [ ] distinct-account count
- [ ] successful-authentication findings
- [ ] privilege level
- [ ] source-asset ownership
- [ ] containment decisions
- [ ] analyst disposition

---

## 13. Closure Criteria

Close as **Benign / False Positive** when an authorized explanation is
established and no contradictory evidence remains.

Close as **Suspicious / Unconfirmed** when the behavior remains concerning but
compromise cannot be established.

Close as **Confirmed Incident** only when corroborating evidence establishes
unauthorized access or malicious activity.

---

## 14. Post-Incident Actions

- review authentication detection thresholds;
- tune approved infrastructure where appropriate;
- document detection gaps;
- update identity monitoring;
- record lessons learned;
- update the playbook when investigation experience reveals improvements.
