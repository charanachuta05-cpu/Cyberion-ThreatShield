# INC-001 — Kerberos Multi-Account Authentication Failure Investigation

## Incident Metadata

- **Incident ID:** INC-001
- **Title:** Kerberos Multi-Account Authentication Failure Investigation
- **Status:** Investigated
- **Severity:** High
- **Confidence:** High behavioral confidence
- **Analyst:** Cyberion ThreatShield
- **Investigation Date:** 2026-09-09
- **Primary ATT&CK Tactic:** Credential Access
- **Primary ATT&CK Technique:** T1110.003 — Brute Force: Password Spraying
- **Related Detection:** DET-004
- **Related Correlation:** CORR-001
- **Related Threat Hunt:** TH-001

---

## 1. Executive Incident Summary

Cyberion ThreatShield identified a concentrated series of Kerberos
authentication failures originating from a common source address and affecting
multiple distinct accounts.

The validated telemetry contained:

- 12 total records;
- 9 qualifying Kerberos authentication failures;
- 9 distinct target accounts;
- source address `172.16.66.1`;
- one successful CORR-001 behavioral correlation.

The nine qualifying events occurred within approximately `0.011011 seconds`,
well inside CORR-001's configured ten-minute window.

This pattern is strongly consistent with password-spraying behavior.

The available evidence does not establish a successful authentication,
credential compromise, persistence, privilege escalation, or the identity and
intent of the activity originator.

The case is therefore treated as a high-priority suspicious authentication
event requiring escalation and additional contextual investigation rather than
a confirmed compromise.

---

## 2. Detection Source

### Atomic Detection

**DET-004 — Kerberos Password Spray Indicators Across Multiple Accounts**

DET-004 selects:

- Event ID 4768 with Status `0x00000006`
- Event ID 4771 with Status `0x00000018`

Validation result:

**PASS**

### Correlation Detection

**CORR-001 — Kerberos Failures Across Multiple Accounts From One Source**

Correlation logic:

- group by `IpAddress`;
- count distinct `TargetUserName` values;
- threshold `>= 5`;
- configured timespan `10 minutes`.

Validation result:

**PASS**

### Threat Hunt

**TH-001 — Kerberos Password Spray Threat Hunt**

Hunt disposition:

**SUSPICIOUS ACTIVITY IDENTIFIED**

---

## 3. Evidence Source and Integrity

### Dataset

- Dataset ID: `DS-004`
- Dataset file: `kerberos_pwd_spray_4771.evtx`
- Source: `EVTX-ATTACK-SAMPLES`
- Provider: `Microsoft-Windows-Security-Auditing`
- Primary Event IDs: `4768`, `4771`

### Dataset SHA-256

`4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d`

Dataset hash verification:

**PASS**

Existing evidence artifacts:

- `validation/evidence/DET-004.md`
- `validation/results/DET-004.json`
- `validation/evidence/correlation-validation.txt`
- `threat-hunts/TH-001/TH-001-kerberos-password-spray.md`

---

## 4. Incident Scope

### Source Entity

Observed source address:

`172.16.66.1`

### Target Accounts

Nine distinct target accounts were observed:

1. `Administrator`
2. `HD01`
3. `HD02`
4. `admin`
5. `admin02`
6. `backdoor`
7. `bob`
8. `svc-01`
9. `svc-02`

### Observed Authentication Activity

- Qualifying failures: **9**
- Distinct target accounts: **9**
- Common source addresses: **1**
- Correlation matches: **1**

The observed account count exceeded the CORR-001 threshold of five distinct
accounts.

---

## 5. Incident Timeline

### Correlation Window Start

`2020-07-22T20:29:36.414827+00:00`

### Correlation Window End

`2020-07-22T20:29:36.425838+00:00`

### Observed Activity Span

`0.011011 seconds`

### Timeline Summary

| Time (UTC) | Event | Account | Source |
|---|---:|---|---|
| 20:29:36.414827 | 4768 | HD01 | 172.16.66.1 |
| 20:29:36.414856 | 4768 | admin | 172.16.66.1 |
| 20:29:36.414928 | 4768 | svc-02 | 172.16.66.1 |
| 20:29:36.414967 | 4768 | HD02 | 172.16.66.1 |
| 20:29:36.414984 | 4768 | svc-01 | 172.16.66.1 |
| 20:29:36.415049 | 4768 | bob | 172.16.66.1 |
| 20:29:36.415371 | 4768 | admin02 | 172.16.66.1 |
| 20:29:36.425364 | 4771 | Administrator | 172.16.66.1 |
| 20:29:36.425838 | 4771 | backdoor | 172.16.66.1 |

The nine qualifying failures occurred in extremely close temporal proximity.

---

## 6. Technical Evidence Analysis

### Event ID 4768

Seven qualifying Event ID 4768 records were observed with:

`Status = 0x00000006`

Affected accounts:

- HD01
- admin
- svc-02
- HD02
- svc-01
- bob
- admin02

### Event ID 4771

Two qualifying Event ID 4771 records were observed with:

`Status = 0x00000018`

Affected accounts:

- Administrator
- backdoor

Both event categories shared the source:

`172.16.66.1`

The combination of a common source, multiple distinct target accounts, and
extremely concentrated timing creates a substantially stronger signal than an
isolated authentication failure.

---

## 7. Correlation Analysis

CORR-001 requires:

`>= 5 distinct TargetUserName values`

grouped by:

`IpAddress`

within:

`10 minutes`

Observed:

- distinct users: **9**
- threshold: **5**
- threshold exceeded by: **4**
- observed event span: **0.011011 seconds**
- correlation matches: **1**

Result:

**CORRELATION VALIDATED — PASS**

The observed behavior substantially satisfies the correlation criteria.

---

## 8. ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Password Spraying | T1110.003 | DET-004, CORR-001, TH-001 |

The mapping describes the observed multi-account authentication-failure
pattern.

ATT&CK mapping is used as behavioral classification and does not by itself
establish malicious intent.

---

## 9. Severity and Confidence Assessment

### Severity: HIGH

Rationale:

- nine distinct accounts were targeted;
- a common source generated all qualifying failures;
- the configured correlation threshold was substantially exceeded;
- events occurred in extremely close temporal proximity;
- both atomic and correlation analytics validated the behavior.

### Confidence: HIGH BEHAVIORAL CONFIDENCE

There is strong confidence that the observed telemetry represents a
multi-account authentication-failure pattern consistent with password spraying.

There is **not** sufficient evidence to state with high confidence that:

- credentials were successfully compromised;
- an account was successfully accessed;
- subsequent malicious actions occurred; or
- the activity was unauthorized.

---

## 10. False-Positive Analysis

Potential benign explanations include:

- stale credentials affecting several accounts;
- authentication infrastructure problems;
- authorized authentication testing;
- administrative testing;
- incorrectly configured automated systems.

The unusually concentrated multi-account pattern makes isolated user error a
less persuasive explanation.

However, organizational context would still be required to determine whether
the source was authorized.

---

## 11. Triage Assessment

### Questions Answered by Available Evidence

**Was a multi-account authentication-failure pattern observed?**

Yes.

**Did one source address generate the qualifying activity?**

Yes — `172.16.66.1`.

**Was the correlation threshold exceeded?**

Yes — 9 distinct accounts versus a threshold of 5.

**Did the events occur within the configured correlation window?**

Yes — the observed span was approximately `0.011011 seconds`.

**Was password-spray-like behavior identified?**

Yes — the behavior is consistent with password spraying.

### Questions Not Answered by Available Evidence

The available dataset does not establish:

- whether any authentication later succeeded;
- whether any credential was compromised;
- whether `172.16.66.1` was an approved system;
- whether affected accounts were locked;
- whether endpoint activity followed;
- whether lateral movement occurred;
- whether persistence was established.

---

## 12. Containment Recommendations

If equivalent activity were observed in a production environment, recommended
defensive actions would include:

- investigate the source system associated with `172.16.66.1`;
- review successful authentication activity involving the affected accounts;
- verify whether the source is an approved authentication or administrative
  system;
- review account lockout and identity-provider alerts;
- temporarily restrict suspicious authentication sources when justified by
  corroborating evidence and organizational policy;
- prioritize privileged and service accounts for review;
- preserve relevant authentication and endpoint telemetry.

Account disabling or credential resets should be based on corroborating
evidence and established incident-response procedures.

---

## 13. Eradication Recommendations

If unauthorized activity were confirmed:

- identify and remove the underlying source of unauthorized authentication
  attempts;
- rotate credentials for confirmed affected accounts according to policy;
- remove unauthorized persistence discovered during follow-up investigation;
- review exposed administrative and service credentials;
- validate authentication infrastructure configuration;
- verify that no unauthorized accounts or access paths remain.

These actions are conditional because the current dataset does not establish
successful compromise.

---

## 14. Recovery Recommendations

Following confirmed remediation:

- restore normal account access according to organizational procedures;
- monitor affected accounts for renewed authentication anomalies;
- increase monitoring of the source and related systems;
- confirm expected service-account authentication behavior;
- verify identity and authentication controls are operating normally;
- document closure evidence and residual risk.

---

## 15. Lessons Learned

This investigation demonstrates the value of correlation-based detection.

A single failed authentication can have many benign explanations.

Nine qualifying failures involving nine distinct accounts from a common source
within approximately eleven milliseconds provide significantly stronger
behavioral context.

Combining:

- event-level detection;
- distinct-account correlation;
- time-window analysis; and
- analyst threat hunting

produces a more defensible assessment than relying on an isolated event.

The investigation also demonstrates why suspicious authentication telemetry
should not automatically be classified as confirmed compromise without
successful-authentication or follow-on evidence.

---

## 16. Final Disposition

### Incident Classification

**Suspicious Authentication Activity — Password Spray Pattern**

### Final Severity

**HIGH**

### Final Confidence

**HIGH behavioral confidence**

### Compromise Status

**UNCONFIRMED**

### Escalation

**REQUIRED FOR PRODUCTION EQUIVALENT**

The evidence establishes a concentrated multi-account Kerberos
authentication-failure pattern from `172.16.66.1` consistent with password
spraying.

No evidence in the analyzed dataset establishes successful account compromise.

Additional identity, endpoint, network, and follow-on authentication evidence
would be required before declaring a confirmed security incident.

**INC-001 STATUS: INVESTIGATION COMPLETE — SUSPICIOUS ACTIVITY IDENTIFIED,
COMPROMISE UNCONFIRMED**
