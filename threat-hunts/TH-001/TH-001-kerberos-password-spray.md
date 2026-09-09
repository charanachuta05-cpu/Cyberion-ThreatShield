# TH-001 — Kerberos Password Spray Threat Hunt

## Hunt Metadata

- **Hunt ID:** TH-001
- **Title:** Kerberos Password Spray Across Multiple Accounts
- **Status:** Completed
- **Analyst:** Cyberion ThreatShield
- **Date:** 2026-09-09
- **ATT&CK Tactic:** Credential Access
- **ATT&CK Technique:** T1110.003 — Brute Force: Password Spraying
- **Related Detection:** DET-004
- **Related Correlation:** CORR-001

---

## 1. Hunt Objective

Identify whether Windows Kerberos authentication telemetry contains a pattern
consistent with password spraying: repeated authentication failures originating
from a common source and affecting multiple distinct accounts within a short
time window.

The hunt focuses on behavioral evidence rather than assuming malicious intent
from a single failed authentication event.

---

## 2. Hunt Hypothesis

If a single source address generates qualifying Kerberos authentication failures
against several distinct accounts within a short period, the pattern may
represent password spraying rather than isolated user password mistakes.

A stronger signal is produced when:

- the same source address is observed repeatedly;
- multiple distinct target usernames are involved;
- failures occur within a limited time window; and
- the number of affected accounts exceeds the defined correlation threshold.

---

## 3. Data Source

### Dataset

`kerberos_pwd_spray_4771.evtx`

Source dataset repository:

`EVTX-ATTACK-SAMPLES`

### Log Source

- Platform: Microsoft Windows
- Channel: Security
- Relevant Event IDs:
  - **4768** — Kerberos authentication ticket activity
  - **4771** — Kerberos pre-authentication failure

### Existing Validation Artifacts

- `validation/evidence/DET-004.md`
- `validation/results/DET-004.json`
- `validation/evidence/correlation-validation.txt`
- `validation/README.md`

---

## 4. Hunt Logic

The hunt uses the same qualifying authentication conditions validated by
DET-004.

### Event 4768

Qualifying condition:

- `EventID = 4768`
- `Status = 0x00000006`

### Event 4771

Qualifying condition:

- `EventID = 4771`
- `Status = 0x00000018`

### Correlation Logic

CORR-001 groups qualifying events by:

`IpAddress`

and counts distinct:

`TargetUserName`

within:

`10 minutes`

Correlation threshold:

`>= 5 distinct target accounts`

---

## 5. Observed Evidence

Behavioral validation identified:

- **9 qualifying Kerberos authentication failures**
- **9 distinct target accounts**
- **1 common source address**
- Source IP: `172.16.66.1`
- CORR-001 threshold: `>= 5 distinct accounts`
- Configured correlation window: `10 minutes`

The observed account count exceeded the correlation threshold by four accounts.

The validated correlation analysis also confirmed that the qualifying events
occurred well inside the configured ten-minute window.

---

## 6. Detection and Correlation Results

### DET-004

**Kerberos Password Spray Indicators Across Multiple Accounts**

Result:

`PASS`

DET-004 successfully selected the qualifying Kerberos authentication failures.

### CORR-001

**Kerberos Failures Across Multiple Accounts From One Source**

Result:

`PASS`

The correlation identified one source address generating qualifying failures
against nine distinct accounts, exceeding the required threshold of five.

---

## 7. Hunt Assessment

### Disposition

**Suspicious — behavior consistent with password spraying**

### Confidence

**High behavioral confidence**

The following factors increase confidence:

- one source address generated the qualifying events;
- nine distinct accounts were affected;
- the distinct-account threshold was exceeded;
- activity occurred within the correlation time window;
- both atomic and correlation analytics independently validated the pattern.

The evidence supports classification as activity consistent with password
spraying.

It does **not**, by itself, prove:

- account compromise;
- successful credential use;
- persistence;
- privilege escalation; or
- attacker identity.

Those conclusions would require additional authentication and endpoint
telemetry.

---

## 8. False-Positive Considerations

Possible benign explanations include:

- users entering incorrect credentials;
- stale credentials stored by applications or services;
- authentication failures after password changes;
- identity infrastructure problems;
- authorized authentication testing;
- incorrectly configured automated systems.

However, isolated password mistakes typically affect a small number of users.

The observed pattern is more suspicious because a single source generated
qualifying failures across nine distinct accounts within a short period.

---

## 9. Recommended Analyst Follow-Up

If this pattern were observed in a production environment, the analyst should
review:

- successful authentications involving the same source address;
- subsequent activity involving the affected accounts;
- endpoint telemetry from the source system;
- authentication history immediately before and after the failures;
- account lockout or identity-provider alerts;
- whether the source system is an approved authentication service;
- privileged-group membership of affected accounts;
- related remote-service or scheduled-task activity.

Any containment decision should be based on corroborating evidence and the
organization's incident-response process.

---

## 10. ATT&CK Mapping

| Tactic | Technique | ID | Coverage |
|---|---|---|---|
| Credential Access | Brute Force: Password Spraying | T1110.003 | DET-004 + CORR-001 |

The atomic rule provides event-level visibility while CORR-001 provides stronger
behavioral context through distinct-account counting from a common source.

---

## 11. Hunt Limitations

This hunt is based on selected pre-recorded Windows EVTX telemetry.

Limitations include:

- no live production telemetry;
- no identity-provider context;
- no endpoint telemetry from the source system;
- no network-flow evidence;
- no confirmed successful authentication linked to the observed failures;
- no evidence establishing the identity or intent of the activity originator.

Therefore, the hunt identifies suspicious authentication behavior but does not
assert a confirmed security incident.

---

## 12. Hunt Conclusion

TH-001 identified a Kerberos authentication pattern consistent with password
spraying.

Nine qualifying authentication failures affected nine distinct accounts from
the common source address `172.16.66.1`.

This exceeded the CORR-001 threshold of five distinct accounts within ten
minutes.

Both DET-004 and CORR-001 were previously behaviorally validated against the
underlying EVTX telemetry.

**Final Hunt Status: SUSPICIOUS ACTIVITY IDENTIFIED**

**Escalation Recommendation:** Review related successful authentication,
endpoint, identity, and follow-on activity before determining whether an
incident occurred.
