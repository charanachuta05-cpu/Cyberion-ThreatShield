# INC-002 — Network Logon Followed by Scheduled Task Modification Investigation

## Incident Metadata

- **Incident ID:** INC-002
- **Title:** Network Logon Followed by Scheduled Task Modification Investigation
- **Status:** Investigated
- **Severity:** High
- **Confidence:** High behavioral confidence
- **Analyst:** Cyberion ThreatShield
- **Investigation Date:** 2026-09-09
- **Primary ATT&CK Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Related Detection:** CORR-003
- **Related Threat Hunt:** TH-002

---

## 1. Executive Incident Summary

Cyberion ThreatShield identified a successful Windows network logon followed
almost immediately by modification of a scheduled task on the same host.

The validated telemetry established the following sequence:

1. A successful Event ID 4624 network logon occurred from `172.16.66.142`.
2. The target account was `a-jbrown`.
3. The logon used Logon Type `3`.
4. The authentication session was assigned TargetLogonId
   `0x00000000021a8c68`.
5. Scheduled task `\LMST` was modified in Event ID 4702.
6. The task modification was associated with `a-jbrown`.
7. Event 4702 contained SubjectLogonId `0x00000000021a8c68`.
8. The task modification occurred only `0.389267 seconds` after the network
   logon.

The exact relationship:

`4624.TargetLogonId == 4702.SubjectLogonId`

was behaviorally verified.

This creates a strong authentication-to-action relationship between the
network logon and scheduled-task modification.

The telemetry is suspicious and warrants investigation. However, the available
evidence does not establish whether the remote activity was authorized or
whether the system was compromised.

---

## 2. Detection and Hunt Sources

### Correlation Detection

**CORR-003 — Network Logon Followed by Scheduled Task Modification**

CORR-003 identifies:

- Event ID 4624;
- Logon Type 3;
- subsequent Event ID 4702;
- same host;
- ordered temporal relationship;
- configured window of 60 seconds.

Behavioral validation additionally verifies:

`4624.TargetLogonId == 4702.SubjectLogonId`

Validation result:

**PASS**

### Threat Hunt

**TH-002 — Remote Network Logon Followed by Scheduled Task Modification**

Hunt disposition:

**SUSPICIOUS ACTIVITY IDENTIFIED**

---

## 3. Evidence Source and Integrity

### Dataset

`remote task update 4624 4702 same logonid.evtx`

Source:

`EVTX-ATTACK-SAMPLES`

### SHA-256

`82ef6ef9e7616c441e79059fcad9ea7b53358431769e924a0bba6408ecba5fce`

Hash validation:

**VERIFIED**

### Dataset Inventory

- Total records: **8**
- Event ID 1102: **1**
- Event ID 4624: **6**
- Event ID 4702: **1**
- Qualifying network logons: **6**
- Scheduled-task updates: **1**
- CORR-003 matches: **1**

Existing supporting artifacts:

- `detections/correlation/CORR-003-network-logon-followed-by-task-update.yml`
- `validation/evidence/batch3-evtx-validation.txt`
- `validation/results/batch3-validation.md`
- `scripts/validate_batch3.py`
- `threat-hunts/TH-002/TH-002-remote-logon-scheduled-task.md`

---

## 4. Incident Scope

### Source Address

`172.16.66.142`

### Account

`a-jbrown`

### Scheduled Task

`\LMST`

### Authentication Context

- Event ID: `4624`
- Logon Type: `3`
- TargetLogonId: `0x00000000021a8c68`

### Task Modification Context

- Event ID: `4702`
- Subject user: `a-jbrown`
- SubjectLogonId: `0x00000000021a8c68`

The identical LogonId values establish a direct authentication-session
relationship in the analyzed telemetry.

---

## 5. Incident Timeline

| Timestamp (UTC) | Event | Observed Activity |
|---|---:|---|
| 2020-09-02 11:47:48.570501 | 4624 | Successful network logon for `a-jbrown` from `172.16.66.142` |
| 2020-09-02 11:47:48.959768 | 4702 | Scheduled task `\LMST` modified by `a-jbrown` |

### Observed Delta

`0.389267 seconds`

### Configured Correlation Window

`60 seconds`

The task modification occurred less than one second after the qualifying
network logon.

---

## 6. Authentication Analysis

The qualifying Event ID 4624 contained:

- source IP: `172.16.66.142`;
- target user: `a-jbrown`;
- Logon Type: `3`;
- TargetLogonId: `0x00000000021a8c68`;
- timestamp: `2020-09-02 11:47:48.570501+00:00`.

Logon Type 3 establishes a Windows network logon.

The event provides authentication context but does not independently identify
the specific remote service or protocol responsible for the connection.

For this reason, the investigation does not assign a specific Remote Services
ATT&CK sub-technique solely from Event ID 4624.

---

## 7. Scheduled Task Analysis

The subsequent Event ID 4702 contained:

- task name: `\LMST`;
- subject user: `a-jbrown`;
- SubjectLogonId: `0x00000000021a8c68`;
- timestamp: `2020-09-02 11:47:48.959768+00:00`.

Event ID 4702 establishes that an existing scheduled task was modified.

The modification occurred approximately `0.389267 seconds` after the
qualifying network logon.

---

## 8. Cross-Event Correlation Analysis

The critical analytical relationship is:

`4624.TargetLogonId == 4702.SubjectLogonId`

Observed:

`0x00000000021a8c68 == 0x00000000021a8c68`

Result:

**VERIFIED**

Additional relationships:

- same host: **VERIFIED**
- same username: **OBSERVED**
- correct temporal ordering: **VERIFIED**
- configured 60-second window: **SATISFIED**
- observed delta: `0.389267 seconds`
- CORR-003 behavioral result: **PASS**

This provides substantially stronger evidence than temporal proximity alone.

---

## 9. ATT&CK Mapping

| Tactic | Technique | ATT&CK ID | Evidence |
|---|---|---|---|
| Execution / Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Event 4702, CORR-003, TH-002 |

The scheduled-task modification provides direct behavioral evidence for
scheduled-task activity.

The preceding Event ID 4624 supplies authentication context.

The investigation does not infer an additional remote-service technique without
telemetry identifying a specific service or protocol.

---

## 10. Severity and Confidence Assessment

### Severity: HIGH

Rationale:

- successful network authentication preceded the task change;
- scheduled-task modification occurred almost immediately afterward;
- the same user appears in both relevant events;
- exact cross-event LogonId linkage was verified;
- same-host relationship was verified;
- temporal ordering was verified;
- CORR-003 passed behavioral validation.

### Confidence: HIGH BEHAVIORAL CONFIDENCE

There is high confidence that the network-logon session and scheduled-task
modification are related in the analyzed telemetry.

There is insufficient evidence to establish that:

- the activity was unauthorized;
- the account was compromised;
- the source host was attacker-controlled;
- the modified task executed malicious content;
- persistence was successfully established; or
- lateral movement was successfully performed.

---

## 11. False-Positive Analysis

Potential legitimate explanations include:

- authorized remote administration;
- approved scheduled-task maintenance;
- administrator automation;
- software deployment systems;
- configuration-management tooling;
- activity occurring during an approved maintenance window.

Important contextual questions include:

- Is `172.16.66.142` an approved administrative source?
- Is `a-jbrown` authorized to modify scheduled tasks?
- Is `\LMST` a known and approved task?
- Was a change request associated with the modification?
- What action does the task execute?
- Did the task execute after modification?

Without this organizational context, malicious intent cannot be established.

---

## 12. Triage Assessment

### Questions Answered

**Was there a successful network logon?**

Yes.

**Did scheduled-task modification follow?**

Yes.

**Did both events occur in the required order?**

Yes.

**Did the task modification occur inside the 60-second window?**

Yes.

**Were the authentication sessions linked by LogonId?**

Yes.

**Was the same username observed?**

Yes — `a-jbrown`.

### Questions Not Answered

The available evidence does not establish:

- authorization status of `172.16.66.142`;
- authorization status of `a-jbrown`;
- contents of the modified task action;
- whether the task later executed;
- whether malicious process execution occurred;
- whether additional hosts were accessed;
- whether persistence was achieved;
- whether the activity formed part of a broader intrusion.

---

## 13. Containment Recommendations

If equivalent activity were observed in production:

- investigate the endpoint receiving the network logon;
- determine the asset associated with `172.16.66.142`;
- verify whether `a-jbrown` was performing approved administration;
- inspect the current and historical definition of `\LMST`;
- preserve Windows Security and endpoint telemetry;
- review related scheduled-task events;
- review authentication activity involving the account and source;
- review process activity associated with the modified task;
- restrict suspicious access when supported by corroborating evidence and
  organizational policy.

Containment decisions should be based on authorization context and additional
evidence rather than the correlation alone.

---

## 14. Eradication Recommendations

If investigation confirms unauthorized activity:

- remove unauthorized scheduled-task modifications;
- remove unauthorized persistence discovered during investigation;
- secure affected credentials according to organizational policy;
- investigate and remediate the originating endpoint;
- review administrative access paths;
- identify related unauthorized task changes;
- validate that affected systems no longer contain unauthorized configuration.

These actions remain conditional because compromise is not established by the
available dataset.

---

## 15. Recovery Recommendations

Following confirmed remediation:

- restore approved scheduled-task configuration;
- restore authorized account access according to policy;
- monitor the account and source system for recurrence;
- verify expected administrative workflows;
- monitor task creation, modification, deletion, and execution;
- document closure evidence;
- record residual risks and follow-up monitoring requirements.

---

## 16. Lessons Learned

This investigation demonstrates the importance of correlating authentication
telemetry with subsequent administrative activity.

A network logon alone may be routine.

A scheduled-task modification alone may also be legitimate.

Combining:

- successful network authentication;
- same-host context;
- same-user context;
- exact LogonId linkage;
- temporal ordering; and
- a sub-second event relationship

creates a significantly stronger behavioral signal.

The case also demonstrates why strong behavioral correlation must remain
separate from attribution or compromise claims. Telemetry can establish that
events are related without proving whether the activity was authorized.

---

## 17. Final Disposition

### Incident Classification

**Suspicious Remote Administrative Activity — Scheduled Task Modification**

### Final Severity

**HIGH**

### Final Confidence

**HIGH behavioral confidence**

### Correlation Status

**VERIFIED**

### Compromise Status

**UNCONFIRMED**

### Escalation

**REQUIRED FOR PRODUCTION EQUIVALENT**

The evidence establishes that a successful network logon from
`172.16.66.142` for `a-jbrown` was followed approximately `0.389267 seconds`
later by modification of scheduled task `\LMST`.

The authentication context was linked through the exact relationship:

`4624.TargetLogonId == 4702.SubjectLogonId`

The available evidence does not establish whether this activity was authorized
or malicious.

Additional endpoint, identity, task-definition, network, and organizational
context would be required before declaring a confirmed compromise.

**INC-002 STATUS: INVESTIGATION COMPLETE — SUSPICIOUS ACTIVITY IDENTIFIED,
COMPROMISE UNCONFIRMED**
