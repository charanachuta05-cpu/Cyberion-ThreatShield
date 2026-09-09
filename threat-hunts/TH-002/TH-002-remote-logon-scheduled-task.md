# TH-002 — Remote Network Logon Followed by Scheduled Task Modification

## Hunt Metadata

- **Hunt ID:** TH-002
- **Title:** Remote Network Logon Followed by Scheduled Task Modification
- **Status:** Completed
- **Analyst:** Cyberion ThreatShield
- **Date:** 2026-09-09
- **Primary ATT&CK Tactic:** Execution / Persistence
- **Primary ATT&CK Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Related Detection:** CORR-003

---

## 1. Hunt Objective

Identify suspicious relationships between successful Windows network logons and
scheduled-task modifications occurring shortly afterward on the same host.

The hunt focuses on whether authentication context can be linked to a subsequent
scheduled-task change using event ordering, host context, user identity, and
Windows LogonId values.

---

## 2. Hunt Hypothesis

A successful remote network logon followed almost immediately by modification
of a scheduled task under the same authentication context may represent
suspicious remote administrative activity.

Confidence increases when:

- the initial authentication is a successful network logon;
- the task modification occurs on the same host;
- the same user is associated with both events;
- the 4624 TargetLogonId matches the 4702 SubjectLogonId; and
- the task modification occurs shortly after authentication.

This pattern may occur legitimately during remote administration, so the
relationship requires contextual analyst review.

---

## 3. Data Source

### Dataset

`remote task update 4624 4702 same logonid.evtx`

Source dataset repository:

`EVTX-ATTACK-SAMPLES`

### Log Source

- Platform: Microsoft Windows
- Channel: Security
- Total records in validation sample: **8**

Observed Event IDs:

- Event ID 1102: **1**
- Event ID 4624: **6**
- Event ID 4702: **1**

### Relevant Events

**4624 — Successful Account Logon**

Hunt condition:

- `EventID = 4624`
- `LogonType = 3`

**4702 — Scheduled Task Updated**

Hunt condition:

- `EventID = 4702`

### Existing Validation Artifacts

- `validation/evidence/batch3-evtx-validation.txt`
- `validation/results/batch3-validation.md`
- `detections/correlation/CORR-003-network-logon-followed-by-task-update.yml`

---

## 4. Hunt Logic

The hunt searches for:

1. a successful Windows network logon;
2. a subsequent scheduled-task modification;
3. both events occurring on the same host;
4. task modification occurring within 60 seconds of the network logon; and
5. authentication-context linkage where:

`4624.TargetLogonId == 4702.SubjectLogonId`

CORR-003 implements the temporal relationship at the host level.

Behavioral validation provides the additional cross-field LogonId verification.

---

## 5. Observed Evidence

### Successful Network Logon

- Event ID: **4624**
- Logon type: **3**
- Source IP: `172.16.66.142`
- Target user: `a-jbrown`
- TargetLogonId: `0x00000000021a8c68`
- Timestamp: `2020-09-02 11:47:48.570501+00:00`

### Scheduled Task Modification

- Event ID: **4702**
- Task name: `\LMST`
- Subject user: `a-jbrown`
- SubjectLogonId: `0x00000000021a8c68`
- Timestamp: `2020-09-02 11:47:48.959768+00:00`

### Temporal Relationship

Observed delta:

`0.389267 seconds`

Configured CORR-003 window:

`60 seconds`

The scheduled-task modification therefore occurred less than one second after
the qualifying network logon.

---

## 6. Cross-Event Authentication Linkage

The strongest relationship in the hunt is:

`4624.TargetLogonId == 4702.SubjectLogonId`

Observed values:

`0x00000000021a8c68 == 0x00000000021a8c68`

Result:

**VERIFIED**

The same username, `a-jbrown`, is also associated with both events.

This establishes that the task-modification event is linked to the same Windows
logon session represented by the qualifying network-logon event in the
validation telemetry.

---

## 7. Correlation Result

### CORR-003

**Network Logon Followed by Scheduled Task Modification**

Validation results:

- Qualifying network logons: **6**
- Scheduled-task updates: **1**
- Correlation matches: **1**
- Same-host relationship: **VERIFIED**
- Temporal ordering: **VERIFIED**
- Cross-field LogonId linkage: **VERIFIED**
- Configured time window satisfied: **YES**

**CORR-003 STATUS: PASS**

---

## 8. Hunt Assessment

### Disposition

**Suspicious — remote administrative activity requiring investigation**

### Confidence

**High behavioral confidence**

Confidence is increased by:

- a successful network logon;
- immediate scheduled-task modification;
- same-host relationship;
- same username across both relevant events;
- exact LogonId linkage;
- correct temporal ordering; and
- a delta of only `0.389267` seconds.

The evidence establishes a strong relationship between the authentication event
and scheduled-task modification.

It does not independently establish that the activity was unauthorized.

---

## 9. ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution / Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | CORR-003 + Event ID 4702 |

The observed scheduled-task modification provides direct visibility into
scheduled-task activity.

The preceding network logon provides authentication context that increases the
analytical value of the task-modification event.

The hunt does not assign a separate remote-services technique solely from Event
ID 4624 because a generic network logon does not independently identify the
specific remote service or protocol used.

---

## 10. False-Positive Considerations

Legitimate activity may produce the same sequence.

Examples include:

- authorized remote system administration;
- approved scheduled-task maintenance;
- software-management systems;
- deployment or orchestration tooling;
- administrator automation;
- scheduled changes performed during an approved maintenance window.

Analysts should therefore review:

- whether `172.16.66.142` is an approved administrative source;
- whether `a-jbrown` is authorized to modify scheduled tasks;
- the purpose and expected configuration of `\LMST`;
- change-management records;
- endpoint role;
- surrounding authentication activity; and
- related process execution.

---

## 11. Recommended Analyst Follow-Up

In a production investigation, review:

- task definition and configuration associated with `\LMST`;
- task execution events following the modification;
- process creation associated with the task;
- authentication history for `a-jbrown`;
- other systems accessed from `172.16.66.142`;
- additional scheduled-task creation, update, or deletion events;
- endpoint telemetry from the source and destination systems;
- privileged-group membership of the account;
- approved administrative and change-management records.

Containment or account actions should depend on corroborating evidence and the
organization's incident-response procedures.

---

## 12. Hunt Limitations

This hunt uses selected pre-recorded Windows EVTX telemetry.

Limitations include:

- no live production telemetry;
- no independent asset inventory;
- no change-management context;
- no endpoint process telemetry included in this hunt;
- no network-flow evidence;
- no evidence establishing whether the source system was authorized;
- no evidence establishing the intent of the user or activity originator.

A network logon followed by a task modification is not inherently malicious.

The hunt therefore identifies a suspicious behavioral relationship requiring
contextual investigation rather than declaring a confirmed compromise.

---

## 13. Hunt Conclusion

TH-002 identified a successful Windows network logon from:

`172.16.66.142`

for:

`a-jbrown`

followed by modification of scheduled task:

`\LMST`

only:

`0.389267 seconds`

later.

The authentication context was independently linked through:

`4624.TargetLogonId == 4702.SubjectLogonId`

with the shared value:

`0x00000000021a8c68`

Same-host relationship, temporal ordering, LogonId linkage, and the configured
CORR-003 time window were all behaviorally validated.

The evidence is consistent with suspicious remote administrative activity
involving scheduled-task modification, but additional organizational and
endpoint context would be required to determine whether the activity was
authorized or represented a security incident.

**Final Hunt Status: SUSPICIOUS ACTIVITY IDENTIFIED**

**Escalation Recommendation:** Investigate the source host, account,
scheduled-task definition, related process activity, and authorization context.
