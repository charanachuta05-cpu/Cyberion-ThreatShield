# Batch 3 Detection Validation

## Scope

Batch 3 completes the initial Cyberion ThreatShield detection-engineering
baseline with five additional atomic Sigma detections and one correlation
detection.

Validated rules:

- DET-011 — Windows Security Audit Log Cleared
- DET-012 — MSHTA Executing HTA Content
- DET-013 — BITS Transfer Activity Referencing Command Interpreter
- DET-014 — PowerShell Constrained Language Mode Policy Registry Activity
- DET-015 — Unusual Windows User Account Created
- CORR-003 — Network Logon Followed by Scheduled Task Modification

## Validation Method

Validation was performed against pre-recorded Windows EVTX telemetry from the
EVTX-ATTACK-SAMPLES dataset.

Controls applied:

1. Dataset existence verification
2. SHA-256 integrity verification
3. EVTX parsing with python-evtx
4. Event-ID and field-level behavioral matching
5. Sigma syntax and condition validation
6. Correlation temporal-order verification
7. CORR-003 cross-field LogonId linkage verification

No dataset scripts or offensive tooling were executed.

## Results

| Rule | Dataset Evidence | Matches | Result |
|---|---|---:|---|
| DET-011 | Security Event ID 1102 | 1 | PASS |
| DET-012 | Sysmon Event ID 1, mshta.exe with HTA command line | 1 | PASS |
| DET-013 | BITS Events 59/60 referencing cmd.exe | 4 | PASS |
| DET-014 | Sysmon Event ID 12 targeting __PSLockdownPolicy | 1 | PASS |
| DET-015 | Security Event ID 4720 with unusual `$` target account | 2 | PASS |
| CORR-003 | Network logon followed by scheduled-task modification | 1 correlation | PASS |

## CORR-003 Evidence

Observed successful network logon:

- Source IP: `172.16.66.142`
- Target user: `a-jbrown`
- Logon type: `3`
- TargetLogonId: `0x00000000021a8c68`

Observed scheduled-task modification:

- Task name: `\LMST`
- Subject user: `a-jbrown`
- SubjectLogonId: `0x00000000021a8c68`

The logon and task-modification events occurred on the same host.

Observed time delta:

`0.389267 seconds`

Configured correlation window:

`60 seconds`

Cross-field relationship:

`4624.TargetLogonId == 4702.SubjectLogonId`

Result:

**PASS**

## False-Positive Considerations

### DET-011
Security logs can be cleared during authorized maintenance, troubleshooting,
or approved log-management operations. Administrative context should be
reviewed before escalation.

### DET-012
Some organizations legitimately use HTA applications. Validate the parent
process, command line, user context, HTA location, and surrounding process
activity.

### DET-013
BITS is legitimately used by Windows and enterprise software. Investigation
should focus on unusual job names, unexpected executable references,
unapproved users, and suspicious transfer context.

### DET-014
PowerShell policy-related registry values may be changed during approved
security configuration or administrative testing. Validate the responsible
process, user, change window, and endpoint role.

### DET-015
The validation sample contains the unusual target account name `$`. The rule
is intentionally narrow and should be tuned before production deployment.
Account-provisioning systems and laboratory activity may generate unusual
account names.

### CORR-003
Legitimate remote administration may produce network logons followed by
scheduled-task changes. Administrative source systems, approved operators,
change windows, task names, and LogonId relationships should be reviewed.

## Batch Status

All five atomic detections passed behavioral validation.

CORR-003 passed behavioral validation with:

- temporal ordering verified
- same-host relationship verified
- cross-field LogonId linkage verified
- configured time window satisfied

**BATCH 3 STATUS: PASS**

## Detection Engineering Checkpoint

After Batch 3:

- Atomic Sigma detections: **15**
- Correlation Sigma detections: **3**
- Minimum atomic detection requirement: **SATISFIED**
- Minimum correlation requirement: **SATISFIED**
