# Batch 2 Detection Validation Results

## Scope

This validation covers Cyberion ThreatShield atomic detections DET-006 through
DET-010 and correlation detections CORR-001 and CORR-002.

Validation was performed against pre-recorded Windows EVTX telemetry from the
EVTX-ATTACK-SAMPLES dataset. Raw EVTX files are intentionally excluded from
version control.

## Atomic Detection Results

| Rule | Dataset | Records | Matches | Result |
|---|---|---:|---:|---|
| DET-006 | DS-006 | 2 | 1 | PASS |
| DET-007 | DS-007 | 1 | 1 | PASS |
| DET-008 | DS-008 | 8 | 1 | PASS |
| DET-009 | DS-009 | 7 | 1 | PASS |
| DET-010 | DS-010 | 2 | 1 | PASS |

### DET-006

Windows Security Event ID 4698 was identified in DS-006, producing one
scheduled-task creation match.

**Result:** PASS

### DET-007

One Sysmon process-creation event showed `wsmprovhost.exe` as the parent
process, matching the Windows Remote Management / PowerShell-remoting
detection logic.

**Result:** PASS

### DET-008

One Windows Security Event ID 4688 recorded creation of
`C:\Windows\System32\wbem\WmiPrvSE.exe`.

**Result:** PASS

### DET-009

One Sysmon Event ID 18 recorded named-pipe activity involving the Windows
System process.

**Result:** PASS

### DET-010

One Sysmon process-creation event contained the `/u`, `/s`, and `/i:` switches
together with an HTTP resource. The executable was recorded as
`C:\ProgramData\jabber.exe`, demonstrating that the detection does not depend
solely on the expected regsvr32 filename.

**Result:** PASS

## Correlation Validation

### CORR-001 - Kerberos Failures Across Multiple Accounts From One Source

The validation dataset contained nine qualifying authentication failures from
source IP `172.16.66.1` involving nine distinct usernames.

- Required distinct-user threshold: 5
- Observed distinct users: 9
- Configured window: 10 minutes
- Observed qualifying-event span: 0.011011 seconds

The threshold was therefore reached inside the configured correlation window.

**Result:** PASS

### CORR-002 - Scheduled Task Created Then Rapidly Deleted

DS-006 contained a scheduled-task creation event followed by deletion of the
same task by the same subject.

- Task: `\CYAlyNSS`
- Subject: `Administrator`
- Creation: `2019-03-19T00:02:04.319944+00:00`
- Deletion: `2019-03-19T00:02:04.351252+00:00`
- Observed delta: 0.031308 seconds
- Configured window: 1 minute
- Ordering: verified
- Same task: verified
- Same subject: verified

**Result:** PASS

## Validation Controls

The validation process included:

- SHA-256 verification of every Batch 2 source EVTX file.
- Sigma static validation.
- Direct parsing of pre-recorded EVTX telemetry.
- Field-level comparison with detection logic.
- Explicit correlation-window verification.
- Correlation ordering and grouping verification where applicable.
- Python syntax validation of validation utilities.
- Git whitespace validation.
- Verification that raw EVTX telemetry is excluded from version control.

## Overall Result

**BATCH 2 VALIDATION: PASS**

At this checkpoint, Cyberion ThreatShield contains 10 atomic Sigma detections
and 2 correlation-style Sigma detections.
