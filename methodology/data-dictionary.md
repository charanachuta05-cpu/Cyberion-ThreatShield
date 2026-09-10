# ThreatShield Telemetry Data Dictionary

Fields are documented from telemetry actually inspected during the
engagement. Generic assumptions are not treated as evidence.

---

## Source 1 - Windows Sysmon

**Dataset ID:** DS-001
**Dataset:** EVTX-ATTACK-SAMPLES
**Sample:** `Execution/exec_sysmon_1_ftp.evtx`
**Provider:** Microsoft-Windows-Sysmon
**Observed Event ID:** 1 - Process Creation
**Observed records:** 4

| Field | Meaning | Detection Relevance |
|---|---|---|
| UtcTime | Event time in UTC | Timeline reconstruction |
| ProcessGuid | Sysmon process identifier | Process correlation |
| ProcessId | Operating-system process ID | Process tracking |
| Image | Executable image path | Process identification |
| CommandLine | Process command line | Execution analysis |
| CurrentDirectory | Process working directory | Execution context |
| User | Account executing process | User attribution |
| ParentProcessGuid | Parent process identifier | Parent-child correlation |
| ParentProcessId | Parent operating-system PID | Parent tracking |
| ParentImage | Parent executable path | Process ancestry detection |
| ParentCommandLine | Parent command line | Execution-chain analysis |
| Hashes | Recorded process hashes | IOC/evidence correlation |
| IntegrityLevel | Process integrity level | Privilege context |
| LogonGuid | Associated logon identifier | Authentication correlation |
| LogonId | Associated logon session | Session correlation |
| TerminalSessionId | Terminal session identifier | Session context |
| Company | Executable company metadata | Process context |
| Product | Executable product metadata | Process context |
| Description | Executable description | Process context |
| FileVersion | Executable version metadata | Process context |
| RuleName | Sysmon rule metadata | Collection context |

### DS-001 Observed Process Chain

The inspected telemetry contains the following relevant relationship:

`ftp.exe -> cmd.exe -> calc.exe`

The Sysmon process-creation event for `cmd.exe` records:

- Image: `C:\Windows\System32\cmd.exe`
- ParentImage: `C:\Windows\System32\ftp.exe`
- User: `IEWIN7\IEUser`

This relationship provides evidence for the first ThreatShield detection.

---

## Source 2 - Windows Security Authentication Telemetry

**Primary dataset:** DS-004 - Kerberos Authentication Failure Activity

**Dataset:** EVTX-ATTACK-SAMPLES

**Provider:** Microsoft-Windows-Security-Auditing / Microsoft-Windows-Eventlog

**Format:** Windows EVTX

**Observed Event IDs:** 1102, 4768, 4771

| Field | Meaning | Detection Relevance |
|---|---|---|
| EventID | Windows event identifier | Authentication-event classification |
| TargetUserName | Account involved in authentication | Distinct-account correlation |
| IpAddress | Authentication source address | Source-based aggregation |
| Status | Kerberos authentication status | Failure-condition identification |
| Computer | Host recording the event | Asset context |
| SystemTime | Event timestamp | Correlation and timeline analysis |

### DS-004 Observed Authentication Pattern

ThreatShield observed nine qualifying Kerberos authentication failures
involving nine distinct target accounts from the common source
`172.16.66.1`.

This telemetry supports:

- DET-004;
- CORR-001;
- TH-001;
- INC-001;
- PB-001.

---

## Source 3 - Windows Security Administrative and Correlation Telemetry

**Primary correlation dataset:** DS-C03 - Network Logon Followed by Scheduled
Task Update

**Dataset:** EVTX-ATTACK-SAMPLES

**Provider:** Microsoft-Windows-Security-Auditing

**Format:** Windows EVTX

**Relevant Event IDs:** 4624, 4702

| Field | Meaning | Detection Relevance |
|---|---|---|
| EventID | Windows event identifier | Event-type classification |
| Computer | Host recording the event | Same-host correlation |
| IpAddress | Source address for network authentication | Source-system context |
| TargetUserName | Account authenticated by Event ID 4624 | Identity context |
| LogonType | Windows authentication type | Network-logon identification |
| TargetLogonId | Logon session identifier | Cross-event correlation |
| SubjectUserName | Account modifying the scheduled task | Administrative attribution |
| SubjectLogonId | Logon context associated with task modification | Cross-event correlation |
| TaskName | Scheduled task affected by Event ID 4702 | Persistence/administrative context |
| SystemTime | Event timestamp | Temporal correlation |

### DS-C03 Observed Correlation

ThreatShield observed a successful network logon from `172.16.66.142` for
`a-jbrown`, followed approximately `0.389267 seconds` later by modification
of scheduled task `\LMST`.

Behavioral validation confirmed:

`4624.TargetLogonId == 4702.SubjectLogonId`

This telemetry supports:

- CORR-003;
- TH-002;
- INC-002;
- PB-002.

The evidence establishes the event relationship but does not independently
establish whether the activity was authorized or malicious.

---

## Evidence Policy

Fields are added only after confirming their presence in the telemetry
used by ThreatShield.

Detection rules and threat-hunting conclusions must remain traceable to
the corresponding dataset and validation evidence.
