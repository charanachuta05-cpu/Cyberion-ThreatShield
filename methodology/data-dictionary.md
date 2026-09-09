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

## Source 2 - Network Telemetry

**Dataset:** Pending selection

| Field | Meaning | Detection Relevance |
|---|---|---|
| Pending | Pending dataset inspection | Pending |

---

## Source 3 - Authentication Telemetry

**Dataset:** Pending selection

| Field | Meaning | Detection Relevance |
|---|---|---|
| Pending | Pending dataset inspection | Pending |

---

## Evidence Policy

Fields are added only after confirming their presence in the telemetry
used by ThreatShield.

Detection rules and threat-hunting conclusions must remain traceable to
the corresponding dataset and validation evidence.
