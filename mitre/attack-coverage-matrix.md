# Cyberion ThreatShield — MITRE ATT&CK Coverage Matrix

## Purpose

This matrix assesses the current Cyberion ThreatShield detection baseline
against MITRE ATT&CK Enterprise techniques.

Coverage is based on validated Sigma rules, correlation analytics, and
pre-recorded Windows EVTX telemetry.

The matrix distinguishes between:

- **Detected** — a validated ThreatShield detection directly addresses the behavior.
- **Partial** — available telemetry or related analytics provide useful visibility,
  but coverage is incomplete.
- **Gap** — no dedicated validated detection currently exists in the baseline.

A Gap does not imply that the technique occurred in the validation datasets.
It identifies an area where the current detection baseline does not provide
dedicated coverage.

---

## Coverage Matrix

| # | Tactic | Technique | ATT&CK ID | ThreatShield Coverage | Detection / Evidence | Assessment |
|---:|---|---|---|---|---|---|
| 1 | Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Detected | DET-001 | FTP client spawning command/script interpreter behavior is detected. |
| 2 | Discovery | Account Discovery: Local Account | T1087.001 | Detected | DET-002 | Windows local account enumeration is detected through Security telemetry. |
| 3 | Discovery | Permission Groups Discovery: Local Groups | T1069.001 | Detected | DET-002 | Local group enumeration is covered by the same validated discovery analytic. |
| 4 | Persistence | Account Manipulation | T1098 | Detected | DET-003 | Addition of a member to the local Administrators group is detected. |
| 5 | Credential Access | Brute Force: Password Spraying | T1110.003 | Detected | DET-004, CORR-001 | Kerberos failures across multiple accounts and source-based correlation are validated. |
| 6 | Persistence / Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 | Detected | DET-005 | Suspicious Windows service installation telemetry is detected. |
| 7 | Execution / Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Detected | DET-006, CORR-002, CORR-003 | Task creation plus rapid create/delete and remote-logon/task-update correlations are covered. |
| 8 | Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | Detected | DET-007 | Processes spawned through the WinRM provider host are detected. |
| 9 | Execution | Windows Management Instrumentation | T1047 | Detected | DET-008 | WMI provider process-creation activity is detected. |
| 10 | Execution / IPC | Inter-Process Communication | T1559 | Partial | DET-009 | Named-pipe activity provides IPC visibility, but the current rule does not cover all IPC mechanisms. |
| 11 | Defense Evasion | System Binary Proxy Execution: Regsvr32 | T1218.010 | Detected | DET-010 | Regsvr32-style remote scriptlet command-line behavior is detected. |
| 12 | Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Detected | DET-011 + EVTX Event 1102 | Security audit-log clearing is behaviorally validated. |
| 13 | Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | Detected | DET-012 | mshta.exe execution of HTA content is validated against Sysmon telemetry. |
| 14 | Persistence / Defense Evasion | BITS Jobs | T1197 | Detected | DET-013 | BITS transfer events referencing command interpreters are detected. |
| 15 | Defense Evasion | Modify Registry | T1112 | Detected | DET-014 | Registry activity involving PowerShell __PSLockdownPolicy is validated. |
| 16 | Persistence | Create Account | T1136 | Detected | DET-015 | Windows Event ID 4720 confirms account-creation activity; the validation evidence does not independently establish a specific local/domain account subtype. |
| 17 | Credential Access | OS Credential Dumping | T1003 | Gap | None | No dedicated credential-dumping analytic exists in the validated baseline. |
| 18 | Discovery | System Information Discovery | T1082 | Gap | None | No dedicated host/system-information discovery analytic exists. |
| 19 | Discovery | Process Discovery | T1057 | Gap | None | Process enumeration is not directly covered by a validated rule. |
| 20 | Discovery | Network Service Discovery | T1046 | Gap | None | No dedicated network-service scanning/discovery detection is present. |
| 21 | Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | Gap | None | WinRM is covered, but RDP-specific lateral-movement detection is not. |
| 22 | Collection | Archive Collected Data | T1560 | Gap | None | No dedicated archive/staging analytic exists in the current baseline. |
| 23 | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Gap | None | Current telemetry does not provide a dedicated HTTP/HTTPS C2 analytic. |
| 24 | Exfiltration | Exfiltration Over Web Service | T1567 | Gap | None | No dedicated exfiltration analytic exists in the validated baseline. |

---

## Coverage Summary

### Techniques Assessed

- Total ATT&CK techniques/sub-techniques assessed: **24**
- Directly detected: **15**
- Partial coverage: **1**
- Identified gaps: **8**

### Tactics Represented

The assessment spans behavior associated with:

- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration

This exceeds the project requirement to assess at least 20 ATT&CK techniques
across at least four tactics.

---

## Strongest Coverage Areas

### Execution and Persistence

ThreatShield has multiple validated analytics covering:

- command-shell execution relationships
- Windows service installation
- scheduled-task activity
- WMI execution
- WinRM-related execution
- BITS activity
- account creation and manipulation

### Defense Evasion

Validated telemetry provides coverage for:

- Regsvr32-style proxy execution
- Mshta execution
- Windows Security log clearing
- registry modification associated with PowerShell policy controls
- BITS-related activity

### Credential Access

Password spraying has both:

- an atomic detection
- a multi-account correlation analytic

This provides stronger behavioral coverage than a single-event rule alone.

### Lateral Movement

WinRM-related process execution is directly detected.

CORR-003 additionally associates a network logon with subsequent scheduled-task
modification on the same host, while behavioral validation verifies the
cross-event LogonId relationship.

---

## Principal Detection Gaps

The current baseline has weaker or absent dedicated coverage for:

1. Credential dumping
2. RDP-specific lateral movement
3. Broad host and process discovery
4. Network-service discovery
5. Collection and archive staging
6. Web-based command-and-control behavior
7. Exfiltration behavior

These gaps should be treated as future detection-engineering opportunities,
not as evidence that those behaviors occurred in the analyzed datasets.

---

## Coverage Limitations

This matrix represents the scope of the Cyberion ThreatShield project and
should not be interpreted as complete enterprise security coverage.

Important limitations include:

- validation is based on selected pre-recorded Windows EVTX telemetry;
- the project does not ingest live production telemetry;
- some rules intentionally detect narrow behaviors demonstrated by the
  validation datasets;
- ATT&CK technique coverage does not guarantee detection of every
  implementation of a technique;
- correlation quality depends on event availability, field normalization,
  retention, and time synchronization;
- false-positive rates in a production environment may differ from the
  controlled validation datasets.

---

## Recommended Future Improvements

Future detection-engineering iterations should prioritize:

- credential-dumping telemetry and analytics;
- RDP authentication and session correlation;
- process and system discovery analytics;
- network-service discovery visibility;
- collection and archive-staging detection;
- DNS and HTTP/HTTPS network telemetry for command-and-control analysis;
- exfiltration-oriented network analytics;
- continued tuning and false-positive measurement against representative
  enterprise telemetry.

---

## Conclusion

Cyberion ThreatShield currently provides a validated Windows-focused
detection baseline with strong coverage across execution, persistence,
defense evasion, credential-access, discovery, and lateral-movement behaviors.

The matrix assesses **24 ATT&CK techniques/sub-techniques** and explicitly
separates validated detection coverage from partial coverage and known gaps.

This approach avoids overstating defensive capability while providing a
reproducible roadmap for future detection-engineering improvements.
