# ThreatShield Dataset Sources

## DS-001 - EVTX-ATTACK-SAMPLES

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Telemetry:** Microsoft-Windows-Sysmon
**Selected sample:** `Execution/exec_sysmon_1_ftp.evtx`
**Local identifier:** DS-001
**Format:** Windows EVTX
**Observed records:** 4
**Observed Event ID:** Sysmon Event ID 1 - Process Creation

## Purpose

DS-001 is used as recorded defensive telemetry for detection engineering
and rule-validation exercises.

ThreatShield does not execute or reproduce the activity represented by
the sample. Analysis is performed against the pre-recorded event log.

## Provenance

The original sample remains attributable to its upstream public dataset.
Raw EVTX files are excluded from the ThreatShield Git repository.

Derived evidence, field observations, validation results, and detection
content are version controlled within ThreatShield.

---

## DS-002 - Windows Account and Group Discovery

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Sample:** `Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx`
**Provider:** Microsoft-Windows-Security-Auditing
**Format:** Windows EVTX
**Observed records:** 3
**Observed Event IDs:** 4798, 4799
**SHA-256:** `dc2d739363f7ee4c27c429bcff0676e70d605b1f99198fd59433969dc455d65f`

Purpose: validation of Windows account and local-group discovery detections.

---

## DS-003 - Local Administrators Membership Modification

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Sample:** `Persistence/Network_Service_Guest_added_to_admins_4732.evtx`
**Provider:** Microsoft-Windows-Security-Auditing
**Format:** Windows EVTX
**Observed records:** 2
**Observed Event ID:** 4732
**SHA-256:** `9619b9d9d7bb8a277080167ff639fd9162e3d88d61d674cf1606beadce17ea5a`

Purpose: validation of privileged local-group membership change detections.

---

## DS-004 - Kerberos Authentication Failure Activity

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Sample:** `Credential Access/kerberos_pwd_spray_4771.evtx`
**Provider:** Microsoft-Windows-Security-Auditing / Microsoft-Windows-Eventlog
**Format:** Windows EVTX
**Observed records:** 12
**Observed Event IDs:** 1102, 4768, 4771
**SHA-256:** `4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d`

Purpose: validation of repeated Kerberos authentication-failure and correlation detections.

---

## DS-005 - Windows Service Installation

**Source:** EVTX-ATTACK-SAMPLES public security telemetry collection
**Sample:** `Lateral Movement/LM_Remote_Service02_7045.evtx`
**Provider:** Service Control Manager
**Format:** Windows EVTX
**Observed records:** 3
**Observed Event ID:** 7045
**SHA-256:** `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458`

Purpose: validation of suspicious Windows service-installation detections.

## DS-006 - Windows Scheduled Task Creation and Deletion

**Source:** EVTX-ATTACK-SAMPLES
**Sample:** `Execution/temp_scheduled_task_4698_4699.evtx`
**Provider:** Microsoft-Windows-Security-Auditing
**Format:** Windows EVTX
**Observed records:** 2
**Observed Event IDs:** 4698 (1), 4699 (1)
**SHA-256:** `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70`
**Purpose:** Validate scheduled-task creation detection using recorded Windows Security telemetry.

## DS-007 - PowerShell Remoting Process Activity

**Source:** EVTX-ATTACK-SAMPLES
**Sample:** `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
**Provider:** Microsoft-Windows-Sysmon
**Format:** Windows EVTX
**Observed records:** 1
**Observed Event IDs:** 1 (1)
**SHA-256:** `c890d2b67dc2902b2fa5a094e517674920911a15b273f43c674fbfaa69540658`
**Purpose:** Validate detection of processes spawned through the WinRM PowerShell remoting provider host.

## DS-008 - WMI Remote Execution Target Telemetry

**Source:** EVTX-ATTACK-SAMPLES
**Sample:** `Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx`
**Provider:** Microsoft-Windows-Security-Auditing
**Format:** Windows EVTX
**Observed records:** 8
**Observed Event IDs:** 4624 (6), 4688 (2)
**SHA-256:** `3ff3fcdb55c08ec0eaa39b25c1e02a205314f367bcedc662586bd063185ca41d`
**Purpose:** Validate WMI-related process creation and supporting remote-logon telemetry.

## DS-009 - Remote Shell Named Pipe Telemetry

**Source:** EVTX-ATTACK-SAMPLES
**Sample:** `Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx`
**Provider:** Microsoft-Windows-Sysmon
**Format:** Windows EVTX
**Observed records:** 7
**Observed Event IDs:** 18 (1), 3 (1), 1 (3), 10 (2)
**SHA-256:** `efdb2b2f2dd0864e82dabb693d38b44aea93e43c7df490ca3c94a4084da5c173`
**Purpose:** Validate suspicious named-pipe telemetry and associated remote-shell process activity.

## DS-010 - Renamed Regsvr32-Style Execution

**Source:** EVTX-ATTACK-SAMPLES
**Sample:** `Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx`
**Provider:** Microsoft-Windows-Sysmon
**Format:** Windows EVTX
**Observed records:** 2
**Observed Event IDs:** 1 (2)
**SHA-256:** `4baa0bc603d1e8b50212e60931431c5c6f7bf35fcdedb80bf6ab1fc77907ec04`
**Purpose:** Validate detection of an unexpected executable exhibiting regsvr32-style remote scriptlet command-line behavior.
