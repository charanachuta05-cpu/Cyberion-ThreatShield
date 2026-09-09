from __future__ import annotations

import hashlib
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

from Evtx.Evtx import Evtx


DATASET_ROOT = Path.home() / "Cyberion-ThreatShield-Datasets" / "EVTX-ATTACK-SAMPLES"

SAMPLES = {
    "DET-011": {
        "path": DATASET_ROOT / "Defense Evasion/DE_1102_security_log_cleared.evtx",
        "sha256": "a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8",
    },
    "DET-012": {
        "path": DATASET_ROOT / "Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx",
        "sha256": "a2c396ac66aed02c0e36c6e467db3c3b83a57d003604ca79eb2a33175efcbad1",
    },
    "DET-013": {
        "path": DATASET_ROOT / "Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx",
        "sha256": "c2ed1a0248ab716a863f52bbfbd04d215f919c7ecefdfe6778a383b5552fb4f7",
    },
    "DET-014": {
        "path": DATASET_ROOT / "Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx",
        "sha256": "3eb77febe76db38146275927c57fa7fcb98394c2261858d957dabc90573ac7c0",
    },
    "DET-015": {
        "path": DATASET_ROOT / "Defense Evasion/DE_Fake_ComputerAccount_4720.evtx",
        "sha256": "8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9",
    },
    "CORR-003": {
        "path": DATASET_ROOT / "Lateral Movement/remote task update 4624 4702 same logonid.evtx",
        "sha256": "82ef6ef9e7616c441e79059fcad9ea7b53358431769e924a0bba6408ecba5fce",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_records(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []

    with Evtx(str(path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            event: dict[str, str] = {}

            for elem in root.iter():
                tag = local_name(elem.tag)

                if tag == "EventID" and "EventID" not in event:
                    event["EventID"] = (elem.text or "").strip()

                elif tag == "TimeCreated":
                    value = elem.attrib.get("SystemTime")
                    if value:
                        event["SystemTime"] = value

                elif tag == "Provider":
                    value = elem.attrib.get("Name")
                    if value:
                        event["ProviderName"] = value

                elif tag in {"Channel", "Computer"} and tag not in event:
                    event[tag] = (elem.text or "").strip()

                elif tag == "Data":
                    name = elem.attrib.get("Name")
                    if name:
                        event[name] = elem.text or ""

            records.append(event)

    return records


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def print_header(name: str) -> None:
    print()
    print("=" * 78)
    print(name)
    print("=" * 78)


def validate_sample(name: str) -> list[dict[str, str]]:
    info = SAMPLES[name]
    path = info["path"]

    if not path.exists():
        raise RuntimeError(f"{name}: missing dataset: {path}")

    actual = sha256_file(path)

    if actual != info["sha256"]:
        raise RuntimeError(
            f"{name}: SHA-256 mismatch\n"
            f"expected: {info['sha256']}\n"
            f"actual:   {actual}"
        )

    records = parse_records(path)

    print(f"Dataset: {path}")
    print("SHA-256: VERIFIED")
    print(f"Records: {len(records)}")
    print(
        "Event IDs:",
        dict(Counter(r.get("EventID", "<none>") for r in records)),
    )

    return records


def validate_det011() -> bool:
    print_header("DET-011 — Windows Security Audit Log Cleared")
    records = validate_sample("DET-011")

    matches = [r for r in records if r.get("EventID") == "1102"]

    print(f"Matches: {len(matches)}")

    for match in matches:
        print(
            "Match:",
            match.get("SystemTime"),
            match.get("Computer"),
            "EventID=1102",
        )

    passed = len(matches) >= 1
    print("STATUS:", "PASS" if passed else "FAIL")
    return passed


def validate_det012() -> bool:
    print_header("DET-012 — MSHTA Executing HTA Content")
    records = validate_sample("DET-012")

    matches = []

    for r in records:
        image = r.get("Image", "").lower()
        command = r.get("CommandLine", "").lower()

        if (
            r.get("EventID") == "1"
            and image.endswith("\\mshta.exe")
            and ".hta" in command
        ):
            matches.append(r)

    print(f"Matches: {len(matches)}")

    for match in matches:
        print("Image:", match.get("Image"))
        print("ParentImage:", match.get("ParentImage"))
        print("CommandLine:", match.get("CommandLine"))

    passed = len(matches) >= 1
    print("STATUS:", "PASS" if passed else "FAIL")
    return passed


def validate_det013() -> bool:
    print_header("DET-013 — BITS Transfer Referencing Command Interpreter")
    records = validate_sample("DET-013")

    suspicious = (
        "\\cmd.exe",
        "\\powershell.exe",
        "\\pwsh.exe",
    )

    matches = []

    for r in records:
        url = r.get("url", "").lower()

        if (
            r.get("EventID") in {"59", "60"}
            and url.endswith(suspicious)
        ):
            matches.append(r)

    print(f"Matches: {len(matches)}")

    for match in matches:
        print(
            "Match:",
            match.get("SystemTime"),
            f"EventID={match.get('EventID')}",
            f"name={match.get('name')}",
            f"url={match.get('url')}",
        )

    passed = len(matches) >= 1
    print("STATUS:", "PASS" if passed else "FAIL")
    return passed


def validate_det014() -> bool:
    print_header("DET-014 — PowerShell CLM Policy Registry Activity")
    records = validate_sample("DET-014")

    matches = []

    for r in records:
        target = r.get("TargetObject", "").lower()

        if (
            r.get("EventID") == "12"
            and target.endswith("\\__pslockdownpolicy")
        ):
            matches.append(r)

    print(f"Matches: {len(matches)}")

    for match in matches:
        print("Image:", match.get("Image"))
        print("TargetObject:", match.get("TargetObject"))
        print("RuleName:", match.get("RuleName"))

    passed = len(matches) >= 1
    print("STATUS:", "PASS" if passed else "FAIL")
    return passed


def validate_det015() -> bool:
    print_header("DET-015 — Unusual Windows User Account Created")
    records = validate_sample("DET-015")

    matches = [
        r
        for r in records
        if (
            r.get("EventID") == "4720"
            and r.get("TargetUserName") == "$"
        )
    ]

    print(f"Matches: {len(matches)}")

    for match in matches:
        print(
            "Match:",
            match.get("SystemTime"),
            f"Subject={match.get('SubjectDomainName')}\\"
            f"{match.get('SubjectUserName')}",
            f"Target={match.get('TargetDomainName')}\\"
            f"{match.get('TargetUserName')}",
        )

    passed = len(matches) >= 1
    print("STATUS:", "PASS" if passed else "FAIL")
    return passed


def validate_corr003() -> bool:
    print_header(
        "CORR-003 — Network Logon Followed by Scheduled Task Modification"
    )
    records = validate_sample("CORR-003")

    logons = [
        r
        for r in records
        if r.get("EventID") == "4624" and r.get("LogonType") == "3"
    ]

    task_updates = [
        r for r in records if r.get("EventID") == "4702"
    ]

    matches = []

    for logon in logons:
        target_logon_id = logon.get("TargetLogonId")

        if not target_logon_id:
            continue

        for task in task_updates:
            if logon.get("Computer") != task.get("Computer"):
                continue

            if task.get("SubjectLogonId") != target_logon_id:
                continue

            t_logon = parse_time(logon["SystemTime"])
            t_task = parse_time(task["SystemTime"])

            delta = (t_task - t_logon).total_seconds()

            if 0 <= delta <= 60:
                matches.append((logon, task, delta))

    print(f"Qualifying network logons: {len(logons)}")
    print(f"Scheduled task updates: {len(task_updates)}")
    print(f"Correlation matches: {len(matches)}")

    for logon, task, delta in matches:
        print()
        print("Source IP:", logon.get("IpAddress"))
        print("Target user:", logon.get("TargetUserName"))
        print("TargetLogonId:", logon.get("TargetLogonId"))
        print("Logon time:", logon.get("SystemTime"))
        print("TaskName:", task.get("TaskName"))
        print("Subject user:", task.get("SubjectUserName"))
        print("SubjectLogonId:", task.get("SubjectLogonId"))
        print("Task update time:", task.get("SystemTime"))
        print(f"Observed delta: {delta:.6f} seconds")
        print("Configured correlation window: 60 seconds")

    passed = len(matches) >= 1

    print("Cross-field LogonId linkage:", "VERIFIED" if passed else "NOT VERIFIED")
    print("Temporal ordering:", "VERIFIED" if passed else "NOT VERIFIED")
    print("STATUS:", "PASS" if passed else "FAIL")

    return passed


def main() -> int:
    checks = {
        "DET-011": validate_det011(),
        "DET-012": validate_det012(),
        "DET-013": validate_det013(),
        "DET-014": validate_det014(),
        "DET-015": validate_det015(),
        "CORR-003": validate_corr003(),
    }

    print()
    print("=" * 78)
    print("BATCH 3 SUMMARY")
    print("=" * 78)

    for name, passed in checks.items():
        print(f"{name}: {'PASS' if passed else 'FAIL'}")

    overall = all(checks.values())

    print()
    print("BATCH STATUS:", "PASS" if overall else "FAIL")

    return 0 if overall else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"\nVALIDATION ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
