from __future__ import annotations

import hashlib
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from Evtx.Evtx import Evtx


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "raw"

DATASETS = {
    "DET-006": {
        "file": RAW / "temp_scheduled_task_4698_4699.evtx",
        "sha256": "a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70",
    },
    "DET-007": {
        "file": RAW / "LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx",
        "sha256": "c890d2b67dc2902b2fa5a094e517674920911a15b273f43c674fbfaa69540658",
    },
    "DET-008": {
        "file": RAW / "LM_WMI_4624_4688_TargetHost.evtx",
        "sha256": "3ff3fcdb55c08ec0eaa39b25c1e02a205314f367bcedc662586bd063185ca41d",
    },
    "DET-009": {
        "file": RAW / "lm_sysmon_18_remshell_over_namedpipe.evtx",
        "sha256": "efdb2b2f2dd0864e82dabb693d38b44aea93e43c7df490ca3c94a4084da5c173",
    },
    "DET-010": {
        "file": RAW / "exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx",
        "sha256": "4baa0bc603d1e8b50212e60931431c5c6f7bf35fcdedb80bf6ab1fc77907ec04",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_record(xml_text: str) -> dict[str, str]:
    root = ET.fromstring(xml_text)
    event: dict[str, str] = {}

    # Parse System fields.
    for element in root.iter():
        name = local_name(element.tag)

        if name == "EventID" and "EventID" not in event:
            event["EventID"] = (element.text or "").strip()

        elif name == "Provider":
            provider = element.attrib.get("Name")
            if provider:
                event["Provider"] = provider

        elif name == "TimeCreated":
            timestamp = element.attrib.get("SystemTime")
            if timestamp:
                event["SystemTime"] = timestamp

    # Parse EventData/Data fields.
    for element in root.iter():
        if local_name(element.tag) != "Data":
            continue

        field_name = element.attrib.get("Name")
        if field_name:
            event[field_name] = element.text or ""

    return event


def load_events(path: Path) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []

    with Evtx(str(path)) as log:
        for record in log.records():
            events.append(parse_record(record.xml()))

    return events


def endswith_ci(value: str | None, suffix: str) -> bool:
    return (value or "").lower().endswith(suffix.lower())


def contains_ci(value: str | None, needle: str) -> bool:
    return needle.lower() in (value or "").lower()


def validate_det006(events: list[dict[str, str]]) -> list[dict[str, str]]:
    # Sigma:
    # EventID: 4698
    return [
        event
        for event in events
        if event.get("EventID") == "4698"
    ]


def validate_det007(events: list[dict[str, str]]) -> list[dict[str, str]]:
    # Sigma:
    # ParentImage|endswith: '\wsmprovhost.exe'
    return [
        event
        for event in events
        if endswith_ci(event.get("ParentImage"), r"\wsmprovhost.exe")
    ]


def validate_det008(events: list[dict[str, str]]) -> list[dict[str, str]]:
    # Sigma:
    # EventID: 4688
    # NewProcessName|endswith: '\WmiPrvSE.exe'
    return [
        event
        for event in events
        if event.get("EventID") == "4688"
        and endswith_ci(event.get("NewProcessName"), r"\WmiPrvSE.exe")
    ]


def validate_det009(events: list[dict[str, str]]) -> list[dict[str, str]]:
    # Sigma:
    # EventID: 18
    # Image: System
    return [
        event
        for event in events
        if event.get("EventID") == "18"
        and (event.get("Image") or "").lower() == "system"
    ]


def validate_det010(events: list[dict[str, str]]) -> list[dict[str, str]]:
    # Sigma:
    # CommandLine contains ALL /u, /s, /i:
    # AND contains http:// OR https://
    matches = []

    for event in events:
        command = event.get("CommandLine") or ""

        switches = all(
            contains_ci(command, value)
            for value in ("/u", "/s", "/i:")
        )

        remote = any(
            contains_ci(command, value)
            for value in ("http://", "https://")
        )

        if switches and remote:
            matches.append(event)

    return matches


VALIDATORS = {
    "DET-006": validate_det006,
    "DET-007": validate_det007,
    "DET-008": validate_det008,
    "DET-009": validate_det009,
    "DET-010": validate_det010,
}


def print_match(rule_id: str, event: dict[str, str], index: int) -> None:
    print(f"  MATCH {index}:")
    print(f"    EventID: {event.get('EventID', '-')}")
    print(f"    SystemTime: {event.get('SystemTime', '-')}")

    interesting_fields = {
        "DET-006": ("SubjectUserName", "TaskName"),
        "DET-007": ("Image", "ParentImage", "CommandLine", "User"),
        "DET-008": ("NewProcessName", "SubjectUserName", "ProcessId"),
        "DET-009": ("Image", "PipeName", "ProcessId"),
        "DET-010": ("Image", "CommandLine", "ParentImage", "User"),
    }

    for field in interesting_fields[rule_id]:
        value = event.get(field)

        if value:
            print(f"    {field}: {value}")


def main() -> int:
    overall_pass = True

    print("========== CYBERION THREATSHIELD ==========")
    print("Batch 2 EVTX Behavioral Validation")
    print()

    for rule_id, dataset in DATASETS.items():
        path = dataset["file"]
        expected_hash = dataset["sha256"]

        print(f"========== {rule_id} ==========")
        print(f"Dataset: {path.name}")

        if not path.is_file():
            print("STATUS: FAIL")
            print("Reason: dataset not found")
            print()
            overall_pass = False
            continue

        actual_hash = sha256_file(path)
        hash_ok = actual_hash == expected_hash

        print(f"SHA-256: {actual_hash}")
        print(f"Hash verified: {'YES' if hash_ok else 'NO'}")

        if not hash_ok:
            print("STATUS: FAIL")
            print("Reason: SHA-256 mismatch")
            print()
            overall_pass = False
            continue

        try:
            events = load_events(path)
        except Exception as exc:
            print("STATUS: FAIL")
            print(f"Reason: EVTX parse error: {exc}")
            print()
            overall_pass = False
            continue

        event_ids = Counter(
            event.get("EventID", "UNKNOWN")
            for event in events
        )

        matches = VALIDATORS[rule_id](events)

        print(f"Records: {len(events)}")
        print(
            "Event IDs: "
            + ", ".join(
                f"{event_id}={count}"
                for event_id, count in sorted(event_ids.items())
            )
        )
        print(f"Matches: {len(matches)}")

        for index, event in enumerate(matches, start=1):
            print_match(rule_id, event, index)

        passed = hash_ok and len(matches) >= 1

        print(f"STATUS: {'PASS' if passed else 'FAIL'}")
        print()

        if not passed:
            overall_pass = False

    print("========== BATCH 2 RESULT ==========")

    if overall_pass:
        print("BATCH STATUS: PASS")
        return 0

    print("BATCH STATUS: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
