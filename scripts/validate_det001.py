#!/usr/bin/env python3

import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from Evtx.Evtx import Evtx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "datasets/raw/exec_sysmon_1_ftp.evtx"
RESULT = PROJECT_ROOT / "validation/results/DET-001.json"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

INTERPRETERS = (
    "\\cmd.exe",
    "\\powershell.exe",
    "\\pwsh.exe",
    "\\wscript.exe",
    "\\cscript.exe",
)


def normalize(value):
    return (value or "").strip().lower()


def endswith_any(value, endings):
    normalized = normalize(value)
    return any(normalized.endswith(item) for item in endings)


def parse_record(record):
    root = ET.fromstring(record.xml())

    event_id = root.findtext(
        "e:System/e:EventID",
        namespaces=NS,
    )

    fields = {}

    for data in root.findall("e:EventData/e:Data", NS):
        name = data.attrib.get("Name")
        if name:
            fields[name] = data.text or ""

    return event_id, fields


def matches_det001(event_id, fields):
    if event_id != "1":
        return False

    parent_match = normalize(
        fields.get("ParentImage")
    ).endswith("\\ftp.exe")

    child_match = endswith_any(
        fields.get("Image"),
        INTERPRETERS,
    )

    return parent_match and child_match


def main():
    if not DATASET.exists():
        print(f"ERROR: Dataset not found: {DATASET}", file=sys.stderr)
        return 2

    total_records = 0
    process_creation_records = 0
    matches = []

    with Evtx(str(DATASET)) as log:
        for record_number, record in enumerate(log.records(), start=1):
            total_records += 1

            event_id, fields = parse_record(record)

            if event_id == "1":
                process_creation_records += 1

            if matches_det001(event_id, fields):
                matches.append(
                    {
                        "record_number": record_number,
                        "event_id": event_id,
                        "utc_time": fields.get("UtcTime"),
                        "user": fields.get("User"),
                        "image": fields.get("Image"),
                        "command_line": fields.get("CommandLine"),
                        "parent_image": fields.get("ParentImage"),
                        "parent_command_line": fields.get(
                            "ParentCommandLine"
                        ),
                    }
                )

    status = "PASS" if matches else "FAIL"

    result = {
        "detection_id": "DET-001",
        "dataset_id": "DS-001",
        "dataset_file": DATASET.name,
        "validation_timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "validation_method": (
            "Local EVTX field evaluation reproducing "
            "DET-001 Sigma selection logic"
        ),
        "total_records": total_records,
        "sysmon_process_creation_records": process_creation_records,
        "match_count": len(matches),
        "matches": matches,
        "status": status,
    }

    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )

    print("========== DET-001 VALIDATION ==========")
    print(f"Dataset: {DATASET}")
    print(f"Total records: {total_records}")
    print(
        "Sysmon Event ID 1 records: "
        f"{process_creation_records}"
    )
    print(f"DET-001 matches: {len(matches)}")

    for match in matches:
        print("\n--- MATCH ---")
        print(f"Record: {match['record_number']}")
        print(f"UtcTime: {match['utc_time']}")
        print(f"User: {match['user']}")
        print(f"Image: {match['image']}")
        print(f"CommandLine: {match['command_line']}")
        print(f"ParentImage: {match['parent_image']}")
        print(
            "ParentCommandLine: "
            f"{match['parent_command_line']}"
        )

    print(f"\nValidation status: {status}")
    print(f"Evidence written: {RESULT}")

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
