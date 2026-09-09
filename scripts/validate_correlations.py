from __future__ import annotations

import hashlib
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from Evtx.Evtx import Evtx


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "raw"

CORR001_DATASET = RAW / "kerberos_pwd_spray_4771.evtx"
CORR002_DATASET = RAW / "temp_scheduled_task_4698_4699.evtx"

CORR001_HASH = (
    "4a0a1c7132e216dbc704c806e9429df9"
    "ae3ac00485d5238e50c776e3099ae11d"
)

CORR002_HASH = (
    "a7decf0fbabc340e37de7e7c39fddd53"
    "98a7106a4f6acded0ea1d2ffa6bf8b70"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path: Path) -> list[dict[str, str]]:
    events = []

    with Evtx(str(path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())

            event: dict[str, str] = {}

            for element in root.iter():
                name = local_name(element.tag)

                if name == "EventID" and "EventID" not in event:
                    event["EventID"] = (element.text or "").strip()

                elif name == "TimeCreated":
                    timestamp = element.attrib.get("SystemTime")
                    if timestamp:
                        event["SystemTime"] = timestamp

                elif name == "Data":
                    field = element.attrib.get("Name")
                    if field:
                        event[field] = element.text or ""

            events.append(event)

    return events


def validate_corr001() -> bool:
    print("========== CORR-001 ==========")
    print("Kerberos Failures Across Multiple Accounts From One Source")

    actual_hash = sha256_file(CORR001_DATASET)

    print(f"Dataset: {CORR001_DATASET.name}")
    print(f"SHA-256: {actual_hash}")
    print(f"Hash verified: {'YES' if actual_hash == CORR001_HASH else 'NO'}")

    if actual_hash != CORR001_HASH:
        print("STATUS: FAIL")
        print("Reason: dataset hash mismatch")
        return False

    events = load_events(CORR001_DATASET)

    qualifying = []

    for event in events:
        event_id = event.get("EventID")
        status = event.get("Status")

        if (
            event_id == "4768"
            and status == "0x00000006"
        ) or (
            event_id == "4771"
            and status == "0x00000018"
        ):
            if (
                event.get("IpAddress")
                and event.get("TargetUserName")
                and event.get("SystemTime")
            ):
                qualifying.append(event)

    print(f"Total records: {len(events)}")
    print(f"Qualifying authentication failures: {len(qualifying)}")

    by_ip: dict[str, list[dict[str, str]]] = defaultdict(list)

    for event in qualifying:
        by_ip[event["IpAddress"]].append(event)

    threshold = 5
    window = timedelta(minutes=10)
    correlation_matches = []

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: parse_time(e["SystemTime"]))

        for start_index, start_event in enumerate(ip_events):
            start_time = parse_time(start_event["SystemTime"])
            end_time = start_time + window

            window_events = [
                event
                for event in ip_events[start_index:]
                if parse_time(event["SystemTime"]) <= end_time
            ]

            users = {
                event["TargetUserName"]
                for event in window_events
            }

            if len(users) >= threshold:
                last_time = max(
                    parse_time(event["SystemTime"])
                    for event in window_events
                )

                correlation_matches.append(
                    {
                        "ip": ip,
                        "start": start_time,
                        "end": last_time,
                        "users": sorted(users),
                        "count": len(window_events),
                    }
                )
                break

    if not correlation_matches:
        print("Correlation matches: 0")
        print("STATUS: FAIL")
        print("Reason: no source reached 5 distinct users within 10 minutes")
        return False

    print(f"Correlation matches: {len(correlation_matches)}")

    for match in correlation_matches:
        print(f"Source IP: {match['ip']}")
        print(f"Window start: {match['start'].isoformat()}")
        print(f"Window end:   {match['end'].isoformat()}")
        print(f"Observed span: {match['end'] - match['start']}")
        print(f"Events in window: {match['count']}")
        print(f"Distinct users: {len(match['users'])}")
        print(f"Users: {', '.join(match['users'])}")

    print("Required threshold: >=5 distinct users")
    print("Configured timespan: 10 minutes")
    print("STATUS: PASS")
    return True


def validate_corr002() -> bool:
    print()
    print("========== CORR-002 ==========")
    print("Scheduled Task Created Then Rapidly Deleted")

    actual_hash = sha256_file(CORR002_DATASET)

    print(f"Dataset: {CORR002_DATASET.name}")
    print(f"SHA-256: {actual_hash}")
    print(f"Hash verified: {'YES' if actual_hash == CORR002_HASH else 'NO'}")

    if actual_hash != CORR002_HASH:
        print("STATUS: FAIL")
        print("Reason: dataset hash mismatch")
        return False

    events = load_events(CORR002_DATASET)

    relevant = [
        event
        for event in events
        if event.get("EventID") in {"4698", "4699"}
        and event.get("TaskName")
        and event.get("SubjectUserName")
        and event.get("SystemTime")
    ]

    relevant.sort(key=lambda e: parse_time(e["SystemTime"]))

    print(f"Total records: {len(events)}")
    print(f"Relevant 4698/4699 records: {len(relevant)}")

    window = timedelta(minutes=1)
    matches = []

    for created in relevant:
        if created["EventID"] != "4698":
            continue

        created_time = parse_time(created["SystemTime"])

        for deleted in relevant:
            if deleted["EventID"] != "4699":
                continue

            if deleted["TaskName"] != created["TaskName"]:
                continue

            if deleted["SubjectUserName"] != created["SubjectUserName"]:
                continue

            deleted_time = parse_time(deleted["SystemTime"])
            delta = deleted_time - created_time

            # temporal_ordered:
            # deletion must occur after creation and within 1 minute.
            if timedelta(0) <= delta <= window:
                matches.append(
                    {
                        "task": created["TaskName"],
                        "user": created["SubjectUserName"],
                        "created": created_time,
                        "deleted": deleted_time,
                        "delta": delta,
                    }
                )

    print(f"Correlation matches: {len(matches)}")

    if not matches:
        print("STATUS: FAIL")
        print(
            "Reason: no same-task creation/deletion sequence "
            "was observed within one minute"
        )
        return False

    for match in matches:
        print(f"TaskName: {match['task']}")
        print(f"SubjectUserName: {match['user']}")
        print(f"Created: {match['created'].isoformat()}")
        print(f"Deleted: {match['deleted'].isoformat()}")
        print(f"Observed delta: {match['delta']}")

    print("Configured timespan: 1 minute")
    print("Ordering verified: YES")
    print("Same TaskName verified: YES")
    print("Same SubjectUserName verified: YES")
    print("STATUS: PASS")
    return True


def main() -> int:
    print("========== CYBERION THREATSHIELD ==========")
    print("Correlation Behavioral Validation")
    print()

    corr001 = validate_corr001()
    corr002 = validate_corr002()

    print()
    print("========== CORRELATION RESULT ==========")

    if corr001 and corr002:
        print("CORR-001: PASS")
        print("CORR-002: PASS")
        print("CORRELATION VALIDATION: PASS")
        return 0

    print(f"CORR-001: {'PASS' if corr001 else 'FAIL'}")
    print(f"CORR-002: {'PASS' if corr002 else 'FAIL'}")
    print("CORRELATION VALIDATION: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
