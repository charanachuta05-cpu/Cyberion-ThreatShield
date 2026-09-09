from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "raw"
RESULTS = ROOT / "validation" / "results"

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def read_evtx(path: Path) -> list[dict]:
    events = []

    with Evtx(str(path)) as log:
        for record_number, record in enumerate(log.records(), start=1):
            root = ET.fromstring(record.xml())

            event_id_text = root.findtext(
                "e:System/e:EventID",
                namespaces=NS,
            )

            provider_node = root.find(
                "e:System/e:Provider",
                NS,
            )

            provider = (
                provider_node.attrib.get("Name", "")
                if provider_node is not None
                else ""
            )

            time_node = root.find(
                "e:System/e:TimeCreated",
                NS,
            )

            system_time = (
                time_node.attrib.get("SystemTime", "")
                if time_node is not None
                else ""
            )

            fields = {}

            for data in root.findall(
                "e:EventData/e:Data",
                NS,
            ):
                name = data.attrib.get("Name")

                if name:
                    fields[name] = data.text or ""

            try:
                event_id = int(event_id_text)
            except (TypeError, ValueError):
                event_id = None

            events.append(
                {
                    "record": record_number,
                    "event_id": event_id,
                    "provider": provider,
                    "system_time": system_time,
                    "fields": fields,
                }
            )

    return events


def compact_event(event: dict, names: list[str]) -> dict:
    result = {
        "record": event["record"],
        "event_id": event["event_id"],
        "provider": event["provider"],
        "system_time": event["system_time"],
    }

    for name in names:
        value = event["fields"].get(name)

        if value not in (None, ""):
            result[name] = value

    return result


def validate_det002(events: list[dict]) -> dict:
    matches = [
        event
        for event in events
        if event["event_id"] in {4798, 4799}
    ]

    return {
        "matches": [
            compact_event(
                event,
                [
                    "TargetUserName",
                    "TargetDomainName",
                    "TargetSid",
                    "SubjectUserName",
                    "SubjectDomainName",
                    "CallerProcessName",
                ],
            )
            for event in matches
        ],
        "match_count": len(matches),
        "pass": len(matches) >= 1,
    }


def validate_det003(events: list[dict]) -> dict:
    matches = []

    for event in events:
        fields = event["fields"]

        if (
            event["event_id"] == 4732
            and fields.get("TargetSid") == "S-1-5-32-544"
        ):
            matches.append(event)

    return {
        "matches": [
            compact_event(
                event,
                [
                    "MemberName",
                    "MemberSid",
                    "TargetUserName",
                    "TargetDomainName",
                    "TargetSid",
                    "SubjectUserName",
                    "SubjectDomainName",
                ],
            )
            for event in matches
        ],
        "match_count": len(matches),
        "pass": len(matches) >= 1,
    }


def validate_det004(events: list[dict]) -> dict:
    atomic_matches = []

    for event in events:
        fields = event["fields"]

        match_4768 = (
            event["event_id"] == 4768
            and fields.get("Status") == "0x00000006"
        )

        match_4771 = (
            event["event_id"] == 4771
            and fields.get("Status") == "0x00000018"
        )

        if match_4768 or match_4771:
            atomic_matches.append(event)

    # Defensive correlation validation:
    # group atomic authentication failures by source address and
    # measure the number of distinct target accounts observed.
    by_source = defaultdict(set)

    for event in atomic_matches:
        source = event["fields"].get("IpAddress", "")
        account = event["fields"].get("TargetUserName", "")

        if source and account:
            # Normalize IPv4-mapped IPv6 representation if encountered.
            if source.startswith("::ffff:"):
                source = source[7:]

            by_source[source].add(account)

    correlation = []

    for source, accounts in sorted(by_source.items()):
        correlation.append(
            {
                "source_ip": source,
                "distinct_accounts": len(accounts),
                "accounts": sorted(accounts),
            }
        )

    correlation_pass = any(
        item["distinct_accounts"] >= 5
        for item in correlation
    )

    return {
        "matches": [
            compact_event(
                event,
                [
                    "TargetUserName",
                    "TargetDomainName",
                    "ServiceName",
                    "Status",
                    "PreAuthType",
                    "IpAddress",
                    "IpPort",
                ],
            )
            for event in atomic_matches
        ],
        "match_count": len(atomic_matches),
        "correlation_threshold": {
            "distinct_accounts": 5,
            "group_by": "IpAddress",
        },
        "correlation": correlation,
        "correlation_pass": correlation_pass,
        "pass": len(atomic_matches) >= 1,
    }


def validate_det005(events: list[dict]) -> dict:
    suspicious_suffixes = (
        "\\cmd.exe",
        "\\powershell.exe",
        "\\pwsh.exe",
        "\\calc.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "calc.exe",
    )

    matches = []

    for event in events:
        fields = event["fields"]
        image_path = fields.get("ImagePath", "").lower()

        if (
            event["event_id"] == 7045
            and image_path.endswith(suspicious_suffixes)
        ):
            matches.append(event)

    return {
        "matches": [
            compact_event(
                event,
                [
                    "ServiceName",
                    "ImagePath",
                    "ServiceType",
                    "StartType",
                    "AccountName",
                ],
            )
            for event in matches
        ],
        "match_count": len(matches),
        "pass": len(matches) >= 1,
    }


VALIDATIONS = {
    "DET-002": {
        "dataset": "DS-002",
        "file": (
            "discovery_local_user_or_group_"
            "windows_security_4799_4798.evtx"
        ),
        "validator": validate_det002,
    },
    "DET-003": {
        "dataset": "DS-003",
        "file": "Network_Service_Guest_added_to_admins_4732.evtx",
        "validator": validate_det003,
    },
    "DET-004": {
        "dataset": "DS-004",
        "file": "kerberos_pwd_spray_4771.evtx",
        "validator": validate_det004,
    },
    "DET-005": {
        "dataset": "DS-005",
        "file": "LM_Remote_Service02_7045.evtx",
        "validator": validate_det005,
    },
}


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)

    overall_pass = True

    print("=" * 68)
    print("THREATSHIELD BATCH VALIDATION")
    print("=" * 68)

    for detection_id, config in VALIDATIONS.items():
        path = RAW / config["file"]

        if not path.exists():
            print(f"{detection_id}: FAIL - dataset not found: {path}")
            overall_pass = False
            continue

        events = read_evtx(path)
        validation = config["validator"](events)

        result = {
            "detection_id": detection_id,
            "dataset_id": config["dataset"],
            "dataset_file": config["file"],
            "total_records": len(events),
            "validation_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            **validation,
        }

        output_path = RESULTS / f"{detection_id}.json"

        output_path.write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )

        status = "PASS" if validation["pass"] else "FAIL"

        print(
            f"{detection_id}: {status} "
            f"| records={len(events)} "
            f"| matches={validation['match_count']}"
        )

        if detection_id == "DET-004":
            corr_status = (
                "PASS"
                if validation["correlation_pass"]
                else "FAIL"
            )

            print(
                "         correlation="
                f"{corr_status} "
                "| threshold=5 distinct accounts/source"
            )

            for item in validation["correlation"]:
                print(
                    "         "
                    f"{item['source_ip']} -> "
                    f"{item['distinct_accounts']} accounts"
                )

        if not validation["pass"]:
            overall_pass = False

    print("=" * 68)

    if overall_pass:
        print("BATCH STATUS: PASS")
        return 0

    print("BATCH STATUS: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
