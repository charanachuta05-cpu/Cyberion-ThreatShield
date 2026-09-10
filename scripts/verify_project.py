#!/usr/bin/env python3
"""Repository-level verification for Cyberion ThreatShield.

This utility performs safe, defensive checks against the cloned project.
It does not execute attacks, replay telemetry, or require raw EVTX datasets.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "atomic_detections": 15,
    "correlation_detections": 3,
    "attack_rows": 24,
    "threat_hunts": 2,
    "incidents": 2,
    "playbooks": 3,
}


def result(ok: bool, label: str, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"[{status}] {label}{suffix}")
    return ok


def count_files(pattern: str) -> int:
    return len(list(ROOT.glob(pattern)))


def check_detection_inventory() -> list[bool]:
    atomic = count_files("detections/**/DET-*.yml")
    correlation = count_files("detections/**/CORR-*.yml")

    return [
        result(
            atomic == EXPECTED["atomic_detections"],
            "Atomic Sigma detections",
            f"{atomic}/{EXPECTED['atomic_detections']}",
        ),
        result(
            correlation == EXPECTED["correlation_detections"],
            "Correlation detections",
            f"{correlation}/{EXPECTED['correlation_detections']}",
        ),
    ]


def check_yaml() -> bool:
    files = sorted((ROOT / "detections").rglob("*.yml"))
    documents = 0

    try:
        for path in files:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
            if not docs:
                raise ValueError(f"{path.relative_to(ROOT)} contains no YAML document")
            documents += len(docs)
    except Exception as exc:
        return result(False, "Detection YAML parsing", str(exc))

    return result(
        True,
        "Detection YAML parsing",
        f"{len(files)} files / {documents} YAML documents",
    )


def check_empty_atomic_tags() -> bool:
    bad: list[str] = []

    try:
        for path in sorted((ROOT / "detections").rglob("DET-*.yml")):
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if (
                    isinstance(doc, dict)
                    and "tags" in doc
                    and doc["tags"] in (None, [])
                ):
                    bad.append(str(path.relative_to(ROOT)))
    except Exception as exc:
        return result(False, "Atomic Sigma metadata", str(exc))

    if bad:
        return result(
            False,
            "Atomic Sigma metadata",
            "empty tags block: " + ", ".join(bad),
        )

    return result(True, "Atomic Sigma metadata", "no empty tags blocks")


def check_sigma() -> bool:
    sigma = shutil.which("sigma")
    if sigma is None:
        return result(
            False,
            "Sigma validation",
            "sigma CLI not found; run pip install -r requirements.txt",
        )

    completed = subprocess.run(
        [sigma, "check", str(ROOT / "detections")],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        message = detail[-1] if detail else "sigma check failed"
        return result(False, "Sigma validation", message)

    return result(True, "Sigma validation", "sigma check detections passed")


def count_attack_rows() -> int:
    matrix = ROOT / "mitre" / "attack-coverage-matrix.md"
    if not matrix.is_file():
        return 0

    count = 0
    for line in matrix.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue

        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and cells[0].isdigit():
            count += 1

    return count


def check_artifacts() -> list[bool]:
    attack_rows = count_attack_rows()
    hunts = count_files("threat-hunts/**/TH-*.md")
    incidents = count_files("incidents/**/INC-*.md")
    playbooks = count_files("playbooks/PB-*.md")

    checks = [
        result(
            attack_rows == EXPECTED["attack_rows"],
            "MITRE ATT&CK assessment",
            f"{attack_rows}/{EXPECTED['attack_rows']} rows",
        ),
        result(
            hunts == EXPECTED["threat_hunts"],
            "Threat hunts",
            f"{hunts}/{EXPECTED['threat_hunts']}",
        ),
        result(
            incidents == EXPECTED["incidents"],
            "Incident investigations",
            f"{incidents}/{EXPECTED['incidents']}",
        ),
        result(
            playbooks == EXPECTED["playbooks"],
            "Incident-response playbooks",
            f"{playbooks}/{EXPECTED['playbooks']}",
        ),
    ]

    required = {
        "IOC research": ROOT
        / "ioc-research"
        / "IOC-001-observed-indicators-and-threat-context.md",
        "Detection methodology": ROOT
        / "methodology"
        / "detection-methodology.md",
        "Data dictionary": ROOT / "methodology" / "data-dictionary.md",
        "Executive summary": ROOT / "reports" / "executive-summary.md",
        "Final technical report": ROOT
        / "reports"
        / "final-technical-report.md",
        "README": ROOT / "README.md",
        "PowerPoint presentation": ROOT
        / "presentation"
        / "Cyberion_ThreatShield_Final_Presentation.pptx",
    }

    for label, path in required.items():
        checks.append(
            result(
                path.is_file() and path.stat().st_size > 0,
                label,
                str(path.relative_to(ROOT)),
            )
        )

    return checks


def main() -> int:
    print("=" * 64)
    print("CYBERION THREATSHIELD — PROJECT VERIFICATION")
    print("=" * 64)
    print("Repository-level defensive verification")
    print("Raw EVTX datasets are not required for this quick-start check.")
    print()

    checks: list[bool] = []
    checks.extend(check_detection_inventory())
    checks.append(check_yaml())
    checks.append(check_empty_atomic_tags())
    checks.append(check_sigma())
    checks.extend(check_artifacts())

    print()
    print("=" * 64)

    if all(checks):
        print("PROJECT VERIFICATION: PASS")
        print("The repository baseline is structurally ready for review.")
        return 0

    failed = sum(not check for check in checks)
    print(f"PROJECT VERIFICATION: FAIL ({failed} check(s) failed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
