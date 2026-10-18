#!/usr/bin/env python3
import csv
import hashlib
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence" / "authentication.log"
HASH_FILE = ROOT / "evidence" / "SHA256SUMS"
TIMELINE = ROOT / "timeline" / "incident_timeline.csv"
REPORT = ROOT / "reports" / "incident_report.txt"

PATTERN = re.compile(
    r"^(?P<timestamp>\S+) .*?sshd\[\d+\]: "
    r"(?P<event>Accepted publickey|Failed password) "
    r"for (?:(?:invalid user) )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def main():
    if not EVIDENCE.is_file() or not HASH_FILE.is_file():
        print("ERROR: Evidence log or SHA256SUMS is missing.")
        return 1

    actual_hash = hashlib.sha256(EVIDENCE.read_bytes()).hexdigest()
    expected_hash = HASH_FILE.read_text().split()[0]

    if actual_hash != expected_hash:
        print("INTEGRITY CHECK FAILED: Evidence hash does not match.")
        return 1

    events = []
    unparsed = 0

    for line in EVIDENCE.read_text().splitlines():
        match = PATTERN.match(line)
        if not match:
            unparsed += 1
            continue

        item = match.groupdict()
        try:
            item["timestamp"] = datetime.fromisoformat(
                item["timestamp"].replace("Z", "+00:00")
            ).isoformat()
        except ValueError:
            unparsed += 1
            continue

        events.append(item)

    events.sort(key=lambda item: item["timestamp"])
    TIMELINE.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    with TIMELINE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file, fieldnames=["timestamp", "event", "user", "ip"]
        )
        writer.writeheader()
        writer.writerows(events)

    failures = [event for event in events if event["event"] == "Failed password"]
    successes = [event for event in events if event["event"] == "Accepted publickey"]
    sources = {}
    for event in failures:
        sources[event["ip"]] = sources.get(event["ip"], 0) + 1

    with REPORT.open("w") as file:
        file.write("INCIDENT RESPONSE — INITIAL EVIDENCE REPORT\n")
        file.write("=" * 46 + "\n")
        file.write("Evidence type: Simulated SSH authentication log\n")
        file.write(f"SHA-256 verified: {actual_hash}\n")
        file.write(f"Parsed events: {len(events)}\n")
        file.write(f"Failed logins: {len(failures)}\n")
        file.write(f"Successful logins: {len(successes)}\n")
        file.write(f"Unparsed lines: {unparsed}\n\n")
        file.write("Failed login counts by source IP:\n")
        for ip, count in sorted(sources.items()):
            file.write(f"  {ip}: {count}\n")
        file.write(
            "\nAssessment: Repeated failures from one source may warrant "
            "investigation. This simulated log alone does not prove "
            "a successful compromise.\n"
        )

    print("INTEGRITY CHECK: PASS")
    print(f"Parsed events: {len(events)}")
    print(f"Failed logins: {len(failures)}")
    print(f"Successful logins: {len(successes)}")
    print(f"Unparsed lines: {unparsed}")
    print(f"Timeline: {TIMELINE.relative_to(ROOT)}")
    print(f"Report: {REPORT.relative_to(ROOT)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
