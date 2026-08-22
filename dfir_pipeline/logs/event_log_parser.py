"""Parses normalized Windows Event Log / Sysmon log exports (JSON
lines) into typed LogEvent objects and flags high-value event IDs.

Real deployments typically convert raw .evtx files to JSON first
(e.g. via `evtx_dump`, or a SIEM/EDR export) before analysis - this
module consumes that normalized JSON form rather than parsing the
binary .evtx format directly, which is the same shape most log
analysis and hunting tooling (Zircolite, Chainsaw, Hayabusa) works
against.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dfir_pipeline.models import LogEvent

# Real, publicly documented Windows Security log and Sysmon event IDs that are
# high-signal for incident response triage.
HIGH_VALUE_EVENT_IDS = {
    4688: "Process creation (Security log)",
    4624: "Successful logon",
    4625: "Failed logon",
    4672: "Special privileges assigned to new logon",
    1102: "Audit log cleared",
    7045: "New service installed",
    4698: "Scheduled task created",
    1: "Sysmon: Process creation",
    3: "Sysmon: Network connection",
    7: "Sysmon: Image/DLL loaded",
    11: "Sysmon: File created",
}


class EventLogParser:
    def parse_file(self, path: str | Path) -> list[LogEvent]:
        content = Path(path).read_text()
        try:
            rows = json.loads(content)
        except json.JSONDecodeError:
            rows = [json.loads(line) for line in content.splitlines() if line.strip()]
        return self.parse_rows(rows)

    def parse_rows(self, rows: list[dict]) -> list[LogEvent]:
        events = []
        for row in rows:
            events.append(
                LogEvent(
                    event_id=int(row["EventID"]),
                    time_created=datetime.fromisoformat(row["TimeCreated"].replace("Z", "+00:00")),
                    computer=row.get("Computer", "unknown"),
                    user=row.get("User", ""),
                    command_line=row.get("CommandLine", ""),
                    description=HIGH_VALUE_EVENT_IDS.get(int(row["EventID"]), row.get("Description", "")),
                )
            )
        return events

    def is_high_value(self, event: LogEvent) -> bool:
        return event.event_id in HIGH_VALUE_EVENT_IDS
