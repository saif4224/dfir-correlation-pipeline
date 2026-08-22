"""Loads the IOC watchlist and matches arbitrary values (IPs, domains,
filenames, hashes, process names) against it - the mechanism that lets
the timeline builder flag the *same* indicator wherever it shows up
across filesystem, memory, log, and network evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from dfir_pipeline.models import IOC

DEFAULT_WATCHLIST_PATH = Path(__file__).resolve().parents[2] / "data" / "ioc_watchlist.json"


class IOCWatchlist:
    def __init__(self, path: str | Path = DEFAULT_WATCHLIST_PATH):
        data = json.loads(Path(path).read_text())
        self._iocs = [
            IOC(ioc_type=i["ioc_type"], value=i["value"], description=i["description"], severity=i["severity"])
            for i in data["iocs"]
        ]

    def match(self, ioc_type: str, value: str) -> IOC | None:
        if not value:
            return None
        value_lower = value.lower()
        for ioc in self._iocs:
            if ioc.ioc_type == ioc_type and ioc.value.lower() in value_lower:
                return ioc
        return None

    def match_any_field(self, *values: str, ioc_type: str) -> list[IOC]:
        matches = []
        for value in values:
            matched = self.match(ioc_type, value)
            if matched:
                matches.append(matched)
        return matches
