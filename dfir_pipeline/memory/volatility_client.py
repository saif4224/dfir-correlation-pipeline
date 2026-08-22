"""Client for Volatility3 (the standard open-source memory forensics
framework): runs the pslist/netscan/malfind plugins against a memory
image and parses their JSON output.

Requires the real `vol` CLI on PATH for live mode (`pip install
volatility3`) plus a real memory image (raw/.vmem/.dmp) and a matching
symbol table for the target OS - genuinely producing one requires a
real captured memory snapshot, which this repo deliberately does not
ship or fabricate (unlike a PE file, a valid memory dump's internal
kernel structures can't be meaningfully hand-built). Offline/demo mode
instead loads a bundled fixture that mirrors the *shape* of vol3's
`--output json` output - see tests/fixtures/synthetic_volatility_report.json.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from dfir_pipeline.models import MemoryInjection, MemoryNetworkConnection, MemoryProcess

logger = logging.getLogger(__name__)


class VolatilityNotFound(RuntimeError):
    pass


class VolatilityClient:
    def __init__(self, vol_path: str = "vol"):
        self.vol_path = vol_path

    def run_plugin(self, memory_image: str | Path, plugin: str) -> list[dict]:
        if not shutil.which(self.vol_path):
            raise VolatilityNotFound(
                f"'{self.vol_path}' not found on PATH. Install volatility3 or use --demo mode."
            )

        cmd = [self.vol_path, "-f", str(memory_image), "-r", "json", plugin]
        logger.info("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def analyze(
        self, memory_image: str | Path
    ) -> tuple[list[MemoryProcess], list[MemoryNetworkConnection], list[MemoryInjection]]:
        """Convenience wrapper: runs pslist + netscan + malfind against a real image."""
        processes = self._parse_processes(self.run_plugin(memory_image, "windows.pslist.PsList"))
        connections = self._parse_connections(self.run_plugin(memory_image, "windows.netscan.NetScan"))
        injections = self._parse_injections(self.run_plugin(memory_image, "windows.malfind.Malfind"))
        return processes, connections, injections

    def from_fixture_file(
        self, path: str | Path
    ) -> tuple[list[MemoryProcess], list[MemoryNetworkConnection], list[MemoryInjection]]:
        report = json.loads(Path(path).read_text())
        return (
            self._parse_processes(report["pslist"]),
            self._parse_connections(report["netscan"]),
            self._parse_injections(report["malfind"]),
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _parse_processes(self, rows: list[dict]) -> list[MemoryProcess]:
        return [
            MemoryProcess(
                pid=row["PID"],
                ppid=row["PPID"],
                name=row["ImageFileName"],
                create_time=self._parse_timestamp(row["CreateTime"]),
                command_line=row.get("Cmdline", ""),
            )
            for row in rows
        ]

    def _parse_connections(self, rows: list[dict]) -> list[MemoryNetworkConnection]:
        return [
            MemoryNetworkConnection(
                pid=row["PID"],
                process_name=row.get("Owner", "unknown"),
                local_addr=row["LocalAddr"],
                local_port=row["LocalPort"],
                remote_addr=row["ForeignAddr"],
                remote_port=row["ForeignPort"],
                protocol=row.get("Proto", "TCP"),
                state=row.get("State", ""),
            )
            for row in rows
        ]

    def _parse_injections(self, rows: list[dict]) -> list[MemoryInjection]:
        return [
            MemoryInjection(
                pid=row["PID"],
                process_name=row.get("Process", "unknown"),
                address=row["Address"],
                protection=row.get("Protection", ""),
            )
            for row in rows
        ]
