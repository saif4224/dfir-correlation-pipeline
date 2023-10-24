"""Command-line entry point.

    # Demo mode - no real evidence required, uses bundled synthetic
    # fixtures for all four sources.
    python -m dfir_pipeline.cli --demo

    # Live mode - any subset of sources may be supplied; omitted
    # sources are simply skipped (real cases rarely have all four).
    python -m dfir_pipeline.cli --live --case "Case 2026-001" \\
        --fs-root /mnt/evidence --memory-image /evidence/mem.raw \\
        --log-file /evidence/security.json --pcap /evidence/capture.pcap
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from dfir_pipeline.filesystem.mac_timeline import FilesystemScanner
from dfir_pipeline.logs.event_log_parser import EventLogParser
from dfir_pipeline.memory.volatility_client import VolatilityClient
from dfir_pipeline.models import (
    DNSQuery,
    FileArtifact,
    LogEvent,
    MemoryInjection,
    MemoryNetworkConnection,
    MemoryProcess,
    NetworkFlow,
)
from dfir_pipeline.network.pcap_analyzer import PcapAnalyzer
from dfir_pipeline.pipeline import run_pipeline

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_FS_ROOT = REPO_ROOT / "tests" / "fixtures" / "synthetic_evidence_fs"
FIXTURE_MEMORY_REPORT = REPO_ROOT / "tests" / "fixtures" / "synthetic_volatility_report.json"
FIXTURE_LOG_FILE = REPO_ROOT / "tests" / "fixtures" / "synthetic_event_logs.json"
FIXTURE_PCAP = REPO_ROOT / "tests" / "fixtures" / "synthetic_capture.pcap"
FIXTURE_SNAPSHOT_TIME = datetime(2026, 3, 14, 9, 32, 0, tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cross-Source DFIR Correlation & Timeline Pipeline")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run end-to-end against bundled synthetic fixtures.")
    mode.add_argument("--live", action="store_true", help="Run against real evidence sources (any subset).")

    parser.add_argument("--case", type=str, default="untitled-case", help="Case name for the report.")
    parser.add_argument("--fs-root", type=str, help="Directory to scan for filesystem artifacts.")
    parser.add_argument(
        "--memory-image", type=str, help="Path to a real memory image (requires volatility3's 'vol' on PATH)."
    )
    parser.add_argument("--log-file", type=str, help="Path to a normalized JSON event log export.")
    parser.add_argument("--pcap", type=str, help="Path to a .pcap/.pcapng capture file.")
    parser.add_argument(
        "--snapshot-time", type=str, help="ISO8601 time the memory image was acquired (default: now)."
    )
    parser.add_argument("--output-dir", type=str, default="output", help="Where to write the report/visuals.")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def run_demo(output_dir: str) -> dict:
    logging.info("Running in DEMO mode: synthetic evidence across all four sources, nothing real.")
    file_artifacts = FilesystemScanner().scan(FIXTURE_FS_ROOT)
    processes, mem_connections, injections = VolatilityClient().from_fixture_file(FIXTURE_MEMORY_REPORT)
    log_events = EventLogParser().parse_file(FIXTURE_LOG_FILE)
    flows, dns_queries = PcapAnalyzer().analyze(FIXTURE_PCAP)

    return run_pipeline(
        "demo-case", file_artifacts, processes, mem_connections, injections, log_events, flows, dns_queries,
        snapshot_time=FIXTURE_SNAPSHOT_TIME, output_dir=output_dir,
    )


def run_live(args: argparse.Namespace) -> dict:
    file_artifacts: list[FileArtifact] = []
    processes: list[MemoryProcess] = []
    mem_connections: list[MemoryNetworkConnection] = []
    injections: list[MemoryInjection] = []
    log_events: list[LogEvent] = []
    flows: list[NetworkFlow] = []
    dns_queries: list[DNSQuery] = []

    if args.fs_root:
        logging.info("Scanning filesystem root: %s", args.fs_root)
        file_artifacts = FilesystemScanner().scan(args.fs_root)

    if args.memory_image:
        logging.info("Analyzing memory image via volatility3: %s", args.memory_image)
        processes, mem_connections, injections = VolatilityClient().analyze(args.memory_image)

    if args.log_file:
        logging.info("Parsing event log export: %s", args.log_file)
        log_events = EventLogParser().parse_file(args.log_file)

    if args.pcap:
        logging.info("Analyzing packet capture: %s", args.pcap)
        flows, dns_queries = PcapAnalyzer().analyze(args.pcap)

    if not any([file_artifacts, processes, log_events, flows]):
        raise SystemExit("At least one of --fs-root/--memory-image/--log-file/--pcap is required for --live")

    snapshot_time = (
        datetime.fromisoformat(args.snapshot_time) if args.snapshot_time else datetime.now(timezone.utc)
    )

    return run_pipeline(
        args.case, file_artifacts, processes, mem_connections, injections, log_events, flows, dns_queries,
        snapshot_time=snapshot_time, output_dir=args.output_dir,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")

    report = run_demo(args.output_dir) if args.demo else run_live(args)

    print("\n=== Incident Report Summary ===")
    print(f"case: {report['case_name']}")
    print(f"timeline events: {len(report['timeline'])}")
    print(f"source breakdown: {report['source_counts']}")
    print(f"IOC-flagged events: {report['ioc_hit_count']}")
    print(f"risk_score: {report['risk_score']}/100")
    print(f"\nFull report: {Path(args.output_dir) / 'incident_report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
