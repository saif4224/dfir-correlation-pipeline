"""Orchestrates the full lifecycle: four evidence sources -> IOC
matching -> correlated master timeline -> incident report + evidence
visuals.

Kept as a pure function over already-produced typed source records
(rather than doing the disk walk / vol3 invocation / log parse / pcap
read itself) so it's trivially testable against fixtures - see
tests/test_pipeline.py. cli.py wires up the real scanners/clients for
demo/live mode.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from dfir_pipeline.correlate.ioc_matcher import IOCWatchlist
from dfir_pipeline.correlate.timeline_builder import build_master_timeline
from dfir_pipeline.models import (
    DNSQuery,
    FileArtifact,
    LogEvent,
    MemoryInjection,
    MemoryNetworkConnection,
    MemoryProcess,
    NetworkFlow,
)
from dfir_pipeline.report.report_builder import build_incident_report, incident_report_to_dict
from dfir_pipeline.report.visualize import plot_ioc_hits_by_source, plot_source_counts, plot_timeline_swimlane

logger = logging.getLogger(__name__)


def run_pipeline(
    case_name: str,
    file_artifacts: list[FileArtifact],
    processes: list[MemoryProcess],
    mem_connections: list[MemoryNetworkConnection],
    injections: list[MemoryInjection],
    log_events: list[LogEvent],
    flows: list[NetworkFlow],
    dns_queries: list[DNSQuery],
    snapshot_time: datetime,
    output_dir: str | Path = "output",
    watchlist: IOCWatchlist | None = None,
) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    watchlist = watchlist or IOCWatchlist()

    timeline = build_master_timeline(
        file_artifacts, processes, mem_connections, injections, log_events, flows, dns_queries,
        watchlist, snapshot_time,
    )
    incident_report = build_incident_report(case_name, timeline)
    report_dict = incident_report_to_dict(incident_report)

    report_path = output_dir / "incident_report.json"
    report_path.write_text(json.dumps(report_dict, indent=2))
    logger.info("Wrote incident report to %s", report_path)
    logger.info(
        "Case '%s': %d timeline events (%d IOC-flagged), risk_score=%d",
        case_name, len(timeline), incident_report.ioc_hit_count, incident_report.risk_score,
    )

    plot_timeline_swimlane(timeline, output_dir / "timeline_swimlane.png", title=f"Incident Timeline: {case_name}")
    plot_source_counts(timeline, output_dir / "source_counts.png")
    plot_ioc_hits_by_source(timeline, output_dir / "ioc_hits_by_source.png")

    return report_dict
