"""Normalizes every evidence source into one TimelineEvent stream and
sorts it by timestamp - the cross-source "super timeline" technique
this whole pipeline exists to automate.

Memory forensics is a single snapshot, not a stream: plugins like
netscan/malfind don't carry their own per-record timestamp, so
memory-sourced events (other than pslist's CreateTime, which is real)
are anchored to the supplied `snapshot_time` (when the memory image
was acquired) - this is standard DFIR practice, not a limitation of
this pipeline specifically.
"""
from __future__ import annotations

from datetime import datetime

from dfir_pipeline.correlate.ioc_matcher import IOCWatchlist
from dfir_pipeline.models import (
    DNSQuery,
    FileArtifact,
    LogEvent,
    MemoryInjection,
    MemoryNetworkConnection,
    MemoryProcess,
    NetworkFlow,
    TimelineEvent,
)


def build_master_timeline(
    file_artifacts: list[FileArtifact],
    processes: list[MemoryProcess],
    mem_connections: list[MemoryNetworkConnection],
    injections: list[MemoryInjection],
    log_events: list[LogEvent],
    flows: list[NetworkFlow],
    dns_queries: list[DNSQuery],
    watchlist: IOCWatchlist,
    snapshot_time: datetime,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    for artifact in file_artifacts:
        from pathlib import Path

        filename = Path(artifact.path).name
        matched = watchlist.match_any_field(filename, ioc_type="filename")
        matched += watchlist.match_any_field(artifact.sha256, ioc_type="hash")
        events.append(
            TimelineEvent(
                timestamp=artifact.mtime,
                source="filesystem",
                event_type="file_write",
                entity=artifact.path,
                description=(
                    f"File written: {artifact.path}"
                    + (f" [{', '.join(artifact.suspicion_reasons)}]" if artifact.is_suspicious else "")
                ),
                matched_iocs=matched,
            )
        )

    for proc in processes:
        matched = watchlist.match_any_field(proc.name, ioc_type="process")
        events.append(
            TimelineEvent(
                timestamp=proc.create_time,
                source="memory",
                event_type="process_created",
                entity=proc.name,
                description=f"Process created: {proc.name} (PID {proc.pid}, PPID {proc.ppid})"
                + (f" — {proc.command_line}" if proc.command_line else ""),
                matched_iocs=matched,
            )
        )

    for conn in mem_connections:
        matched = watchlist.match_any_field(conn.remote_addr, ioc_type="ip")
        events.append(
            TimelineEvent(
                timestamp=snapshot_time,
                source="memory",
                event_type="network_connection",
                entity=f"{conn.process_name} (PID {conn.pid})",
                description=f"{conn.protocol} connection to {conn.remote_addr}:{conn.remote_port}",
                matched_iocs=matched,
            )
        )

    for inj in injections:
        events.append(
            TimelineEvent(
                timestamp=snapshot_time,
                source="memory",
                event_type="code_injection",
                entity=f"{inj.process_name} (PID {inj.pid})",
                description=f"Injected memory region at {inj.address} (protection={inj.protection})",
                matched_iocs=[],  # malfind hits are inherently suspicious; no IOC lookup needed
            )
        )

    for log_event in log_events:
        matched = watchlist.match_any_field(log_event.command_line, ioc_type="filename")
        description = log_event.description
        if log_event.command_line:
            description += f" — {log_event.command_line}"
        events.append(
            TimelineEvent(
                timestamp=log_event.time_created,
                source="log",
                event_type=f"event_id_{log_event.event_id}",
                entity=log_event.computer,
                description=description,
                matched_iocs=matched,
            )
        )

    for flow in flows:
        matched = watchlist.match_any_field(flow.dst_ip, ioc_type="ip")
        events.append(
            TimelineEvent(
                timestamp=flow.first_seen,
                source="network",
                event_type="network_flow",
                entity=f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}",
                description=f"{flow.protocol} flow, {flow.packet_count} packets / {flow.byte_count} bytes",
                matched_iocs=matched,
            )
        )

    for dns in dns_queries:
        matched = watchlist.match_any_field(dns.query_name, ioc_type="domain")
        events.append(
            TimelineEvent(
                timestamp=dns.query_time,
                source="network",
                event_type="dns_query",
                entity=dns.query_name,
                description=f"DNS query for {dns.query_name} from {dns.src_ip}",
                matched_iocs=matched,
            )
        )

    return sorted(events, key=lambda e: e.timestamp)
