"""Core data model shared across every evidence source and the
correlation stage.

Each source (filesystem, memory, logs, network) produces its own typed
records; the correlator normalizes all of them into a single
TimelineEvent stream sorted by timestamp - the "super timeline"
technique real DFIR tooling (log2timeline/plaso, Kansa, Velociraptor)
is built around.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class FileArtifact:
    path: str
    size: int
    mtime: datetime
    atime: datetime
    ctime: datetime
    sha256: str
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)


@dataclass
class MemoryProcess:
    pid: int
    ppid: int
    name: str
    create_time: datetime
    command_line: str = ""


@dataclass
class MemoryNetworkConnection:
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    state: str = ""


@dataclass
class MemoryInjection:
    pid: int
    process_name: str
    address: str
    protection: str


@dataclass
class LogEvent:
    event_id: int
    time_created: datetime
    computer: str
    description: str
    user: str = ""
    command_line: str = ""


@dataclass
class NetworkFlow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass
class DNSQuery:
    query_name: str
    query_time: datetime
    src_ip: str


@dataclass
class IOC:
    ioc_type: str  # ip | domain | hash | filename
    value: str
    description: str
    severity: int  # 1-10


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str  # filesystem | memory | log | network
    event_type: str
    entity: str
    description: str
    matched_iocs: list[IOC] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return len(self.matched_iocs) > 0


@dataclass
class IncidentReport:
    case_name: str
    generated_at: datetime
    timeline: list[TimelineEvent]
    source_counts: dict[str, int]
    ioc_hit_count: int
    risk_score: int  # 0-100
