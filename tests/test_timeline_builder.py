from datetime import datetime, timezone
from pathlib import Path

from dfir_pipeline.correlate.ioc_matcher import IOCWatchlist
from dfir_pipeline.correlate.timeline_builder import build_master_timeline
from dfir_pipeline.filesystem.mac_timeline import FilesystemScanner
from dfir_pipeline.logs.event_log_parser import EventLogParser
from dfir_pipeline.memory.volatility_client import VolatilityClient
from dfir_pipeline.network.pcap_analyzer import PcapAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT_TIME = datetime(2026, 3, 14, 9, 32, 0, tzinfo=timezone.utc)


def _build_demo_timeline():
    file_artifacts = FilesystemScanner().scan(FIXTURES / "synthetic_evidence_fs")
    processes, mem_connections, injections = VolatilityClient().from_fixture_file(
        FIXTURES / "synthetic_volatility_report.json"
    )
    log_events = EventLogParser().parse_file(FIXTURES / "synthetic_event_logs.json")
    flows, dns_queries = PcapAnalyzer().analyze(FIXTURES / "synthetic_capture.pcap")
    watchlist = IOCWatchlist()

    return build_master_timeline(
        file_artifacts, processes, mem_connections, injections, log_events, flows, dns_queries,
        watchlist, SNAPSHOT_TIME,
    )


def test_timeline_is_sorted_by_timestamp():
    timeline = _build_demo_timeline()
    timestamps = [e.timestamp for e in timeline]
    assert timestamps == sorted(timestamps)


def test_timeline_covers_all_four_sources():
    timeline = _build_demo_timeline()
    sources = {e.source for e in timeline}
    assert sources == {"filesystem", "memory", "log", "network"}


def test_c2_ip_flagged_in_both_memory_and_network_events():
    timeline = _build_demo_timeline()
    flagged_entities = [e.entity for e in timeline if e.is_flagged]
    assert any("synth_updater.exe" in e for e in flagged_entities)  # memory connection
    assert any("203.0.113.42" in e for e in flagged_entities)  # network flow


def test_c2_domain_flagged_in_dns_events():
    timeline = _build_demo_timeline()
    dns_events = [e for e in timeline if e.event_type == "dns_query"]
    flagged_dns = [e for e in dns_events if e.is_flagged]
    assert len(flagged_dns) == 2  # both example-c2.test domains
    assert not any(e.entity == "www.example.com" for e in flagged_dns)


def test_injection_event_present_even_without_ioc_match():
    timeline = _build_demo_timeline()
    injection_events = [e for e in timeline if e.event_type == "code_injection"]
    assert len(injection_events) == 1
    assert "svchost.exe" in injection_events[0].entity
