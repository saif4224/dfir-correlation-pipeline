import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dfir_pipeline.filesystem.mac_timeline import FilesystemScanner
from dfir_pipeline.logs.event_log_parser import EventLogParser
from dfir_pipeline.memory.volatility_client import VolatilityClient
from dfir_pipeline.network.pcap_analyzer import PcapAnalyzer
from dfir_pipeline.pipeline import run_pipeline

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT_TIME = datetime(2026, 3, 14, 9, 32, 0, tzinfo=timezone.utc)


def test_full_pipeline_end_to_end_offline():
    file_artifacts = FilesystemScanner().scan(FIXTURES / "synthetic_evidence_fs")
    processes, mem_connections, injections = VolatilityClient().from_fixture_file(
        FIXTURES / "synthetic_volatility_report.json"
    )
    log_events = EventLogParser().parse_file(FIXTURES / "synthetic_event_logs.json")
    flows, dns_queries = PcapAnalyzer().analyze(FIXTURES / "synthetic_capture.pcap")

    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(
            "unit-test-case", file_artifacts, processes, mem_connections, injections, log_events, flows,
            dns_queries, snapshot_time=SNAPSHOT_TIME, output_dir=tmp,
        )

        assert report["case_name"] == "unit-test-case"
        assert len(report["timeline"]) > 0
        assert report["ioc_hit_count"] > 0
        assert 0 <= report["risk_score"] <= 100

        expected_files = (
            "incident_report.json", "timeline_swimlane.png", "source_counts.png", "ioc_hits_by_source.png",
        )
        for name in expected_files:
            assert (Path(tmp) / name).exists(), f"missing {name}"

        on_disk = json.loads((Path(tmp) / "incident_report.json").read_text())
        assert on_disk["case_name"] == "unit-test-case"


def test_pipeline_with_no_evidence_produces_empty_but_valid_report():
    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(
            "empty-case", [], [], [], [], [], [], [], snapshot_time=SNAPSHOT_TIME, output_dir=tmp,
        )
        assert report["timeline"] == []
        assert report["risk_score"] == 0
