from datetime import datetime, timezone

from dfir_pipeline.models import IOC, TimelineEvent
from dfir_pipeline.report.report_builder import build_incident_report, incident_report_to_dict

NOW = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)


def test_clean_timeline_scores_zero_risk():
    timeline = [
        TimelineEvent(timestamp=NOW, source="filesystem", event_type="file_write", entity="a", description="")
    ]
    report = build_incident_report("clean-case", timeline)
    assert report.risk_score == 0
    assert report.ioc_hit_count == 0


def test_flagged_events_and_injection_raise_risk_score():
    ioc = IOC(ioc_type="ip", value="203.0.113.42", description="C2", severity=8)
    timeline = [
        TimelineEvent(timestamp=NOW, source="network", event_type="network_flow", entity="x",
                       description="", matched_iocs=[ioc]),
        TimelineEvent(timestamp=NOW, source="memory", event_type="code_injection", entity="y", description=""),
    ]
    report = build_incident_report("bad-case", timeline)
    assert report.risk_score > 50
    assert report.ioc_hit_count == 1


def test_source_counts_tally_correctly():
    timeline = [
        TimelineEvent(timestamp=NOW, source="filesystem", event_type="file_write", entity="a", description=""),
        TimelineEvent(timestamp=NOW, source="filesystem", event_type="file_write", entity="b", description=""),
        TimelineEvent(timestamp=NOW, source="network", event_type="dns_query", entity="c", description=""),
    ]
    report = build_incident_report("case", timeline)
    assert report.source_counts == {"filesystem": 2, "network": 1}


def test_to_dict_serializes_timestamps_as_strings():
    timeline = [
        TimelineEvent(timestamp=NOW, source="log", event_type="event_id_4688", entity="a", description="")
    ]
    report = build_incident_report("case", timeline)
    payload = incident_report_to_dict(report)
    assert isinstance(payload["timeline"][0]["timestamp"], str)
    assert isinstance(payload["generated_at"], str)
