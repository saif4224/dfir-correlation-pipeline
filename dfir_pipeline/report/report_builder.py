"""Assembles the final incident report: the correlated master timeline
plus per-source counts and a heuristic 0-100 risk score.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import asdict

from dfir_pipeline.models import IncidentReport, TimelineEvent


def _compute_risk_score(events: list[TimelineEvent]) -> int:
    flagged = [e for e in events if e.is_flagged]
    max_severity = max((ioc.severity for e in flagged for ioc in e.matched_iocs), default=0)
    injection_events = sum(1 for e in events if e.event_type == "code_injection")

    score = max_severity * 6 + len(flagged) * 4 + injection_events * 15
    return int(max(0, min(100, score)))


def build_incident_report(case_name: str, timeline: list[TimelineEvent]) -> IncidentReport:
    source_counts = dict(Counter(e.source for e in timeline))
    ioc_hit_count = sum(1 for e in timeline if e.is_flagged)

    return IncidentReport(
        case_name=case_name,
        generated_at=dt.datetime.now(dt.timezone.utc),
        timeline=timeline,
        source_counts=source_counts,
        ioc_hit_count=ioc_hit_count,
        risk_score=_compute_risk_score(timeline),
    )


def incident_report_to_dict(report: IncidentReport) -> dict:
    payload = asdict(report)
    payload["generated_at"] = report.generated_at.isoformat()
    for event in payload["timeline"]:
        timestamp = event["timestamp"]
        event["timestamp"] = timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp
    return payload
