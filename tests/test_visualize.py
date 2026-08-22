import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dfir_pipeline.models import IOC, TimelineEvent
from dfir_pipeline.report.visualize import plot_ioc_hits_by_source, plot_source_counts, plot_timeline_swimlane

NOW = datetime(2026, 3, 14, 10, 0, 0, tzinfo=timezone.utc)


def _sample_events():
    ioc = IOC(ioc_type="ip", value="203.0.113.42", description="C2", severity=8)
    return [
        TimelineEvent(timestamp=NOW, source="filesystem", event_type="file_write", entity="a", description=""),
        TimelineEvent(timestamp=NOW, source="network", event_type="network_flow", entity="b", description="",
                      matched_iocs=[ioc]),
    ]


def test_plot_timeline_swimlane_writes_png():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "timeline.png"
        plot_timeline_swimlane(_sample_events(), out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_source_counts_writes_png():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "counts.png"
        plot_source_counts(_sample_events(), out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_ioc_hits_writes_png_even_with_no_hits():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "hits.png"
        plot_ioc_hits_by_source([], out)
        assert out.exists() and out.stat().st_size > 0
