"""Renders evidence visuals for the correlated timeline: a swimlane
plot (the classic DFIR "super timeline" view - one lane per evidence
source, IOC-flagged events highlighted), plus summary bar charts.
All headless-safe (Agg backend) for CI/Docker.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from dfir_pipeline.models import TimelineEvent

SOURCE_ORDER = ["filesystem", "memory", "log", "network"]
SOURCE_COLOR = {"filesystem": "#2563eb", "memory": "#9333ea", "log": "#0891b2", "network": "#16a34a"}


def _agg_pyplot():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def plot_timeline_swimlane(
    events: list[TimelineEvent], out_path: str | Path, title: str = "Cross-Source Incident Timeline"
) -> Path:
    plt = _agg_pyplot()

    fig, ax = plt.subplots(figsize=(13, 5))
    lane_index = {source: i for i, source in enumerate(SOURCE_ORDER)}

    for event in events:
        y = lane_index.get(event.source, len(SOURCE_ORDER))
        color = "#dc2626" if event.is_flagged else SOURCE_COLOR.get(event.source, "#6b7280")
        marker = "X" if event.is_flagged else "o"
        size = 90 if event.is_flagged else 40
        ax.scatter(event.timestamp, y, color=color, marker=marker, s=size, zorder=3)

    ax.set_yticks(range(len(SOURCE_ORDER)), [s.capitalize() for s in SOURCE_ORDER])
    ax.set_ylim(-0.5, len(SOURCE_ORDER) - 0.5)
    ax.grid(axis="x", alpha=0.3)
    ax.set_title(title + "  (✕ = IOC-flagged event)")
    fig.autofmt_xdate()
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_source_counts(events: list[TimelineEvent], out_path: str | Path) -> Path:
    plt = _agg_pyplot()

    counts = Counter(e.source for e in events)
    sources = [s for s in SOURCE_ORDER if s in counts] or ["(none)"]
    values = [counts.get(s, 0) for s in sources]
    colors = [SOURCE_COLOR.get(s, "#6b7280") for s in sources]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.bar([s.capitalize() for s in sources], values, color=colors)
    ax.set_ylabel("Events")
    ax.set_title("Timeline Events by Source")
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_ioc_hits_by_source(events: list[TimelineEvent], out_path: str | Path) -> Path:
    plt = _agg_pyplot()

    flagged = [e for e in events if e.is_flagged]
    counts = Counter(e.source for e in flagged)
    sources = [s for s in SOURCE_ORDER if s in counts] or ["(none)"]
    values = [counts.get(s, 0) for s in sources]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.bar([s.capitalize() for s in sources], values, color="#dc2626")
    ax.set_ylabel("IOC-flagged events")
    ax.set_title("IOC Hits by Evidence Source")
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
