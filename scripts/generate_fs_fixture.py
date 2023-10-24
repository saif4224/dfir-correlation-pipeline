#!/usr/bin/env python3
"""One-time (dev-only) generator for tests/fixtures/synthetic_evidence_fs/.

Builds a small synthetic "extracted evidence" directory tree with
controlled MAC timestamps (via os.utime) matching the fictional
incident narrative used consistently across all four fixture sources
in this repo (see data/ioc_watchlist.json). Every file's content is
either plain text or a handful of real PE-header bytes (`MZ` + padding)
- enough for the magic-byte/double-extension heuristics in
filesystem/mac_timeline.py to fire, not a functional program.

Usage: python scripts/generate_fs_fixture.py
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic_evidence_fs"

# (relative path, content bytes, mtime)
FILES = [
    (
        "Downloads/invoice.pdf.exe",
        b"MZ" + b"\x90" * 62 + b"synthetic-fixture-not-a-real-executable",
        datetime(2026, 3, 14, 9, 0, 5, tzinfo=timezone.utc),
    ),
    (
        "Downloads/readme.txt",
        b"Quarterly reminder: submit expenses by Friday.\n",
        datetime(2026, 3, 14, 8, 55, 0, tzinfo=timezone.utc),
    ),
    (
        "AppData/Local/Temp/helper.dll",
        b"MZ" + b"\x90" * 62 + b"synthetic-fixture-dropped-payload-not-real",
        datetime(2026, 3, 14, 9, 0, 12, tzinfo=timezone.utc),
    ),
    (
        "Documents/quarterly_report.docx",
        b"PK\x03\x04" + b"synthetic-fixture-office-doc-not-real" * 4,
        datetime(2026, 3, 13, 20, 0, 0, tzinfo=timezone.utc),
    ),
]


def main() -> None:
    for rel_path, content, mtime in FILES:
        path = ROOT / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        ts = mtime.timestamp()
        os.utime(path, (ts, ts))

    print(f"Wrote {len(FILES)} synthetic evidence files under {ROOT}")


if __name__ == "__main__":
    main()
