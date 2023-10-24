"""Filesystem triage: walks a directory tree (a mounted/extracted
evidence root, or a live system path) and builds a MAC(B) timestamp
timeline per file - the same starting point as `fls`/`mactime` in The
Sleuth Kit - plus a small set of real, well-known disguised-executable
heuristics.

Deliberately stdlib-only (os/pathlib/hashlib) so it needs nothing
beyond Python to run against a real evidence directory.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from dfir_pipeline.models import FileArtifact

# Magic bytes for common file types, used to detect extension/content mismatches
# (a classic "disguised executable" indicator: a file named report.pdf that is
# actually a Windows PE, or invoice.doc.exe with a double extension).
MAGIC_SIGNATURES = {
    b"MZ": "pe_executable",
    b"\x7fELF": "elf_executable",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip_or_office",
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG": "png",
}

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}
EXECUTABLE_MAGICS = {"pe_executable", "elf_executable"}
SUSPICIOUS_PATH_HINTS = ("temp", "tmp", "appdata\\local\\temp", "downloads", "startup")


def _detect_magic(header: bytes) -> str:
    for sig, kind in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            return kind
    return "unknown"


def _has_double_extension(name: str) -> bool:
    parts = name.split(".")
    return len(parts) >= 3 and parts[-1].lower() in {"exe", "scr", "bat", "cmd", "com", "js", "vbs"}


class FilesystemScanner:
    def scan(self, root: str | Path) -> list[FileArtifact]:
        root = Path(root)
        artifacts: list[FileArtifact] = []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            artifacts.append(self._analyze_file(path))

        return artifacts

    def _analyze_file(self, path: Path) -> FileArtifact:
        stat = path.stat()
        raw = path.read_bytes()
        header = raw[:8]
        detected_type = _detect_magic(header)

        reasons: list[str] = []
        if _has_double_extension(path.name):
            reasons.append("double_extension")
        if detected_type in EXECUTABLE_MAGICS and path.suffix.lower() in DOCUMENT_EXTENSIONS:
            reasons.append(f"extension_content_mismatch:{path.suffix}_but_{detected_type}")
        path_lower = str(path).lower()
        if any(hint in path_lower for hint in SUSPICIOUS_PATH_HINTS) and detected_type in EXECUTABLE_MAGICS:
            reasons.append("executable_in_suspicious_path")

        return FileArtifact(
            path=str(path),
            size=stat.st_size,
            mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
            atime=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc),
            ctime=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
            sha256=hashlib.sha256(raw).hexdigest(),
            is_suspicious=len(reasons) > 0,
            suspicion_reasons=reasons,
        )
