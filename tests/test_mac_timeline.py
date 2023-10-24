from pathlib import Path

from dfir_pipeline.filesystem.mac_timeline import FilesystemScanner

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "synthetic_evidence_fs"


def test_scans_all_files():
    artifacts = FilesystemScanner().scan(FIXTURE_ROOT)
    names = {Path(a.path).name for a in artifacts}
    assert names == {"invoice.pdf.exe", "readme.txt", "helper.dll", "quarterly_report.docx"}


def test_disguised_executable_flagged_double_extension():
    artifacts = FilesystemScanner().scan(FIXTURE_ROOT)
    invoice = next(a for a in artifacts if a.path.endswith("invoice.pdf.exe"))
    assert invoice.is_suspicious
    assert "double_extension" in invoice.suspicion_reasons
    assert "executable_in_suspicious_path" in invoice.suspicion_reasons


def test_dropped_dll_flagged_via_suspicious_path():
    artifacts = FilesystemScanner().scan(FIXTURE_ROOT)
    helper = next(a for a in artifacts if a.path.endswith("helper.dll"))
    assert helper.is_suspicious
    assert "executable_in_suspicious_path" in helper.suspicion_reasons


def test_benign_files_not_flagged():
    artifacts = FilesystemScanner().scan(FIXTURE_ROOT)
    readme = next(a for a in artifacts if a.path.endswith("readme.txt"))
    report = next(a for a in artifacts if a.path.endswith("quarterly_report.docx"))
    assert not readme.is_suspicious
    assert not report.is_suspicious


def test_hashes_are_deterministic_and_well_formed():
    a = FilesystemScanner().scan(FIXTURE_ROOT)
    b = FilesystemScanner().scan(FIXTURE_ROOT)
    a_map = {x.path: x.sha256 for x in a}
    b_map = {x.path: x.sha256 for x in b}
    assert a_map == b_map
    assert all(len(h) == 64 for h in a_map.values())
