import tempfile
from pathlib import Path

from dfir_pipeline.cli import main


def test_demo_mode_runs_end_to_end_and_prints_summary(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        exit_code = main(["--demo", "--output-dir", tmp])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Incident Report Summary" in captured.out
        assert (Path(tmp) / "incident_report.json").exists()


def test_live_mode_without_any_source_exits():
    try:
        main(["--live"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass


def test_live_mode_filesystem_only(capsys):
    fixture_root = Path(__file__).parent / "fixtures" / "synthetic_evidence_fs"
    with tempfile.TemporaryDirectory() as tmp:
        exit_code = main(["--live", "--fs-root", str(fixture_root), "--output-dir", tmp])
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "'filesystem': 4" in captured.out
