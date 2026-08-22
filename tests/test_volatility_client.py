from pathlib import Path

from dfir_pipeline.memory.volatility_client import VolatilityClient

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_volatility_report.json"


def test_parses_all_processes():
    procs, _, _ = VolatilityClient().from_fixture_file(FIXTURE)
    names = {p.name for p in procs}
    assert names == {"explorer.exe", "svchost.exe", "invoice.pdf.exe", "synth_updater.exe"}


def test_process_parent_child_chain():
    procs, _, _ = VolatilityClient().from_fixture_file(FIXTURE)
    by_name = {p.name: p for p in procs}
    assert by_name["synth_updater.exe"].ppid == by_name["invoice.pdf.exe"].pid
    assert by_name["invoice.pdf.exe"].ppid == by_name["explorer.exe"].pid


def test_parses_network_connections():
    _, conns, _ = VolatilityClient().from_fixture_file(FIXTURE)
    assert len(conns) == 1
    assert conns[0].remote_addr == "203.0.113.42"
    assert conns[0].remote_port == 443


def test_parses_malfind_injections():
    _, _, injections = VolatilityClient().from_fixture_file(FIXTURE)
    assert len(injections) == 1
    assert injections[0].process_name == "svchost.exe"
    assert "EXECUTE_READWRITE" in injections[0].protection
