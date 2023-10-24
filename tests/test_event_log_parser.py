from pathlib import Path

from dfir_pipeline.logs.event_log_parser import EventLogParser

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_event_logs.json"


def test_parses_all_events():
    events = EventLogParser().parse_file(FIXTURE)
    assert len(events) == 6


def test_high_value_event_ids_get_real_descriptions():
    events = EventLogParser().parse_file(FIXTURE)
    process_creation = next(e for e in events if e.event_id == 4688)
    assert process_creation.description == "Process creation (Security log)"

    service_installed = next(e for e in events if e.event_id == 7045)
    assert service_installed.description == "New service installed"


def test_is_high_value_helper():
    parser = EventLogParser()
    events = parser.parse_file(FIXTURE)
    logon = next(e for e in events if e.event_id == 4624)
    assert parser.is_high_value(logon)


def test_events_carry_command_line_when_present():
    events = EventLogParser().parse_file(FIXTURE)
    proc_event = next(e for e in events if e.event_id == 1)
    assert "synth_updater.exe" in proc_event.command_line
