from pathlib import Path

from dfir_pipeline.network.pcap_analyzer import PcapAnalyzer

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_capture.pcap"


def test_extracts_flows():
    flows, _ = PcapAnalyzer().analyze(FIXTURE)
    assert len(flows) > 0
    c2_flow = next(f for f in flows if f.dst_ip == "203.0.113.42")
    assert c2_flow.dst_port == 443
    assert c2_flow.packet_count == 4


def test_extracts_dns_queries():
    _, dns_queries = PcapAnalyzer().analyze(FIXTURE)
    names = {d.query_name for d in dns_queries}
    assert "update-check.example-c2.test" in names
    assert "telemetry.example-c2.test" in names
    assert "www.example.com" in names


def test_flows_have_valid_timestamps():
    flows, _ = PcapAnalyzer().analyze(FIXTURE)
    for flow in flows:
        assert flow.first_seen <= flow.last_seen
