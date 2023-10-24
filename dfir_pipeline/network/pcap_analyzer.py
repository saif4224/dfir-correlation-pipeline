"""Network forensics: parses a real PCAP file (via scapy) into
aggregated flows and DNS queries.

Works on any real .pcap/.pcapng - this module only ever reads capture
files, it never sniffs live traffic. The bundled demo fixture
(tests/fixtures/synthetic_capture.pcap) is a synthetic capture built
with scapy itself (see scripts/generate_pcap_fixture.py), not a real
network capture.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap

from dfir_pipeline.models import DNSQuery, NetworkFlow


class PcapAnalyzer:
    def analyze(self, path: str | Path) -> tuple[list[NetworkFlow], list[DNSQuery]]:
        packets = rdpcap(str(path))
        return self._extract_flows(packets), self._extract_dns_queries(packets)

    def _extract_flows(self, packets) -> list[NetworkFlow]:
        aggregated: dict[tuple, dict] = defaultdict(
            lambda: {"packet_count": 0, "byte_count": 0, "first_seen": None, "last_seen": None}
        )

        for pkt in packets:
            if IP not in pkt:
                continue
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
            if proto == "OTHER":
                continue

            layer = pkt[TCP] if proto == "TCP" else pkt[UDP]
            key = (pkt[IP].src, layer.sport, pkt[IP].dst, layer.dport, proto)

            entry = aggregated[key]
            entry["packet_count"] += 1
            entry["byte_count"] += len(pkt)
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
            entry["first_seen"] = min(entry["first_seen"], ts) if entry["first_seen"] else ts
            entry["last_seen"] = max(entry["last_seen"], ts) if entry["last_seen"] else ts

        return [
            NetworkFlow(
                src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport, protocol=proto,
                packet_count=v["packet_count"], byte_count=v["byte_count"],
                first_seen=v["first_seen"], last_seen=v["last_seen"],
            )
            for (src, sport, dst, dport, proto), v in aggregated.items()
        ]

    def _extract_dns_queries(self, packets) -> list[DNSQuery]:
        queries = []
        for pkt in packets:
            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                queries.append(
                    DNSQuery(
                        query_name=qname,
                        query_time=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                        src_ip=pkt[IP].src if IP in pkt else "unknown",
                    )
                )
        return queries
