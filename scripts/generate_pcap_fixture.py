#!/usr/bin/env python3
"""One-time (dev-only) generator for tests/fixtures/synthetic_capture.pcap.

Builds a real, valid PCAP file with scapy - not a mock: every packet is
constructed and serialized through scapy's actual packet-building code
path, and the result is parsed the same way network/pcap_analyzer.py
parses a real capture. The traffic itself is entirely synthetic and
matches the fictional incident narrative shared across this repo's
fixtures (see data/ioc_watchlist.json) - it was never captured on a
real network.

Usage: python scripts/generate_pcap_fixture.py
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

OUT_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic_capture.pcap"

VICTIM_IP = "10.0.0.15"
C2_IP = "203.0.113.42"
BENIGN_IP = "10.0.0.1"
DNS_SERVER = "10.0.0.53"


def _ts(hour: int, minute: int, second: int) -> float:
    return datetime(2026, 3, 14, hour, minute, second, tzinfo=timezone.utc).timestamp()


def main() -> None:
    packets = []

    # Benign DNS lookup + HTTPS traffic (a normal browsing session, for contrast)
    benign_dns = Ether() / IP(src=VICTIM_IP, dst=DNS_SERVER) / UDP(sport=52345, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="www.example.com")
    )
    benign_dns.time = _ts(8, 58, 0)
    packets.append(benign_dns)

    for i in range(3):
        pkt = Ether() / IP(src=VICTIM_IP, dst=BENIGN_IP) / TCP(sport=51000 + i, dport=443, flags="PA", seq=i * 100)
        pkt.time = _ts(8, 58, 1 + i)
        packets.append(pkt)

    # C2 beacon: DNS query for the watchlisted domain, then an outbound TCP connection to the watchlisted IP
    c2_dns_1 = Ether() / IP(src=VICTIM_IP, dst=DNS_SERVER) / UDP(sport=52400, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="update-check.example-c2.test")
    )
    c2_dns_1.time = _ts(9, 0, 25)
    packets.append(c2_dns_1)

    for i in range(4):
        pkt = Ether() / IP(src=VICTIM_IP, dst=C2_IP) / TCP(sport=51422, dport=443, flags="PA", seq=i * 200)
        pkt.time = _ts(9, 0, 30 + i)
        packets.append(pkt)

    c2_dns_2 = Ether() / IP(src=VICTIM_IP, dst=DNS_SERVER) / UDP(sport=52401, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="telemetry.example-c2.test")
    )
    c2_dns_2.time = _ts(9, 15, 0)
    packets.append(c2_dns_2)

    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} synthetic packets to {OUT_PATH}")


if __name__ == "__main__":
    main()
