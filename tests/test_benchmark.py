"""Unit tests for the multi‑protocol pcap benchmark harness."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import (
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    wrpcap,
)

from pcap_parser import parse_capture


@pytest.fixture
def multi_protocol_pcap(tmp_path: Path) -> Path:
    """Generate a small synthetic pcap containing HTTP/1.1, DNS, and DHCP."""
    packets = []

    # HTTP/1.1 GET request (raw TCP payload)
    http_request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: pytest\r\n"
        b"\r\n"
    )
    packets.append(
        Ether() / IP(dst="93.184.216.34") / TCP(sport=12345, dport=80) / Raw(http_request)
    )

    # DNS query for www.example.com
    packets.append(
        Ether()
        / IP(dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(qd=DNSQR(qname="www.example.com"))
    )

    # DHCP Discover
    packets.append(
        Ether()
        / IP(dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00\x01\x02\x03\x04\x05")
        / DHCP(options=[("message-type", "discover"), "end"])
    )

    pcap_path = tmp_path / "multi_protocol.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path
