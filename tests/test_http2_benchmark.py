"""Benchmark HTTP/2 frame parsing performance."""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcap_parser import parse_capture


FRAME_COUNT = 1000
MAX_PARSE_SECONDS = 1.0


def _http2_priority_frame(stream_id: int) -> bytes:
    """Build a minimal HTTP/2 PRIORITY frame."""
    payload = struct.pack("!IB", 0, 16)
    length = len(payload).to_bytes(3, "big")
    frame_type = b"\x02"
    flags = b"\x00"
    stream_identifier = (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return length + frame_type + flags + stream_identifier + payload


@pytest.fixture
def large_http2_pcap(tmp_path: Path) -> Path:
    """Generate a synthetic pcap containing many HTTP/2 frames."""
    packets = []
    for index in range(FRAME_COUNT):
        frame = _http2_priority_frame(index + 1)
        packets.append(
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=443, dport=50000, seq=index * len(frame))
            / Raw(frame)
        )

    pcap_path = tmp_path / "large_http2.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path


def test_http2_parse_benchmark(
    request: pytest.FixtureRequest, large_http2_pcap: Path
) -> None:
    """Benchmark parsing a pcap with 1000 synthetic HTTP/2 frames."""
    if request.config.pluginmanager.hasplugin("benchmark"):
        benchmark = request.getfixturevalue("benchmark")
        result = benchmark(parse_capture, large_http2_pcap)
        elapsed = benchmark.stats.stats.mean
    else:
        start = time.perf_counter()
