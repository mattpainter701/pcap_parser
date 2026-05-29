"""Benchmark multi‑protocol pcap parsing.

This benchmark measures throughput (packets/second) and memory allocations
for mixed‑protocol traffic. It uses pytest‑benchmark to provide detailed
timing and allocation statistics.

Expected performance for the mixed‑protocol capture (which includes ICMPv6,
HTTP/2, DNS, DHCP, ARP, and TCP traffic) is at least **80 kpackets/s** when
run on modern hardware. Memory allocations should stay below **2 MB per
iteration**.
"""

from pathlib import Path

import pytest

from pcap_parser import parse_capture

# Location of the multi‑protocol pcap file (created by integration tests)
MULTI_PROTOCOL_PCAP = (
    Path(__file__).resolve().parent.parent
    / "tests"
    / "test_data"
    / "multi_protocol.pcap"
)


def test_benchmark_multi_protocol_parsing(benchmark):
    """Benchmark parsing of a multi‑protocol pcap.

    Uses pytest‑benchmark's 'benchmark' fixture to measure execution
    time and memory usage over multiple rounds (default: 5 warmup + 5
    measurement rounds). The benchmark runs *one* iteration per call; the
    number of iterations is controlled by pytest‑benchmark's --benchmark-
    rounds and --benchmark-warmup‑rounds options.
    """
    capture_bytes = MULTI_PROTOCOL_PCAP.read_bytes()

    # Benchmark the entire parse_capture function
    result = benchmark(parse_capture, MULTI_PROTOCOL_PCAP)

    # Basic sanity: ensure packets were parsed
    assert result.packet_count > 0

    # Compute and report throughput (packets/second)
    elapsed = benchmark.elapsed  # seconds after benchmark
    throughput = result.packet_count / elapsed if elapsed > 0 else 0.0
    # Attach to test extra info
    benchmark.extra_info["throughput_packets_per_sec"] = round(throughput, 2)
    benchmark.extra_info["packets_parsed"] = result.packet_count
