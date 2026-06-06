"""Benchmark for parsing HTTP/2 GOAWAY, SETTINGS, and PUSH_PROMISE frames.

This benchmark uses pytest-benchmark to measure parsing throughput for
individual frame types and a mixed interleaved workload.  It reports
average time per frame for each test.

Run with:
    python3 -m pytest tests/benchmark_http2_extra_frames.py --benchmark-only -v
"""

from __future__ import annotations

import random
import struct
from typing import Callable, List

import pytest

from pcap_parser.http2_frame_parser import (
    parse_http2_goaway_frame,
    parse_http2_push_promise_frame,
    parse_http2_settings_frame,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_goaway_payload(last_stream_id: int = 0, error_code: int = 0) -> bytes:
    """Build a 8‑byte GOAWAY frame payload."""
    return struct.pack("!II", last_stream_id, error_code)


def _make_settings_payload(entries: int = 5) -> bytes:
    """Build a SETTINGS frame payload consisting of *entries* settings.

    Each setting is 6 bytes: 2‑byte identifier + 4‑byte value.
    """
    payload = bytearray()
    for _ in range(entries):
        identifier = random.randrange(1, 0xFFFF)      # valid settings id
        value = random.randrange(0, 0xFFFFFFFF)      # arbitrary 32‑bit value
        payload += struct.pack("!HI", identifier, value)
    return bytes(payload)


def _make_push_promise_payload(
    promised_stream_id: int = 1,
    header_block_fragment_size: int = 50,
) -> bytes:
    """Build a PUSH_PROMISE frame payload.

    The payload consists of a 4‑byte promised stream ID followed by
    a variable‑length header block fragment (filled with random bytes).
    """
    header_block = bytes(random.randrange(0, 256) for _ in range(header_block_fragment_size))
    return struct.pack("!I", promised_stream_id) + header_block


def generate_frames(
    frame_type: str,
    count: int = 1000,
) -> List[bytes]:
    """Generate a list of synthetic HTTP/2 frame payloads.

    Parameters
    ----------
    frame_type : str
        One of ``"goaway"``, ``"settings"``, or ``"push_promise"``.
    count : int
        Number of payloads to generate.
    """
    random.seed(42)  # deterministic for reproducible benchmarks
    if frame_type == "goaway":
        return [
            _make_goaway_payload(
                last_stream_id=random.randrange(0, 0x7FFFFFFF),
                error_code=random.randrange(0, 0xFFFFFFFF),
            )
            for _ in range(count)
        ]
    elif frame_type == "settings":
        return [_make_settings_payload(entries=5) for _ in range(count)]
    elif frame_type == "push_promise":
        return [
            _make_push_promise_payload(
                promised_stream_id=random.randrange(1, 0x7FFFFFFF),
                header_block_fragment_size=50,
            )
            for _ in range(count)
        ]
    else:
        raise ValueError(f"Unknown frame_type: {frame_type}")


def benchmark_frames(
    benchmark: pytest.BenchmarkFixture,
    parser_func: Callable[[bytes], dict],
    payloads: List[bytes],
    label: str,
) -> None:
    """Run *benchmark* on *parser_func* for every payload in *payloads*.

    The function is called once per payload (not per list) to measure
    per‑frame parsing cost.  After the run, ``benchmark.extra_info``
    is updated with the total frame count and the average time per frame.
    """
    frames = len(payloads)

    # Define a helper that parses one frame at a time
    def parse_all():
        for payload in payloads:
            parser_func(payload)

    benchmark(parse_all)

    total_time = benchmark.elapsed  # seconds
    avg_per_frame = total_time / frames

    benchmark.extra_info["frame_type"] = label
    benchmark.extra_info["total_frames"] = frames
    benchmark.extra_info["avg_time_per_frame_ms"] = avg_per_frame * 1000


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

FRAME_COUNT = 1000


def test_benchmark_http2_goaway(benchmark: pytest.BenchmarkFixture) -> None:
    """Benchmark parsing of GOAWAY frames."""
    payloads = generate_frames("goaway", FRAME_COUNT)
    benchmark_frames(benchmark, parse_http2_goaway_frame, payloads, "GOAWAY")


def test_benchmark_http2_settings(benchmark: pytest.BenchmarkFixture) -> None:
    """Benchmark parsing of SETTINGS frames."""
    payloads = generate_frames("settings", FRAME_COUNT)
    benchmark_frames(benchmark, parse_http2_settings_frame, payloads, "SETTINGS")


def test_benchmark_http2_push_promise(benchmark: pytest.BenchmarkFixture) -> None:
    """Benchmark parsing of PUSH_PROMISE frames."""
    payloads = generate_frames("push_promise", FRAME_COUNT)
    benchmark_frames(benchmark, parse_http2_push_promise_frame, payloads, "PUSH_PROMISE")


def test_benchmark_http2_mixed(benchmark: pytest.BenchmarkFixture) -> None:
    """Benchmark parsing of interleaved GOAWAY, SETTINGS, PUSH_PROMISE frames."""
    random.seed(42)
    # Generate one set of payloads per frame type and interleave them
    goaway_payloads = generate_frames("goaway", FRAME_COUNT)
    settings_payloads = generate_frames("settings", FRAME_COUNT)
    push_promise_payloads = generate_frames("push_promise", FRAME_COUNT)

    mixed_payloads: List[bytes] = []
    for i in range(FRAME_COUNT):
        mixed_payloads.append(goaway_payloads[i])
        mixed_payloads.append(settings_payloads[i])
