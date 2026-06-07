"""Benchmark HTTP/2 frame parser performance."""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dissectors.http2 import dissect_http2_frame

ITERATIONS = 1000

FRAME_TYPES = {
    "DATA": 0x0,
    "HEADERS": 0x1,
    "PRIORITY": 0x2,
    "RST_STREAM": 0x3,
    "SETTINGS": 0x4,
    "PUSH_PROMISE": 0x5,
    "PING": 0x6,
    "GOAWAY": 0x7,
    "WINDOW_UPDATE": 0x8,
    "CONTINUATION": 0x9,
}


def priority_payload() -> bytes:
    """Build a valid PRIORITY payload for the currently supported parser."""
    return struct.pack("!IB", 0x80000003, 16)


def synthetic_payloads() -> dict[str, bytes]:
    """Return representative synthetic HTTP/2 frame payloads by frame name."""
    header_block = (
        b"\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5"
        b"\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"
    )
    return {
        "DATA": b"hello, http2 data frame payload",
        "HEADERS": header_block,
        "PRIORITY": priority_payload(),
        "RST_STREAM": struct.pack("!I", 0),
        "SETTINGS": struct.pack("!HIHI", 0x1, 4096, 0x3, 100),
        "PUSH_PROMISE": struct.pack("!I", 2) + header_block,
        "PING": b"12345678",
        "GOAWAY": struct.pack("!II", 1, 0) + b"benchmark shutdown",
        "WINDOW_UPDATE": struct.pack("!I", 65535),
        "CONTINUATION": header_block,
    }


def run_benchmark(name: str, frames: Iterable[tuple[int, bytes]]) -> float:
    """Run the parser repeatedly and return average seconds per frame."""
    frame_sequence = tuple(frames)
    total_frames = len(frame_sequence) * ITERATIONS

    start = time.perf_counter()
    for _ in range(ITERATIONS):
        for frame_type, payload in frame_sequence:
            dissect_http2_frame(frame_type, payload)
    elapsed = time.perf_counter() - start

    average = elapsed / total_frames if total_frames else 0.0
    print(
        f"{name:<28} {average * 1_000_000:>10.3f} us/frame "
        f"({total_frames} frames)"
    )
    return average


def main() -> None:
    payloads = synthetic_payloads()

    benchmarks = [
        ("GOAWAY", [(FRAME_TYPES["GOAWAY"], payloads["GOAWAY"])]),
        ("SETTINGS", [(FRAME_TYPES["SETTINGS"], payloads["SETTINGS"])]),
        (
            "Mixed supported frames",
            [
                (frame_type, payloads[name])
                for name, frame_type in FRAME_TYPES.items()
            ],
        ),
    ]

    print("HTTP/2 frame parser benchmark")
    print(f"Iterations: {ITERATIONS}")
