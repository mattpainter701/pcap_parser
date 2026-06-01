"""Benchmark mixed HTTP/2 frame parsing throughput."""

from __future__ import annotations

import struct
import sys
import tempfile
import time
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pcap_parser import parse_capture


ITERATIONS = 1000
FRAMES_PER_CAPTURE = 100


def _http2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a single HTTP/2 frame."""
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def _settings_frame() -> bytes:
    """Build a SETTINGS frame."""
    payload = struct.pack("!HIHI", 0x01, 4096, 0x03, 100)
    return _http2_frame(0x04, 0x00, 0, payload)


def _headers_frame(stream_id: int) -> bytes:
    """Build a minimal HEADERS frame with HPACK indexed header fields."""
    return _http2_frame(0x01, 0x05, stream_id, b"\x82\x84\x87")


def _data_frame(stream_id: int) -> bytes:
    """Build a DATA frame."""
    return _http2_frame(0x00, 0x01, stream_id, b"hello-http2-payload")


def _window_update_frame(stream_id: int) -> bytes:
    """Build a WINDOW_UPDATE frame."""
    return _http2_frame(0x08, 0x00, stream_id, struct.pack("!I", 65535))


def _goaway_frame(last_stream_id: int) -> bytes:
    """Build a GOAWAY frame with NO_ERROR."""
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") + struct.pack("!I", 0)
    return _http2_frame(0x07, 0x00, 0, payload)


def _mixed_http2_frames(frame_count: int = FRAMES_PER_CAPTURE) -> list[bytes]:
    """Create a deterministic mix of common HTTP/2 frame types."""
    builders = (
        lambda index: _settings_frame(),
        lambda index: _headers_frame(index + 1),
        lambda index: _data_frame(index + 1),
        lambda index: _window_update_frame(index + 1),
        lambda index: _goaway_frame(index + 1),
    )
    return [builders[index % len(builders)](index) for index in range(frame_count)]


def generate_mixed_http2_pcap(
    path: Path, frame_count: int = FRAMES_PER_CAPTURE
) -> int:
    """Generate a synthetic pcap containing mixed HTTP/2 frames."""
    packets = []
    for index, frame in enumerate(_mixed_http2_frames(frame_count)):
        packets.append(
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=443, dport=50000, seq=index * len(frame))
            / Raw(frame)
        )

    wrpcap(str(path), packets)
    return len(packets)


def benchmark_http2_mixed(iterations: int = ITERATIONS) -> float:
    """Benchmark mixed HTTP/2 frame parsing and return frames parsed per second."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / "http2_mixed.pcap"
        frame_count = generate_mixed_http2_pcap(pcap_path)

        start = time.perf_counter()
        for _ in range(iterations):
            parse_capture(pcap_path)
        elapsed = time.perf_counter() - start
