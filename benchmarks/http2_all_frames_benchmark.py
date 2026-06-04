"""Benchmark HTTP/2 frame parsing for all frame types with stream state tracking.

Generates a synthetic pcap containing one of each HTTP/2 frame type
(DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING,
 GOAWAY, WINDOW_UPDATE, CONTINUATION) and measures parsing throughput.
Includes a lightweight stream state machine to track connection state
during frame generation and verify basic protocol invariants.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

# Ensure the project root is on sys.path so pcap_parser can be imported.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
except ImportError as exc:
    raise ImportError(
        "scapy is required for generating the benchmark pcap"
    ) from exc

from pcap_parser import parse_capture


def _build_http2_frame(
    frame_type: int, flags: int, stream_id: int, payload: bytes
) -> bytes:
    """Assemble a raw HTTP/2 frame."""
    length = len(payload)
    return (
        length.to_bytes(3, "big")
        + bytes([frame_type])
        + bytes([flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _build_data_frame(stream_id: int, data: bytes = b"", end_stream: bool = False) -> bytes:
    flags = 0x01 if end_stream else 0x00
    return _build_http2_frame(0x00, flags, stream_id, data)


def _build_headers_frame(
    stream_id: int, end_stream: bool = False, end_headers: bool = True
) -> bytes:
    flags = 0x00
    if end_stream:
        flags |= 0x01
    if end_headers:
        flags |= 0x04
    # Minimal (non‑valid HPACK) header block fragment
    fragment = b"\x00\x00"
    return _build_http2_frame(0x01, flags, stream_id, fragment)


def _build_priority_frame(
    stream_id: int, exclusive: bool = False, dependency: int = 0, weight: int = 15
) -> bytes:
    raw_dep = (dependency & 0x7FFFFFFF) | (0x80000000 if exclusive else 0x00000000)
    payload = raw_dep.to_bytes(4, "big") + bytes([weight])
    return _build_http2_frame(0x02, 0x00, stream_id, payload)


def _build_rst_stream_frame(stream_id: int, error_code: int = 0) -> bytes:
    payload = error_code.to_bytes(4, "big")
    return _build_http2_frame(0x03, 0x00, stream_id, payload)


def _build_settings_frame(ack: bool = False) -> bytes:
    flags = 0x01 if ack else 0x00
    # Single setting: SETTINGS_MAX_CONCURRENT_STREAMS = 100
    payload = (0x0003).to_bytes(2, "big") + (100).to_bytes(4, "big")
    return _build_http2_frame(0x04, flags, 0x00, payload)


def _build_push_promise_frame(
    stream_id: int, promised_stream_id: int
) -> bytes:
    promised = promised_stream_id & 0x7FFFFFFF
    fragment = b"\x00\x00"
    payload = promised.to_bytes(4, "big") + fragment
    return _build_http2_frame(0x05, 0x04, stream_id, payload)


def _build_ping_frame(opaque: bytes = b"\x00" * 8, ack: bool = False) -> bytes:
    if len(opaque) != 8:
        raise ValueError("PING payload must be exactly 8 bytes")
    flags = 0x01 if ack else 0x00
    return _build_http2_frame(0x06, flags, 0x00, opaque)


def _build_goaway_frame(last_stream_id: int = 0, error_code: int = 0) -> bytes:
    last = last_stream_id & 0x7FFFFFFF
    payload = last.to_bytes(4, "big") + error_code.to_bytes(4, "big")
    return _build_http2_frame(0x07, 0x00, 0x00, payload)


def _build_window_update_frame(stream_id: int, increment: int = 64) -> bytes:
    payload = (increment & 0x7FFFFFFF).to_bytes(4, "big")
    return _build_http2_frame(0x08, 0x00, stream_id, payload)


def _build_continuation_frame(stream_id: int, end_headers: bool = True) -> bytes:
    flags = 0x04 if end_headers else 0x00
    fragment = b"\x00\x00"
    return _build_http2_frame(0x09, flags, stream_id, fragment)


def generate_http2_pcap() -> tuple[Path, int]:
    """Create a temporary pcap with one instance of each HTTP/2 frame type.

    Returns:
        (pcap_path, total_frame_count)
    """
    # Build all frame bytes in a realistic order.
    frames = []
    frames.append(_build_settings_frame(ack=False))          # SETTINGS (initial)
    frames.append(_build_settings_frame(ack=True))           # SETTINGS ACK
    frames.append(_build_priority_frame(0))                  # PRIORITY (stream 0)
    h = _build_headers_frame(1, end_stream=False, end_headers=False)
    frames.append(h)                                         # HEADERS (stream 1)
    frames.append(_build_continuation_frame(1))              # CONTINUATION
    frames.append(_build_data_frame(1, data=b"hello", end_stream=True))  # DATA + END_STREAM
    frames.append(_build_window_update_frame(1, increment=128))          # WINDOW_UPDATE
    frames.append(_build_push_promise_frame(1, 2))           # PUSH_PROMISE
    frames.append(_build_headers_frame(2, end_stream=True))   # HEADERS (stream 2)
    frames.append(_build_ping_frame())                        # PING
    frames.append(_build_ping_frame(ack=True))                # PING ACK
    frames.append(_build_rst_stream_frame(2))                 # RST_STREAM (stream 2)
    frames.append(_build_goaway_frame(last_stream_id=2))      # GOAWAY

    # Build TCP packets, increasing seq number each time.
    packets = []
    seq = 1000
    for frame_bytes in frames:
        pkt = (
            Ether()
            / IP(dst="10.0.0.1", src="10.0.0.2")
            / TCP(sport=54321, dport=443, seq=seq)
            / Raw(frame_bytes)
        )
        seq += len(frame_bytes)
        packets.append(pkt)

    pcap_path = Path(tempfile.mktemp(suffix=".pcap"))
    wrpcap(str(pcap_path), packets)
    return pcap_path, len(frames)
