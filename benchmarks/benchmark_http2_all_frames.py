#!/usr/bin/env python3
"""Benchmark HTTP/2 frame parser throughput.

Generates a pcap file containing one HTTP/2 frame of each type (DATA,
HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY,
WINDOW_UPDATE, CONTINUATION, ALTSVC, ORIGIN) with valid stream state
transitions.  Parses the pcap using the existing pcap_parser module and
measures throughput in frames per second.
"""

from __future__ import annotations

import struct
import sys
import time
import tempfile
from pathlib import Path

# Ensure the project root is on sys.path so pcap_parser is importable.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore[import-untyped]
except ImportError:
    print("ERROR: scapy is required.  Install it with:  pip install scapy")
    sys.exit(1)

from pcap_parser import parse_capture


# ---------------------------------------------------------------------------
# HTTP/2 frame helpers
# ---------------------------------------------------------------------------

def _build_http2_frame(frame_type: int, flags: int, stream_id: int,
                       payload: bytes) -> bytes:
    """Build a raw HTTP/2 frame (9‑byte header + payload).

    Args:
        frame_type: HTTP/2 frame type identifier (0‑0xFF).
        flags: Frame flags (8‑bit mask).
        stream_id: 31‑bit stream identifier (non‑negative integer, high bit ignored).
        payload: Frame payload as bytes.

    Returns:
        The complete frame bytes.
    """
    length = len(payload)
    # 3‑byte length, big‑endian
    length_bytes = length.to_bytes(3, 'big')
    # 4‑byte stream id (high bit reserved, always 0)
    stream_id_bytes = (stream_id & 0x7FFFFFFF).to_bytes(4, 'big')
    header = length_bytes + struct.pack('BB', frame_type, flags) + stream_id_bytes
    return header + payload


# ---------------------------------------------------------------------------
# Frame parameters
# ---------------------------------------------------------------------------

FRAME_TYPES = {
    'DATA':          0x0,
    'HEADERS':       0x1,
    'PRIORITY':      0x2,
    'RST_STREAM':    0x3,
    'SETTINGS':      0x4,
    'PUSH_PROMISE':  0x5,
    'PING':          0x6,
    'GOAWAY':        0x7,
    'WINDOW_UPDATE': 0x8,
    'CONTINUATION':  0x9,
    'ALTSVC':        0xA,
    'ORIGIN':        0xF,
}


def _generate_frames() -> list[bytes]:
    """Return a list of 12 raw HTTP/2 frame bytes, one per type.

    The order follows a valid client‑server conversation:
      - Client sends SETTINGS (stream 0)
      - Client sends HEADERS (stream 1, no END_HEADERS)
      - Client sends CONTINUATION (stream 1, END_HEADERS)
      - Client sends DATA (stream 1)
      - Server sends PUSH_PROMISE on stream 1 (promising stream 2)
      - Client sends PRIORITY (stream 1)
      - Client sends RST_STREAM (stream 1)
      - Client sends WINDOW_UPDATE (stream 0)
      - Client sends PING (stream 0)
      - Client sends GOAWAY (stream 0)
      - Client sends ALTSVC (stream 0)
      - Client sends ORIGIN (stream 0)
    """
    frames: list[bytes] = []
    stream = 1  # client‑initiated stream

    # SETTINGS (stream 0) – empty payload, no ACK
    frames.append(_build_http2_frame(FRAME_TYPES['SETTINGS'], 0, 0, b''))

    # HEADERS (stream 1) – no END_HEADERS (continuation follows)
    headers_payload = b'x' * 10  # dummy header block
    frames.append(
        _build_http2_frame(FRAME_TYPES['HEADERS'],
                           flags=0x00,  # no END_HEADERS, no END_STREAM
                           stream_id=stream,
                           payload=headers_payload)
    )

    # CONTINUATION (stream 1) – END_HEADERS
    continuation_payload = b'y' * 8
    frames.append(
        _build_http2_frame(FRAME_TYPES['CONTINUATION'],
                           flags=0x04,  # END_HEADERS
                           stream_id=stream,
                           payload=continuation_payload)
    )

    # DATA (stream 1) – no END_STREAM
    data_payload = b'data payload'
    frames.append(
        _build_http2_frame(FRAME_TYPES['DATA'],
                           flags=0x00,  # no END_STREAM
                           stream_id=stream,
                           payload=data_payload)
    )

    # PUSH_PROMISE (stream 1) – server pushes stream 2
    promised_stream = 2
    # Payload: 4‑byte promised stream id + header block
    push_promise_payload = promised_stream.to_bytes(4, 'big') + b'push header'
    frames.append(
        _build_http2_frame(FRAME_TYPES['PUSH_PROMISE'],
                           flags=0x04,  # END_HEADERS
                           stream_id=stream,
                           payload=push_promise_payload)
    )

    # PRIORITY (stream 1) – payload: exclusive bit + stream dependency + weight
    # Use dependency on stream 0, exclusive = 0, weight = 16
    dependency = 0  # stream 0
    exclusive_bit = 0
    raw_dependency = (exclusive_bit << 31) | dependency
    priority_payload = raw_dependency.to_bytes(4, 'big') + struct.pack('B', 16)
    frames.append(
        _build_http2_frame(FRAME_TYPES['PRIORITY'],
                           flags=0x00,
                           stream_id=stream,
                           payload=priority_payload)
    )

    # RST_STREAM (stream 1) – payload: 4‑byte error code (NO_ERROR = 0)
    rst_payload = (0).to_bytes(4, 'big')
    frames.append(
        _build_http2_frame(FRAME_TYPES['RST_STREAM'],
                           flags=0x00,
                           stream_id=stream,
                           payload=rst_payload)
    )

    # WINDOW_UPDATE (stream 0) – payload: 4‑byte window size increment
    window_payload = (1024).to_bytes(4, 'big')
    frames.append(
        _build_http2_frame(FRAME_TYPES['WINDOW_UPDATE'],
                           flags=0x00,
                           stream_id=0,
                           payload=window_payload)
    )

    # PING (stream 0) – payload: 8 opaque bytes
    ping_payload = b'12345678'
    frames.append(
        _build_http2_frame(FRAME_TYPES['PING'],
                           flags=0x00,
                           stream_id=0,
                           payload=ping_payload)
    )

    # GOAWAY (stream 0) – payload: last stream id + error code + debug data
    last_stream = 2
    error_code = 0  # NO_ERROR
    goaway_payload = struct.pack('!II', last_stream, error_code) + b'graceful shutdown'
    frames.append(
        _build_http2_frame(FRAME_TYPES['GOAWAY'],
                           flags=0x00,
                           stream_id=0,
                           payload=goaway_payload)
    )

    # ALTSVC (stream 0) – payload: origin length + origin + protocol length + protocol
    origin = b'example.com'
    protocol = b'h2'
    altsvc_payload = (len(origin).to_bytes(2, 'big') + origin +
                      len(protocol).to_bytes(2, 'big') + protocol)
    frames.append(
        _build_http2_frame(FRAME_TYPES['ALTSVC'],
                           flags=0x00,
                           stream_id=0,
                           payload=altsvc_payload)
    )

    # ORIGIN (stream 0) – payload: list of origins
    origin_entry = len(origin).to_bytes(2, 'big') + origin
    frames.append(
        _build_http2_frame(FRAME_TYPES['ORIGIN'],
                           flags=0x00,
                           stream_id=0,
                           payload=origin_entry)
    )

    return frames


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def main() -> None:
    """Build the pcap, run the parser benchmark, and print results."""
    print("Building test pcap…")
    frames = _generate_frames()
    assert len(frames) == len(FRAME_TYPES)

    # Create one TCP packet per frame (simple Ethernet/IP/PSH+ACK)
    packets = []
    for frame_bytes in frames:
        pkt = Ether() / IP(src='192.0.2.1', dst='203.0.113.1') / TCP(
            sport=54321, dport=80, flags=0x18  # PSH + ACK
        ) / Raw(load=frame_bytes)
        packets.append(pkt)
