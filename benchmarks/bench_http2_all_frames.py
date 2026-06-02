#!/usr/bin/env python3
"""Benchmark HTTP/2 frame parsing throughput with all frame types.

Generates a synthetic pcap containing one frame of each HTTP/2 type,
wraps it in a minimal pcap header, then measures the time to parse it
100 times using the pcap-parser library. Prints average parse time and
frames per second.
"""

from __future__ import annotations

import struct
import sys
import tempfile
import timeit
from pathlib import Path

# Ensure the project root is on sys.path to allow importing pcap_parser
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pcap_parser import parse_capture


def build_synthetic_pcap() -> str:
    """Create a temporary pcap file containing a single HTTP/2 packet
    with one frame of each type and return its path."""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap

    # Helper to build an HTTP/2 frame header
    def frame_header(
        stream_id: int, frame_type: int, flags: int = 0, payload_length: int = 0
    ) -> bytes:
        # 3-byte length (big-endian)
        length_bytes = struct.pack("!I", payload_length)[1:]
        # 1-byte type, 1-byte flags, 4-byte stream ID (31 bits, reserved bit 0)
        stream_bytes = struct.pack("!I", stream_id & 0x7FFFFFFF)
        return length_bytes + bytes([frame_type, flags]) + stream_bytes

    # Build connection preface + all 10 frames
    frame_data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # 1. DATA (type 0x0)
    payload = b""  # empty
    frame_data += frame_header(1, 0x0, 0, len(payload)) + payload
    # 2. HEADERS (0x1)
    payload = b"\x00"
    frame_data += frame_header(1, 0x1, 0x4, len(payload)) + payload
    # 3. PRIORITY (0x2)
    payload = struct.pack("!I", 0) + b"\x10"  # 5 bytes
    frame_data += frame_header(1, 0x2, 0, len(payload)) + payload
    # 4. RST_STREAM (0x3)
    payload = struct.pack("!I", 0)  # NO_ERROR
    frame_data += frame_header(1, 0x3, 0, len(payload)) + payload
    # 5. SETTINGS (0x4) – empty, no ACK
    payload = b""
    frame_data += frame_header(0, 0x4, 0, len(payload)) + payload
    # 6. PUSH_PROMISE (0x5)
    # Promised stream ID (4 bytes) + empty header block fragment
    payload = struct.pack("!I", 2 & 0x7FFFFFFF)
    frame_data += frame_header(1, 0x5, 0x4, len(payload)) + payload
    # 7. PING (0x6)
    payload = b"\x00" * 8
    frame_data += frame_header(0, 0x6, 0, len(payload)) + payload
    # 8. GOAWAY (0x7)
    last_stream_id = 0
    error_code = 0  # NO_ERROR
    payload = struct.pack("!II", last_stream_id, error_code)
    frame_data += frame_header(0, 0x7, 0, len(payload)) + payload
    # 9. WINDOW_UPDATE (0x8)
    increment = 1  # 31-bit value
    payload = struct.pack("!I", increment)
    frame_data += frame_header(0, 0x8, 0, len(payload)) + payload
    # 10. CONTINUATION (0x9)
    payload = b"\x00"
    frame_data += frame_header(1, 0x9, 0x4, len(payload)) + payload

    # Build a single TCP packet carrying all frames
    pkt = (
        Ether()
        / IP(dst="93.184.216.34")
        / TCP(sport=12345, dport=443, flags="PA")
        / Raw(load=frame_data)
    )

    # Write to a temporary file
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp.close()
    wrpcap(tmp.name, pkt)
    return tmp.name


def main() -> None:
    pcap_path = build_synthetic_pcap()

    # Verify that the pcap is parseable
    try:
        result = parse_capture(pcap_path)
        if result is None:
            print("Warning: parse_capture returned None", file=sys.stderr)
    except Exception as e:
        print(f"Error parsing pcap: {e}", file=sys.stderr)
        Path(pcap_path).unlink() if Path(pcap_path).exists() else None
        sys.exit(1)

    # Benchmark: 100 iterations
    number = 100
    elapsed = timeit.timeit(lambda: parse_capture(pcap_path), number=number)
    avg_time = elapsed / number
