#!/usr/bin/env python3
"""Benchmark script for HTTP/2 frame parsing.

Generates a PCAP containing one of each HTTP/2 frame type (DATA, HEADERS,
PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE,
CONTINUATION, ALTSVC, ORIGIN, PRIORITY_UPDATE) with valid payloads and
stream IDs.  Uses pcap_parser to parse the file and measures total parse
time.  Additionally times each frame type's dissection individually.
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

import scapy.all as scapy

# Ensure the project root is on the import path so that pcap_parser and
# dissectors.http2 can be imported when running this script directly.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pcap_parser import parse_capture
from dissectors.http2 import dissect_http2_frame

# ---------------------------------------------------------------------------
# HTTP/2 frame construction helpers
# ---------------------------------------------------------------------------

_TYPE_NAMES: dict[int, str] = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x02: "PRIORITY",
    0x03: "RST_STREAM",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x06: "PING",
    0x07: "GOAWAY",
    0x08: "WINDOW_UPDATE",
    0x09: "CONTINUATION",
    0x0A: "ALTSVC",
    0x0C: "ORIGIN",
    0x0F: "PRIORITY_UPDATE",
}


def _build_http2_frame(
    frame_type: int, flags: int, stream_id: int, payload: bytes
) -> bytes:
    """Construct a raw HTTP/2 frame (9‑byte header + payload).

    Args:
        frame_type: HTTP/2 frame type identifier.
        flags: 8-bit flags field.
        stream_id: 31-bit stream identifier (most‑significant bit must be 0).
        payload: Frame payload bytes.

    Returns:
        Complete frame as ``bytes`` suitable for sending over TCP.
    """
    if stream_id & ~0x7FFFFFFF:
        raise ValueError("stream_id must be a 31‑bit value (≤ 0x7FFFFFFF)")
    length = len(payload)
    header = (
        length.to_bytes(3, "big")
        + frame_type.to_bytes(1, "big")
        + flags.to_bytes(1, "big")
        + stream_id.to_bytes(4, "big")
    )
    return header + payload


# ---------------------------------------------------------------------------
# PCAP generation
# ---------------------------------------------------------------------------

def _generate_pcap(dest: Path) -> dict[str, bytes]:
    """Write a synthetic PCAP containing one packet per HTTP/2 frame type.

    Returns:
        A mapping from frame-type name to the raw frame bytes.
    """
    frames: dict[str, bytes] = {}

    # DATA                                                                      (0x0)
    frames["DATA"] = _build_http2_frame(0x00, 0x00, 1, b"Hello, World!")

    # HEADERS (empty header block, END_HEADERS flag set)                        (0x1)
    frames["HEADERS"] = _build_http2_frame(0x01, 0x04, 3, b"")

    # PRIORITY (stream dependency = 0, exclusive = False, weight = 42)          (0x2)
    dep = struct.pack("!I", 0x00000000)  # 31‑bit stream 0, exclusive bit 0
    frames["PRIORITY"] = _build_http2_frame(0x02, 0x00, 5, dep + bytes([42]))

    # RST_STREAM (error NO_ERROR = 0)                                           (0x3)
    frames["RST_STREAM"] = _build_http2_frame(0x03, 0x00, 7, struct.pack("!I", 0))

    # SETTINGS (empty settings, ACK flag set)                                   (0x4)
    frames["SETTINGS"] = _build_http2_frame(0x04, 0x01, 0, b"")

    # PUSH_PROMISE (promised stream 2, empty header block, END_HEADERS)         (0x5)
    frames["PUSH_PROMISE"] = _build_http2_frame(
        0x05, 0x04, 9, struct.pack("!I", 2)
    )

    # PING (opaque 8 bytes of zeros)                                            (0x6)
    frames["PING"] = _build_http2_frame(0x06, 0x00, 0, b"\x00" * 8)

    # GOAWAY (last stream = 0, error = NO_ERROR)                               (0x7)
    frames["GOAWAY"] = _build_http2_frame(
        0x07, 0x00, 0, struct.pack("!II", 0, 0)
    )

    # WINDOW_UPDATE (increment 1)                                               (0x8)
    frames["WINDOW_UPDATE"] = _build_http2_frame(0x08, 0x00, 0, struct.pack("!I", 1))

    # CONTINUATION (associated with HEADERS on stream 3, END_HEADERS)           (0x9)
    frames["CONTINUATION"] = _build_http2_frame(0x09, 0x04, 3, b"")

    # ALTSVC (RFC 7838: max‑age=0, port=443, alpn="h2", empty origin)         (0xA)
    altsvc = (
        struct.pack("!I", 0)      # max‑age
        + struct.pack("!H", 443)  # port
        + bytes([0, 2])           # reserved + protocol‑len (2 bytes for "h2")
        + b"h2"                   # protocol identifier
        + struct.pack("!H", 0)    # origin‑len = 0
    )
    frames["ALTSVC"] = _build_http2_frame(0x0A, 0x00, 0, altsvc)

    # ORIGIN (RFC 8336: one origin "https://example.com")                      (0xC)
    origin = b"https://example.com"
    origin_fragment = struct.pack("!H", len(origin)) + origin
    frames["ORIGIN"] = _build_http2_frame(0x0C, 0x00, 0, origin_fragment)

    # PRIORITY_UPDATE (RFC 9218 Extensible Priority)                           (0xF)
    # Payload: prioritised stream ID (4 bytes) + empty priority field value.
    frames["PRIORITY_UPDATE"] = _build_http2_frame(
        0x0F, 0x00, 1, struct.pack("!I", 1)
    )

    # Build one Ethernet/IP/TCP packet per frame.
    packets = []
    for i, (name, frame_bytes) in enumerate(frames.items()):
        pkt = (
            scapy.Ether()
            / scapy.IP(dst="127.0.0.1", src="127.0.0.1")
            / scapy.TCP(sport=10000 + i, dport=443)
            / scapy.Raw(frame_bytes)
        )
        packets.append(pkt)
    scapy.wrpcap(str(dest), packets)
    return frames


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Benchmark HTTP/2 frame parsing across all frame types."
    )
    ap.add_argument(
        "--progress",
        action="store_true",
        help="Enable pcap_parser's progress bar during parse.",
    )
    args = ap.parse_args()

    pcap_path = Path("/tmp/http2_frames_bench.pcap")
