#!/usr/bin/env python3
"""Benchmark HTTP/2 frame parsing with stream state tracking."""

from __future__ import annotations

import struct
import time
from typing import Tuple

# HTTP/2 frame type constants
FRAME_HEADERS = 0x1
FRAME_DATA = 0x0
FRAME_GOAWAY = 0x7

# Frame flags
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4

# The stream identifier for the single simulated stream
STREAM_ID = 1


def build_headers_frame(stream_id: int, end_headers: bool = True) -> bytes:
    """Build a minimal HEADERS frame.

    Produces a HEADERS frame with no priority, no padding, and a single
    indexed header block fragment (:method: GET).
    """
    flags = FLAG_END_HEADERS if end_headers else 0
    # Minimal header block fragment: just the :method: GET pseudo-header
    payload = bytes([0x82])
    length = len(payload)
    length_bytes = length.to_bytes(3, "big")
    header = (
        length_bytes
        + bytes([FRAME_HEADERS, flags])
        + struct.pack("!I", stream_id)
    )
    return header + payload


def build_data_frame(stream_id: int, payload_data: bytes, end_stream: bool = True) -> bytes:
    """Build a DATA frame."""
    flags = FLAG_END_STREAM if end_stream else 0
    payload = payload_data
    length = len(payload)
    length_bytes = length.to_bytes(3, "big")
    header = (
        length_bytes
        + bytes([FRAME_DATA, flags])
        + struct.pack("!I", stream_id)
    )
    return header + payload


def build_goaway_frame(last_stream_id: int, error_code: int = 0) -> bytes:
    """Build a GOAWAY frame (always on stream 0)."""
    payload = struct.pack("!II", last_stream_id, error_code)
    length = 8
    length_bytes = length.to_bytes(3, "big")
    header = (
        length_bytes
        + bytes([FRAME_GOAWAY, 0x00])  # no flags
        + struct.pack("!I", 0)          # connection-level frame, stream 0
    )
    return header + payload


def parse_frame(raw: bytes) -> Tuple[int, int, int, bytes]:
    """Parse an HTTP/2 frame header and return (stream_id, type, flags, payload)."""
    if len(raw) < 9:
        raise ValueError("Frame too short")
    length = int.from_bytes(raw[0:3], "big")
    frame_type = raw[3]
    flags = raw[4]
    # Stream ID is the last 4 bytes of the header, with the reserved bit cleared
    stream_id = struct.unpack("!I", raw[5:9])[0] & 0x7FFFFFFF
    payload = raw[9 : 9 + length]
    return stream_id, frame_type, flags, payload


class StreamStateMachine:
    """Simple HTTP/2 stream state machine.

    Transitions: idle → open → half_closed → closed.
    """

    def __init__(self) -> None:
        self.state = "idle"

    def process_frame(
        self, stream_id: int, frame_type: int, flags: int, payload: bytes
    ) -> None:
        """Process a single frame and update the stream state."""
        if frame_type == FRAME_HEADERS:
            if self.state == "idle":
                self.state = "open"
        elif frame_type == FRAME_DATA:
            if self.state == "open":
                if flags & FLAG_END_STREAM:
                    self.state = "half_closed"
        elif frame_type == FRAME_GOAWAY:
            # GOAWAY is connection-level; for this benchmark it closes the stream.
            self.state = "closed"
