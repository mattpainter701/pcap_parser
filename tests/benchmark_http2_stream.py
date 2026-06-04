#!/usr/bin/env python3
"""Benchmark HTTP/2 frame parsing with stream state validation.

Generates a sequence of 10 000 valid HTTP/2 frames (HEADERS, DATA, RST_STREAM)
spread across multiple streams, then measures the time required to parse each
frame and update the per-stream state machine.

Expected completion time: well under 1 second on modern hardware.
"""

from __future__ import annotations

import struct
import time
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FRAME_HEADER_LEN = 9

# Frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3

# Stream states
STATE_IDLE = "idle"
STATE_OPEN = "open"
STATE_CLOSED = "closed"

# ---------------------------------------------------------------------------
# Frame helpers
# ---------------------------------------------------------------------------


def build_http2_frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes,
) -> bytes:
    """Build a raw HTTP/2 frame (9‑byte header + payload).

    Args:
        frame_type: HTTP/2 frame type (0x0 – 0x9).
        flags: 8‑bit flags field.
        stream_id: 31‑bit stream identifier (odd/even per spec).
        payload: frame payload as bytes.

    Returns:
        The complete frame as a byte string.
    """
    length = len(payload)

    # 24‑bit length (big‑endian)
    length_bytes = struct.pack("!I", length)[1:]  # drop the first (zero) byte

    # Stream ID: reserved bit (0) + 31 bits
    stream_bytes = struct.pack("!I", stream_id & 0x7FFFFFFF)

    header = length_bytes + struct.pack("!BB", frame_type, flags) + stream_bytes
    return header + payload


def parse_http2_frame_header(
    data: bytes,
) -> Tuple[int, int, int, bytes]:
    """Parse an HTTP/2 frame header and return relevant fields.

    Args:
        data: At least 9 bytes (the frame header).  Extra trailing bytes are
            ignored; they are returned as the payload.

    Returns:
        A tuple (frame_type, flags, stream_id, payload).

    Raises:
        ValueError: if *data* is shorter than the 9‑byte header.
    """
    if len(data) < FRAME_HEADER_LEN:
        raise ValueError(
            f"Frame header must be at least {FRAME_HEADER_LEN} bytes, "
            f"got {len(data)}"
        )

    # Length: first 3 bytes (big‑endian)
    length = (data[0] << 16) | (data[1] << 8) | data[2]

    frame_type = data[3]
    flags = data[4]

    # Stream ID: bytes 5‑8, last 7 bytes = 31‑bit value (reserved bit cleared)
    stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF

    payload = data[9:]
    if len(payload) < length:
        raise ValueError(
            f"Frame header claims payload length {length}, "
            f"but only {len(payload)} bytes available"
        )
    return frame_type, flags, stream_id, payload[:length]


def parse_headers_frame_payload(payload: bytes) -> dict:
    """Parse a HEADERS frame payload placeholder.

    In a real implementation this would decode HPACK.  For benchmarking
    we simply return the raw payload.
    """
    return {"raw_headers_block": payload}


def parse_data_frame_payload(payload: bytes) -> dict:
    """Parse a DATA frame payload placeholder."""
    return {"raw_data": payload}


def parse_rst_stream_frame_payload(payload: bytes) -> dict:
    """Parse the 4‑byte error code from an RST_STREAM frame."""
    if len(payload) != 4:
        raise ValueError(
            f"RST_STREAM payload must be exactly 4 bytes, got {len(payload)}"
        )
    error_code = struct.unpack("!I", payload)[0]
    return {"error_code": error_code}


def parse_and_validate_frame(
    frame_bytes: bytes,
    stream_states: Dict[int, str],
) -> None:
    """Parse a single HTTP/2 frame and update stream state.

    Args:
        frame_bytes: Raw frame bytes (header + payload).
        stream_states: Mapping from stream_id to current state.  Updated
            in‑place.

    Raises:
        ValueError: if a state transition is invalid.
    """
    frame_type, _flags, stream_id, payload = parse_http2_frame_header(frame_bytes)
    current_state = stream_states.get(stream_id, STATE_IDLE)

    if frame_type == FRAME_HEADERS:
        # HEADERS can be sent on an idle stream → open
        if current_state != STATE_IDLE:
            raise ValueError(
                f"Stream {stream_id} in state {current_state} "
                f"cannot receive HEADERS"
            )
        stream_states[stream_id] = STATE_OPEN
        parse_headers_frame_payload(payload)
    elif frame_type == FRAME_DATA:
        # DATA can only be sent on an open stream
        if current_state != STATE_OPEN:
            raise ValueError(
                f"Stream {stream_id} in state {current_state} "
                f"cannot receive DATA"
            )
        stream_states[stream_id] = STATE_OPEN  # remains open
        parse_data_frame_payload(payload)
    elif frame_type == FRAME_RST_STREAM:
        # RST_STREAM can be sent on an open or half‑closed stream → closed
        if current_state not in (STATE_OPEN,):
            raise ValueError(
                f"Stream {stream_id} in state {current_state} "
                f"cannot receive RST_STREAM"
            )
        stream_states[stream_id] = STATE_CLOSED
        parse_rst_stream_frame_payload(payload)
    else:
        # Unsupported frame type – skip (no state change)
        pass


def generate_frames(num_frames: int) -> List[bytes]:
    """Generate *num_frames* valid HTTP/2 frames (HEADERS / DATA / RST_STREAM)."""
    frames: List[bytes] = []
    stream_id = 1  # client‑initiated streams are odd

    headers_payload = b"\x00" * 10  # dummy HPACK block
    data_payload = b"X" * 200       # dummy data
    rst_payload = struct.pack("!I", 0)  # NO_ERROR

    while len(frames) < num_frames:
        # HEADERS
        frames.append(build_http2_frame(FRAME_HEADERS, 0x04, stream_id, headers_payload))
        if len(frames) >= num_frames:
            break
