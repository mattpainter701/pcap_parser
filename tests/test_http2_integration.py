"""Integration tests for HTTP/2 frame parsing with stream state and size validation."""

from __future__ import annotations

import struct

import pytest

from dissectors.http2 import dissect_http2_frame, parse_http2_priority_frame

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7

# Flags
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_frame(
    frame_type: int,
    payload: bytes,
    flags: int = 0,
    stream_id: int = 0,
) -> bytes:
    """Build an HTTP/2 frame header + payload.

    Args:
        frame_type: HTTP/2 frame type (9.1).
        payload: Raw payload bytes.
        flags: 8-bit flags field.
        stream_id: 31-bit stream identifier (0 for connection-level frames).

    Returns:
        Complete frame bytes including 9-byte header.
    """
    length = len(payload)
    # 24-bit length (big-endian)
    header = struct.pack("!I", length)[1:]  # drop first byte → 3 bytes
    header += struct.pack("!B", frame_type)
    header += struct.pack("!B", flags)
    header += struct.pack("!I", stream_id & 0x7FFFFFFF)
    return header + payload


def parse_frame_header(frame: bytes) -> tuple[int, int, int, int]:
    """Parse an HTTP/2 frame header and return (length, type, flags, stream_id)."""
    if len(frame) < 9:
        raise ValueError("Frame header too short")
    length = (frame[0] << 16) | (frame[1] << 8) | frame[2]
    frame_type = frame[3]
    flags = frame[4]
    raw_stream_id = struct.unpack("!I", frame[5:9])[0]
    stream_id = raw_stream_id & 0x7FFFFFFF
    return length, frame_type, flags, stream_id


def parse_frame_from_stream(data: bytes, offset: int) -> tuple[int, int, int, int, bytes]:
    """Parse a single frame at a given offset in a byte stream.

    Returns:
        (next_offset, length, frame_type, flags, stream_id, payload)
    """
    if offset + 9 > len(data):
        raise ValueError("Incomplete frame header")
    length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
    frame_type = data[offset + 3]
    flags = data[offset + 4]
    raw_stream_id = struct.unpack("!I", data[offset + 5 : offset + 9])[0]
    stream_id = raw_stream_id & 0x7FFFFFFF
    if offset + 9 + length > len(data):
        raise ValueError("Incomplete frame payload")
    payload = data[offset + 9 : offset + 9 + length]
    next_offset = offset + 9 + length
    return next_offset, length, frame_type, flags, stream_id, payload


class _StreamState:
    """Minimal stream state machine for test validation."""

    IDLE = "IDLE"
    OPEN = "OPEN"
    HALF_CLOSED_REMOTE = "HALF_CLOSED_REMOTE"
    CLOSED = "CLOSED"

    def __init__(self) -> None:
        self._streams: dict[int, str] = {}

    def on_frame(self, frame_type: int, flags: int, stream_id: int) -> bool:
        """Update stream state based on a parsed frame.

        Returns:
            True if the transition is valid according to HTTP/2 spec,
            False otherwise.
        """
        if stream_id == 0:
            # Connection-level frames: SETTINGS and GOAWAY are always valid.
            return frame_type in (FRAME_SETTINGS, FRAME_GOAWAY)

        if frame_type == FRAME_HEADERS:
            if stream_id not in self._streams:
                # HEADERS opens a new stream from IDLE -> OPEN
                self._streams[stream_id] = self.OPEN
                return True
            # HEADERS on an already-open stream is allowed (trailers)
            return self._streams[stream_id] == self.OPEN

        if frame_type == FRAME_DATA:
            state = self._streams.get(stream_id)
            if state is None:
                return False  # DATA on idle stream
            if state != self.OPEN:
                return False
            if flags & FLAG_END_STREAM:
                self._streams[stream_id] = self.CLOSED
            return True

        # Unsupported frame type for stream > 0
        return False

    def stream_state(self, stream_id: int) -> str | None:
        """Return the current state for *stream_id* (or *None* if unknown)."""
        return self._streams.get(stream_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def preface() -> bytes:
    """Return the HTTP/2 connection preface."""
    return PREFACE


@pytest.fixture
def settings_frame() -> bytes:
    """Return an empty SETTINGS frame with the ACK flag."""
    return build_frame(FRAME_SETTINGS, b"", flags=FLAG_ACK, stream_id=0)


@pytest.fixture
def headers_frame() -> bytes:
    """Return a HEADERS frame on stream 1 with END_HEADERS flag."""
    # Payload is empty for simplicity; real HPACK data would be longer.
    return build_frame(FRAME_HEADERS, b"", flags=FLAG_END_HEADERS, stream_id=1)


@pytest.fixture
def data_frame() -> bytes:
    """Return a DATA frame on stream 1 with END_STREAM flag."""
    payload = b"Hello, world!"
    return build_frame(FRAME_DATA, payload, flags=FLAG_END_STREAM, stream_id=1)


@pytest.fixture
def goaway_frame() -> bytes:
    """Return a GOAWAY frame on stream 0.

    Payload: last-stream-id=0, error-code=0 (NO_ERROR).
    """
    payload = struct.pack("!II", 0, 0)
    return build_frame(FRAME_GOAWAY, payload, flags=0, stream_id=0)


@pytest.fixture
def complete_byte_stream(
    settings_frame: bytes,
    headers_frame: bytes,
    data_frame: bytes,
    goaway_frame: bytes,
) -> bytes:
    """Combine the preface and all frames into a single byte stream."""
