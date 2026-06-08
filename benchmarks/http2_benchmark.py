"""Benchmark parsing synthetic HTTP/2 frames.

Run with:
    python3 benchmarks/http2_benchmark.py
"""

from __future__ import annotations

import struct
import timeit
from collections import Counter
from typing import Dict, Iterable, List, Tuple

from dissectors.http2 import dissect_http2_frame

FRAME_COUNT = 1000
RUNS = 100

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

STREAM_OPEN = "open"
STREAM_CLOSED = "closed"

Frame = Tuple[int, int, int, bytes]


def build_frame_header(length: int, frame_type: int, flags: int, stream_id: int) -> bytes:
    """Build a 9-byte HTTP/2 frame header."""
    if length > 0xFFFFFF:
        raise ValueError(f"HTTP/2 frame payload too large: {length}")
    if stream_id > 0x7FFFFFFF:
        raise ValueError(f"HTTP/2 stream ID too large: {stream_id}")

    return (
        length.to_bytes(3, "big")
        + bytes((frame_type, flags))
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
    )


def build_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a complete HTTP/2 frame."""
    return build_frame_header(len(payload), frame_type, flags, stream_id) + payload


def build_data_payload(index: int) -> bytes:
    """Build a small DATA payload."""
    return f"chunk-{index:04d}: synthetic http2 body bytes".encode("ascii")


def build_headers_payload(index: int, include_priority: bool = False) -> bytes:
    """Build a synthetic HEADERS payload.

    The header block is intentionally opaque: this benchmark measures HTTP/2
    frame parsing overhead, not HPACK decoding.
    """
    header_block = (
        b"\x82\x86\x41"
        + f"example-{index % 31}.test".encode("ascii")
        + b"\x84"
    )
    if include_priority:
        return build_priority_payload(index) + header_block
    return header_block


def build_priority_payload(index: int) -> bytes:
    """Build a PRIORITY payload."""
    dependency = ((index * 2 + 1) & 0x7FFFFFFF) | (0x80000000 if index % 6 == 0 else 0)
    weight = (index % 256).to_bytes(1, "big")
    return struct.pack("!I", dependency) + weight


def build_rst_stream_payload(index: int) -> bytes:
    """Build an RST_STREAM payload with a rotating error code."""
    error_codes = (0x0, 0x1, 0x2, 0x5, 0x7, 0x8)
    return struct.pack("!I", error_codes[index % len(error_codes)])


def build_settings_payload(index: int) -> bytes:
    """Build a SETTINGS payload containing common settings."""
    if index % 20 == 0:
        return b""

    settings = (
        (0x1, 4096 + index % 1024),  # SETTINGS_HEADER_TABLE_SIZE
        (0x3, 100 + index % 25),  # SETTINGS_MAX_CONCURRENT_STREAMS
        (0x4, 65535 + index),  # SETTINGS_INITIAL_WINDOW_SIZE
    )
    return b"".join(struct.pack("!HI", setting_id, value) for setting_id, value in settings)


def build_push_promise_payload(index: int, promised_stream_id: int) -> bytes:
    """Build a PUSH_PROMISE payload."""
    promised_id = struct.pack("!I", promised_stream_id & 0x7FFFFFFF)
    header_block = b"\x82\x87" + f"/asset-{index % 17}.css".encode("ascii")
    return promised_id + header_block


def build_ping_payload(index: int) -> bytes:
    """Build a PING payload."""
    return struct.pack("!Q", 0x5043415000000000 | index)


def build_goaway_payload(last_stream_id: int, index: int) -> bytes:
    """Build a GOAWAY payload."""
    debug_data = f"bench-goaway-{index}".encode("ascii")
    return struct.pack("!II", last_stream_id & 0x7FFFFFFF, 0x0) + debug_data


def build_window_update_payload(index: int) -> bytes:
    """Build a WINDOW_UPDATE payload."""
    increment = 1024 + (index % 32768)
    return struct.pack("!I", increment & 0x7FFFFFFF)


def build_continuation_payload(index: int) -> bytes:
    """Build a CONTINUATION payload."""
    return b"\x40" + f"continued-header-{index % 29}".encode("ascii")


def generate_frames(frame_count: int = FRAME_COUNT) -> List[Frame]:
    """Generate synthetic HTTP/2 frame metadata and payloads."""
    frames: List[Frame] = []

    for index in range(frame_count):
        stream_id = ((index % 101) * 2) + 1
        frame_kind = index % 10

        if frame_kind == 0:
            flags = FLAG_END_STREAM if index % 40 == 0 else 0
            frames.append((FRAME_DATA, flags, stream_id, build_data_payload(index)))
        elif frame_kind == 1:
            flags = FLAG_END_HEADERS | (FLAG_PRIORITY if index % 3 == 0 else 0)
            if index % 41 == 0:
                flags |= FLAG_END_STREAM
            frames.append(
                (
                    FRAME_HEADERS,
                    flags,
                    stream_id,
                    build_headers_payload(index, include_priority=bool(flags & FLAG_PRIORITY)),
                )
            )
        elif frame_kind == 2:
            frames.append((FRAME_PRIORITY, 0, stream_id, build_priority_payload(index)))
        elif frame_kind == 3:
            frames.append((FRAME_RST_STREAM, 0, stream_id, build_rst_stream_payload(index)))
        elif frame_kind == 4:
            flags = FLAG_ACK if index % 20 == 0 else 0
            frames.append((FRAME_SETTINGS, flags, 0, build_settings_payload(index)))
        elif frame_kind == 5:
            promised_stream_id = (((index + 1) % 101) * 2) + 2
            frames.append(
                (
                    FRAME_PUSH_PROMISE,
                    FLAG_END_HEADERS,
                    stream_id,
                    build_push_promise_payload(index, promised_stream_id),
                )
            )
        elif frame_kind == 6:
            flags = FLAG_ACK if index % 30 == 0 else 0
            frames.append((FRAME_PING, flags, 0, build_ping_payload(index)))
        elif frame_kind == 7:
            last_stream_id = max(1, stream_id - 2)
            frames.append((FRAME_GOAWAY, 0, 0, build_goaway_payload(last_stream_id, index)))
        elif frame_kind == 8:
            update_stream_id = 0 if index % 24 == 0 else stream_id
            frames.append((FRAME_WINDOW_UPDATE, 0, update_stream_id, build_window_update_payload(index)))
        else:
            flags = FLAG_END_HEADERS | (FLAG_END_STREAM if index % 70 == 0 else 0)
            frames.append((FRAME_CONTINUATION, flags, stream_id, build_continuation_payload(index)))

    return frames


def serialize_frames(frames: Iterable[Frame]) -> bytes:
    """Serialize HTTP/2 frame metadata and payloads into bytes."""
    return b"".join(
        build_frame(frame_type, flags, stream_id, payload)
        for frame_type, flags, stream_id, payload in frames
    )


def parse_http2_frames(data: bytes) -> Dict[int, str]:
    """Parse HTTP/2 frames and track stream state."""
    offset = 0
    stream_states: Dict[int, str] = {}
    data_length = len(data)

    while offset < data_length:
        if offset + 9 > data_length:
            raise ValueError("truncated HTTP/2 frame header")

        length = int.from_bytes(data[offset : offset + 3], "big")
        frame_type = data[offset + 3]
        flags = data[offset + 4]
        stream_id = struct.unpack("!I", data[offset + 5 : offset + 9])[0] & 0x7FFFFFFF
        offset += 9

        payload_end = offset + length
        if payload_end > data_length:
            raise ValueError("truncated HTTP/2 frame payload")

        payload = data[offset:payload_end]
        offset = payload_end

        dissect_http2_frame(frame_type, payload)

        if stream_id:
            if frame_type in (FRAME_HEADERS, FRAME_DATA):
                stream_states[stream_id] = STREAM_OPEN
            if flags & FLAG_END_STREAM:
                stream_states[stream_id] = STREAM_CLOSED
            if frame_type == FRAME_RST_STREAM:
                stream_states[stream_id] = STREAM_CLOSED

        if frame_type == FRAME_GOAWAY:
            for tracked_stream_id in list(stream_states):
                stream_states[tracked_stream_id] = STREAM_CLOSED

    return stream_states
