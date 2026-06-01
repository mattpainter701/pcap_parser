"""Benchmark HTTP/2 frame parsing performance."""

from __future__ import annotations

import struct
import time

from dissectors.http2 import dissect_http2_frame


FRAME_COUNT = 10_000
MAX_PARSE_SECONDS = 2.0
HTTP2_FRAME_HEADER_LENGTH = 9


def _http2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a single HTTP/2 frame."""
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def _data_frame(stream_id: int) -> bytes:
    """Build a DATA frame."""
    return _http2_frame(0x00, 0x01, stream_id, b"hello-http2-payload")


def _headers_frame(stream_id: int) -> bytes:
    """Build a minimal HEADERS frame with HPACK indexed header fields."""
    return _http2_frame(0x01, 0x05, stream_id, b"\x82\x84\x87")


def _priority_frame(stream_id: int) -> bytes:
    """Build a PRIORITY frame."""
    return _http2_frame(0x02, 0x00, stream_id, struct.pack("!IB", 0, 16))


def _rst_stream_frame(stream_id: int) -> bytes:
    """Build an RST_STREAM frame with CANCEL."""
    return _http2_frame(0x03, 0x00, stream_id, struct.pack("!I", 0x08))


def _settings_frame() -> bytes:
    """Build a SETTINGS frame."""
    payload = struct.pack("!HIHI", 0x01, 4096, 0x03, 100)
    return _http2_frame(0x04, 0x00, 0, payload)


def _push_promise_frame(stream_id: int) -> bytes:
    """Build a PUSH_PROMISE frame."""
    promised_stream_id = (stream_id + 1) & 0x7FFFFFFF
    payload = promised_stream_id.to_bytes(4, "big") + b"\x82\x84"
    return _http2_frame(0x05, 0x04, stream_id, payload)


def _ping_frame(index: int) -> bytes:
    """Build a PING frame."""
    return _http2_frame(0x06, 0x00, 0, index.to_bytes(8, "big"))


def _goaway_frame(last_stream_id: int) -> bytes:
    """Build a GOAWAY frame with NO_ERROR."""
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") + struct.pack("!I", 0)
    return _http2_frame(0x07, 0x00, 0, payload)


def _window_update_frame(stream_id: int) -> bytes:
    """Build a WINDOW_UPDATE frame."""
    return _http2_frame(0x08, 0x00, stream_id, struct.pack("!I", 65535))


def _continuation_frame(stream_id: int) -> bytes:
    """Build a CONTINUATION frame."""
    return _http2_frame(0x09, 0x04, stream_id, b"\x84\x87")


def _mixed_http2_buffer(frame_count: int = FRAME_COUNT) -> bytes:
    """Create a deterministic byte buffer with all common HTTP/2 frame types."""
    builders = (
        lambda index: _data_frame(index + 1),
        lambda index: _headers_frame(index + 1),
        lambda index: _priority_frame(index + 1),
        lambda index: _rst_stream_frame(index + 1),
        lambda index: _settings_frame(),
        lambda index: _push_promise_frame(index + 1),
        lambda index: _ping_frame(index),
        lambda index: _goaway_frame(index + 1),
        lambda index: _window_update_frame(index + 1),
        lambda index: _continuation_frame(index + 1),
    )
    return b"".join(builders[index % len(builders)](index) for index in range(frame_count))


def _parse_http2_frames(buffer: bytes) -> int:
    """Parse concatenated HTTP/2 frames through the dispatch function."""
    offset = 0
    parsed = 0
    while offset < len(buffer):
        header = buffer[offset : offset + HTTP2_FRAME_HEADER_LENGTH]
        assert len(header) == HTTP2_FRAME_HEADER_LENGTH

        length = int.from_bytes(header[:3], "big")
        frame_type = header[3]
        payload_start = offset + HTTP2_FRAME_HEADER_LENGTH
        payload_end = payload_start + length
        payload = buffer[payload_start:payload_end]
        assert len(payload) == length

        dissect_http2_frame(frame_type, payload)
        parsed += 1
        offset = payload_end

    return parsed


def test_http2_parse_benchmark() -> None:
    """Benchmark dispatch parsing of 10k mixed synthetic HTTP/2 frames."""
    buffer = _mixed_http2_buffer()

    start = time.perf_counter()
    parsed = _parse_http2_frames(buffer)
    elapsed = time.perf_counter() - start

    frames_per_second = parsed / elapsed if elapsed > 0 else float("inf")
    print(
        f"Parsed {parsed} mixed HTTP/2 frames in {elapsed:.6f}s "
        f"({frames_per_second:.2f} frames/s)"
    )

    assert parsed == FRAME_COUNT
    assert elapsed < MAX_PARSE_SECONDS
