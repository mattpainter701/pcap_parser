"""Tests for HTTP/2 frame dissectors."""

from __future__ import annotations

import pytest

from dissectors.http2 import (
    dissect_http2_frame,
    parse_http2_priority_frame,
)


class TestParseHttp2PriorityFrame:
    """Tests for parse_http2_priority_frame."""

    def test_valid_priority_frame(self) -> None:
        """A valid 5-byte payload produces correct fields."""
        # Construct a payload:
        #   exclusive = 1, stream_dependency = 0x12345678
        #   weight = 200
        raw_dependency = (1 << 31) | 0x12345678
        payload = raw_dependency.to_bytes(4, byteorder="big") + bytes([200])

        result = parse_http2_priority_frame(payload)
        assert result["exclusive"] is True
        assert result["stream_dependency"] == 0x12345678
        assert result["weight"] == 200

    def test_exclusive_false(self) -> None:
        """Flags with exclusive=0 are parsed correctly."""
        raw_dependency = 0x0FFFFFFF  # exclusive = 0, stream = 0x0FFFFFFF
        payload = raw_dependency.to_bytes(4, byteorder="big") + bytes([100])

        result = parse_http2_priority_frame(payload)
        assert result["exclusive"] is False
        assert result["stream_dependency"] == 0x0FFFFFFF
        assert result["weight"] == 100

    def test_invalid_payload_length_raises_valueerror(self) -> None:
        """Payload length != 5 raises ValueError."""
        with pytest.raises(ValueError, match="exactly 5 bytes"):
            parse_http2_priority_frame(b"\x00\x00\x00\x01")  # 4 bytes

        with pytest.raises(ValueError, match="exactly 5 bytes"):
            parse_http2_priority_frame(b"\x00\x00\x00\x00\x00\x00")  # 6 bytes


class TestDissectHttp2Frame:
    """Tests for dissect_http2_frame dispatching."""

    def test_priority_frame_dispatched(self) -> None:
        """Frame type 0x2 calls parse_http2_priority_frame."""
        raw_dependency = (0 << 31) | 42
        payload = raw_dependency.to_bytes(4, byteorder="big") + bytes([10])

        result = dissect_http2_frame(0x2, payload)
        assert result is not None
        assert result["stream_dependency"] == 42
        assert result["exclusive"] is False
        assert result["weight"] == 10

    def test_unsupported_frame_returns_none(self) -> None:
        """Unknown frame type returns None."""
        assert dissect_http2_frame(0xFF, b"") is None
        assert dissect_http2_frame(0x0, b"") is None
