"""HTTP/2 frame dissectors."""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional


def parse_http2_priority_frame(payload: bytes) -> Dict[str, Any]:
    """Parse an HTTP/2 PRIORITY frame (type 0x2).

    Args:
        payload: Exactly 5 bytes (4 bytes stream dependency + 1 byte weight).

    Returns:
        dict with keys 'exclusive', 'stream_dependency', and 'weight'.

    Raises:
        ValueError: If payload length is not 5.
    """
    if len(payload) != 5:
        raise ValueError(
            f"PRIORITY frame payload must be exactly 5 bytes, got {len(payload)}"
        )

    # First 4 bytes: 1-bit exclusive flag + 31-bit stream dependency (big-endian)
    raw_dependency = struct.unpack("!I", payload[:4])[0]
    exclusive = bool(raw_dependency >> 31)
    stream_dependency = raw_dependency & 0x7FFFFFFF

    # 5th byte: weight (1 byte, unsigned)
    weight = payload[4]

    return {
        "exclusive": exclusive,
        "stream_dependency": stream_dependency,
        "weight": weight,
    }


def dissect_http2_frame(frame_type: int, payload: bytes) -> Optional[Dict[str, Any]]:
    """Dispatch an HTTP/2 frame to the appropriate sub‑dissector.

    Args:
        frame_type: HTTP/2 frame type identifier.
        payload: Raw frame payload (length determined by frame type).

    Returns:
        Parsed result as a dict, or None if the frame type is not supported.
    """
    if frame_type == 0x2:
        return parse_http2_priority_frame(payload)

    # Other frame types can be added later.
    return None
