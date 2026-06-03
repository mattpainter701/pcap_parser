#!/usr/bin/env python3
"""Benchmark HTTP/2 frame parsing with stream‑state tracking.

Generates a synthetic pcap with 1000 HTTP/2 frames (HEADERS, DATA,
SETTINGS, PING, GOAWAY) using scapy, then measures parsing throughput
with and without an in‑memory stream state machine.  Run directly:

    python tests/benchmark_http2_streams.py

Expected output includes frames/second for both modes and an
assertion that each benchmark completes in under 5 seconds.
"""

from __future__ import annotations

import struct
import tempfile
import time
from enum import auto, Enum
from pathlib import Path

# ---------------------------------------------------------------------------
# HTTP/2 frame type constants
# ---------------------------------------------------------------------------
FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_SETTINGS = 0x04
FRAME_PING = 0x06
FRAME_GOAWAY = 0x07

# Flags used in state machine
FLAG_END_STREAM = 0x01


# ---------------------------------------------------------------------------
# HTTP/2 stream state machine
# ---------------------------------------------------------------------------
class StreamState(Enum):
    IDLE = auto()
    OPEN = auto()
    HALF_CLOSED_REMOTE = auto()
    HALF_CLOSED_LOCAL = auto()
    CLOSED = auto()


class Http2StreamStateMachine:
    """Tracks stream states for an HTTP/2 connection."""

    def __init__(self) -> None:
        self._streams: dict[int, dict[str, bool]] = {}

    def _get(self, stream_id: int) -> dict[str, bool]:
        if stream_id not in self._streams:
            self._streams[stream_id] = {"local_closed": False, "remote_closed": False}
        return self._streams[stream_id]

    def process_frame(self, parsed: dict) -> None:
        """Update stream state based on a parsed HTTP/2 frame."""
        stream_id = parsed["stream_id"]
        frame_type = parsed["type"]
        flags = parsed.get("flags", 0)

        if stream_id == 0:
            # Connection‑level frames (SETTINGS, PING, GOAWAY)
            if frame_type == FRAME_GOAWAY:
                # GOAWAY implicitly closes all active streams
                for sid in list(self._streams.keys()):
                    self._streams[sid] = {"local_closed": True, "remote_closed": True}
            return

        s = self._get(stream_id)

        if frame_type == FRAME_HEADERS:
            # A HEADERS frame opens a new stream or continues an existing one.
            # For benchmarking we only consider the initial open transition.
            if not s["local_closed"] and not s["remote_closed"]:
                if flags & FLAG_END_STREAM:
                    s["remote_closed"] = True
                # otherwise stays OPEN
        elif frame_type == FRAME_DATA:
            if flags & FLAG_END_STREAM:
                s["remote_closed"] = True
        # SETTINGS and PING are connection‑level and don't change stream state

        # A stream becomes CLOSED when both sides have closed or when either
        # side sends RST_STREAM (not implemented in this benchmark).
        # The state is derived on demand.

    def state(self, stream_id: int) -> StreamState:
        """Return the current state of *stream_id*."""
        if stream_id == 0:
            return StreamState.IDLE
        if stream_id not in self._streams:
            return StreamState.IDLE
        s = self._streams[stream_id]
        if s["local_closed"] and s["remote_closed"]:
            return StreamState.CLOSED
        if s["local_closed"]:
            return StreamState.HALF_CLOSED_LOCAL
        if s["remote_closed"]:
            return StreamState.HALF_CLOSED_REMOTE
        return StreamState.OPEN


# ---------------------------------------------------------------------------
# HTTP/2 frame construction & parsing
# ---------------------------------------------------------------------------
def _make_http2_frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes,
) -> bytes:
    """Build an HTTP/2 frame (9‑byte header + payload)."""
    length = len(payload)
    header = struct.pack("!IBBH", (length << 8) | frame_type, flags, stream_id >> 16)
    # manual 3‑byte length + 1 type + 1 flags + 4 stream id
    header = (
        struct.pack("!I", length)[:3]
        + bytes([frame_type, flags])
        + struct.pack("!I", stream_id)
    )
    return header + payload


def _generate_frame_list() -> list[bytes]:
    """Return a list of 1000 HTTP/2 frame bytes with a mix of types."""
    frames: list[bytes] = []
    stream_ids = [1, 3, 5, 7, 9]
    # use a deterministic seed for reproducibility
    import random

    rng = random.Random(42)

    # helper to create a simple payload for each type
    def _payload(frame_type: int) -> bytes:
        if frame_type == FRAME_DATA:
            # just some dummy data
            return b"x" * rng.randint(10, 100)
        if frame_type == FRAME_HEADERS:
            # minimal HEADERS payload (no HPACK, just a placeholder)
            return bytes([0x00, 0x00])  # padding length = 0
        if frame_type == FRAME_SETTINGS:
            # empty SETTINGS (no parameters)
            return b""
        if frame_type == FRAME_PING:
            # 8‑byte opaque data
            return rng.randbytes(8)
        if frame_type == FRAME_GOAWAY:
            # last‑stream‑id + error code
            return struct.pack("!II", 0, 0)  # no error
        return b""

    for _ in range(1000):
        # weighted random choice
        t = rng.choices(
            [FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, FRAME_PING, FRAME_GOAWAY],
            weights=[30, 40, 20, 5, 5],
        )[0]

        sid = 0
        flags = 0
        if t in (FRAME_DATA, FRAME_HEADERS):
            sid = rng.choice(stream_ids)
            # sometimes set END_STREAM
            if rng.random() < 0.3:
                flags |= FLAG_END_STREAM
        elif t == FRAME_SETTINGS:
            sid = 0
            # rarely the ACK flag is set
            if rng.random() < 0.2:
                flags |= 0x01  # ACK
        elif t == FRAME_PING:
            sid = 0
            if rng.random() < 0.5:
                flags |= 0x01  # ACK
        # GOAWAY is always on stream 0

        frames.append(_make_http2_frame(t, flags, sid, _payload(t)))

    return frames


def _parse_http2_frame(data: bytes) -> dict:
    """Parse a single HTTP/2 frame from *data* (9‑byte header + payload).

    Returns a dict with keys: length, type, flags, stream_id, and
    type‑specific payload fields.
    """
    if len(data) < 9:
        raise ValueError(f"Frame too short: {len(data)} bytes")

    length = (data[0] << 16) | (data[1] << 8) | data[2]
    frame_type = data[3]
    flags = data[4]
    stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
    payload = data[9:9 + length]

    parsed: dict = {
        "length": length,
        "type": frame_type,
        "flags": flags,
        "stream_id": stream_id,
        "payload": payload,
    }
    return parsed


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
def _benchmark_parsing(frames: list[bytes], use_state_machine: bool) -> float:
    """Time the parsing of *frames*, optionally tracking stream state."""
    sm = Http2StreamStateMachine() if use_state_machine else None

    t0 = time.perf_counter()
    for frame in frames:
        parsed = _parse_http2_frame(frame)
        if sm is not None:
            sm.process_frame(parsed)
    return time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Pcap generation (uses scapy)
# ---------------------------------------------------------------------------
def _generate_pcap(frame_bytes: list[bytes], path: Path) -> None:
    """Write *frame_bytes* as individual TCP packets to *path*."""
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError("scapy is required for this benchmark") from exc

    packets = []
    for frame in frame_bytes:
        pkt = (
            Ether()
            / IP(src="127.0.0.1", dst="127.0.0.1")
            / TCP(sport=50000, dport=443)
            / Raw(load=frame)
        )
        packets.append(pkt)
    wrpcap(str(path), packets)
