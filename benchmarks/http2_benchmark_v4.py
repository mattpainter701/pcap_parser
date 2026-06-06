#!/usr/bin/env python3
"""HTTP/2 frame parser benchmark for all 10 frame types with stream state tracking.

Measures throughput (frames/sec) for 10,000 frames of mixed HTTP/2 frames.
Supports a ``--progress`` flag to show a progress bar during parsing.
"""

from __future__ import annotations

import argparse
import random
import struct
import sys
import time
from typing import Dict, List, Tuple

# Try to import tqdm for progress bar; if unavailable we simply won't show one.
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# Use the existing parse_http2_frame function from the pcap_parser package.
from pcap_parser import parse_http2_frame


# ---------- HTTP/2 constants ----------
FRAME_TYPES = {
    "DATA": 0x0,
    "HEADERS": 0x1,
    "PRIORITY": 0x2,
    "RST_STREAM": 0x3,
    "SETTINGS": 0x4,
    "PUSH_PROMISE": 0x5,
    "PING": 0x6,
    "GOAWAY": 0x7,
    "WINDOW_UPDATE": 0x8,
    "CONTINUATION": 0x9,
}

# Flags
END_STREAM = 0x1
END_HEADERS = 0x4

# Stream states for our tracking machine
STREAM_IDLE = 0
STREAM_OPEN = 1
STREAM_HALF_CLOSED = 2  # we only model local closure for simplicity
STREAM_CLOSED = 3


# ---------- Helpers ----------
def make_frame_header(length: int, frame_type: int, flags: int, stream_id: int) -> bytes:
    """Build the 9‑byte HTTP/2 frame header (length, type, flags, stream id)."""
    # The stream ID is 31 bits; the most significant bit is reserved and must be 0.
    return struct.pack("!IBBB", length, frame_type, flags,
                       stream_id & 0x7FFFFFFF)


def generate_frames(num_frames: int) -> List[bytes]:
    """Generate a list of *num_frames* HTTP/2 frames as wire byte strings.

    The sequence respects a simplified HTTP/2 stream state machine so that
    frames are semantically valid for the purpose of benchmarking.
    """
    frames: List[bytes] = []
    # Stream states: stream_id -> state
    stream_states: Dict[int, int] = {}
    # Track HEADERS frames that haven't ended the header block (for CONTINUATION)
    pending_continuation: Dict[int, bool] = {}
    # Set of all stream ids that have ever been used (to generate unique new ids)
    used_streams: set = set()

    # Cache of random payloads for DATA frames
    data_payloads = [
        bytes(random.randint(0, 255) for _ in range(random.randint(0, 256)))
        for _ in range(num_frames)
    ]

    def get_state(sid: int) -> int:
        """Return the state of a stream (connection stream 0 is always open)."""
        if sid == 0:
            return STREAM_OPEN
        return stream_states.get(sid, STREAM_IDLE)

    def set_state(sid: int, state: int) -> None:
        if sid != 0:
            stream_states[sid] = state

    def pick_open_stream() -> int:
        """Pick a random open stream (excluding connection). Returns 0 if none."""
        open_sids = [sid for sid, st in stream_states.items()
                     if st == STREAM_OPEN]
        return random.choice(open_sids) if open_sids else 0

    def new_client_stream_id() -> int:
        """Return a new odd stream id that hasn't been used before."""
        sid = 1
        while sid in used_streams:
            sid += 2
        used_streams.add(sid)
        return sid

    for i in range(num_frames):
        # Decide frame type based on current state
        # Build a weighted candidate list
        candidates: List[Tuple[str, int]] = [
            ("DATA", 20),
            ("HEADERS", 15),
            ("PRIORITY", 10),
            ("RST_STREAM", 5),
            ("SETTINGS", 12),
            ("PUSH_PROMISE", 3),
            ("PING", 8),
            ("GOAWAY", 2),
            ("WINDOW_UPDATE", 10),
            ("CONTINUATION", 5),
        ]

        # Remove CONTINUATION if nothing is pending
        if not pending_continuation:
            candidates = [c for c in candidates if c[0] != "CONTINUATION"]

        # Remove frame types that need an open stream when none exists
        has_open = pick_open_stream() != 0
        needs_open = {"DATA", "HEADERS", "RST_STREAM", "PUSH_PROMISE"}
        if not has_open:
            candidates = [c for c in candidates if c[0] not in needs_open]

        # Weighted random selection
        total = sum(w for _, w in candidates)
        r = random.randint(1, total)
        cumulative = 0
        chosen_type = "SETTINGS"
        for tname, w in candidates:
            cumulative += w
            if r <= cumulative:
                chosen_type = tname
                break

        # Determine stream id and flags/payload
        stream_id = 0
        payload = b""
        flags = 0

        if chosen_type == "DATA":
            stream_id = pick_open_stream()
            payload = data_payloads[i % len(data_payloads)]
            if random.random() < 0.1:
                flags |= END_STREAM
                set_state(stream_id, STREAM_HALF_CLOSED)

        elif chosen_type == "HEADERS":
            if random.random() < 0.3 or not has_open:
                # Open a new client stream
                stream_id = new_client_stream_id()
            else:
                stream_id = pick_open_stream()

            # Empty header block fragment is fine for benchmarking
            flags |= END_HEADERS
            if random.random() < 0.1:
                flags |= END_STREAM
                set_state(stream_id, STREAM_HALF_CLOSED)
            else:
                # If we don't end headers, mark for future CONTINUATION
                if random.random() < 0.3:
                    flags &= ~END_HEADERS
                    pending_continuation[stream_id] = True

            if get_state(stream_id) == STREAM_IDLE:
                set_state(stream_id, STREAM_OPEN)

        elif chosen_type == "CONTINUATION":
            stream_id = next(iter(pending_continuation))
            del pending_continuation[stream_id]
            flags |= END_HEADERS

        elif chosen_type == "PRIORITY":
            stream_id = random.randrange(0, 0x7FFFFFFF)
            dep = random.randint(0, 0x7FFFFFFE)
            exclusive = random.randint(0, 1)
            weight = random.randint(1, 256)
            payload = struct.pack("!I", (exclusive << 31) | dep) + bytes([weight])

        elif chosen_type == "RST_STREAM":
            stream_id = pick_open_stream()
            payload = struct.pack("!I", random.randint(0, 11))
            set_state(stream_id, STREAM_CLOSED)

        elif chosen_type == "SETTINGS":
            stream_id = 0
            if random.random() < 0.5:
                flags |= 0x01  # ACK
            payload = b""  # empty settings

        elif chosen_type == "PUSH_PROMISE":
            stream_id = pick_open_stream()
            promised = random.randrange(2, 0x7FFFFFFF, 2)
