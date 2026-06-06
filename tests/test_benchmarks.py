"""Benchmark test for HTTP/2 mixed frame parsing."""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

pytest.importorskip("scapy")
from scapy.all import (
    Ether,
    IP,
    Raw,
    TCP,
    wrpcap,
)

from pcap_parser import parse_capture

# HTTP/2 connection preface (24 bytes)
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _build_http2_frame(
    frame_type: int, flags: int, stream_id: int, payload: bytes = b""
) -> bytes:
    """Construct an HTTP/2 frame (9‑byte header + payload).

    Args:
        frame_type: HTTP/2 frame type identifier (0–10).
        flags: Frame flags byte.
        stream_id: 31‑bit stream identifier (0 for connection‑level frames).
        payload: Frame payload bytes.

    Returns:
        Complete frame as a byte string.
    """
    length = len(payload)
    # Length is encoded as a 3‑byte big‑endian integer.
    length_bytes = struct.pack("!I", length)[1:4]
    header = (
        length_bytes
        + bytes([frame_type, flags])
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
    )
    return header + payload


def _build_priority_payload(
    exclusive: bool, stream_dependency: int, weight: int
) -> bytes:
    """Build a 5‑byte PRIORITY frame payload.

    Args:
        exclusive: Exclusive flag (1 bit).
        stream_dependency: Stream dependency (31 bits).
        weight: Weight (1 byte).

    Returns:
        5 bytes: 4‑byte dependency + 1‑byte weight.
    """
    raw = (1 << 31) if exclusive else 0
    raw |= stream_dependency & 0x7FFFFFFF
    return struct.pack("!I", raw) + bytes([weight])


@pytest.fixture
def http2_mixed_pcap(tmp_path: Path) -> Path:
    """Generate a synthetic pcap with 1000 HTTP/2 frames of mixed types."""

    # ------------------------------------------------------------------
    # 1. Generate 1000 HTTP/2 frames of nine different types.
    # ------------------------------------------------------------------
    frames: list[bytes] = []
    stream_id_counter = 1  # odd numbers for client‑initiated streams
    last_headers_stream: int | None = None

    for i in range(1000):
        type_idx = i % 9

        if type_idx == 0:
            # SETTINGS (type 4) – empty payload, stream 0
            frames.append(_build_http2_frame(4, 0, 0))
        elif type_idx == 1:
            # HEADERS (type 1) – dummy HPACK data, new stream
            stream_id = stream_id_counter
            stream_id_counter += 2
            # No END_HEADERS flag → CONTINUATION will follow
            frames.append(_build_http2_frame(1, 0x00, stream_id, b"\x40\x80"))
            last_headers_stream = stream_id
        elif type_idx == 2:
            # DATA (type 0) – small payload on the same stream
            if last_headers_stream is not None:
                frames.append(
                    _build_http2_frame(0, 0, last_headers_stream, b"hello")
                )
            else:
                frames.append(_build_http2_frame(0, 0, 0, b"\x00"))
        elif type_idx == 3:
            # PING (type 6) – 8‑byte payload, ACK flag
            frames.append(_build_http2_frame(6, 0x01, 0, b"\x00" * 8))
        elif type_idx == 4:
            # GOAWAY (type 7) – last‑stream‑id=0, error=NO_ERROR
            payload = struct.pack("!II", 0, 0)
            frames.append(_build_http2_frame(7, 0, 0, payload))
        elif type_idx == 5:
            # WINDOW_UPDATE (type 8) – 4‑byte increment
            payload = struct.pack("!I", 1)
            frames.append(_build_http2_frame(8, 0, 0, payload))
        elif type_idx == 6:
            # RST_STREAM (type 3) – cancel a new stream
            stream_id = stream_id_counter
            stream_id_counter += 2
            payload = struct.pack("!I", 8)  # CANCEL
            frames.append(_build_http2_frame(3, 0, stream_id, payload))
        elif type_idx == 7:
            # PRIORITY (type 2) – exclusive=0, dependency=0, weight=1
            payload = _build_priority_payload(False, 0, 1)
            frames.append(_build_http2_frame(2, 0, 0, payload))
        elif type_idx == 8:
            # CONTINUATION (type 9) – flags=END_HEADERS
            if last_headers_stream is not None:
                frames.append(
                    _build_http2_frame(9, 0x04, last_headers_stream, b"\x00")
                )
            else:
                frames.append(_build_http2_frame(9, 0x04, 1, b"\x00"))
            last_headers_stream = None  # stream now complete

    # ------------------------------------------------------------------
    # 2. Build TCP packets (handshake + data).
    # ------------------------------------------------------------------
    client_ip = "10.0.0.1"
    server_ip = "10.0.0.2"
    client_port = 12345
    server_port = 443

    seq = 1000
    ack = 2000

    # 2a. TCP three‑way handshake
    syn = (
        Ether()
        / IP(dst=server_ip, src=client_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=seq)
    )

    ack_seq = seq + 1
    syn_ack = (
        Ether()
        / IP(dst=client_ip, src=server_ip)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=ack, ack=ack_seq)
    )

    seq = ack_seq
    ack += 1
    ack_pkt = (
        Ether()
        / IP(dst=server_ip, src=client_ip)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=seq, ack=ack)
    )

    # 2b. Data packets: preface + frames
    all_data = [HTTP2_PREFACE] + frames
    data_packets = []
    for payload in all_data:
        pkt = (
            Ether()
            / IP(dst=server_ip, src=client_ip)
            / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq, ack=ack)
            / Raw(payload)
        )
        data_packets.append(pkt)
