"""DNS over TCP framing helpers.

This module exposes both a lightweight framer that returns the raw DNS wire
message bytes and a legacy compatibility dissector that further decodes the
DNS payload for existing callers.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_DNS_DISSECTOR = None


def _load_dns_dissector():
    global _DNS_DISSECTOR
    if _DNS_DISSECTOR is not None:
        return _DNS_DISSECTOR

    dns_path = Path(__file__).with_name("dns.py")
    spec = importlib.util.spec_from_file_location("pcap_parser_dissectors_dns", dns_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load DNS dissector from {dns_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _DNS_DISSECTOR = module.dissect_dns
    return _DNS_DISSECTOR


def dissect_dns_over_tcp(payload: bytes) -> dict[str, Any]:
    """Return the length-prefixed DNS message bytes from a TCP payload."""
    result: dict[str, Any] = {
        "length_prefix": None,
        "dns_message": b"",
    }

    if len(payload) < 2:
        result["error"] = "truncated DNS TCP length prefix"
        if payload:
            result["remaining_data"] = payload
        return result

    length_prefix = int.from_bytes(payload[:2], "big")
    dns_end = 2 + length_prefix
    dns_message = payload[2:min(len(payload), dns_end)]

    result["length_prefix"] = length_prefix
    result["dns_message"] = dns_message

    if len(payload) > dns_end:
        result["remaining_data"] = payload[dns_end:]

    if len(payload) < dns_end:
        result["error"] = "truncated DNS TCP payload"

    return result


def dissect_dns_tcp(payload: bytes) -> dict[str, Any]:
    """Dissect a DNS-over-TCP payload and decode the DNS message."""
    result: dict[str, Any] = {
        "protocol": "DNS_TCP",
        "length": None,
        "length_prefix": None,
        "dns_message": None,
        "dns": None,
        "raw_payload": b"",
    }

    framed = dissect_dns_over_tcp(payload)
    error = framed.get("error")
    if error == "truncated DNS TCP length prefix":
        result["error"] = error
        return result

    length = framed["length_prefix"]
    dns_payload = framed["dns_message"]
    if not isinstance(length, int):
        result["error"] = "truncated DNS TCP length prefix"
        return result

    packet_info: dict[str, Any] = {
        "transport": "TCP",
        "length_prefix": length,
        "payload_length": len(dns_payload),
        "truncated": len(dns_payload) < length,
        "framed_protocol": "DNS",
    }

    dns_dissector = _load_dns_dissector()
    dns_message = dns_dissector(dns_payload, packet_info)

    result["length"] = length
    result["length_prefix"] = length
    result["raw_payload"] = dns_payload
    result["dns_message"] = dns_message
    result["dns"] = dns_message

    if length == 0:
        result["error"] = "zero-length DNS message"
    elif len(dns_payload) < length and "error" not in dns_message:
        result["error"] = "truncated DNS TCP payload"

    if error == "truncated DNS TCP payload" and "error" not in result:
        result["error"] = error

    return result


__all__ = ["dissect_dns_over_tcp", "dissect_dns_tcp"]
