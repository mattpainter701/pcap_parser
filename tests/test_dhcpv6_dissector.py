from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "pcap_parser" / "dissectors" / "dhcpv6.py"


def load_dhcpv6_module():
    spec = importlib.util.spec_from_file_location("test_dhcpv6_module", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_dhcpv6_message(
    message_type: int,
    transaction_id: int,
    options: list[tuple[int, bytes]] | None = None,
) -> bytes:
    payload = bytes([message_type]) + transaction_id.to_bytes(3, "big")
    for option_type, value in options or []:
        payload += option_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
    return payload


@pytest.fixture(scope="module")
def dhcpv6():
    return load_dhcpv6_module()


def test_dissect_dhcpv6_truncated_header_returns_empty_fields(dhcpv6):
    result = dhcpv6.dissect_dhcpv6(b"\x01\x02\x03")

    assert result == {
        "message_type": None,
        "transaction_id": None,
        "options": [],
    }


def test_dissect_dhcpv6_unknown_option_type(dhcpv6):
    payload = build_dhcpv6_message(2, 0xA1B2C3, [(65000, b"xyz")])

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": "ADVERTISE",
        "transaction_id": 0xA1B2C3,
        "options": [
            {"type": 65000, "length": 3, "data": b"xyz"},
        ],
    }


def test_dissect_dhcpv6_duplicate_options_preserved_in_order(dhcpv6):
    payload = build_dhcpv6_message(
        3,
        0x0A0B0C,
        [
            (13, b"first"),
            (13, b"second"),
        ],
    )

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": "REQUEST",
        "transaction_id": 0x0A0B0C,
        "options": [
            {"type": 13, "length": 5, "data": b"first"},
            {"type": 13, "length": 6, "data": b"second"},
        ],
    }


def test_dissect_dhcpv6_message_with_no_options(dhcpv6):
    payload = build_dhcpv6_message(7, 0x112233)

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": "REPLY",
        "transaction_id": 0x112233,
        "options": [],
    }


def test_parse_dhcpv6_options_truncated_value_is_ignored(dhcpv6):
    payload = build_dhcpv6_message(1, 0x010203, [(1, b"abc")])
    payload += (2).to_bytes(2, "big") + (8).to_bytes(2, "big") + b"abcd"

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": "SOLICIT",
        "transaction_id": 0x010203,
        "options": [
            {"type": 1, "length": 3, "data": b"abc"},
        ],
    }


def test_dissect_dhcpv6_maximum_length_option(dhcpv6):
    value = b"x" * 65535
    payload = bytes([1]) + (0x010203).to_bytes(3, "big")
    payload += (1).to_bytes(2, "big") + len(value).to_bytes(2, "big") + value

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": "SOLICIT",
        "transaction_id": 0x010203,
        "options": [
            {"type": 1, "length": 65535, "data": value},
        ],
    }
