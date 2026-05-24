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


@pytest.mark.parametrize(
    ("message_type", "expected_name"),
    [
        (1, "SOLICIT"),
        (2, "ADVERTISE"),
        (3, "REQUEST"),
        (4, "CONFIRM"),
        (5, "RENEW"),
        (6, "REBIND"),
        (7, "REPLY"),
        (8, "RELEASE"),
        (9, "DECLINE"),
        (10, "RECONFIGURE"),
        (11, "INFORMATION-REQUEST"),
        (12, "RELAY-FORW"),
        (13, "RELAY-REPL"),
        (14, "LEASEQUERY"),
        (15, "LEASEQUERY-REPLY"),
        (16, "DHCPV4-QUERY"),
        (17, "DHCPV4-RESPONSE"),
        (18, "ACTIVELEASEQUERY"),
        (19, "LEASEQUERY-DONE"),
        (20, "LEASEQUERY-DATA"),
    ],
)
def test_dissect_dhcpv6_decodes_all_known_message_types(dhcpv6, message_type, expected_name):
    payload = build_dhcpv6_message(message_type, 0x010203)

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": expected_name,
        "transaction_id": 0x010203,
        "options": [],
    }


def test_dissect_dhcpv6_preserves_unknown_message_type_as_integer(dhcpv6):
    payload = build_dhcpv6_message(99, 0xA1B2C3)

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result == {
        "message_type": 99,
        "transaction_id": 0xA1B2C3,
        "options": [],
    }


def test_parse_dhcpv6_options_parses_common_option_types(dhcpv6):
    options = [
        (1, b"client-id"),
        (2, b"server-id"),
        (3, b"\x00\x00\x00\x01\x00\x00\x00\x02"),
        (5, b"\x12\x34\x56\x78"),
        (6, b"\x00\x17\x00\x18"),
        (7, b"\x64"),
        (8, b"\x00\x0a"),
        (11, b"\x01\x02\x03\x04"),
        (12, b"\x20\x01\r\xb8"),
        (14, b""),
        (17, b"vendor-class"),
        (24, b"\x07example\x03com\x00"),
        (39, b"\x00client"),
        (43, b"\x00\x01abc"),
    ]
    payload = build_dhcpv6_message(1, 0x010203, options)

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["message_type"] == "SOLICIT"
    assert result["transaction_id"] == 0x010203
    assert result["options"] == [
        {"type": 1, "length": 9, "data": b"client-id"},
        {"type": 2, "length": 9, "data": b"server-id"},
        {"type": 3, "length": 8, "data": b"\x00\x00\x00\x01\x00\x00\x00\x02"},
        {"type": 5, "length": 4, "data": b"\x12\x34\x56\x78"},
        {"type": 6, "length": 4, "data": b"\x00\x17\x00\x18"},
        {"type": 7, "length": 1, "data": b"\x64"},
        {"type": 8, "length": 2, "data": b"\x00\x0a"},
        {"type": 11, "length": 4, "data": b"\x01\x02\x03\x04"},
        {"type": 12, "length": 4, "data": b"\x20\x01\r\xb8"},
        {"type": 14, "length": 0, "data": b""},
        {"type": 17, "length": 12, "data": b"vendor-class"},
        {"type": 24, "length": 13, "data": b"\x07example\x03com\x00"},
        {"type": 39, "length": 7, "data": b"\x00client"},
        {"type": 43, "length": 5, "data": b"\x00\x01abc"},
    ]


def test_parse_dhcpv6_options_unknown_option_type_is_preserved(dhcpv6):
    payload = build_dhcpv6_message(2, 0xA1B2C3, [(65000, b"xyz")])

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["message_type"] == "ADVERTISE"
    assert result["transaction_id"] == 0xA1B2C3
    assert result["options"] == [
        {"type": 65000, "length": 3, "data": b"xyz"},
    ]


def test_parse_dhcpv6_options_truncated_option_header_is_ignored(dhcpv6):
    payload = build_dhcpv6_message(3, 0x0A0B0C) + b"\x00\x01\x00"

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["message_type"] == "REQUEST"
    assert result["transaction_id"] == 0x0A0B0C
    assert result["options"] == []


def test_parse_dhcpv6_options_truncated_option_value_is_ignored(dhcpv6):
    payload = build_dhcpv6_message(
        7,
        0x112233,
        [
            (1, b"ok"),
        ],
    )
    payload += (2).to_bytes(2, "big") + (8).to_bytes(2, "big") + b"abcd"

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["message_type"] == "REPLY"
    assert result["transaction_id"] == 0x112233
    assert result["options"] == [
        {"type": 1, "length": 2, "data": b"ok"},
    ]


def test_dissect_dhcpv6_truncated_header_returns_empty_fields(dhcpv6):
    result = dhcpv6.dissect_dhcpv6(b"\x01\x02\x03")

    assert result == {
        "message_type": None,
        "transaction_id": None,
        "options": [],
    }
