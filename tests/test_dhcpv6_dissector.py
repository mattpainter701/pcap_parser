from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "pcap_parser" / "dissectors" / "dhcpv6.py"


@pytest.fixture(scope="module")
def dhcpv6_module():
    spec = importlib.util.spec_from_file_location("test_dhcpv6_module", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def build_dhcpv6_message():
    def _build(message_type: int, transaction_id: int, options: list[tuple[int, bytes]] | None = None) -> bytes:
        payload = bytes([message_type]) + transaction_id.to_bytes(3, "big")
        for code, value in options or []:
            payload += code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
        return payload

    return _build


@pytest.fixture
def build_malformed_option_packet():
    def _build(
        message_type: int,
        transaction_id: int,
        option_code: int,
        declared_length: int,
        actual_value: bytes,
        prefix_options: list[tuple[int, bytes]] | None = None,
    ) -> bytes:
        payload = bytes([message_type]) + transaction_id.to_bytes(3, "big")
        for code, value in prefix_options or []:
            payload += code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
        payload += option_code.to_bytes(2, "big") + declared_length.to_bytes(2, "big") + actual_value
        return payload

    return _build


def test_dissect_dhcpv6_truncated_header(dhcpv6_module):
    result = dhcpv6_module.dissect_dhcpv6(b"\x01\x02\x03")

    assert result == {
        "protocol": "DHCPv6",
        "message_type": None,
        "transaction_id": None,
        "options": [],
        "error": "truncated DHCPv6 header",
    }


def test_dissect_dhcpv6_invalid_option_length(dhcpv6_module, build_malformed_option_packet):
    payload = build_malformed_option_packet(
        message_type=1,
        transaction_id=0x010203,
        option_code=23,
        declared_length=8,
        actual_value=b"abcd",
    )

    result = dhcpv6_module.dissect_dhcpv6(payload)

    assert result["protocol"] == "DHCPv6"
    assert result["message_type"] == "SOLICIT"
    assert result["transaction_id"] == 0x010203
    assert result["options"] == []
    assert result["error"] == "truncated DHCPv6 option value"


def test_dissect_dhcpv6_unknown_option_type(dhcpv6_module, build_dhcpv6_message):
    payload = build_dhcpv6_message(2, 0xA1B2C3, [(65000, b"xyz")])

    result = dhcpv6_module.dissect_dhcpv6(payload)

    assert result["message_type"] == "ADVERTISE"
    assert result["transaction_id"] == 0xA1B2C3
    assert result["options"] == [
        {
            "code": 65000,
            "length": 3,
            "value": b"xyz",
        }
    ]


def test_dissect_dhcpv6_duplicate_options_preserved_in_order(dhcpv6_module, build_dhcpv6_message):
    payload = build_dhcpv6_message(
        3,
        0x0A0B0C,
        [
            (13, b"first"),
            (13, b"second"),
        ],
    )

    result = dhcpv6_module.dissect_dhcpv6(payload)

    assert result["message_type"] == "REQUEST"
    assert result["options"] == [
        {
            "code": 13,
            "length": 5,
            "value": b"first",
        },
        {
            "code": 13,
            "length": 6,
            "value": b"second",
        },
    ]


def test_dissect_dhcpv6_message_with_no_options(dhcpv6_module, build_dhcpv6_message):
    payload = build_dhcpv6_message(7, 0x112233)

    result = dhcpv6_module.dissect_dhcpv6(payload)

    assert result == {
        "protocol": "DHCPv6",
        "message_type": "REPLY",
        "transaction_id": 0x112233,
        "options": [],
    }


def test_dissect_dhcpv6_maximum_length_option(dhcpv6_module):
    value = b"x" * 65535
    payload = bytes([1]) + (0x010203).to_bytes(3, "big")
    payload += (1).to_bytes(2, "big") + len(value).to_bytes(2, "big") + value

    result = dhcpv6_module.dissect_dhcpv6(payload)

    assert result["message_type"] == "SOLICIT"
    assert result["transaction_id"] == 0x010203
    assert "error" not in result
    assert result["options"] == [
        {
            "code": 1,
            "length": 65535,
            "value": value,
        }
    ]
