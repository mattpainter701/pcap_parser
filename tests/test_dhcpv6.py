from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "pcap_parser" / "dissectors" / "dhcpv6.py"


def load_dhcpv6_module():
    spec = importlib.util.spec_from_file_location("test_dhcpv6_module", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_dhcpv6_message(message_type: int, transaction_id: int, options: list[tuple[int, bytes]] | None = None) -> bytes:
    payload = bytes([message_type]) + transaction_id.to_bytes(3, "big")
    for code, value in options or []:
        payload += code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value
    return payload


def test_dissect_dhcpv6_valid_solicit_with_option():
    dhcpv6 = load_dhcpv6_module()
    payload = build_dhcpv6_message(1, 0x010203, [(1, b"abc")])

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["protocol"] == "DHCPv6"
    assert result["message_type"] == "SOLICIT"
    assert result["transaction_id"] == 0x010203
    assert result["options"] == [
        {
            "code": 1,
            "length": 3,
            "value": b"abc",
        }
    ]


def test_dissect_dhcpv6_valid_reply():
    dhcpv6 = load_dhcpv6_module()
    payload = build_dhcpv6_message(7, 0xA1B2C3)

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["protocol"] == "DHCPv6"
    assert result["message_type"] == "REPLY"
    assert result["transaction_id"] == 0xA1B2C3
    assert result["options"] == []


def test_dissect_dhcpv6_truncated_payload():
    dhcpv6 = load_dhcpv6_module()
    payload = b"\x01\x02\x03"

    result = dhcpv6.dissect_dhcpv6(payload)

    assert result["protocol"] == "DHCPv6"
    assert result["message_type"] is None
    assert result["transaction_id"] is None
    assert result["options"] == []
    assert result["error"] == "truncated DHCPv6 header"
