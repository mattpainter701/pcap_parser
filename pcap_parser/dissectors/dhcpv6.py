from __future__ import annotations

from typing import Any

MESSAGE_TYPES: dict[int, str] = {
    1: "SOLICIT",
    2: "ADVERTISE",
    3: "REQUEST",
    4: "CONFIRM",
    5: "RENEW",
    6: "REBIND",
    7: "REPLY",
    8: "RELEASE",
    9: "DECLINE",
    10: "RECONFIGURE",
    11: "INFORMATION-REQUEST",
    12: "RELAY-FORW",
    13: "RELAY-REPL",
    14: "LEASEQUERY",
    15: "LEASEQUERY-REPLY",
    16: "DHCPV4-QUERY",
    17: "DHCPV4-RESPONSE",
    18: "ACTIVELEASEQUERY",
    19: "LEASEQUERY-DONE",
    20: "LEASEQUERY-DATA",
}

OPTION_NAMES: dict[int, str] = {
    1: "CLIENT_IDENTIFIER",
    2: "SERVER_IDENTIFIER",
    3: "IA_NA",
    5: "IA_TA",
    6: "OPTION_REQUEST",
    7: "PREFERENCE",
    8: "ELAPSED_TIME",
    11: "AUTHENTICATION",
    12: "SERVER_UNICAST",
    14: "REBIND_ACCEPT",
    17: "VENDOR_CLASS",
    24: "DOMAIN_SEARCH_LIST",
    39: "CLIENT_FQDN",
    43: "VENDOR_SPECIFIC_INFORMATION",
}

__all__ = ["MESSAGE_TYPES", "OPTION_NAMES", "dissect_dhcpv6", "parse_dhcpv6_options"]


def parse_dhcpv6_options(data: bytes) -> list[dict[str, Any]]:
    """Parse DHCPv6 TLV options from the provided bytes.

    Truncated trailing data is ignored rather than raising an exception.
    """
    payload = bytes(data)
    options: list[dict[str, Any]] = []
    offset = 0

    while offset + 4 <= len(payload):
        option_type = int.from_bytes(payload[offset : offset + 2], "big")
        option_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4

        end = offset + option_length
        if end > len(payload):
            break

        options.append(
            {
                "type": option_type,
                "length": option_length,
                "data": payload[offset:end],
            }
        )
        offset = end

    return options


def dissect_dhcpv6(payload: bytes) -> dict[str, Any]:
    """Dissect a DHCPv6 message into its header fields and options."""
    result: dict[str, Any] = {
        "message_type": None,
        "transaction_id": None,
        "options": [],
    }

    if len(payload) < 4:
        return result

    message_type_code = payload[0]
    result["message_type"] = MESSAGE_TYPES.get(message_type_code, message_type_code)
    result["transaction_id"] = int.from_bytes(payload[1:4], "big")
    result["options"] = parse_dhcpv6_options(payload[4:])

    return result
