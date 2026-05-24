from __future__ import annotations

from typing import Any


MESSAGE_TYPES = {
    1: "SOLICIT",
    2: "ADVERTISE",
    3: "REQUEST",
    7: "REPLY",
}


def dissect_dhcpv6(payload: bytes) -> dict[str, Any]:
    """Dissect a DHCPv6 message and its options."""
    result: dict[str, Any] = {
        "protocol": "DHCPv6",
        "message_type": None,
        "transaction_id": None,
        "options": [],
    }

    if len(payload) < 4:
        result["error"] = "truncated DHCPv6 header"
        return result

    message_type_code = payload[0]
    transaction_id = int.from_bytes(payload[1:4], "big")

    result["message_type"] = MESSAGE_TYPES.get(message_type_code, message_type_code)
    result["transaction_id"] = transaction_id

    options: list[dict[str, Any]] = []
    offset = 4
    while offset < len(payload):
        if len(payload) - offset < 4:
            result["error"] = "truncated DHCPv6 option header"
            result["options"] = options
            return result

        option_code = int.from_bytes(payload[offset : offset + 2], "big")
        option_length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4

        if len(payload) - offset < option_length:
            result["error"] = "truncated DHCPv6 option value"
            result["options"] = options
            return result

        option_value = payload[offset : offset + option_length]
        options.append(
            {
                "code": option_code,
                "length": option_length,
                "value": option_value,
            }
        )
        offset += option_length

    result["options"] = options
    return result
