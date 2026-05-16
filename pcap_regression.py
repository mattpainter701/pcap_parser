from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft7Validator

DEVICE_CSV_HEADERS = [
    "MAC Address",
    "Vendor",
    "IP Address",
    "TCP Ports",
    "UDP Ports",
    "First Seen",
    "Last Seen",
    "Packet Count",
]

CONVERSATION_CSV_HEADERS = [
    "Source IP",
    "Source MAC",
    "Source TCP Port",
    "Source UDP Port",
    "Target IP",
    "Target MAC",
    "Target TCP Port",
    "Target UDP Port",
    "Protocol",
    "Application Protocol",
    "Packets A->B",
    "Packets B->A",
    "Bytes A->B",
    "Bytes B->A",
    "First Seen",
    "Last Seen",
    "Duration (seconds)",
    "Conversation Status",
    "TCP Flags",
    "Stream ID",
    "Frame Protocols",
    "VLAN ID",
    "DiffServ Field",
    "IP Version",
]

NETWORK_JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["metadata", "nodes", "links"],
    "properties": {
        "metadata": {
            "type": "object",
            "additionalProperties": False,
            "required": ["generated_at", "pcap_file", "total_nodes", "total_links"],
            "properties": {
                "generated_at": {"type": "string"},
                "pcap_file": {"type": "string"},
                "total_nodes": {"type": "integer", "minimum": 0},
                "total_links": {"type": "integer", "minimum": 0},
            },
        },
        "nodes": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "id",
                    "label",
                    "vendor",
                    "ips",
                    "tcp_ports",
                    "udp_ports",
                    "packet_count",
                    "first_seen",
                    "last_seen",
                ],
                "properties": {
                    "id": {"type": "string"},
                    "label": {"type": "string"},
                    "vendor": {"type": "string"},
                    "ips": {"type": "array", "items": {"type": "string"}},
                    "tcp_ports": {"type": "array", "items": {"type": "integer", "minimum": 0}},
                    "udp_ports": {"type": "array", "items": {"type": "integer", "minimum": 0}},
                    "packet_count": {"type": "integer", "minimum": 0},
                    "first_seen": {"type": ["string", "null"]},
                    "last_seen": {"type": ["string", "null"]},
                },
            },
        },
        "links": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source",
                    "target",
                    "source_ip",
                    "target_ip",
                    "protocol",
                    "app_protocol",
                    "source_tcp_port",
                    "target_tcp_port",
                    "source_udp_port",
                    "target_udp_port",
                    "packets_a_to_b",
                    "packets_b_to_a",
                    "bytes_a_to_b",
                    "bytes_b_to_a",
                    "first_seen",
                    "last_seen",
                    "duration",
                    "conversation_status",
                    "tcp_flags",
                    "stream_id",
                    "frame_protocols",
                    "vlan_id",
                    "dsfield",
                    "ip_version",
                ],
                "properties": {
                    "source": {"type": ["string", "null"]},
                    "target": {"type": ["string", "null"]},
                    "source_ip": {"type": ["string", "null"]},
                    "target_ip": {"type": ["string", "null"]},
                    "protocol": {"type": ["string", "null"]},
                    "app_protocol": {"type": ["string", "null"]},
                    "source_tcp_port": {"type": ["integer", "null"], "minimum": 0},
                    "target_tcp_port": {"type": ["integer", "null"], "minimum": 0},
                    "source_udp_port": {"type": ["integer", "null"], "minimum": 0},
                    "target_udp_port": {"type": ["integer", "null"], "minimum": 0},
                    "packets_a_to_b": {"type": "integer", "minimum": 0},
                    "packets_b_to_a": {"type": "integer", "minimum": 0},
                    "bytes_a_to_b": {"type": "integer", "minimum": 0},
                    "bytes_b_to_a": {"type": "integer", "minimum": 0},
                    "first_seen": {"type": ["string", "null"]},
                    "last_seen": {"type": ["string", "null"]},
                    "duration": {"type": ["number", "null"]},
                    "conversation_status": {"type": "string"},
                    "tcp_flags": {"type": "array", "items": {"type": "string"}},
                    "stream_id": {"type": ["string", "integer", "null"]},
                    "frame_protocols": {"type": ["string", "null"]},
                    "vlan_id": {"type": ["string", "integer", "null"]},
                    "dsfield": {"type": ["string", "integer", "null"]},
                    "diffserv_label": {"type": ["string", "null"]},
                    "ip_version": {"type": ["integer", "null"], "enum": [4, 6, None]},
                },
            },
        },
    },
}

FIXTURE_MANIFEST_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "fixtures"],
    "properties": {
        "schema_version": {"type": "string"},
        "fixtures": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "pcap", "goldens"],
                "properties": {
                    "name": {"type": "string"},
                    "pcap": {"type": "string"},
                    "description": {"type": "string"},
                    "goldens": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "device_csv": {"type": "string"},
                            "conversation_csv": {"type": "string"},
                            "network_json": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
}


@dataclass(frozen=True)
class RegressionFixture:
    name: str
    pcap: Path
    goldens: dict[str, Path]
    description: str | None = None


class RegressionValidationError(ValueError):
    """Raised when a fixture or output fails regression validation."""


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_schema(schema: dict[str, Any], payload: Any, source: str) -> list[str]:
    validator = Draft7Validator(schema)
    errors = []
    for error in sorted(validator.iter_errors(payload), key=lambda e: e.path):
        location = ".".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{source}: {location}: {error.message}")
    return errors


def load_regression_manifest(manifest_path: str | Path) -> list[RegressionFixture]:
    path = Path(manifest_path)
    manifest = _load_json(path)
    errors = _validate_schema(FIXTURE_MANIFEST_SCHEMA, manifest, str(path))
    if errors:
        raise RegressionValidationError("\n".join(errors))

    fixtures: list[RegressionFixture] = []
    for fixture in manifest["fixtures"]:
        goldens = {
            name: (path.parent / relative_path).resolve()
            for name, relative_path in fixture["goldens"].items()
        }
        fixtures.append(
            RegressionFixture(
                name=fixture["name"],
                pcap=(path.parent / fixture["pcap"]).resolve(),
                goldens=goldens,
                description=fixture.get("description"),
            )
        )
    return fixtures


def validate_device_csv(path: str | Path) -> list[str]:
    return _validate_csv_contract(Path(path), DEVICE_CSV_HEADERS, kind="device")


def validate_conversation_csv(path: str | Path) -> list[str]:
    return _validate_csv_contract(Path(path), CONVERSATION_CSV_HEADERS, kind="conversation")


def validate_network_json(path: str | Path) -> list[str]:
    json_path = Path(path)
    payload = _load_json(json_path)
    return _validate_schema(NETWORK_JSON_SCHEMA, payload, str(json_path))


def compare_device_csv(golden_path: str | Path, actual_path: str | Path, *, timestamp_precision: int = 3) -> list[str]:
    return _compare_csv(
        Path(golden_path),
        Path(actual_path),
        DEVICE_CSV_HEADERS,
        key_fields=("MAC Address", "IP Address"),
        float_fields=("First Seen", "Last Seen"),
        int_fields=("Packet Count",),
        list_fields=("TCP Ports", "UDP Ports"),
        timestamp_precision=timestamp_precision,
        kind="device",
    )


def compare_conversation_csv(golden_path: str | Path, actual_path: str | Path, *, timestamp_precision: int = 3) -> list[str]:
    return _compare_csv(
        Path(golden_path),
        Path(actual_path),
        CONVERSATION_CSV_HEADERS,
        key_fields=("Source IP", "Target IP", "Protocol", "Source TCP Port", "Source UDP Port"),
        float_fields=("Duration (seconds)",),
        int_fields=(
            "Source TCP Port",
            "Source UDP Port",
            "Target TCP Port",
            "Target UDP Port",
            "Packets A->B",
            "Packets B->A",
            "Bytes A->B",
            "Bytes B->A",
            "Stream ID",
            "VLAN ID",
            "DiffServ Field",
            "IP Version",
        ),
        list_fields=("TCP Flags",),
        timestamp_fields=("First Seen", "Last Seen"),
        timestamp_precision=timestamp_precision,
        kind="conversation",
    )


def compare_network_json(golden_path: str | Path, actual_path: str | Path) -> list[str]:
    golden_raw = _load_json(Path(golden_path))
    actual_raw = _load_json(Path(actual_path))
    errors = _validate_schema(NETWORK_JSON_SCHEMA, golden_raw, str(golden_path))
    errors.extend(_validate_schema(NETWORK_JSON_SCHEMA, actual_raw, str(actual_path)))
    if errors:
        return errors
    golden = canonicalize_network_json(golden_raw)
    actual = canonicalize_network_json(actual_raw)
    if golden != actual:
        return ["network JSON differs from golden after canonicalization"]
    return []


def canonicalize_network_json(payload: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(payload))
    metadata = result.get("metadata", {})
    metadata.pop("generated_at", None)
    result["metadata"] = metadata

    result["nodes"] = sorted(
        (
            {
                **node,
                "ips": sorted(node.get("ips", [])),
                "tcp_ports": sorted(node.get("tcp_ports", [])),
                "udp_ports": sorted(node.get("udp_ports", [])),
            }
            for node in result.get("nodes", [])
        ),
        key=lambda node: node.get("id", ""),
    )
    result["links"] = sorted(
        (
            {
                **link,
                "tcp_flags": sorted(link.get("tcp_flags", [])),
            }
            for link in result.get("links", [])
        ),
        key=lambda link: (
            str(link.get("source", "")),
            str(link.get("target", "")),
            str(link.get("source_ip", "")),
            str(link.get("target_ip", "")),
            str(link.get("protocol", "")),
            str(link.get("app_protocol", "")),
        ),
    )
    return result


def _validate_csv_contract(path: Path, expected_headers: list[str], *, kind: str) -> list[str]:
    errors: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        try:
            headers = next(reader)
        except StopIteration:
            return [f"{path}: empty {kind} CSV"]

        if headers != expected_headers:
            errors.append(f"{path}: header mismatch\nexpected: {expected_headers}\nactual:   {headers}")
            return errors

        for row_number, row in enumerate(reader, start=2):
            if len(row) != len(expected_headers):
                errors.append(
                    f"{path}: line {row_number}: expected {len(expected_headers)} columns, found {len(row)}"
                )
                continue
            record = dict(zip(expected_headers, row))
            errors.extend(_validate_csv_record(record, kind=kind, row_number=row_number, path=path))
    return errors


def _validate_csv_record(record: dict[str, str], *, kind: str, row_number: int, path: Path) -> list[str]:
    errors: list[str] = []
    if kind == "device":
        errors.extend(_validate_int(record["Packet Count"], path, row_number, "Packet Count"))
        errors.extend(_validate_float(record["First Seen"], path, row_number, "First Seen"))
        errors.extend(_validate_float(record["Last Seen"], path, row_number, "Last Seen"))
        errors.extend(_validate_int_list(record["TCP Ports"], path, row_number, "TCP Ports"))
        errors.extend(_validate_int_list(record["UDP Ports"], path, row_number, "UDP Ports"))
    elif kind == "conversation":
        for field in (
            "Source TCP Port",
            "Source UDP Port",
            "Target TCP Port",
            "Target UDP Port",
            "Packets A->B",
            "Packets B->A",
            "Bytes A->B",
            "Bytes B->A",
            "Stream ID",
            "VLAN ID",
            "DiffServ Field",
            "IP Version",
        ):
            errors.extend(_validate_optional_int(record[field], path, row_number, field))
        errors.extend(_validate_float(record["Duration (seconds)"], path, row_number, "Duration (seconds)"))
        errors.extend(_validate_iso_timestamp(record["First Seen"], path, row_number, "First Seen"))
        errors.extend(_validate_iso_timestamp(record["Last Seen"], path, row_number, "Last Seen"))
        errors.extend(_validate_int_list(record["TCP Flags"], path, row_number, "TCP Flags", allow_text=True))
    return errors


def _compare_csv(
    golden_path: Path,
    actual_path: Path,
    expected_headers: list[str],
    *,
    key_fields: tuple[str, ...],
    float_fields: tuple[str, ...] = (),
    int_fields: tuple[str, ...] = (),
    list_fields: tuple[str, ...] = (),
    timestamp_fields: tuple[str, ...] = (),
    timestamp_precision: int = 3,
    kind: str,
) -> list[str]:
    golden_rows, golden_errors = _load_and_normalize_csv(
        golden_path,
        expected_headers,
        key_fields=key_fields,
        float_fields=float_fields,
        int_fields=int_fields,
        list_fields=list_fields,
        timestamp_fields=timestamp_fields,
        timestamp_precision=timestamp_precision,
        kind=kind,
    )
    actual_rows, actual_errors = _load_and_normalize_csv(
        actual_path,
        expected_headers,
        key_fields=key_fields,
        float_fields=float_fields,
        int_fields=int_fields,
        list_fields=list_fields,
        timestamp_fields=timestamp_fields,
        timestamp_precision=timestamp_precision,
        kind=kind,
    )
    errors = golden_errors + actual_errors
    if errors:
        return errors
    if golden_rows != actual_rows:
        return [
            f"{actual_path}: normalized {kind} CSV differs from {golden_path}",
            f"golden={golden_rows}",
            f"actual={actual_rows}",
        ]
    return []


def _load_and_normalize_csv(
    path: Path,
    expected_headers: list[str],
    *,
    key_fields: tuple[str, ...],
    float_fields: tuple[str, ...],
    int_fields: tuple[str, ...],
    list_fields: tuple[str, ...],
    timestamp_fields: tuple[str, ...],
    timestamp_precision: int,
    kind: str,
) -> tuple[list[tuple[Any, ...]], list[str]]:
    errors = _validate_csv_contract(path, expected_headers, kind=kind)
    if errors:
        return [], errors

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            normalized = []
            for field in expected_headers:
                value = row[field]
                if field in float_fields:
                    normalized.append(_normalize_float(value, precision=timestamp_precision))
                elif field in int_fields:
                    normalized.append(_normalize_optional_int(value))
                elif field in list_fields:
                    normalized.append(_normalize_list(value))
                elif field in timestamp_fields:
                    normalized.append(_normalize_timestamp(value, precision=timestamp_precision))
                else:
                    normalized.append(value)
            rows.append(tuple(normalized))

    key_indexes = [expected_headers.index(field) for field in key_fields]
    rows.sort(key=lambda row: tuple(row[index] for index in key_indexes))
    return rows, []


def _normalize_float(value: str, *, precision: int) -> str:
    if value == "":
        return ""
    return f"{float(value):.{precision}f}"


def _normalize_timestamp(value: str, *, precision: int) -> str:
    if value == "":
        return ""
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(value)
        if precision <= 0:
            timespec = "seconds"
        elif precision <= 3:
            timespec = "milliseconds"
        else:
            timespec = "microseconds"
        return parsed.isoformat(timespec=timespec)
    except Exception:
        return f"{float(value):.{precision}f}"


def _normalize_optional_int(value: str) -> str:
    if value == "":
        return ""
    return str(int(value))


def _normalize_list(value: str) -> str:
    if value == "":
        return ""
    return ",".join(part.strip() for part in value.split(",") if part.strip())


def _validate_int(value: str, path: Path, row_number: int, field: str) -> list[str]:
    try:
        int(value)
    except Exception:
        return [f"{path}: line {row_number}: {field!r} must be an integer, got {value!r}"]
    return []


def _validate_optional_int(value: str, path: Path, row_number: int, field: str) -> list[str]:
    if value == "":
        return []
    return _validate_int(value, path, row_number, field)


def _validate_float(value: str, path: Path, row_number: int, field: str) -> list[str]:
    if value == "":
        return []
    try:
        float(value)
    except Exception:
        return [f"{path}: line {row_number}: {field!r} must be numeric, got {value!r}"]
    return []


def _validate_iso_timestamp(value: str, path: Path, row_number: int, field: str) -> list[str]:
    if value == "":
        return []
    try:
        from datetime import datetime

        datetime.fromisoformat(value)
    except Exception:
        return [f"{path}: line {row_number}: {field!r} must be ISO-8601, got {value!r}"]
    return []


def _validate_int_list(value: str, path: Path, row_number: int, field: str, *, allow_text: bool = False) -> list[str]:
    if value == "":
        return []
    errors: list[str] = []
    for entry in (part.strip() for part in value.split(",")):
        if not entry:
            continue
        if allow_text:
            continue
        try:
            int(entry)
        except Exception:
            errors.append(f"{path}: line {row_number}: {field!r} entries must be integers, got {entry!r}")
    return errors
