# Canonical Output Schema v1.0.0

This document defines the contract for all generated output artifacts.

Schema files live in `schemas/v1.0.0/`:

- `device-csv-row.schema.json`
- `conversation-csv-row.schema.json`
- `network-data.schema.json`
- `schema-manifest.json`

Versioning policy:

- `SCHEMA_VERSION = 1.0.0` is the canonical contract for this branch.
- Non-breaking additions should preserve backward compatibility where possible.
- Any breaking change to a field name, field type, required field, or CSV header order requires a new schema version and coordinated downstream migration.
- Use `--validate-output` to validate generated CSV/JSON against these contracts.

## Device CSV contract

Header order is fixed:

1. `MAC Address` — example: `58:bf:ea:be:b3:80`
2. `Vendor` — example: `Cisco Systems, Inc`
3. `IP Address` — example: `10.47.178.9`
4. `TCP Ports` — example: `61622` or `8008,8009`
5. `UDP Ports` — example: `53,123`
6. `First Seen` — example: `2024-03-17T12:34:56.123456`
7. `Last Seen` — example: `2024-03-17T12:35:56.123456`
8. `Packet Count` — example: `293`

Notes:

- Each row represents one MAC/IP combination.
- Port lists are comma-separated text values.
- Empty port lists are encoded as an empty string.
- Timestamps are ISO 8601 text generated from packet sniff times.

Example row:

```csv
58:bf:ea:be:b3:80,"Cisco Systems, Inc",10.47.178.9,"61622,49236","53",2024-03-17T12:34:56.123456,2024-03-17T12:35:56.123456,293
```

## Conversation CSV contract

Header order is fixed:

1. `Source IP` — example: `10.47.178.9`
2. `Source MAC` — example: `58:bf:ea:be:b3:80`
3. `Source TCP Port` — example: `61622`
4. `Source UDP Port` — example: `49236`
5. `Target IP` — example: `10.47.178.1`
6. `Target MAC` — example: `00:11:22:33:44:55`
7. `Target TCP Port` — example: `443`
8. `Target UDP Port` — example: `53`
9. `Protocol` — example: `TCP`
10. `Application Protocol` — example: `TLS`
11. `Packets A->B` — example: `12`
12. `Packets B->A` — example: `9`
13. `Bytes A->B` — example: `12345`
14. `Bytes B->A` — example: `6789`
15. `First Seen` — example: `2024-03-17T12:34:56.123456`
16. `Last Seen` — example: `2024-03-17T12:35:56.123456`
17. `Duration (seconds)` — example: `60.000`
18. `Conversation Status` — example: `request-accepted`
19. `TCP Flags` — example: `SYN,ACK`
20. `Stream ID` — example: `42`
21. `Frame Protocols` — example: `eth:ethertype:ip:tcp`
22. `VLAN ID` — example: `240`
23. `DiffServ Field` — example: `0x00`
24. `IP Version` — example: `4`

Notes:

- Each row represents one bidirectional conversation key.
- Fields are stored as text in CSV, even when they encode numeric values.
- Empty values are allowed for fields that may not be present in every packet trace.

Example row:

```csv
10.47.178.9,58:bf:ea:be:b3:80,61622,,10.47.178.1,00:11:22:33:44:55,443,,TCP,TLS,12,9,12345,6789,2024-03-17T12:34:56.123456,2024-03-17T12:35:56.123456,60.000,request-accepted,"SYN,ACK",42,eth:ethertype:ip:tcp,240,0x00,4
```

## Network JSON contract

Top-level object:

- `metadata` — run information and schema version
- `nodes` — device records
- `links` — conversation records

### metadata

- `schema_version` — example: `1.0.0`
- `generated_at` — example: `2024-03-17T12:34:56.123456`
- `pcap_file` — example: `capture.pcapng`
- `total_nodes` — example: `2`
- `total_links` — example: `1`

### nodes[]

Each node contains:

- `id` — example: `58:bf:ea:be:b3:80`
- `label` — example: `58:bf:ea:be:b3:80`
- `vendor` — example: `Cisco Systems, Inc`
- `ips` — example: `["10.47.178.9"]`
- `tcp_ports` — example: `[61622, 49236]`
- `udp_ports` — example: `[53, 123]`
- `packet_count` — example: `293`
- `first_seen` — example: `2024-03-17T12:34:56.123456`
- `last_seen` — example: `2024-03-17T12:35:56.123456`

### links[]

Each link contains:

- `source` — example: `58:bf:ea:be:b3:80`
- `target` — example: `00:11:22:33:44:55`
- `source_ip` — example: `10.47.178.9`
- `target_ip` — example: `10.47.178.1`
- `protocol` — example: `TCP`
- `app_protocol` — example: `TLS`
- `source_tcp_port` — example: `61622`
- `target_tcp_port` — example: `443`
- `source_udp_port` — example: `49236`
- `target_udp_port` — example: `53`
- `packets_a_to_b` — example: `12`
- `packets_b_to_a` — example: `9`
- `bytes_a_to_b` — example: `12345`
- `bytes_b_to_a` — example: `6789`
- `first_seen` — example: `2024-03-17T12:34:56.123456`
- `last_seen` — example: `2024-03-17T12:35:56.123456`
- `duration` — example: `60.0`
- `conversation_status` — example: `request-accepted`
- `tcp_flags` — example: `["SYN", "ACK"]`
- `stream_id` — example: `42`
- `frame_protocols` — example: `eth:ethertype:ip:tcp`
- `vlan_id` — example: `240`
- `dsfield` — example: `0x00`
- `ip_version` — example: `4`

Example JSON excerpt:

```json
{
  "metadata": {
    "schema_version": "1.0.0",
    "generated_at": "2024-03-17T12:34:56.123456",
    "pcap_file": "capture.pcapng",
    "total_nodes": 2,
    "total_links": 1
  },
  "nodes": [
    {
      "id": "58:bf:ea:be:b3:80",
      "label": "58:bf:ea:be:b3:80",
      "vendor": "Cisco Systems, Inc",
      "ips": ["10.47.178.9"],
      "tcp_ports": [61622, 49236],
      "udp_ports": [53, 123],
      "packet_count": 293,
      "first_seen": "2024-03-17T12:34:56.123456",
      "last_seen": "2024-03-17T12:35:56.123456"
    }
  ],
  "links": [
    {
      "source": "58:bf:ea:be:b3:80",
      "target": "00:11:22:33:44:55",
      "source_ip": "10.47.178.9",
      "target_ip": "10.47.178.1",
      "protocol": "TCP",
      "app_protocol": "TLS",
      "source_tcp_port": 61622,
      "target_tcp_port": 443,
      "source_udp_port": null,
      "target_udp_port": null,
      "packets_a_to_b": 12,
      "packets_b_to_a": 9,
      "bytes_a_to_b": 12345,
      "bytes_b_to_a": 6789,
      "first_seen": "2024-03-17T12:34:56.123456",
      "last_seen": "2024-03-17T12:35:56.123456",
      "duration": 60.0,
      "conversation_status": "request-accepted",
      "tcp_flags": ["SYN", "ACK"],
      "stream_id": 42,
      "frame_protocols": "eth:ethertype:ip:tcp",
      "vlan_id": 240,
      "dsfield": "0x00",
      "ip_version": 4
    }
  ]
}
```
