# Streaming NDJSON Example

Stream NDJSON (newline-delimited JSON) from pcap-parser and pipe into
jq, duckdb, or Python for downstream processing.

## CLI Usage

```bash
# Stream all records
pcap-parser capture.pcapng --stream-json

# Stream only device records
pcap-parser capture.pcapng --stream-json | jq 'select(.type == "device")'

# Stream only conversation records
pcap-parser capture.pcapng --stream-json | jq 'select(.type == "conversation")'

# Extract the summary
pcap-parser capture.pcapng --stream-json | jq 'select(.type == "summary")'

# Count devices
pcap-parser capture.pcapng --stream-json | jq -s '[.[] | select(.type=="device")] | length'

# Extract all MAC addresses
pcap-parser capture.pcapng --stream-json | jq -r 'select(.type=="device") | .mac'

# Find conversations with HTTP/HTTPS
pcap-parser capture.pcapng --stream-json | jq 'select(.type=="conversation" and (.app_protocol == "HTTP" or .app_protocol == "HTTPS"))'

# Load into duckdb for SQL analysis
pcap-parser capture.pcapng --stream-json | duckdb -c "
  SELECT app_protocol, COUNT(*) as count, SUM(bytes_a_to_b + bytes_b_to_a) as total_bytes
  FROM read_json_auto('/dev/stdin')
  WHERE type = 'conversation'
  GROUP BY app_protocol
  ORDER BY total_bytes DESC
"
```

## Library Usage

```python
from pcap_parser import parse_capture_streaming
import json, sys

for record in parse_capture_streaming("capture.pcapng"):
    if record["type"] == "device":
        print(f"Device: {record['mac']} ({record['vendor']})")
    elif record["type"] == "conversation":
        print(f"  Flow: {record['source_ip']} -> {record['target_ip']} ({record['app_protocol']})")
    elif record["type"] == "summary":
        print(f"\nDone. {record['device_count']} devices, {record['conversation_count']} conversations")

# Write NDJSON to file
with open("output.ndjson", "w") as f:
    for record in parse_capture_streaming("capture.pcapng"):
        f.write(json.dumps(record) + "\n")
```

## Record Schema

### device
```json
{
  "type": "device",
  "mac": "aa:bb:cc:11:22:33",
  "vendor": "Intel Corporate",
  "ips": ["192.168.1.10"],
  "tcp_ports": [80, 443],
  "udp_ports": [53],
  "packet_count": 1204,
  "first_seen": 1715800000.0,
  "last_seen": 1715800100.0
}
```

### conversation
```json
{
  "type": "conversation",
  "source_ip": "192.168.1.10",
  "source_mac": "aa:bb:cc:11:22:33",
  "source_tcp_port": 52341,
  "source_udp_port": null,
  "target_ip": "93.184.216.34",
  "target_mac": "dd:ee:ff:44:55:66",
  "target_tcp_port": 443,
  "target_udp_port": null,
  "protocol": "TCP",
  "app_protocol": "HTTPS",
  "packets_a_to_b": 42,
  "packets_b_to_a": 38,
  "bytes_a_to_b": 28672,
  "bytes_b_to_a": 1245184,
  "first_seen": 1715800001.5,
  "last_seen": 1715800005.8,
  "duration": 4.3,
  "conversation_status": "request-accepted",
  "tcp_flags": ["ACK", "SYN"],
  "stream_id": "0",
  "frame_protocols": ["eth:ethertype:ip:tcp"],
  "vlan_id": null,
  "dsfield": "CS0 / Not-ECT",
  "ip_version": 4
}
```

### summary
```json
{
  "type": "summary",
  "pcap_file": "capture.pcapng",
  "elapsed_seconds": 0.42,
  "device_count": 12,
  "conversation_count": 47,
  "total_packets": 15203,
  "total_bytes": 8380416,
  "protocols_detected": ["TCP", "UDP"]
}
```
