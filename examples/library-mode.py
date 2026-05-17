# Library Mode Example

Demonstrates using pcap-parser as a Python library rather than a CLI tool.

```python
#!/usr/bin/env python3
"""pcap_parser library usage examples."""

import json
import sys
from pcap_parser import parse_capture, parse_capture_streaming

# ============================================================
# Example 1: One-shot parse — get all data at once
# ============================================================
data = parse_capture("pcaps/sample.pcapng")
print(f"PCAP: {data.pcap_file}")
print(f"Devices: {data.device_count}")
print(f"Conversations: {data.conversation_count}")
print(f"Parse time: {data.elapsed_seconds:.2f}s")
print(f"Total packets: {data.total_packets}")
print(f"Total bytes: {data.total_bytes}")
print(f"Protocols: {', '.join(data.protocols_detected)}")

# Iterate devices
for device in data.devices:
    print(f"\nDevice: {device.mac}")
    print(f"  Vendor: {device.vendor}")
    print(f"  IPs: {', '.join(device.ips)}")
    print(f"  TCP ports: {device.tcp_ports}")
    print(f"  UDP ports: {device.udp_ports}")
    print(f"  Packets: {device.packet_count}")
    print(f"  First seen: {device.first_seen}")
    print(f"  Last seen: {device.last_seen}")

# Iterate conversations
for conv in data.conversations[:5]:  # first 5
    print(f"\nConversation: {conv.source_ip}:{conv.source_tcp_port} -> {conv.target_ip}:{conv.target_tcp_port}")
    print(f"  Protocol: {conv.protocol} / {conv.app_protocol}")
    print(f"  Packets: {conv.packets_a_to_b} A->B, {conv.packets_b_to_a} B->A")
    print(f"  Bytes: {conv.bytes_a_to_b} A->B, {conv.bytes_b_to_a} B->A")
    print(f"  Status: {conv.conversation_status}")
    print(f"  Duration: {conv.duration:.2f}s")
    print(f"  TCP flags: {conv.tcp_flags}")

# Export to JSON
print(f"\nFull JSON export: {json.dumps(data.to_dict(), indent=2)[:500]}...")

# ============================================================
# Example 2: Streaming NDJSON — one record at a time
# ============================================================
print("\n" + "=" * 60)
print("STREAMING NDJSON:")
print("=" * 60)
count = 0
for record in parse_capture_streaming("pcaps/sample.pcapng"):
    json.dump(record, sys.stdout)
    sys.stdout.write("\n")
    count += 1
print(f"\nStreamed {count} records")

# ============================================================
# Example 3: With BPF filter
# ============================================================
print("\n" + "=" * 60)
print("FILTERED PARSE (tcp.port==443):")
print("=" * 60)
data = parse_capture("pcaps/sample.pcapng", bpf_filter="tcp.port==443")
print(f"Devices: {data.device_count}, Conversations: {data.conversation_count}")

# ============================================================
# Example 4: Convert to pandas DataFrame (requires pandas)
# ============================================================
try:
    import pandas as pd
    data = parse_capture("pcaps/sample.pcapng")
    df = pd.DataFrame([d.to_dict() for d in data.devices])
    print(f"\nPandas DataFrame shape: {df.shape}")
    print(df[["mac", "vendor", "packet_count"]].head())
except ImportError:
    print("\n[pandas not installed — skipping DataFrame example]")
```
