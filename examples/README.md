# Example Gallery

This directory contains sample outputs and usage patterns demonstrating the
full capabilities of **pcap-parser**. Each example is self-contained — clone
the repo, `pip install .`, and run.

## Directory Index

| Example | Description | Command |
|---------|-------------|---------|
| [basic-parse](basic-parse.md) | Single capture → CSV + JSON reports | `pcap-parser capture.pcapng` |
| [streaming-ndjson](streaming-ndjson.md) | NDJSON streaming → jq pipeline | `pcap-parser capture.pcap --stream-json \| jq 'select(.type=="device")'` |
| [filtered-parse](filtered-parse.md) | BPF-filtered extraction | `pcap-parser capture.pcap --filter "tcp.port==443"` |
| [compare-diff](compare-diff.md) | Diff two captures | `pcap-parser before.pcap after.pcap --compare` |
| [stats-only](stats-only.md) | Quick statistics without file output | `pcap-parser large.pcap --stats-only` |
| [advanced-analysis](advanced-analysis.md) | Role inference, anomalies, timeline | `pcap-parser capture.pcapng --analyze` |
| [library-mode](library-mode.py) | Python library import | `from pcap_parser import parse_capture` |
| [benchmark](benchmark.md) | Performance profiling | `pcap-parser capture.pcapng --benchmark` |
| [docker](docker.md) | Docker container usage | `docker run --rm -v $(pwd):/data pcap-parser /data/capture.pcapng` |
| [regression](regression.md) | Golden regression testing | `pcap-parser --regression` |

---

## Quick Start

```bash
# Install
git clone https://github.com/mattpainter701/pcap_parser.git
cd pcap_parser
pip install -e .

# Download OUI database (required once)
curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt

# Run!
pcap-parser pcaps/sample.pcapng
```

## Sample Output Preview

### Device Inventory (CSV excerpt)
```
MAC Address         | Vendor              | IP Address      | TCP Ports | UDP Ports | Packet Count
aa:bb:cc:11:22:33   | Intel Corporate     | 192.168.1.10    | 443,80    | 53        | 1,204
dd:ee:ff:44:55:66   | Cisco Systems       | 10.0.0.1        | 22        |           | 487
```

### NDJSON Streaming Output
```jsonl
{"type":"device","mac":"aa:bb:cc:11:22:33","vendor":"Intel Corporate","ips":["192.168.1.10"],"tcp_ports":[80,443],"udp_ports":[53],"packet_count":1204,"first_seen":1715800000.0,"last_seen":1715800100.0}
{"type":"conversation","source_ip":"192.168.1.10","source_mac":"aa:bb:cc:11:22:33","target_ip":"93.184.216.34","target_mac":"dd:ee:ff:44:55:66","protocol":"TCP","app_protocol":"HTTPS","packets_a_to_b":42,"packets_b_to_a":38,"bytes_a_to_b":28672,"bytes_b_to_a":1245184,"conversation_status":"request-accepted"}
{"type":"summary","pcap_file":"capture.pcapng","elapsed_seconds":0.42,"device_count":12,"conversation_count":47,"total_packets":15203,"total_bytes":8380416,"protocols_detected":["TCP","UDP"]}
```

### Library Mode
```python
from pcap_parser import parse_capture, parse_capture_streaming

# One-shot parse
data = parse_capture("capture.pcapng")
print(f"Found {data.device_count} devices, {data.conversation_count} conversations")

for device in data.devices:
    print(f"  {device.mac} — {device.vendor} — {len(device.ips)} IPs")

# Streaming NDJSON to stdout
import sys, json
for record in parse_capture_streaming("capture.pcapng"):
    json.dump(record, sys.stdout)
    sys.stdout.write("\n")
```
