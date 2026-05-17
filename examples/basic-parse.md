# Basic Parse Example

```bash
# Parse a single capture — generates device and conversation CSV + network JSON
pcap-parser pcaps/sample.pcapng

# Output: outputs/sample-device_info.csv
#         outputs/sample-conversation_info.csv
#         outputs/sample-network_data.json
```

## JSON-only output

```bash
pcap-parser pcaps/sample.pcapng --format json
```

## CSV-only output

```bash
pcap-parser pcaps/sample.pcapng --format csv
```

## Custom output directory and name

```bash
pcap-parser pcaps/sample.pcapng --output myaudit --output-dir results/
```
