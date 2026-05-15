# PCAP Network Device Discovery Tool

This Python script parses PCAP files to discover network devices, identify vendors based on MAC addresses, map IP addresses to services, and analyze network conversations.

## Features
- Identifies devices by MAC address
- Resolves vendor information using IEEE OUI database
- Maps IP addresses to devices
- Tracks TCP and UDP ports for each IP address
- Analyzes bidirectional conversations between devices
- Detects conversation statuses (request-accepted, request-rejected, etc.)
- Tracks traffic volume in both directions
- Supports both IPv4 and IPv6
- Extracts VLAN IDs and DiffServ fields
- Captures TCP flag information (SYN, ACK, RST, FIN)
- Generates detailed CSV and JSON reports optimized for visualization
- Validates output against versioned JSON Schema contracts with `--validate-output`
  
## Requirements
- Python 3.x
- PyShark library
- jsonschema (only needed when output validation is enabled)

## Installation
```bash
# Clone the repository
git clone https://github.com/mattpainter701/pcap_parser.git
cd pcap-parser

# Install dependencies
pip install -r requirements.txt

# Download the IEEE OUI database
python pcap_parser.py --download-instructions
# Then follow the instructions to download the OUI database
```

## Usage
### Basic Usage
```bash
# Analyze a PCAP file and generate device and conversation reports (CSV and JSON)
python pcap_parser.py path/to/capture.pcap

# Generate only JSON output (for visualization)
python pcap_parser.py path/to/capture.pcap --format json

# Generate only CSV reports
python pcap_parser.py path/to/capture.pcap --format csv

# Validate generated outputs against the canonical schema contracts
python pcap_parser.py path/to/capture.pcap --validate-output

# Specify a custom output filename base
python pcap_parser.py path/to/capture.pcap --output network_analysis

# Enable detailed debug output
python pcap_parser.py path/to/capture.pcap --debug
```

## Output Files
The script generates the following output files in the `outputs` directory:

### Device Information CSV
Canonical header order:
1. `MAC Address`
2. `Vendor`
3. `IP Address`
4. `TCP Ports`
5. `UDP Ports`
6. `First Seen`
7. `Last Seen`
8. `Packet Count`

### Conversation Information CSV
Canonical header order:
1. `Source IP`
2. `Source MAC`
3. `Source TCP Port`
4. `Source UDP Port`
5. `Target IP`
6. `Target MAC`
7. `Target TCP Port`
8. `Target UDP Port`
9. `Protocol`
10. `Application Protocol`
11. `Packets A->B`
12. `Packets B->A`
13. `Bytes A->B`
14. `Bytes B->A`
15. `First Seen`
16. `Last Seen`
17. `Duration (seconds)`
18. `Conversation Status`
19. `TCP Flags`
20. `Stream ID`
21. `Frame Protocols`
22. `VLAN ID`
23. `DiffServ Field`
24. `IP Version`

### Network Data JSON
JSON format optimized for D3 visualizations:
- Nodes representing devices with MAC addresses, vendor info, IPs, and port sets
- Links representing conversations between devices
- Metadata includes `schema_version`, generation time, source PCAP, and counts
- Schema is versioned at `1.0.0`

## Schema Contract
Canonical schema files live in `schemas/v1.0.0/`:
- `device-csv-row.schema.json`
- `conversation-csv-row.schema.json`
- `network-data.schema.json`
- `schema-manifest.json`

Breaking changes require a schema version bump and coordinated downstream migration.

## How It Works
1. The script loads the IEEE OUI database to map MAC address prefixes to vendors
2. It processes each packet in the PCAP file to extract network data
3. For each packet, it updates device information and conversation tracking
4. The script analyzes bidirectional traffic flows and determines conversation status
5. It generates three detailed reports (device CSV, conversation CSV, and network JSON)
6. The JSON output is specially formatted for D3-based network visualizations

## Conversation Status Detection
The tool uses a combination of TCP flags and packet flow analysis to determine conversation status:
- `request-accepted`: A successful connection (SYN-ACK handshake completed)
- `request-rejected`: Connection refused (RST flag or no response to SYN)
- `response`: Traffic flowing in both directions
- `no-response`: Unanswered request (no return traffic)

