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
  
## Requirements
- Python 3.x
- PyShark library

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

# Specify a custom output filename base
python pcap_parser.py path/to/capture.pcap --output network_analysis

# Enable detailed debug output
python pcap_parser.py path/to/capture.pcap --debug
```

## Output Files
The script generates the following output files in the `outputs` directory:

### Device Information CSV
- MAC Address: The hardware address of the device
- Vendor: The manufacturer of the device (based on MAC OUI)
- IP Address: The IP address associated with the MAC
- TCP Ports: Comma-separated list of TCP ports (e.g., "80,443,8080")
- UDP Ports: Comma-separated list of UDP ports (e.g., "53,123")
- First Seen: Timestamp of first packet for this device
- Last Seen: Timestamp of last packet for this device
- Packet Count: Number of packets for this device

### Conversation Information CSV
Detailed analysis of each conversation between pairs of devices:
- Source/Target IP and MAC addresses
- Protocol information (transport and application layer)
- Port numbers (TCP/UDP)
- Traffic statistics (packets and bytes in both directions)
- Timestamps and duration
- Conversation status
- TCP flags
- VLAN IDs and DiffServ fields
- Frame protocols

### Network Data JSON
JSON format optimized for D3 visualizations:
- Nodes representing devices with MAC addresses, vendor info, and IPs
- Links representing conversations between devices
- Complete traffic flow information
- Connection states and statistics
- Perfect for building interactive network visualizations

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

