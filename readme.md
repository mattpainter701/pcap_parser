# PCAP Network Device Discovery Tool

This Python script parses PCAP files to discover network devices, identify vendors based on MAC addresses, and map IP addresses to services (ports).

## Features
- Identifies devices by MAC address
- Resolves vendor information using IEEE OUI database
- Maps IP addresses to devices
- Tracks TCP and UDP ports for each IP address
- Identifies message types in packet data
- Generates detailed CSV reports with device information
- Works with PyShark (built on top of TShark)

## Requirements
- Python 3.x
- PyShark library

## Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/pcap-parser.git
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
# Analyze a PCAP file and generate a device info report
python pcap_parser.py path/to/capture.pcap
```

### Advanced Options
```bash
# Enable debug logging
python pcap_parser.py path/to/capture.pcap --debug

# Specify a custom output file
python pcap_parser.py path/to/capture.pcap --output custom_output.csv
```

### Example
```bash
# Analyze a PCAP file and save the report to a specific location
python pcap_parser.py pcaps/network_capture.pcap --output network_devices.csv
```

## Command Line Arguments
- `pcap_file`: Path to the pcap file (required)
- `--debug`: Enable debug logging
- `--download-instructions`: Show instructions for downloading the OUI database
- `--output`: Output CSV file path (default: <pcap_name>-device_info.csv)

## CSV Report Format
The generated CSV report includes:
- MAC Address: The hardware address of the device
- Vendor: The manufacturer of the device (based on MAC OUI)
- IP Address: The IP address associated with the MAC
- TCP Ports: Comma-separated list of TCP ports (e.g., "80,443,8080")
- UDP Ports: Comma-separated list of UDP ports (e.g., "53,123")
- First Seen: Timestamp of first packet for this device
- Last Seen: Timestamp of last packet for this device
- Packet Count: Number of packets for this device

## How It Works
1. The script loads the IEEE OUI database to map MAC address prefixes to vendors
2. It processes each packet in the PCAP file to extract MAC and IP addresses
3. For each MAC address, it tracks associated IP addresses and ports
4. The script generates a CSV report with one row per MAC-IP combination, with TCP and UDP ports in separate columns

## License
This project is licensed under the MIT License - see the LICENSE file for details.
