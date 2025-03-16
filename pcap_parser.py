#!/usr/bin/env python3

import pyshark
import re
import argparse
import os
import csv
from collections import defaultdict, Counter, namedtuple

# Path for the OUI database file
OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt")
OUI_CSV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.csv")

def parse_oui_file():
    """
    Parses the IEEE OUI database from a local file.
    Returns a dictionary mapping MAC OUIs to vendor names.
    """
    oui_dict = {}
    
    # First try to use the CSV file if it exists (faster parsing)
    if os.path.exists(OUI_CSV_FILE):
        try:
            with open(OUI_CSV_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        mac = row[0].upper()
                        vendor = row[1]
                        oui_dict[mac] = vendor
            print(f"[+] Loaded {len(oui_dict)} OUI entries from CSV file")
            return oui_dict
        except Exception as e:
            print(f"[!] Error reading OUI CSV file: {e}")
    
    # If CSV doesn't exist or fails, try the TXT file
    if os.path.exists(OUI_FILE):
        try:
            with open(OUI_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.strip().split("(hex)")
                        if len(parts) == 2:
                            mac = parts[0].strip().replace("-", ":").upper()
                            vendor = parts[1].strip()
                            oui_dict[mac] = vendor
            
            # Save as CSV for faster future parsing
            try:
                with open(OUI_CSV_FILE, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    for mac, vendor in oui_dict.items():
                        writer.writerow([mac, vendor])
            except Exception as e:
                print(f"[!] Error saving OUI CSV file: {e}")
            
            print(f"[+] Loaded {len(oui_dict)} OUI entries from TXT file")
            return oui_dict
        except Exception as e:
            print(f"[!] Error reading OUI TXT file: {e}")
    
    print(f"[!] OUI database file not found. Please download it manually from:")
    print(f"[!] https://standards-oui.ieee.org/oui/oui.txt")
    print(f"[!] and save it as {OUI_FILE}")
    return {}

# Load the IEEE OUI database
ieee_oui_db = {}
try:
    ieee_oui_db = parse_oui_file()
except Exception as e:
    print(f"[!] Failed to load IEEE OUI database: {e}")

def get_vendor(mac: str) -> str:
    """Return vendor based on MAC OUI."""
    if not mac:
        return None
        
    # Try using the IEEE OUI database
    try:
        # Format MAC address to match the format in the database
        parts = mac.split(":")
        if len(parts) >= 3:
            oui = ":".join(parts[:3]).upper()
            if oui in ieee_oui_db:
                return ieee_oui_db[oui]
    except Exception:
        pass
            
    return None

def extract_serial_numbers(pkt_str, mac, ip=None, debug=False):
    """
    Extract potential serial numbers from packet payload.
    
    Args:
        pkt_str: String representation of the packet
        mac: MAC address associated with the packet
        ip: IP address associated with the packet (optional)
        debug: Enable debug output
        
    Returns:
        List of potential serial numbers
    """
    # Common serial number patterns
    patterns = [
        # Look for context keywords followed by numbers
        r'(?:serial|s/?n|serialnumber|serialnum|serial number|device id|asset|product)[^\w\r\n]{0,10}([A-Z0-9][A-Z0-9-]{5,20})',
        # Look for formatted serial numbers (common patterns)
        r'\b([A-Z0-9]{2,4}[-][A-Z0-9]{4,8}[-][A-Z0-9]{4,8})\b',  # Format: XX-XXXX-XXXX
        r'\b([A-Z0-9]{4,8}[-][A-Z0-9]{4,8})\b',                  # Format: XXXX-XXXX
        # Common formats without context
        r'\b([A-Z]{2,3}[0-9]{5,10})\b',                           # Format: XX12345
        r'\b([0-9]{5,8}[A-Z]{1,3})\b',                            # Format: 12345XX
        # Baxter-specific patterns (if targeting medical devices)
        r'\b(9[0-9]{5})\b',                                       # Baxter 6-digit format starting with 9
        # Additional medical device patterns
        r'\b(MD[0-9]{4,8})\b',                                    # Medical device format
        r'\b(SN-[A-Z0-9]{6,12})\b',                               # SN-prefixed format
    ]
    
    serials = []
    
    # Apply each pattern
    for pattern in patterns:
        matches = re.finditer(pattern, pkt_str, re.IGNORECASE)
        for match in matches:
            serial = match.group(1).strip()
            # Basic validation - ensure it's not just a number, date, or common false positive
            if (len(serial) >= 5 and 
                not re.match(r'^[0-9]{1,3}$', serial) and
                not re.match(r'^(19|20)\d{2}[01]\d[0-3]\d$', serial) and  # Exclude dates
                not re.match(r'^(0|255|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}$', serial)):  # Exclude IPs
                if debug:
                    print(f"[DEBUG] Found potential S/N: {serial} (MAC: {mac}, IP: {ip})")
                serials.append(serial)
    
    return serials

def extract_device_info(pcap_file, debug=False):
    """
    Extracts device information from all packets in the provided pcap file, aggregating by MAC addresses.

    Args:
        pcap_file (str): Path to the pcap file.
        debug (bool): Enable debug logging.

    Returns:
        dict: device_info mapping MAC addresses to device information
    """
    print(f"\n[+] Loading capture file: {pcap_file}")
    capture = pyshark.FileCapture(pcap_file)

    # Track device information keyed by MAC address
    device_info = defaultdict(lambda: {
        'vendor': None,
        'packet_count': 0,
        'first_seen': None,
        'last_seen': None,
        'message_types': Counter(),
        'serial_numbers': set(),
        'ip_connections': defaultdict(lambda: {
            'tcp_ports': set(),
            'udp_ports': set(),
            'packet_count': 0,
            'first_seen': None,
            'last_seen': None
        })
    })

    message_type_pattern = re.compile(r'(Status|Alarm|Alert|Config|Data|Command|Response)', re.IGNORECASE)

    for pkt in capture:
        try:
            pkt_str = str(pkt)
            pkt_time = float(pkt.sniff_time.timestamp()) if hasattr(pkt, 'sniff_time') else 0

            # Extract IP and MAC addresses
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
            src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
            dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None

            # Look for serial numbers in the packet
            serials = extract_serial_numbers(pkt_str, src_mac, src_ip, debug)
            for serial in serials:
                if src_mac:
                    device_info[src_mac]['serial_numbers'].add(serial)
                if dst_mac:
                    device_info[dst_mac]['serial_numbers'].add(serial)

            # Process both source and destination MAC addresses
            for mac in [src_mac, dst_mac]:
                if not mac:
                    continue
                record = device_info[mac]
                
                # Track IP connections for this MAC
                for ip in [src_ip, dst_ip]:
                    if not ip:
                        continue
                    ip_record = record['ip_connections'][ip]
                    if ip_record['first_seen'] is None:
                        ip_record['first_seen'] = pkt_time
                    ip_record['last_seen'] = pkt_time
                    ip_record['packet_count'] += 1

                if record['vendor'] is None:
                    record['vendor'] = get_vendor(mac)

                if hasattr(pkt, 'tcp'):
                    try:
                        tcp_src = pkt.tcp.srcport if hasattr(pkt.tcp, 'srcport') else None
                        tcp_dst = pkt.tcp.dstport if hasattr(pkt.tcp, 'dstport') else None
                        # Associate ports with specific IP connections
                        if src_ip and tcp_src and mac == src_mac:
                            record['ip_connections'][src_ip]['tcp_ports'].add(tcp_src)
                        if dst_ip and tcp_dst and mac == dst_mac:
                            record['ip_connections'][dst_ip]['tcp_ports'].add(tcp_dst)
                    except Exception:
                        pass

                if hasattr(pkt, 'udp'):
                    try:
                        udp_src = pkt.udp.srcport if hasattr(pkt.udp, 'srcport') else None
                        udp_dst = pkt.udp.dstport if hasattr(pkt.udp, 'dstport') else None
                        # Associate ports with specific IP connections
                        if src_ip and udp_src and mac == src_mac:
                            record['ip_connections'][src_ip]['udp_ports'].add(udp_src)
                        if dst_ip and udp_dst and mac == dst_mac:
                            record['ip_connections'][dst_ip]['udp_ports'].add(udp_dst)
                    except Exception:
                        pass

                record['packet_count'] += 1
                if record['first_seen'] is None:
                    record['first_seen'] = pkt_time
                record['last_seen'] = pkt_time

            # Extract message types from the entire packet
            msg_match = message_type_pattern.search(pkt_str)
            if msg_match:
                msg_type = msg_match.group(0)
                # Record per device (choose first MAC if available)
                if src_mac and src_mac in device_info:
                    device_info[src_mac]['message_types'][msg_type] += 1
        except Exception as e:
            if debug:
                print(f"[DEBUG] Exception encountered in packet processing: {e}")
            continue

    capture.close()
    
    # Convert message_types Counter to dict for JSON serialization
    for mac, info in device_info.items():
        info['message_types'] = dict(info['message_types'])
        info['serial_numbers'] = list(info['serial_numbers'])

    return device_info

def download_oui_instructions():
    """Print instructions for manually downloading the OUI database."""
    print("\n[!] To manually download the IEEE OUI database:")
    print("1. Visit: https://standards-oui.ieee.org/oui/oui.txt")
    print("2. Save the file as 'oui.txt' in the same directory as this script")
    print(f"   ({os.path.dirname(os.path.abspath(__file__))})")
    print("3. Run the script again\n")

def write_csv_report(device_info, output_csv):
    """Write device information to a CSV file."""
    try:
        with open(output_csv, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["MAC Address", "Vendor", "IP Address", "TCP Ports", "UDP Ports", "First Seen", "Last Seen", "Packet Count"])
            
            # Generate one row per MAC-IP-service combination
            for mac, info in device_info.items():
                vendor = info.get("vendor") or "Unknown"
                
                # For each IP address associated with this MAC
                for ip, ip_info in info.get('ip_connections', {}).items():
                    tcp_ports = sorted(ip_info.get('tcp_ports', []))
                    udp_ports = sorted(ip_info.get('udp_ports', []))
                    
                    # Format TCP and UDP ports as comma-separated lists
                    tcp_ports_str = ",".join(map(str, tcp_ports)) if tcp_ports else ""
                    udp_ports_str = ",".join(map(str, udp_ports)) if udp_ports else ""
                    
                    # One row per IP address with combined ports
                    writer.writerow([
                        mac,
                        vendor,
                        ip,
                        tcp_ports_str,
                        udp_ports_str,
                        ip_info.get("first_seen", ""),
                        ip_info.get("last_seen", ""),
                        ip_info.get("packet_count", 0)
                    ])
        
        print(f"\n[+] CSV report generated: {output_csv}")
        return True
    except PermissionError:
        print(f"\n[!] Permission denied when writing to {output_csv}")
        print(f"[!] Try specifying a different output file with --output")
        return False
    except Exception as e:
        print(f"\n[!] Error writing CSV file: {e}")
        return False

def extract_baxter_serials(pcap_file):
    """Extract potential Baxter serial numbers (format: 9XXXXX)"""
    capture = pyshark.FileCapture(pcap_file)
    results = []
    
    for pkt in capture:
        try:
            pkt_str = str(pkt)
            # Find all 6-digit numbers starting with 9
            matches = re.finditer(r'\b(9[0-9]{5})\b', pkt_str)
            
            for match in matches:
                potential_sn = match.group(1)
                # Get some context (20 chars before and after)
                start_pos = max(0, match.start() - 20)
                end_pos = min(len(pkt_str), match.end() + 20)
                context = pkt_str[start_pos:end_pos]
                
                # Get source/destination info
                src_ip = pkt.ip.src if hasattr(pkt, 'ip') else "N/A"
                dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else "N/A"
                protocol = pkt.highest_layer
                
                results.append({
                    'serial': potential_sn,
                    'context': context,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'frame_num': pkt.number
                })
                
        except Exception as e:
            continue
            
    return results

def analyze_baxter_serials_command(pcap_file):
    """
    Command to specifically analyze and display potential Baxter serial numbers with context.
    This function is designed to be called directly from the command line.
    """
    print(f"\n[+] Analyzing {pcap_file} for potential Baxter serial numbers (format: 9XXXXX)")
    results = extract_baxter_serials(pcap_file)
    
    if not results:
        print("[-] No potential Baxter serial numbers found.")
        return
    
    print(f"[+] Found {len(results)} potential matches:")
    
    # Group by serial number
    by_serial = defaultdict(list)
    for result in results:
        by_serial[result['serial']].append(result)
    
    # Display results grouped by serial number
    for serial, occurrences in by_serial.items():
        print(f"\n[+] Potential Serial Number: {serial} (found in {len(occurrences)} packets)")
        
        # Show the first few occurrences with context
        for i, occurrence in enumerate(occurrences[:3]):  # Limit to first 3 for readability
            print(f"  Packet #{occurrence['frame_num']} ({occurrence['protocol']})")
            print(f"  {occurrence['src_ip']} → {occurrence['dst_ip']}")
            
            # Check if this looks like a timestamp
            is_timestamp = False
            if "Date:" in occurrence['context'] or "time" in occurrence['context'].lower():
                is_timestamp = True
                print(f"  WARNING: This appears to be a timestamp, not a serial number")
            
            # Clean up and display the context
            context = occurrence['context'].replace('\n', ' ').replace('\r', ' ')
            # Highlight the serial number in the context
            highlighted = context.replace(serial, f"[{serial}]")
            print(f"  Context: ...{highlighted}...")
            print()
        
        if len(occurrences) > 3:
            print(f"  ... and {len(occurrences) - 3} more occurrences")
    
    return by_serial

def main():
    parser = argparse.ArgumentParser(description="PCAP Asset Discovery - CSV Report focusing on MAC addresses")
    parser.add_argument("pcap_file", help="Path to the pcap file", nargs='?')
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--download-instructions", action="store_true", help="Show instructions for downloading the OUI database")
    parser.add_argument("--serial-only", action="store_true", help="Only show devices with detected serial numbers")
    parser.add_argument("--analyze-baxter", action="store_true", help="Analyze potential Baxter serial numbers (format: 9XXXXX)")
    parser.add_argument("--output", help="Output CSV file path (default: <pcap_name>-device_info.csv)")
    args = parser.parse_args()

    # Show download instructions if requested
    if args.download_instructions:
        download_oui_instructions()
        return

    # Check if OUI database file exists
    if not os.path.exists(OUI_FILE) and not os.path.exists(OUI_CSV_FILE):
        print("[!] OUI database file not found.")
        download_oui_instructions()

    # Ensure pcap_file is provided if not showing download instructions
    if not args.pcap_file:
        parser.error("the following arguments are required: pcap_file")

    if not os.path.isfile(args.pcap_file):
        print(f"[-] File not found: {args.pcap_file}")
        return

    # Special mode for analyzing Baxter serial numbers
    if args.analyze_baxter:
        analyze_baxter_serials_command(args.pcap_file)
        return

    device_info = extract_device_info(args.pcap_file, debug=args.debug)

    if device_info:
        print(f"\n[+] Devices Found: {len(device_info)}")
        devices_with_serials = 0
        serials_found = set()
        
        for mac, info in device_info.items():
            vendor = info.get('vendor') or "Unknown"
            serial_numbers = info.get('serial_numbers', [])
            
            # Skip devices without serial numbers if --serial-only is specified
            if args.serial_only and not serial_numbers:
                continue
            
            devices_with_serials += 1 if serial_numbers else 0
            for sn in serial_numbers:
                serials_found.add(sn)
            
            if serial_numbers:
                print(f" - MAC: {mac} (Vendor: {vendor}, S/N: {', '.join(serial_numbers)})")
            else:
                print(f" - MAC: {mac} (Vendor: {vendor})")
        
        # Print summary of serial numbers found
        if serials_found:
            print(f"\n[+] Serial Numbers Found: {len(serials_found)}")
            for sn in sorted(serials_found):
                print(f" - {sn}")
        elif args.serial_only:
            print("\n[-] No serial numbers found.")
    else:
        print("\n[-] No devices found.")

    base = os.path.splitext(os.path.basename(args.pcap_file))[0]
    output_csv = args.output if args.output else f"{base}-device_info.csv"
    
    write_csv_report(device_info, output_csv)

if __name__ == "__main__":
    main()
