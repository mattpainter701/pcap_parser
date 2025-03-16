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
        'ip_connections': defaultdict(lambda: {
            'tcp_ports': set(),
            'udp_ports': set(),
            'packet_count': 0,
            'first_seen': None,
            'last_seen': None
        })
    })

    for pkt in capture:
        try:
            pkt_str = str(pkt)
            pkt_time = float(pkt.sniff_time.timestamp()) if hasattr(pkt, 'sniff_time') else 0

            # Extract IP and MAC addresses
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
            src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
            dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None

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

        except Exception as e:
            if debug:
                print(f"[DEBUG] Exception encountered in packet processing: {e}")
            continue

    capture.close()
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
            writer.writerow([
                "MAC Address", 
                "Vendor", 
                "IP Address", 
                "TCP Ports", 
                "UDP Ports", 
                "First Seen", 
                "Last Seen", 
                "Packet Count"
            ])
            
            # Generate one row per MAC-IP-service combination
            for mac, info in device_info.items():
                vendor = info.get("vendor") or "Unknown"
                
                # For each IP address associated with this MAC
                for ip, ip_info in info.get("ip_connections", {}).items():
                    tcp_ports = sorted(ip_info.get("tcp_ports", []))
                    udp_ports = sorted(ip_info.get("udp_ports", []))
                    
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

def main():
    parser = argparse.ArgumentParser(description="PCAP Asset Discovery - CSV Report focusing on MAC addresses")
    parser.add_argument("pcap_file", help="Path to the pcap file", nargs='?')
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--download-instructions", action="store_true", help="Show instructions for downloading the OUI database")
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

    device_info = extract_device_info(args.pcap_file, debug=args.debug)

    if device_info:
        print(f"\n[+] Devices Found: {len(device_info)}")
        
        for mac, info in device_info.items():
            vendor = info.get('vendor') or "Unknown"
            print(f" - MAC: {mac} (Vendor: {vendor})")
    else:
        print("\n[-] No devices found.")

    base = os.path.splitext(os.path.basename(args.pcap_file))[0]
    output_csv = args.output if args.output else f"{base}-device_info.csv"
    
    write_csv_report(device_info, output_csv)

if __name__ == "__main__":
    main()
