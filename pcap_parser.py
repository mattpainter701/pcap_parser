import sys
from collections import defaultdict
import pyshark
import argparse
import csv
import os
import re

OUI_FILE = "oui.txt"
OUI_CSV_FILE = "oui.csv"
OUTPUT_DIR = "outputs"

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

def is_valid_mac(mac: str) -> bool:
    """Check if MAC address is valid and not broadcast/multicast."""
    if not mac:
        return False
        
    # Filter out broadcast/multicast addresses
    if mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
        
    # Filter out multicast addresses (first byte's LSB is 1)
    try:
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 0x01:
            return False
    except (ValueError, IndexError):
        return False
        
    return True

def check_tshark_installation():
    """Check if TShark is installed and accessible."""
    try:
        from pyshark.tshark.tshark import get_process_path
        try:
            get_process_path()
            return True
        except Exception:
            print("\n[!] TShark not found. Please install Wireshark/tshark to use this tool.")
            print("[!] You can download it from: https://www.wireshark.org/download.html")
            print("[!] Make sure to add tshark to your system PATH during installation.")
            return False
    except ImportError:
        print("\n[!] pyshark not installed. Please install it with:")
        print("    pip install pyshark")
        return False

def extract_device_info(pcap_file, debug=False):
    """
    Extracts device information from all packets in the provided pcap file, aggregating by MAC addresses.
    """
    print(f"\n[+] Loading capture file: {pcap_file}")
    
    try:
        capture = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"[!] Error opening capture file: {e}")
        print("[!] Make sure the file exists and is a valid PCAP file")
        return None

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

    packet_count = 0
    processed_count = 0
    
    try:
        for pkt in capture:
            packet_count += 1
            try:
                pkt_time = float(pkt.sniff_time.timestamp()) if hasattr(pkt, 'sniff_time') else 0

                # Extract IP and MAC addresses
                src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
                dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
                src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
                dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None
                
                # Check for TCP/UDP ports
                src_port = None
                dst_port = None
                proto = None
                
                if hasattr(pkt, 'tcp'):
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                    proto = 'tcp'
                elif hasattr(pkt, 'udp'):
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                    proto = 'udp'

                # Filter out invalid MAC addresses
                if not src_mac or not dst_mac:
                    continue
                
                if not is_valid_mac(src_mac) or not is_valid_mac(dst_mac):
                    continue
                
                # Process source MAC address
                if src_mac:
                    record = device_info[src_mac]
                    if record['vendor'] is None:
                        record['vendor'] = get_vendor(src_mac)
                    
                    if record['first_seen'] is None:
                        record['first_seen'] = pkt_time
                    record['last_seen'] = pkt_time
                    record['packet_count'] += 1
                    
                    # If we have source IP and it's communicating with a destination
                    if src_ip and dst_ip:
                        ip_record = record['ip_connections'][src_ip]
                        if ip_record['first_seen'] is None:
                            ip_record['first_seen'] = pkt_time
                        ip_record['last_seen'] = pkt_time
                        ip_record['packet_count'] += 1
                        
                        # If we have port information, record it
                        if proto == 'tcp' and src_port:
                            ip_record['tcp_ports'].add(src_port)
                        elif proto == 'udp' and src_port:
                            ip_record['udp_ports'].add(src_port)
                
                # Process destination MAC address similarly
                if dst_mac:
                    record = device_info[dst_mac]
                    if record['vendor'] is None:
                        record['vendor'] = get_vendor(dst_mac)
                    
                    if record['first_seen'] is None:
                        record['first_seen'] = pkt_time
                    record['last_seen'] = pkt_time
                    record['packet_count'] += 1
                    
                    # If we have destination IP and it's communicating with a source
                    if dst_ip and src_ip:
                        ip_record = record['ip_connections'][dst_ip]
                        if ip_record['first_seen'] is None:
                            ip_record['first_seen'] = pkt_time
                        ip_record['last_seen'] = pkt_time
                        ip_record['packet_count'] += 1
                        
                        # If we have port information, record it
                        if proto == 'tcp' and dst_port:
                            ip_record['tcp_ports'].add(dst_port)
                        elif proto == 'udp' and dst_port:
                            ip_record['udp_ports'].add(dst_port)
                
                processed_count += 1
                
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Exception encountered in packet {packet_count}: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[!] Processing interrupted by user")
    except Exception as e:
        print(f"[!] Error processing packets: {e}")
    finally:
        capture.close()
        
    print(f"[+] Processed {processed_count} of {packet_count} packets")
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
        # Create outputs directory if it doesn't exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        output_path = os.path.join(OUTPUT_DIR, output_csv)
        
        with open(output_path, "w", newline="") as csv_file:
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
        
        print(f"\n[+] CSV report generated: {output_path}")
        return True
    except PermissionError:
        print(f"\n[!] Permission denied when writing to {output_path}")
        print(f"[!] Try specifying a different output file with --output")
        return False
    except Exception as e:
        print(f"\n[!] Error writing CSV file: {e}")
        return False

def main():
    # Check dependencies before proceeding
    if not check_tshark_installation():
        sys.exit(1)
        
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
