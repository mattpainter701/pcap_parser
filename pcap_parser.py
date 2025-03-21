import sys
from collections import defaultdict
import pyshark
import argparse
import csv
import os
import re
import time
import json
from datetime import datetime

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
    Extracts device information from all packets in the provided pcap file.
    Now extracting detailed conversation data between pairs of IP addresses.
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
    
    # New structure to track conversations between pairs of endpoints
    # Key is a tuple of (src_ip, dst_ip, src_port, dst_port, protocol)
    conversation_data = defaultdict(lambda: {
        'source_ip': None,
        'source_mac': None,
        'source_tcp_port': None,
        'source_udp_port': None,
        'target_ip': None,
        'target_mac': None, 
        'target_tcp_port': None,
        'target_udp_port': None,
        'protocol': None,
        'app_protocol': None,
        'packets_a_to_b': 0,
        'packets_b_to_a': 0,
        'bytes_a_to_b': 0,
        'bytes_b_to_a': 0,
        'first_seen': None,
        'last_seen': None,
        'duration': 0,
        'conversation_status': 'unknown',
        'tcp_flags': set(),
        'stream_id': None,
        'frame_protocols': set(),
        'vlan_id': None,
        'dsfield': None,
        'ip_version': None,
    })

    packet_count = 0
    processed_count = 0
    
    try:
        for pkt in capture:
            packet_count += 1
            try:
                pkt_time = float(pkt.sniff_time.timestamp()) if hasattr(pkt, 'sniff_time') else 0
                
                # Extract IP addresses with IPv6 support
                ip_version = None
                if hasattr(pkt, 'ip'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    ip_version = 4
                    # Get DiffServ field if available
                    dsfield = pkt.ip.dsfield if hasattr(pkt.ip, 'dsfield') else None
                elif hasattr(pkt, 'ipv6'):
                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst
                    ip_version = 6
                    # Get DiffServ field if available (traffic class in IPv6)
                    dsfield = pkt.ipv6.tclass if hasattr(pkt.ipv6, 'tclass') else None
                else:
                    src_ip = None
                    dst_ip = None
                    dsfield = None

                src_mac = pkt.eth.src if hasattr(pkt, 'eth') else None
                dst_mac = pkt.eth.dst if hasattr(pkt, 'eth') else None
                
                # Extract VLAN ID if available
                vlan_id = None
                if hasattr(pkt, 'vlan'):
                    vlan_id = pkt.vlan.id if hasattr(pkt.vlan, 'id') else None
                
                # Skip if missing critical information
                if not src_ip or not dst_ip or not src_mac or not dst_mac:
                    if debug:
                        print(f"[DEBUG] Packet #{packet_count} - Skipping, missing critical info: src_ip={src_ip}, dst_ip={dst_ip}, src_mac={src_mac}, dst_mac={dst_mac}")
                    continue
                
                # Skip invalid MAC addresses
                if not is_valid_mac(src_mac) or not is_valid_mac(dst_mac):
                    if debug:
                        print(f"[DEBUG] Packet #{packet_count} - Skipping, invalid MAC: src_mac={src_mac}, dst_mac={dst_mac}")
                    continue
                
                # Get frame length for byte counts
                frame_length = int(pkt.length) if hasattr(pkt, 'length') else 0
                
                # Extract protocols
                transport_protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
                app_protocol = pkt.highest_layer if hasattr(pkt, 'highest_layer') else None
                
                if debug:
                    print(f"[DEBUG] Packet #{packet_count} - IP: {src_ip} -> {dst_ip}, Protocol: {transport_protocol}, App: {app_protocol}")
                    if vlan_id:
                        print(f"[DEBUG] Packet #{packet_count} - VLAN ID: {vlan_id}, DSField: {dsfield}")
                
                # Get frame protocols
                frame_protocols = pkt.frame_info.protocols if hasattr(pkt, 'frame_info') and hasattr(pkt.frame_info, 'protocols') else ""
                
                # Extract port information
                src_port = None
                dst_port = None
                src_tcp_port = None
                dst_tcp_port = None
                src_udp_port = None
                dst_udp_port = None
                stream_id = None
                tcp_flags = set()
                
                # TCP-specific information
                if hasattr(pkt, 'tcp'):
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                    src_tcp_port = src_port
                    dst_tcp_port = dst_port
                    
                    # Get TCP stream ID if available
                    stream_id = pkt.tcp.stream if hasattr(pkt.tcp, 'stream') else None
                    
                    # Get TCP flags
                    if hasattr(pkt.tcp, 'flags'):
                        # Check for SYN, ACK, RST, FIN flags
                        if hasattr(pkt.tcp.flags, 'syn') and int(pkt.tcp.flags.syn) == 1:
                            tcp_flags.add('SYN')
                        if hasattr(pkt.tcp.flags, 'ack') and int(pkt.tcp.flags.ack) == 1:
                            tcp_flags.add('ACK')
                        if hasattr(pkt.tcp.flags, 'reset') and int(pkt.tcp.flags.reset) == 1:
                            tcp_flags.add('RST')
                        if hasattr(pkt.tcp.flags, 'fin') and int(pkt.tcp.flags.fin) == 1:
                            tcp_flags.add('FIN')
                
                # UDP-specific information
                elif hasattr(pkt, 'udp'):
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                    src_udp_port = src_port
                    dst_udp_port = dst_port
                
                # Create a conversation key that works in both directions
                # We need to know which way is A→B and which is B→A
                # Create a canonical conversation key that works in both directions
                # Sort IP addresses to get consistent key regardless of direction
                if (src_ip, src_port) < (dst_ip, dst_port):
                    conv_key = (src_ip, dst_ip, src_port, dst_port, transport_protocol)
                    is_forward = True
                else:
                    conv_key = (dst_ip, src_ip, dst_port, src_port, transport_protocol)
                    is_forward = False
                
                # Update conversation data
                conv = conversation_data[conv_key]
                
                # Set initial values if this is the first packet in the conversation
                if conv['source_ip'] is None:
                    conv['source_ip'] = src_ip if is_forward else dst_ip
                    conv['source_mac'] = src_mac if is_forward else dst_mac
                    conv['target_ip'] = dst_ip if is_forward else src_ip
                    conv['target_mac'] = dst_mac if is_forward else src_mac
                    conv['protocol'] = transport_protocol
                    conv['app_protocol'] = app_protocol
                    conv['stream_id'] = stream_id
                    conv['vlan_id'] = vlan_id
                    conv['dsfield'] = dsfield
                    conv['ip_version'] = ip_version
                    
                    # Set port information according to protocol
                    if transport_protocol == 'TCP':
                        conv['source_tcp_port'] = src_tcp_port if is_forward else dst_tcp_port
                        conv['target_tcp_port'] = dst_tcp_port if is_forward else src_tcp_port
                    elif transport_protocol == 'UDP':
                        conv['source_udp_port'] = src_udp_port if is_forward else dst_udp_port
                        conv['target_udp_port'] = dst_udp_port if is_forward else src_udp_port
                
                # Update timestamps
                if conv['first_seen'] is None or pkt_time < conv['first_seen']:
                    conv['first_seen'] = pkt_time
                if conv['last_seen'] is None or pkt_time > conv['last_seen']:
                    conv['last_seen'] = pkt_time
                
                # Update frame protocols
                if frame_protocols:
                    conv['frame_protocols'].add(frame_protocols)
                
                # Update TCP flags
                conv['tcp_flags'].update(tcp_flags)
                
                # Update packet and byte counts based on direction
                # For A→B direction (original direction from key creation)
                if (is_forward and src_ip == conv['source_ip']) or (not is_forward and dst_ip == conv['source_ip']):
                    conv['packets_a_to_b'] += 1
                    conv['bytes_a_to_b'] += frame_length
                # For B→A direction
                else:
                    conv['packets_b_to_a'] += 1
                    conv['bytes_b_to_a'] += frame_length
                
                # Update conversation status based on TCP flags or packet counts
                if transport_protocol == 'TCP':
                    if 'RST' in conv['tcp_flags']:
                        conv['conversation_status'] = 'request-rejected'
                    elif 'SYN' in conv['tcp_flags'] and 'ACK' in conv['tcp_flags']:
                        if conv['packets_b_to_a'] > 0:
                            conv['conversation_status'] = 'request-accepted'
                        else:
                            conv['conversation_status'] = 'request-rejected'
                    elif 'SYN' in conv['tcp_flags'] and conv['packets_b_to_a'] == 0:
                        conv['conversation_status'] = 'no-response'
                    elif conv['packets_b_to_a'] > 0:
                        conv['conversation_status'] = 'response'
                else:
                    # For non-TCP protocols, use simple heuristic based on return traffic
                    if conv['packets_b_to_a'] > 0:
                        conv['conversation_status'] = 'response'
                    else:
                        conv['conversation_status'] = 'no-response'
                
                # Update the original device_info structure as well for backward compatibility
                # Process source device
                record = device_info[src_mac]
                if record['vendor'] is None:
                    record['vendor'] = get_vendor(src_mac)
                
                if record['first_seen'] is None or pkt_time < record['first_seen']:
                    record['first_seen'] = pkt_time
                if record['last_seen'] is None or pkt_time > record['last_seen']:
                    record['last_seen'] = pkt_time
                record['packet_count'] += 1
                
                if src_ip:
                    ip_record = record['ip_connections'][src_ip]
                    if ip_record['first_seen'] is None or pkt_time < ip_record['first_seen']:
                        ip_record['first_seen'] = pkt_time
                    if ip_record['last_seen'] is None or pkt_time > ip_record['last_seen']:
                        ip_record['last_seen'] = pkt_time
                    ip_record['packet_count'] += 1
                    
                    if src_tcp_port:
                        ip_record['tcp_ports'].add(src_tcp_port)
                    if src_udp_port:
                        ip_record['udp_ports'].add(src_udp_port)
                
                # Process destination device
                record = device_info[dst_mac]
                if record['vendor'] is None:
                    record['vendor'] = get_vendor(dst_mac)
                
                if record['first_seen'] is None or pkt_time < record['first_seen']:
                    record['first_seen'] = pkt_time
                if record['last_seen'] is None or pkt_time > record['last_seen']:
                    record['last_seen'] = pkt_time
                record['packet_count'] += 1
                
                if dst_ip:
                    ip_record = record['ip_connections'][dst_ip]
                    if ip_record['first_seen'] is None or pkt_time < ip_record['first_seen']:
                        ip_record['first_seen'] = pkt_time
                    if ip_record['last_seen'] is None or pkt_time > ip_record['last_seen']:
                        ip_record['last_seen'] = pkt_time
                    ip_record['packet_count'] += 1
                    
                    if dst_tcp_port:
                        ip_record['tcp_ports'].add(dst_tcp_port)
                    if dst_udp_port:
                        ip_record['udp_ports'].add(dst_udp_port)
                
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
    
    # Calculate durations for all conversations
    for conv_key, conv in conversation_data.items():
        if conv['first_seen'] is not None and conv['last_seen'] is not None:
            conv['duration'] = conv['last_seen'] - conv['first_seen']
    
    print(f"[+] Processed {processed_count} of {packet_count} packets")
    print(f"[+] Found {len(conversation_data)} unique conversations")
    
    return device_info, conversation_data

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

def deduplicate_protocols(protocols_set):
    """Deduplicate redundant protocol indicators in frame protocols."""
    if not protocols_set:
        return ""
    
    # Convert to a list of protocols, often delimited by ':'
    all_protocols = []
    for protocol_string in protocols_set:
        # Split by colon if present
        parts = protocol_string.split(':')
        all_protocols.extend(parts)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_protocols = []
    for protocol in all_protocols:
        # Skip empty strings
        if not protocol.strip():
            continue
        # Only add if not already seen
        if protocol not in seen:
            seen.add(protocol)
            unique_protocols.append(protocol)
    
    # Join back with commas
    return ",".join(unique_protocols)

def write_conversation_report(conversation_data, output_csv):
    """Write conversation data to a CSV file."""
    try:
        # Create outputs directory if it doesn't exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        output_path = os.path.join(OUTPUT_DIR, output_csv)
        
        with open(output_path, "w", newline="", encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow([
                "Source IP",
                "Source MAC",
                "Source TCP Port",
                "Source UDP Port",
                "Target IP",
                "Target MAC",
                "Target TCP Port", 
                "Target UDP Port",
                "Protocol",
                "Application Protocol",
                "Packets A->B",
                "Packets B->A",
                "Bytes A->B",
                "Bytes B->A",
                "First Seen",
                "Last Seen",
                "Duration (seconds)",
                "Conversation Status",
                "TCP Flags",
                "Stream ID",
                "Frame Protocols",
                "VLAN ID",
                "DiffServ Field",
                "IP Version"
            ])
            
            # Generate one row per conversation
            for conv_key, conv in conversation_data.items():
                # Format timestamps as ISO strings if they exist
                first_seen = datetime.fromtimestamp(conv['first_seen']).isoformat() if conv['first_seen'] else ""
                last_seen = datetime.fromtimestamp(conv['last_seen']).isoformat() if conv['last_seen'] else ""
                
                # Format TCP flags and frame protocols as comma-separated lists
                tcp_flags_str = ",".join(sorted(conv['tcp_flags'])) if conv['tcp_flags'] else ""
                frame_protocols_str = deduplicate_protocols(conv['frame_protocols'])
                
                writer.writerow([
                    conv['source_ip'],
                    conv['source_mac'],
                    conv['source_tcp_port'],
                    conv['source_udp_port'],
                    conv['target_ip'],
                    conv['target_mac'],
                    conv['target_tcp_port'],
                    conv['target_udp_port'],
                    conv['protocol'],
                    conv['app_protocol'],
                    conv['packets_a_to_b'],
                    conv['packets_b_to_a'],
                    conv['bytes_a_to_b'],
                    conv['bytes_b_to_a'],
                    first_seen,
                    last_seen,
                    round(conv['duration'], 3) if conv['duration'] else "",
                    conv['conversation_status'],
                    tcp_flags_str,
                    conv['stream_id'],
                    frame_protocols_str,
                    conv['vlan_id'],
                    conv['dsfield'],
                    conv['ip_version']
                ])
        
        print(f"\n[+] Conversation report generated: {output_path}")
        return True
    except PermissionError:
        print(f"\n[!] Permission denied when writing to {output_path}")
        print(f"[!] Try specifying a different output file with --output")
        return False
    except Exception as e:
        print(f"\n[!] Error writing conversation CSV file: {e}")
        return False

def write_json_report(device_info, conversation_data, pcap_file, output_json):
    """Write device and conversation data to a JSON file optimized for visualization."""
    try:
        # Create outputs directory if it doesn't exist
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        output_path = os.path.join(OUTPUT_DIR, output_json)
        
        # Create nodes from device_info
        nodes = []
        for mac, info in device_info.items():
            # Collect all IPs associated with this MAC
            ips = list(info.get('ip_connections', {}).keys())
            
            # Collect all TCP and UDP ports across all IPs
            all_tcp_ports = set()
            all_udp_ports = set()
            for ip_info in info.get('ip_connections', {}).values():
                all_tcp_ports.update(ip_info.get('tcp_ports', set()))
                all_udp_ports.update(ip_info.get('udp_ports', set()))
            
            # Format timestamps
            first_seen = datetime.fromtimestamp(info['first_seen']).isoformat() if info.get('first_seen') else None
            last_seen = datetime.fromtimestamp(info['last_seen']).isoformat() if info.get('last_seen') else None
            
            # Create node entry
            node = {
                "id": mac,
                "label": mac,
                "vendor": info.get('vendor') or "Unknown",
                "ips": ips,
                "tcp_ports": sorted(all_tcp_ports) if all_tcp_ports else [],
                "udp_ports": sorted(all_udp_ports) if all_udp_ports else [],
                "packet_count": info.get('packet_count', 0),
                "first_seen": first_seen,
                "last_seen": last_seen
            }
            nodes.append(node)
        
        # Create links from conversation_data
        links = []
        for conv_key, conv in conversation_data.items():
            # Format timestamps
            first_seen = datetime.fromtimestamp(conv['first_seen']).isoformat() if conv.get('first_seen') else None
            last_seen = datetime.fromtimestamp(conv['last_seen']).isoformat() if conv.get('last_seen') else None
            
            # Create link entry
            link = {
                "source": conv['source_mac'],
                "target": conv['target_mac'],
                "source_ip": conv['source_ip'],
                "target_ip": conv['target_ip'],
                "protocol": conv['protocol'],
                "app_protocol": conv['app_protocol'],
                "source_tcp_port": conv['source_tcp_port'],
                "target_tcp_port": conv['target_tcp_port'],
                "source_udp_port": conv['source_udp_port'],
                "target_udp_port": conv['target_udp_port'],
                "packets_a_to_b": conv['packets_a_to_b'],
                "packets_b_to_a": conv['packets_b_to_a'],
                "bytes_a_to_b": conv['bytes_a_to_b'],
                "bytes_b_to_a": conv['bytes_b_to_a'],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "duration": round(conv['duration'], 3) if conv.get('duration') else None,
                "conversation_status": conv['conversation_status'],
                "tcp_flags": sorted(list(conv['tcp_flags'])) if conv.get('tcp_flags') else [],
                "stream_id": conv['stream_id'],
                "frame_protocols": deduplicate_protocols(conv['frame_protocols']),
                "vlan_id": conv['vlan_id'],
                "dsfield": conv['dsfield'],
                "ip_version": conv['ip_version']
            }
            links.append(link)
        
        # Create metadata
        metadata = {
            "generated_at": datetime.now().isoformat(),
            "pcap_file": os.path.basename(pcap_file),
            "total_nodes": len(nodes),
            "total_links": len(links)
        }
        
        # Create final JSON structure
        network_data = {
            "metadata": metadata,
            "nodes": nodes,
            "links": links
        }
        
        # Write JSON to file
        with open(output_path, 'w') as json_file:
            json.dump(network_data, json_file, indent=2)
        
        print(f"\n[+] JSON report generated: {output_path}")
        return True
    except PermissionError:
        print(f"\n[!] Permission denied when writing to {output_path}")
        print(f"[!] Try specifying a different output file with --output")
        return False
    except Exception as e:
        print(f"\n[!] Error writing JSON file: {e}")
        return False

def main():
    # Check dependencies before proceeding
    if not check_tshark_installation():
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="PCAP Asset and Conversation Discovery Tool")
    parser.add_argument("pcap_file", help="Path to the pcap file", nargs='?')
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--download-instructions", action="store_true", help="Show instructions for downloading the OUI database")
    parser.add_argument("--output", help="Output base filename (default: <pcap_name>)")
    parser.add_argument("--format", choices=["csv", "json", "both"], default="both", 
                       help="Output format: csv, json, or both (default: both)")
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

    # Extract both device info and conversation data
    start_time = time.time()
    result = extract_device_info(args.pcap_file, debug=args.debug)
    elapsed_time = time.time() - start_time
    
    if not result:
        print("\n[-] No data extracted from PCAP file.")
        return
    
    device_info, conversation_data = result

    if device_info:
        print(f"\n[+] Devices Found: {len(device_info)}")
        print(f"[+] Conversations Found: {len(conversation_data)}")
        print(f"[+] Processing time: {elapsed_time:.2f} seconds")
    else:
        print("\n[-] No devices found.")
        return

    # Generate output filenames
    base = os.path.splitext(os.path.basename(args.pcap_file))[0]
    base_output = args.output if args.output else base
    
    device_csv = f"{base_output}-device_info.csv"
    conversation_csv = f"{base_output}-conversation_info.csv"
    network_json = f"{base_output}-network_data.json"
    
    # Write reports based on format option
    if args.format in ["csv", "both"]:
        write_csv_report(device_info, device_csv)
        write_conversation_report(conversation_data, conversation_csv)
    
    if args.format in ["json", "both"]:
        write_json_report(device_info, conversation_data, args.pcap_file, network_json)

if __name__ == "__main__":
    main()
