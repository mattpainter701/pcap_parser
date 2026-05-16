import cProfile
import sys
from collections import defaultdict
import pyshark
import argparse
import csv
import os
import re
import time
import json
import pstats
import tracemalloc
from dataclasses import dataclass, field
from functools import lru_cache
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    # tqdm-less no-op progress stub
    class _ProgressStub:
        def update(self, n=1): pass
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def tqdm(iterable=None, **kwargs):
        if iterable is not None:
            return iterable
        return _ProgressStub()

from pcap_regression import (
    run_regression_suite,
    summarize_regression_results,
    validate_conversation_csv,
    validate_device_csv,
    validate_network_json,
)

OUI_FILE = "oui.txt"
OUI_CSV_FILE = "oui.csv"
OUTPUT_DIR = "outputs"


def _resolve_output_path(output_name: str | Path, output_dir: str | Path | None = None) -> Path:
    base_dir = Path(output_dir) if output_dir is not None else Path(OUTPUT_DIR)
    return base_dir / output_name


def _expand_user_path(path: str | Path | None) -> Path | None:
    if path is None:
        return None
    return Path(path).expanduser()


def _discover_capture_files(pcap_path: str | Path) -> list[Path]:
    input_path = Path(pcap_path)
    if input_path.is_dir():
        capture_files = [
            path
            for path in sorted(input_path.iterdir())
            if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng", ".cap"}
        ]
        return capture_files
    return [input_path]


def _build_output_base(capture_path: str | Path, output_prefix: str | None = None) -> str:
    stem = Path(capture_path).stem
    if output_prefix:
        return f"{output_prefix}-{stem}"
    return stem


def _mac_to_oui(mac: str | None) -> str | None:
    """Normalize a MAC address to the OUI key format used by the IEEE DB."""
    if not mac:
        return None

    try:
        normalized_mac = mac.replace("-", ":")
        parts = normalized_mac.split(":")
        if len(parts) < 3:
            return None
        return ":".join(parts[:3]).upper()
    except Exception:
        return None


@lru_cache(maxsize=4096)
def _lookup_vendor_by_oui(oui: str | None) -> str | None:
    if not oui:
        return None
    return ieee_oui_db.get(oui)


@dataclass(slots=True)
class PortSummary:
    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    packet_count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass(slots=True)
class DeviceSummary:
    vendor: str | None = None
    packet_count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    ip_connections: defaultdict[str, PortSummary] = field(default_factory=lambda: defaultdict(PortSummary))

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass(slots=True)
class ConversationSummary:
    source_ip: str | None = None
    source_mac: str | None = None
    source_tcp_port: int | None = None
    source_udp_port: int | None = None
    target_ip: str | None = None
    target_mac: str | None = None
    target_tcp_port: int | None = None
    target_udp_port: int | None = None
    protocol: str | None = None
    app_protocol: str | None = None
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    duration: float = 0
    conversation_status: str = "unknown"
    tcp_flags: set[str] = field(default_factory=set)
    stream_id: str | None = None
    frame_protocols: set[str] = field(default_factory=set)
    vlan_id: str | None = None
    dsfield: str | None = None
    ip_version: int | None = None

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


SERVICE_PORT_MAP: dict[int, tuple[str, float]] = {
    22: ("SSH", 0.98),
    25: ("SMTP", 0.95),
    53: ("DNS", 0.98),
    80: ("HTTP", 0.95),
    110: ("POP3", 0.95),
    123: ("NTP", 0.96),
    143: ("IMAP", 0.95),
    161: ("SNMP", 0.94),
    389: ("LDAP", 0.93),
    443: ("HTTPS", 0.98),
    445: ("SMB", 0.97),
    587: ("SMTP", 0.92),
    993: ("IMAPS", 0.96),
    995: ("POP3S", 0.96),
    3306: ("MySQL", 0.95),
    3389: ("RDP", 0.96),
    5432: ("PostgreSQL", 0.95),
    5060: ("SIP", 0.90),
    6379: ("Redis", 0.92),
    8080: ("HTTP", 0.85),
    8443: ("HTTPS", 0.90),
    27017: ("MongoDB", 0.92),
}

APP_PROTOCOL_SERVICE_MAP: dict[str, str] = {
    "DNS": "DNS",
    "FTP": "FTP",
    "HTTP": "HTTP",
    "HTTP2": "HTTP",
    "HTTPS": "HTTPS",
    "IMAP": "IMAP",
    "IMAPS": "IMAPS",
    "LDAP": "LDAP",
    "MQTT": "MQTT",
    "MYSQL": "MySQL",
    "NTP": "NTP",
    "POP3": "POP3",
    "POP3S": "POP3S",
    "POSTGRESQL": "PostgreSQL",
    "RDP": "RDP",
    "REDIS": "Redis",
    "SIP": "SIP",
    "SMB": "SMB",
    "SMTP": "SMTP",
    "SSH": "SSH",
    "TLS": "HTTPS",
    "SSL": "HTTPS",
}

DIFFSERV_DSCP_NAME_MAP: dict[int, str] = {
    0: "CS0",
    8: "CS1",
    10: "AF11",
    12: "AF12",
    14: "AF13",
    16: "CS2",
    18: "AF21",
    20: "AF22",
    22: "AF23",
    24: "CS3",
    26: "AF31",
    28: "AF32",
    30: "AF33",
    32: "CS4",
    34: "AF41",
    36: "AF42",
    38: "AF43",
    40: "CS5",
    46: "EF",
    48: "CS6",
    56: "CS7",
}

DIFFSERV_ECN_NAME_MAP: dict[int, str] = {
    0: "Not-ECT",
    1: "ECT(1)",
    2: "ECT(0)",
    3: "CE",
}


def _normalize_protocol_name(value: str | None) -> str | None:
    if not value:
        return None
    normalized = re.sub(r"[^A-Z0-9]+", "", value.upper())
    return normalized or None


def interpret_diffserv_field(dsfield: str | int | None) -> str | None:
    """Return a compact human-readable DiffServ interpretation.

    The field is treated as the full 8-bit DS field, where the upper 6 bits
    encode the DSCP and the lower 2 bits encode ECN.
    """

    if dsfield in (None, ""):
        return None

    try:
        value = int(str(dsfield), 0)
    except (TypeError, ValueError):
        return None

    if value < 0 or value > 0xFF:
        return None

    dscp = value >> 2
    ecn = value & 0x03
    dscp_label = DIFFSERV_DSCP_NAME_MAP.get(dscp, f"DSCP {dscp}")
    ecn_label = DIFFSERV_ECN_NAME_MAP.get(ecn, f"ECN {ecn}")
    return f"{dscp_label} / {ecn_label}"


def infer_service_name(
    *,
    source_tcp_port: int | None = None,
    target_tcp_port: int | None = None,
    source_udp_port: int | None = None,
    target_udp_port: int | None = None,
    app_protocol: str | None = None,
    protocol: str | None = None,
) -> tuple[str | None, float]:
    """Infer a likely service label and confidence score from ports and protocol hints."""

    app_name = _normalize_protocol_name(app_protocol)
    transport_name = _normalize_protocol_name(protocol)
    candidate_scores: dict[str, float] = {}

    if app_name:
        mapped_service = APP_PROTOCOL_SERVICE_MAP.get(app_name)
        if mapped_service:
            candidate_scores[mapped_service] = max(candidate_scores.get(mapped_service, 0.0), 0.70)

    for port in (source_tcp_port, target_tcp_port, source_udp_port, target_udp_port):
        if port is None:
            continue

        service = SERVICE_PORT_MAP.get(int(port))
        if not service:
            continue

        service_name, base_confidence = service
        confidence = base_confidence
        if app_name and APP_PROTOCOL_SERVICE_MAP.get(app_name) == service_name:
            confidence = max(confidence, 0.98)
        elif transport_name and transport_name in {"TCP", "UDP"}:
            confidence = max(confidence, 0.80)

        candidate_scores[service_name] = max(candidate_scores.get(service_name, 0.0), confidence)

    if not candidate_scores:
        return (app_protocol, 0.0) if app_protocol else (None, 0.0)

    service_name, confidence = max(candidate_scores.items(), key=lambda item: item[1])
    return service_name, confidence


def _select_display_app_protocol(conv: ConversationSummary) -> str | None:
    service_name, confidence = infer_service_name(
        source_tcp_port=conv.get("source_tcp_port"),
        target_tcp_port=conv.get("target_tcp_port"),
        source_udp_port=conv.get("source_udp_port"),
        target_udp_port=conv.get("target_udp_port"),
        app_protocol=conv.get("app_protocol"),
        protocol=conv.get("protocol"),
    )
    if service_name and confidence >= 0.75:
        return service_name
    return conv.get("app_protocol")

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
                        normalized = _mac_to_oui(mac)
                        if normalized:
                            oui_dict[normalized] = vendor
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
                            normalized = _mac_to_oui(mac)
                            if normalized:
                                oui_dict[normalized] = vendor
            
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
    _lookup_vendor_by_oui.cache_clear()
except Exception as e:
    print(f"[!] Failed to load IEEE OUI database: {e}")

def get_vendor(mac: str) -> str | None:
    """Return vendor based on MAC OUI."""
    return _lookup_vendor_by_oui(_mac_to_oui(mac))



def _populate_device_vendors(device_info: dict[str, DeviceSummary]) -> None:
    """Populate missing vendor names once per device after packet aggregation."""
    vendor_by_oui: dict[str | None, str | None] = {}
    for mac, info in device_info.items():
        if info.vendor is not None:
            continue
        oui = _mac_to_oui(mac)
        if oui not in vendor_by_oui:
            vendor_by_oui[oui] = _lookup_vendor_by_oui(oui)
        info.vendor = vendor_by_oui[oui]

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

def extract_device_info(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
    """
    Extracts device information from all packets in the provided pcap file.
    Now extracting detailed conversation data between pairs of IP addresses.

    Args:
        pcap_file: Path to a PCAP/PCAPNG file.
        debug: Enable debug-level logging per packet.
        collect_metrics: Return a third metrics dict alongside (device_info, conversation_data).
        bpf_filter: Optional BPF-style display filter passed to PyShark (e.g. "ip", "tcp.port==443").
    """
    print(f"\n[+] Loading capture file: {pcap_file}")
    if bpf_filter:
        print(f"[+] Applying display filter: {bpf_filter}")
    
    try:
        kwargs = {"keep_packets": False, "use_json": True}
        if bpf_filter:
            kwargs["display_filter"] = bpf_filter
        capture = pyshark.FileCapture(pcap_file, **kwargs)
    except Exception as e:
        print(f"[!] Error opening capture file: {e}")
        if bpf_filter:
            print("[!] The display filter may be invalid. Try without --filter.")
        else:
            print("[!] Make sure the file exists and is a valid PCAP file")
        return None

    # Track device information keyed by MAC address
    device_info = defaultdict(DeviceSummary)

    # Track conversations between pairs of endpoints.
    conversation_data = defaultdict(ConversationSummary)

    packet_count = 0
    processed_count = 0
    
    # Try to get total packet estimate for progress bar
    total_estimate = None
    try:
        total_estimate = int(capture.captured_length)
    except (TypeError, ValueError, AttributeError):
        pass
    
    progress = tqdm(desc=f"Parsing {Path(pcap_file).name}", unit=" pkt",
                    total=total_estimate, disable=(not os.isatty(1)))
    
    try:
        for pkt in capture:
            packet_count += 1
            if packet_count % 100 == 0:
                progress.update(100)
            try:
                transport_protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else None
                if transport_protocol not in {"TCP", "UDP"}:
                    if debug:
                        print(f"[DEBUG] Packet #{packet_count} - Skipping unsupported transport: {transport_protocol}")
                    continue

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
                
                # Extract application protocol after non-TCP/UDP packets have been filtered.
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
                if conv.source_ip is None:
                    conv.source_ip = src_ip if is_forward else dst_ip
                    conv.source_mac = src_mac if is_forward else dst_mac
                    conv.target_ip = dst_ip if is_forward else src_ip
                    conv.target_mac = dst_mac if is_forward else src_mac
                    conv.protocol = transport_protocol
                    conv.app_protocol = app_protocol
                    conv.stream_id = stream_id
                    conv.vlan_id = vlan_id
                    conv.dsfield = dsfield
                    conv.ip_version = ip_version
                    
                    # Set port information according to protocol
                    if transport_protocol == 'TCP':
                        conv.source_tcp_port = src_tcp_port if is_forward else dst_tcp_port
                        conv.target_tcp_port = dst_tcp_port if is_forward else src_tcp_port
                    elif transport_protocol == 'UDP':
                        conv.source_udp_port = src_udp_port if is_forward else dst_udp_port
                        conv.target_udp_port = dst_udp_port if is_forward else src_udp_port
                
                # Update timestamps
                if conv.first_seen is None or pkt_time < conv.first_seen:
                    conv.first_seen = pkt_time
                if conv.last_seen is None or pkt_time > conv.last_seen:
                    conv.last_seen = pkt_time
                
                # Update frame protocols
                if frame_protocols:
                    conv.frame_protocols.add(frame_protocols)
                
                # Update TCP flags
                conv.tcp_flags.update(tcp_flags)
                
                # Update packet and byte counts based on direction
                # For A→B direction (original direction from key creation)
                if (is_forward and src_ip == conv.source_ip) or (not is_forward and dst_ip == conv.source_ip):
                    conv.packets_a_to_b += 1
                    conv.bytes_a_to_b += frame_length
                # For B→A direction
                else:
                    conv.packets_b_to_a += 1
                    conv.bytes_b_to_a += frame_length
                
                # Update conversation status based on TCP flags or packet counts
                if transport_protocol == 'TCP':
                    if 'RST' in conv.tcp_flags:
                        conv.conversation_status = 'request-rejected'
                    elif 'SYN' in conv.tcp_flags and 'ACK' in conv.tcp_flags:
                        if conv.packets_b_to_a > 0:
                            conv.conversation_status = 'request-accepted'
                        else:
                            conv.conversation_status = 'request-rejected'
                    elif 'SYN' in conv.tcp_flags and conv.packets_b_to_a == 0:
                        conv.conversation_status = 'no-response'
                    elif conv.packets_b_to_a > 0:
                        conv.conversation_status = 'response'
                else:
                    # For non-TCP protocols, use simple heuristic based on return traffic
                    if conv.packets_b_to_a > 0:
                        conv.conversation_status = 'response'
                    else:
                        conv.conversation_status = 'no-response'
                
                # Update device summaries after conversation aggregation. Vendor
                # attribution is intentionally batched after the packet loop so the
                # hot path only mutates counters and sets.
                record = device_info[src_mac]
                if record.first_seen is None or pkt_time < record.first_seen:
                    record.first_seen = pkt_time
                if record.last_seen is None or pkt_time > record.last_seen:
                    record.last_seen = pkt_time
                record.packet_count += 1

                ip_record = record.ip_connections[src_ip]
                if ip_record.first_seen is None or pkt_time < ip_record.first_seen:
                    ip_record.first_seen = pkt_time
                if ip_record.last_seen is None or pkt_time > ip_record.last_seen:
                    ip_record.last_seen = pkt_time
                ip_record.packet_count += 1
                if src_tcp_port:
                    ip_record.tcp_ports.add(src_tcp_port)
                if src_udp_port:
                    ip_record.udp_ports.add(src_udp_port)

                record = device_info[dst_mac]
                if record.first_seen is None or pkt_time < record.first_seen:
                    record.first_seen = pkt_time
                if record.last_seen is None or pkt_time > record.last_seen:
                    record.last_seen = pkt_time
                record.packet_count += 1

                ip_record = record.ip_connections[dst_ip]
                if ip_record.first_seen is None or pkt_time < ip_record.first_seen:
                    ip_record.first_seen = pkt_time
                if ip_record.last_seen is None or pkt_time > ip_record.last_seen:
                    ip_record.last_seen = pkt_time
                ip_record.packet_count += 1
                if dst_tcp_port:
                    ip_record.tcp_ports.add(dst_tcp_port)
                if dst_udp_port:
                    ip_record.udp_ports.add(dst_udp_port)
                
                processed_count += 1
                
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Exception encountered in packet {packet_count}: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[!] Processing interrupted by user")
    except Exception as e:
        print(f"\n[!] Error processing packets: {e}")
    finally:
        progress.close()
        capture.close()
    
    _populate_device_vendors(device_info)

    # Calculate durations for all conversations
    for conv in conversation_data.values():
        if conv.first_seen is not None and conv.last_seen is not None:
            conv.duration = conv.last_seen - conv.first_seen
    
    print(f"[+] Processed {processed_count} of {packet_count} packets")
    print(f"[+] Found {len(conversation_data)} unique conversations")

    if collect_metrics:
        metrics = {
            "packet_count": packet_count,
            "processed_count": processed_count,
            "device_count": len(device_info),
            "conversation_count": len(conversation_data),
        }
        return device_info, conversation_data, metrics
    
    return device_info, conversation_data

def download_oui_instructions():
    """Print instructions for manually downloading the OUI database."""
    print("\n[!] To manually download the IEEE OUI database:")
    print("1. Visit: https://standards-oui.ieee.org/oui/oui.txt")
    print("2. Save the file as 'oui.txt' in the same directory as this script")
    print(f"   ({os.path.dirname(os.path.abspath(__file__))})")
    print("3. Run the script again\n")


@dataclass(frozen=True, slots=True)
class BenchmarkFunctionStat:
    function: str
    primitive_calls: int
    total_calls: int
    total_time_seconds: float
    cumulative_time_seconds: float


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    pcap_file: str
    wall_time_seconds: float
    cpu_time_seconds: float
    peak_memory_bytes: int
    packet_count: int
    processed_packets: int
    device_count: int
    conversation_count: int
    packets_per_second: float
    cpu_utilization_percent: float
    top_functions: list[BenchmarkFunctionStat]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pcap_file": self.pcap_file,
            "wall_time_seconds": self.wall_time_seconds,
            "cpu_time_seconds": self.cpu_time_seconds,
            "peak_memory_bytes": self.peak_memory_bytes,
            "packet_count": self.packet_count,
            "processed_packets": self.processed_packets,
            "device_count": self.device_count,
            "conversation_count": self.conversation_count,
            "packets_per_second": self.packets_per_second,
            "cpu_utilization_percent": self.cpu_utilization_percent,
            "top_functions": [
                {
                    "function": item.function,
                    "primitive_calls": item.primitive_calls,
                    "total_calls": item.total_calls,
                    "total_time_seconds": item.total_time_seconds,
                    "cumulative_time_seconds": item.cumulative_time_seconds,
                }
                for item in self.top_functions
            ],
        }


def _profile_top_functions(profile: cProfile.Profile, limit: int = 10) -> list[BenchmarkFunctionStat]:
    stats = pstats.Stats(profile)
    rows: list[BenchmarkFunctionStat] = []
    for (filename, line_number, function_name), (primitive_calls, total_calls, total_time, cumulative_time, _) in stats.stats.items():
        rows.append(
            BenchmarkFunctionStat(
                function=f"{Path(filename).name}:{line_number}:{function_name}",
                primitive_calls=primitive_calls,
                total_calls=total_calls,
                total_time_seconds=total_time,
                cumulative_time_seconds=cumulative_time,
            )
        )
    rows.sort(key=lambda item: (item.cumulative_time_seconds, item.total_time_seconds, item.total_calls), reverse=True)
    return rows[:limit]


def collect_benchmark_report(
    pcap_file: str | Path,
    *,
    debug: bool = False,
    top_n: int = 10,
    capture_runner=None,
) -> BenchmarkReport:
    runner = capture_runner or extract_device_info
    profiler = cProfile.Profile()

    tracemalloc.start()
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    profiler.enable()
    try:
        result = runner(pcap_file, debug=debug, collect_metrics=True)
    finally:
        profiler.disable()
        cpu_time_seconds = time.process_time() - cpu_start
        wall_time_seconds = time.perf_counter() - wall_start
        _, peak_memory_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    if not result:
        raise RuntimeError("benchmark capture produced no data")

    if len(result) == 3:
        device_info, conversation_data, metrics = result
    else:
        device_info, conversation_data = result
        metrics = {}

    packet_count = int(metrics.get("packet_count", metrics.get("processed_count", 0)))
    processed_packets = int(metrics.get("processed_count", packet_count))
    packets_per_second = processed_packets / wall_time_seconds if wall_time_seconds else 0.0
    cpu_utilization_percent = (cpu_time_seconds / wall_time_seconds * 100.0) if wall_time_seconds else 0.0

    return BenchmarkReport(
        pcap_file=str(pcap_file),
        wall_time_seconds=wall_time_seconds,
        cpu_time_seconds=cpu_time_seconds,
        peak_memory_bytes=peak_memory_bytes,
        packet_count=packet_count,
        processed_packets=processed_packets,
        device_count=len(device_info),
        conversation_count=len(conversation_data),
        packets_per_second=packets_per_second,
        cpu_utilization_percent=cpu_utilization_percent,
        top_functions=_profile_top_functions(profiler, limit=top_n),
    )


def render_benchmark_report(report: BenchmarkReport) -> str:
    lines = [
        "Benchmark report",
        f"PCAP: {report.pcap_file}",
        f"Wall time: {report.wall_time_seconds:.3f}s",
        f"CPU time: {report.cpu_time_seconds:.3f}s",
        f"Peak memory: {report.peak_memory_bytes / (1024 * 1024):.2f} MiB",
        f"Packets seen: {report.packet_count}",
        f"Packets processed: {report.processed_packets}",
        f"Devices found: {report.device_count}",
        f"Conversations found: {report.conversation_count}",
        f"Throughput: {report.packets_per_second:.2f} packets/sec",
        f"CPU utilization: {report.cpu_utilization_percent:.1f}%",
        "Top functions by cumulative time:",
    ]
    for index, item in enumerate(report.top_functions, start=1):
        lines.append(
            f"{index}. {item.function} | calls {item.primitive_calls}/{item.total_calls} | "
            f"self {item.total_time_seconds:.3f}s | cum {item.cumulative_time_seconds:.3f}s"
        )
    return "\n".join(lines)


def write_benchmark_report(report: BenchmarkReport, path: str | Path) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return output_path


def _validate_generated_outputs(device_csv=None, conversation_csv=None, network_json=None, output_dir: str | Path | None = None):
    """Validate generated output files against the regression contracts."""
    errors = []
    if device_csv:
        errors.extend(validate_device_csv(_resolve_output_path(device_csv, output_dir)))
    if conversation_csv:
        errors.extend(validate_conversation_csv(_resolve_output_path(conversation_csv, output_dir)))
    if network_json:
        errors.extend(validate_network_json(_resolve_output_path(network_json, output_dir)))
    return errors

def write_csv_report(device_info, output_csv, output_dir: str | Path | None = None):
    """Write device information to a CSV file."""
    try:
        output_path = _resolve_output_path(output_csv, output_dir)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
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

def write_conversation_report(conversation_data, output_csv, output_dir: str | Path | None = None):
    """Write conversation data to a CSV file."""
    try:
        output_path = _resolve_output_path(output_csv, output_dir)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
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
                    _select_display_app_protocol(conv),
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

def write_json_report(device_info, conversation_data, pcap_file, output_json, output_dir: str | Path | None = None):
    """Write device and conversation data to a JSON file optimized for visualization."""
    try:
        output_path = _resolve_output_path(output_json, output_dir)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
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
                "app_protocol": _select_display_app_protocol(conv),
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
                "diffserv_label": interpret_diffserv_field(conv['dsfield']),
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

def _compute_stats(device_info, conversation_data, capture_file, elapsed_time):
    """Compute summary statistics from parsed data without writing output files."""
    total_packets = sum(d.packet_count for d in device_info.values())
    total_bytes = sum(
        c.bytes_a_to_b + c.bytes_b_to_a for c in conversation_data.values()
    )
    protocols = set()
    for c in conversation_data.values():
        if c.protocol:
            protocols.add(c.protocol)
    top_talkers = sorted(
        [(mac, d.packet_count) for mac, d in device_info.items()],
        key=lambda x: x[1], reverse=True
    )[:10]
    top_convos = sorted(
        [(k, c.packets_a_to_b + c.packets_b_to_a) for k, c in conversation_data.items()],
        key=lambda x: x[1], reverse=True
    )[:10]
    total_conversation_packets = sum(c.packets_a_to_b + c.packets_b_to_a for c in conversation_data.values())
    return {
        "pcap_file": str(capture_file),
        "elapsed_seconds": round(elapsed_time, 3),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "device_count": len(device_info),
        "conversation_count": len(conversation_data),
        "protocols_detected": sorted(protocols),
        "top_talkers": [(mac, count) for mac, count in top_talkers],
        "top_conversations": [
            (f"{k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({k[4]})", count)
            for k, count in top_convos
        ],
    }


def _process_capture_file(
    capture_file: str | Path,
    *,
    args: argparse.Namespace,
    output_dir: Path,
    output_base: str,
) -> bool:
    if args.benchmark:
        benchmark_report = collect_benchmark_report(capture_file, debug=args.debug)
        benchmark_output = (
            _expand_user_path(args.benchmark_output)
            if args.benchmark_output
            else _resolve_output_path(f"{output_base}-benchmark.json", output_dir)
        )
        benchmark_path = write_benchmark_report(benchmark_report, benchmark_output)
        print(render_benchmark_report(benchmark_report))
        print(f"\n[+] Benchmark report written: {benchmark_path}")
        return True

    start_time = time.time()
    result = extract_device_info(str(capture_file), debug=args.debug, bpf_filter=args.filter)
    elapsed_time = time.time() - start_time

    if not result:
        print("\n[-] No data extracted from PCAP file.")
        return False

    device_info, conversation_data = result

    if device_info:
        print(f"\n[+] Devices Found: {len(device_info)}")
        print(f"[+] Conversations Found: {len(conversation_data)}")
        print(f"[+] Processing time: {elapsed_time:.2f} seconds")
    else:
        print("\n[-] No devices found.")
        return False

    # --stats-only: print summary and return without writing output files
    if args.stats_only:
        stats = _compute_stats(device_info, conversation_data, capture_file, elapsed_time)
        print("\n" + "=" * 56)
        print("  PARSING STATISTICS")
        print("=" * 56)
        print(f"  PCAP file:          {stats['pcap_file']}")
        print(f"  Processing time:    {stats['elapsed_seconds']}s")
        print(f"  Total packets:      {stats['total_packets']}")
        print(f"  Total bytes:        {stats['total_bytes']}")
        print(f"  Devices:            {stats['device_count']}")
        print(f"  Conversations:      {stats['conversation_count']}")
        print(f"  Protocols detected: {', '.join(stats['protocols_detected']) or 'none'}")
        if stats['top_talkers']:
            print(f"\n  Top talkers (MAC, packets):")
            for mac, count in stats['top_talkers']:
                print(f"    {mac}  {count}")
        if stats['top_conversations']:
            print(f"\n  Top conversations:")
            for label, count in stats['top_conversations']:
                print(f"    {label}  {count}")
        print("=" * 56)
        return True

    device_csv = f"{output_base}-device_info.csv"
    conversation_csv = f"{output_base}-conversation_info.csv"
    network_json = f"{output_base}-network_data.json"

    if args.format in ["csv", "both"]:
        write_csv_report(device_info, device_csv, output_dir=output_dir)
        write_conversation_report(conversation_data, conversation_csv, output_dir=output_dir)

    if args.format in ["json", "both"]:
        write_json_report(device_info, conversation_data, str(capture_file), network_json, output_dir=output_dir)

    if args.validate_output:
        validation_errors = []
        if args.format in ["csv", "both"]:
            validation_errors.extend(
                _validate_generated_outputs(device_csv=device_csv, conversation_csv=conversation_csv, output_dir=output_dir)
            )
        if args.format in ["json", "both"]:
            validation_errors.extend(_validate_generated_outputs(network_json=network_json, output_dir=output_dir))

        if validation_errors:
            print("\n[!] Output validation failed:")
            for error in validation_errors:
                print(f"[!] {error}")
            sys.exit(1)

        print("\n[+] Output validation passed")

    return True


def _run_compare_mode(
    left_path: str,
    right_path: str,
    *,
    args: argparse.Namespace,
    output_dir: Path,
) -> None:
    """Parse two PCAPs and diff their outputs printed to stdout."""
    print(f"\n{'=' * 60}")
    print("  COMPARE MODE")
    print(f"{'=' * 60}")
    
    for label, path in [("LEFT", left_path), ("RIGHT", right_path)]:
        p = _expand_user_path(path)
        if p is None or not os.path.exists(p):
            print(f"[-] {label} file not found: {path}")
            return

    left_devices = []
    left_convs = []
    right_devices = []
    right_convs = []
    
    for label, path, dev_list, conv_list in [
        ("LEFT", left_path, left_devices, left_convs),
        ("RIGHT", right_path, right_devices, right_convs),
    ]:
        print(f"\n  Parsing {label}: {path}")
        result = extract_device_info(
            _expand_user_path(path), debug=args.debug, bpf_filter=args.filter
        )
        if not result:
            print(f"  {label}: no data")
            return
        device_info, conversation_data = result
        dev_list.extend((k, d) for k, d in device_info.items())
        conv_list.extend((k, c) for k, c in conversation_data.items())

    # Compare device counts
    left_dev_count = len(left_devices)
    right_dev_count = len(right_devices)
    left_macs = {k for k, _ in left_devices}
    right_macs = {k for k, _ in right_devices}
    new_macs = right_macs - left_macs
    removed_macs = left_macs - right_macs

    left_conv_count = len(left_convs)
    right_conv_count = len(right_convs)
    left_conv_keys = {k for k, _ in left_convs}
    right_conv_keys = {k for k, _ in right_convs}
    new_convs = right_conv_keys - left_conv_keys
    removed_convs = left_conv_keys - right_conv_keys

    print(f"\n{'=' * 60}")
    print("  DIFF SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Devices:     {left_dev_count} -> {right_dev_count} ({'+' if right_dev_count >= left_dev_count else ''}{right_dev_count - left_dev_count})")
    print(f"  Convs:       {left_conv_count} -> {right_conv_count} ({'+' if right_conv_count >= left_conv_count else ''}{right_conv_count - left_conv_count})")

    if removed_macs:
        print(f"\n  Devices removed ({len(removed_macs)}):")
        for mac in sorted(removed_macs):
            print(f"    - {mac}")
    if new_macs:
        print(f"\n  Devices added ({len(new_macs)}):")
        for mac in sorted(new_macs):
            print(f"    + {mac}")
    if removed_convs:
        print(f"\n  Conversations removed ({len(removed_convs)}):")
        for ck in sorted(removed_convs):
            print(f"    - {ck[0]}:{ck[2]} <-> {ck[1]}:{ck[3]} ({ck[4]})")
    if new_convs:
        print(f"\n  Conversations added ({len(new_convs)}):")
        for ck in sorted(new_convs):
            print(f"    + {ck[0]}:{ck[2]} <-> {ck[1]}:{ck[3]} ({ck[4]})")

    # Packet count diffs for conversations that exist in both
    shared_convs = left_conv_keys & right_conv_keys
    if shared_convs:
        changes = []
        for ck in shared_convs:
            left_c = next(c for k, c in left_convs if k == ck)
            right_c = next(c for k, c in right_convs if k == ck)
            left_pkts = left_c.packets_a_to_b + left_c.packets_b_to_a
            right_pkts = right_c.packets_a_to_b + right_c.packets_b_to_a
            diff = right_pkts - left_pkts
            if diff != 0:
                changes.append((ck, diff, left_pkts, right_pkts))
        if changes:
            print(f"\n  Packet count changes (shared conversations):")
            for ck, diff, left_pkts, right_pkts in sorted(changes, key=lambda x: -abs(x[1]))[:10]:
                print(f"    {ck[0]}:{ck[2]} <-> {ck[1]}:{ck[3]} ({ck[4]}): {left_pkts} -> {right_pkts} ({'+' if diff > 0 else ''}{diff})")

    print(f"\n{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Network Capture Analyzer — extract device inventories, "
                    "conversation flows, and structured reports from PCAP/PCAPNG files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  Parse a single capture and write CSV+JSON reports:
    pcap_parser.py capture.pcapng

  Process all PCAPs in a directory with a common output prefix:
    pcap_parser.py ./captures/ --output myaudit

  Quick statistics without writing output files:
    pcap_parser.py large_capture.pcap --stats-only

  Filter packets with a display filter (Wireshark/tshark syntax):
    pcap_parser.py capture.pcap --filter "tcp.port==443"

  Diff two captures to see what changed:
    pcap_parser.py before.pcap after.pcap --compare

  Profile parsing performance:
    pcap_parser.py capture.pcapng --benchmark

See SPEC.md for the full sprint roadmap.
""",
    )
    parser.add_argument("pcap_file", nargs="*",
                        help="Path to a PCAP/PCAPNG file or directory of captures")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose per-packet debug logging")
    parser.add_argument("--download-instructions", action="store_true",
                        help="Show instructions for downloading the IEEE OUI database")
    parser.add_argument("--output",
                        help="Output base filename (default: derived from pcap file name)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help=f"Directory for generated reports (default: {OUTPUT_DIR})")
    parser.add_argument("--format", choices=["csv", "json", "both"], default="both",
                        help="Output format: csv, json, or both (default: both)")
    parser.add_argument("--validate-output", action="store_true",
                        help="Validate generated output files against the regression schema contracts")
    parser.add_argument("--regression", action="store_true",
                        help="Run the committed golden regression suite and exit")
    parser.add_argument("--regression-manifest", default="fixtures/regression_manifest.json",
                        help="Path to regression fixture manifest (default: fixtures/regression_manifest.json)")
    parser.add_argument("--regression-actual-dir",
                        help="Directory containing regenerated outputs to compare against golden fixtures")
    parser.add_argument("--benchmark", action="store_true",
                        help="Profile parsing and write a performance benchmark report")
    parser.add_argument("--benchmark-output",
                        help="Path for benchmark JSON output (default: outputs/<base>-benchmark.json)")
    parser.add_argument("--stats-only", action="store_true",
                        help="Print summary statistics only — no output files written")
    parser.add_argument("--filter",
                        help="Wireshark/tshark display filter expression (e.g. 'tcp.port==443', 'ip.addr==10.0.0.0/8')")
    parser.add_argument("--compare", action="store_true",
                        help="Diff two captures: pcap_parser.py before.pcap after.pcap --compare")
    args = parser.parse_args()

    if args.download_instructions:
        download_oui_instructions()
        return

    if args.regression:
        manifest_path = _expand_user_path(args.regression_manifest) or Path("fixtures/regression_manifest.json")
        actual_dir = _expand_user_path(args.regression_actual_dir) if args.regression_actual_dir else None
        results = run_regression_suite(manifest_path, actual_dir=actual_dir)
        summary = summarize_regression_results(results)
        print(json.dumps(summary, indent=2))
        if summary["failed"]:
            raise SystemExit(1)
        return

    # Check packet parsing dependency only for commands that process PCAP files.
    if not check_tshark_installation():
        sys.exit(1)

    if not os.path.exists(OUI_FILE) and not os.path.exists(OUI_CSV_FILE):
        print("[!] OUI database file not found.")
        download_oui_instructions()

    output_dir = _expand_user_path(args.output_dir) or Path(OUTPUT_DIR)

    # --compare mode: parse two PCAPs and diff their outputs
    if args.compare:
        if len(args.pcap_file) < 2:
            print("[-] --compare requires exactly two PCAP file paths: pcap_parser.py left.pcap right.pcap --compare")
            return
        left_path, right_path = args.pcap_file[:2]
        _run_compare_mode(left_path, right_path, args=args, output_dir=output_dir)
        return

    # Normal mode: must have exactly one PCAP path
    if not args.pcap_file or len(args.pcap_file) == 0:
        parser.error("the following arguments are required: pcap_file")

    pcap_file_arg = args.pcap_file[0]
    input_path = _expand_user_path(pcap_file_arg)
    if input_path is None or not os.path.exists(input_path):
        print(f"[-] File not found: {pcap_file_arg}")
        return

    capture_files = _discover_capture_files(input_path)

    if input_path.is_dir():
        if not capture_files:
            print(f"[-] No capture files found in directory: {input_path}")
            return
        if args.benchmark:
            print("[-] Benchmark mode currently accepts a single capture file, not a directory.")
            return
        print(f"[+] Found {len(capture_files)} capture file(s) in directory: {input_path}")

    for capture_file in capture_files:
        base_output = _build_output_base(capture_file, args.output if input_path.is_dir() else None)
        if not input_path.is_dir() and args.output:
            base_output = args.output

        if not _process_capture_file(capture_file, args=args, output_dir=output_dir, output_base=base_output):
            if input_path.is_dir():
                continue
            return


if __name__ == "__main__":
    main()


