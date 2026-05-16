"""
pcap_analysis.py — Advanced Analysis Features (Sprint 10)

Device role inference, network segment discovery, topology inference,
anomaly detection, conversation timeline, automated summary report,
GeoIP enrichment, and PCAP slicing.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional

# ---------------------------------------------------------------------------
# Reuse types from pcap_parser (lightweight dependency on dataclass shapes)
# ---------------------------------------------------------------------------

try:
    from pcap_parser import (
        DeviceSummary,
        ConversationSummary,
        _mac_to_oui,
        _lookup_vendor_by_oui,
        get_vendor,
        infer_service_name,
        interpret_diffserv_field,
    )
except ImportError:
    # Fallback stubs so the module can be loaded stand-alone for testing
    @dataclass(slots=True)
    class DeviceSummary:
        vendor: str | None = None
        packet_count: int = 0
        first_seen: float | None = None
        last_seen: float | None = None
        ip_connections: Any = field(default_factory=dict)

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
        diffserv_label: str | None = None
        ip_version: int | None = None
        service_name: str | None = None
        service_confidence: float = 0.0
        traffic_pattern: str | None = None


# ---------------------------------------------------------------------------
# 1. DEVICE ROLE INFERENCE
# ---------------------------------------------------------------------------

# Known MAC OUI prefixes for common device categories
ROUTER_OUIS: set[str] = {
    "CISCO", "JUNIPER", "ARISTA", "MIKROT", "UBIQUITI", "NETGEAR",
    "TPLINK", "D-LINK", "ASUS", "HUAWEI", "ZYXEL", "FORTINET",
    "PALOALTO", "SONICWALL", "WATCHGUARD",
}

SWITCH_OUIS: set[str] = {
    "CISCO", "JUNIPER", "ARISTA", "BROCADE", "HUAWEI", "ZYXEL",
    "NETGEAR", "D-LINK", "TPLINK",
}

FIREWALL_OUIS: set[str] = {
    "PALOALTO", "FORTINET", "CHECKPOINT", "SOPHOS", "WATCHGUARD",
    "BARRACUDA", "SMOOTHWA", "PFSENSE", "UNTANGLE",
}

IOT_OUIS: set[str] = {
    "NEST", "RING", "AMAZON", "ECOBEE", "PHILIPS", "HUE", "LIFX",
    "SAMSUNG", "LG", "SONY", "BELKIN", "WEMO", "WYZE",
    "ROKU", "CHROMECAST", "ESP", "ARDUINO", "RASPBERRY",
}

PRINTER_OUIS: set[str] = {
    "HP", "CANON", "EPSON", "BROTHER", "XEROX", "LEXMARK",
    "RICOH", "KONICA", "ZEBRA", "DYMO", "OKI",
}

VOIP_OUIS: set[str] = {
    "POLYCOM", "CISCO", "AVAYA", "GRANDSTREAM", "YEALINK",
    "SNOM", "MITEL", "PANASONIC", "SPECTRALINK", "VOCERA",
    "AUDIOCODE",
}

CAMERA_OUIS: set[str] = {
    "AXIS", "HIKVISION", "DAHUA", "VIVOTEK", "BOSCH", "PANASONIC",
    "SONY", "SAMSUNG", "LOREX", "SWANN", "AMCREST", "REOLINK",
    "UBIQUITI", "VERKADA", "ARLO",
}

# Service ports that strongly indicate a server role
SERVER_PORTS: set[int] = {
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 3389, 5432, 6379, 8080, 8443, 27017, 9200, 11211,
}

# Service ports that often indicate a client
CLIENT_PORTS: set[int] = set()  # ephemeral ports are dynamic, no fixed set

# Protocol hints
SERVER_PROTOCOLS: set[str] = {
    "HTTP", "HTTPS", "SSH", "SMTP", "DNS", "FTP", "IMAP", "IMAPS",
    "POP3", "POP3S", "MYSQL", "POSTGRESQL", "REDIS", "MONGODB",
    "RDP", "LDAP", "SMB", "NTP", "SIP",
}

CLIENT_PROTOCOLS: set[str] = {
    "HTTP", "HTTPS",
}


def _oui_category(vendor: str | None) -> str:
    """Map a vendor name to a coarse device category based on OUI heuristics."""
    if not vendor:
        return "unknown"
    upper = vendor.upper()
    for keyword in CAMERA_OUIS:
        if keyword in upper:
            return "camera"
    for keyword in PRINTER_OUIS:
        if keyword in upper:
            return "printer"
    for keyword in IOT_OUIS:
        if keyword in upper:
            return "iot"
    for keyword in VOIP_OUIS:
        if keyword in upper:
            return "voip"
    for keyword in FIREWALL_OUIS:
        if keyword in upper:
            return "firewall"
    for keyword in SWITCH_OUIS:
        if keyword in upper:
            return "switch"
    for keyword in ROUTER_OUIS:
        if keyword in upper:
            return "router"
    return "unknown"


def _port_role_hint(tcp_ports: Iterable[int], udp_ports: Iterable[int]) -> float:
    """Return a server-role score (-1..1) based on ports."""
    tcp_set = set(tcp_ports)
    udp_set = set(udp_ports)
    all_ports = tcp_set | udp_set

    if not all_ports:
        return 0.0

    server_ports_found = all_ports & SERVER_PORTS
    # If a device has only well-known server ports (e.g. 22, 80, 443),
    # it behaves like a server.
    if server_ports_found and len(server_ports_found) >= len(all_ports) * 0.5:
        return 0.8

    # If it has mostly low ports (<1024) that aren't server ports,
    # it's ambiguous.
    low_ports = {p for p in all_ports if p < 1024}
    if low_ports and len(low_ports) >= len(all_ports) * 0.5:
        return 0.5

    # If exclusively high ports (>49152, ephemeral), strong client signal.
    high_ports = {p for p in all_ports if p > 49152}
    if high_ports and high_ports == all_ports:
        return -0.6

    return 0.0


def _traffic_pattern_role(
    convs_out: int, convs_in: int, pkts_out: int, pkts_in: int
) -> float:
    """Return a server-role score (-1..1) based on traffic asymmetry."""
    total_conv = convs_out + convs_in
    total_pkts = pkts_out + pkts_in
    if total_conv == 0 and total_pkts == 0:
        return 0.0

    out_ratio = (convs_out / max(total_conv, 1.0)) * 0.5 + (
        pkts_out / max(total_pkts, 1.0)
    ) * 0.5

    if out_ratio > 0.7:
        return -0.5  # mostly initiating → client
    elif out_ratio < 0.3:
        return 0.5  # mostly responding → server
    return 0.0


def infer_device_roles(
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
) -> dict[str, dict[str, Any]]:
    """Infer a device role for each MAC address.

    Returns a dict keyed by MAC with fields:
        role, confidence, evidence (list of signals)
    """
    # Aggregate per-device traffic stats
    device_ports: dict[str, tuple[set[int], set[int]]] = {}
    device_outbound: dict[str, int] = defaultdict(int)
    device_inbound: dict[str, int] = defaultdict(int)
    device_out_conv: dict[str, int] = defaultdict(int)
    device_in_conv: dict[str, int] = defaultdict(int)

    for mac, info in device_info.items():
        tcp = set()
        udp = set()
        for ip_entry in info.ip_connections.values():
            tcp.update(getattr(ip_entry, "tcp_ports", set()))
            udp.update(getattr(ip_entry, "udp_ports", set()))
        device_ports[mac] = (tcp, udp)

    for conv in conversation_data.values():
        if conv.source_mac:
            device_out_conv[conv.source_mac] += 1
            device_outbound[conv.source_mac] += (
                conv.packets_a_to_b + conv.bytes_a_to_b
            )
        if conv.target_mac:
            device_in_conv[conv.target_mac] += 1
            device_inbound[conv.target_mac] += (
                conv.packets_b_to_a + conv.bytes_b_to_a
            )

    roles: dict[str, dict[str, Any]] = {}
    for mac, info in device_info.items():
        vendor = getattr(info, "vendor", None) or get_vendor(mac) if hasattr(
            sys.modules.get("pcap_parser", None), "get_vendor"
        ) else None
        oui_cat = _oui_category(vendor or "Unknown")
        tcp_ports, udp_ports = device_ports.get(mac, (set(), set()))
        port_score = _port_role_hint(tcp_ports, udp_ports)
        traffic_score = _traffic_pattern_role(
            device_out_conv.get(mac, 0),
            device_in_conv.get(mac, 0),
            device_outbound.get(mac, 0),
            device_inbound.get(mac, 0),
        )

        evidence: list[str] = []
        score = 0.0

        # Strongest signal: OUI category
        if oui_cat in ("router", "switch", "firewall"):
            role = oui_cat
            confidence = 0.85
            evidence.append(f"OUI vendor '{vendor}' matches {oui_cat}")
        elif oui_cat in ("iot", "printer", "voip", "camera"):
            role = oui_cat
            confidence = 0.80
            evidence.append(f"OUI vendor '{vendor}' matches {oui_cat}")
        else:
            # Synthesize from port and traffic signals
            combined = port_score * 0.6 + traffic_score * 0.4
            # Strong server-port signal is a reliable indicator
            if port_score > 0.5:
                role = "server"
                confidence = min(port_score * 1.1, 0.85)
                evidence.append(
                    f"Server-like ports ({len(tcp_ports)} TCP / {len(udp_ports)} UDP)"
                )
            elif combined > 0.4:
                role = "server"
                confidence = min(combined * 1.2, 0.85)
                evidence.append(
                    f"Server-like ports ({len(tcp_ports)} TCP / {len(udp_ports)} UDP)"
                )
                if traffic_score > 0.3:
                    evidence.append("Traffic asymmetry suggests server (responder)")
            elif combined < -0.3:
                role = "workstation"
                confidence = min(abs(combined) * 1.2, 0.80)
                evidence.append("Mostly ephemeral/client ports")
                if traffic_score < -0.2:
                    evidence.append("Traffic asymmetry suggests client (initiator)")
            else:
                role = "workstation"
                confidence = 0.50
                evidence.append("Ambiguous — defaulting to workstation")

        # Refine: high packet count + many conversations → likely a server/hub
        total_pkts = info.packet_count
        total_conv = len(
            [
                c
                for c in conversation_data.values()
                if c.source_mac == mac or c.target_mac == mac
            ]
        )
        if total_pkts > 1000 and total_conv > 50 and role == "workstation":
            role = "server"
            confidence = 0.7
            evidence.append("High packet/connection volume suggests server role")

        # Refine: DHCP/BOOTP ports (67/68) suggest infrastructure
        if 67 in tcp_ports | udp_ports or 68 in tcp_ports | udp_ports:
            if role not in ("router", "switch", "firewall"):
                role = "server"
                confidence = max(confidence, 0.75)
                evidence.append("DHCP service detected")

        roles[mac] = {
            "role": role,
            "confidence": round(confidence, 3),
            "evidence": evidence,
            "vendor": vendor or "Unknown",
        }

    return roles


# ---------------------------------------------------------------------------
# 2. NETWORK SEGMENT DISCOVERY
# ---------------------------------------------------------------------------


@dataclass
class SubnetInfo:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    devices: set[str]  # MACs
    gateway_candidates: list[str]
    vlan_ids: set[str]


def discover_network_segments(
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
) -> dict[str, Any]:
    """Discover network segments, inferred subnets, VLAN boundaries, and gateways."""
    # Collect all IPs per MAC
    mac_ips: dict[str, list[str]] = {}
    for mac, info in device_info.items():
        mac_ips[mac] = list(info.ip_connections.keys())

    # Collect all IPs used in conversations
    all_ips: set[str] = set()
    for mac, ips in mac_ips.items():
        all_ips.update(ips)

    # Collect VLAN IDs
    all_vlans: set[str] = set()
    for conv in conversation_data.values():
        if conv.vlan_id:
            all_vlans.add(str(conv.vlan_id))

    # Analyze IP → subnet grouping
    ip4_addrs: list[ipaddress.IPv4Address] = []
    ip6_addrs: list[ipaddress.IPv6Address] = []
    for ip_str in all_ips:
        try:
            ip4_addrs.append(ipaddress.IPv4Address(ip_str))
        except (ValueError, ipaddress.AddressValueError):
            try:
                ip6_addrs.append(ipaddress.IPv6Address(ip_str))
            except (ValueError, ipaddress.AddressValueError):
                pass

    # Infer subnets: group IPs by common /24 prefix for IPv4, /64 for IPv6
    subnets: dict[str, set[str]] = defaultdict(set)
    for addr in ip4_addrs:
        # Try /24 then /16
        net24 = ipaddress.IPv4Network(f"{addr}/24", strict=False)
        subnets[str(net24)].add(str(addr))

    # Merge /24 subnets that belong to the same /16
    # (simplistic heuristic for now)
    segments: list[dict[str, Any]] = []
    for net_str, ips in sorted(subnets.items()):
        net = ipaddress.IPv4Network(net_str, strict=False)
        macs: set[str] = set()
        for ip in ips:
            for mac, dev_ips in mac_ips.items():
                if ip in dev_ips:
                    macs.add(mac)

        # Gateway candidates: devices that appear as .1 or .254
        gateway_macs: list[str] = []
        for host in net.hosts():
            host_str = str(host)
            if host_str in ips and (
                host_str.endswith(".1") or host_str.endswith(".254")
            ):
                for mac, dev_ips in mac_ips.items():
                    if host_str in dev_ips:
                        gateway_macs.append(mac)
                        break

        segments.append(
            {
                "subnet": net_str,
                "prefix_length": net.prefixlen,
                "num_ips": len(ips),
                "devices": sorted(macs),
                "gateway_candidates": gateway_macs,
                "sample_ips": sorted(ips)[:10],
            }
        )

    # VLAN analysis
    vlan_devices: dict[str, set[str]] = defaultdict(set)
    for conv in conversation_data.values():
        if not conv.vlan_id:
            continue
        vlan = str(conv.vlan_id)
        if conv.source_mac:
            vlan_devices[vlan].add(conv.source_mac)
        if conv.target_mac:
            vlan_devices[vlan].add(conv.target_mac)

    vlans = [
        {
            "vlan_id": vlan,
            "num_devices": len(macs),
            "devices": sorted(macs),
        }
        for vlan, macs in sorted(vlan_devices.items())
    ]

    return {
        "ipv4_segments": segments,
        "vlans": vlans,
        "total_ips": len(all_ips),
        "total_subnets": len(segments),
        "ipv6_present": len(ip6_addrs) > 0,
    }


# ---------------------------------------------------------------------------
# 3. TOPOLOGY INFERENCE
# ---------------------------------------------------------------------------


def infer_topology(
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
    roles: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a network topology graph from conversation data.

    Returns nodes and links suitable for D3/Graphviz rendering.
    """
    if roles is None:
        roles = {}

    nodes: list[dict[str, Any]] = []
    for mac, info in device_info.items():
        vendor = getattr(info, "vendor", "Unknown") or "Unknown"
        role_info = roles.get(mac, {})
        ips = list(info.ip_connections.keys())
        tcp = set()
        udp = set()
        for ip_info in info.ip_connections.values():
            tcp.update(getattr(ip_info, "tcp_ports", set()))
            udp.update(getattr(ip_info, "udp_ports", set()))

        nodes.append(
            {
                "id": mac,
                "label": mac,
                "vendor": vendor,
                "ips": ips,
                "role": role_info.get("role", "unknown"),
                "role_confidence": role_info.get("confidence", 0),
                "packet_count": info.packet_count,
                "tcp_ports": sorted(tcp),
                "udp_ports": sorted(udp),
                "group": role_info.get("role", "unknown"),
                "vlans": [],  # populated below if VLAN data available
                "services": sorted(
                    {
                        (c.service_name or c.app_protocol or "unknown")
                        for c in conversation_data.values()
                        if c.source_mac == mac or c.target_mac == mac
                        if c.service_name or c.app_protocol
                    }
                ),
            }
        )

    # Aggregate links by (source_mac, target_mac, protocol)
    link_agg: dict[tuple[str, str, str], dict[str, Any]] = {}
    for conv in conversation_data.values():
        src_mac = conv.source_mac
        tgt_mac = conv.target_mac
        if not src_mac or not tgt_mac:
            continue
        proto = conv.protocol or "unknown"
        key = (src_mac, tgt_mac, proto)
        if key not in link_agg:
            link_agg[key] = {
                "source": src_mac,
                "target": tgt_mac,
                "protocol": proto,
                "app_protocols": set(),
                "service_names": set(),
                "traffic_patterns": set(),
                "vlan_ids": set(),
                "diffserv_labels": set(),
                "total_packets": 0,
                "total_bytes": 0,
                "first_seen": None,
                "last_seen": None,
                "conversation_count": 0,
            }
        entry = link_agg[key]
        entry["total_packets"] += conv.packets_a_to_b + conv.packets_b_to_a
        entry["total_bytes"] += conv.bytes_a_to_b + conv.bytes_b_to_a
        entry["conversation_count"] += 1
        if conv.app_protocol:
            entry["app_protocols"].add(conv.app_protocol)
        if getattr(conv, "service_name", None):
            entry["service_names"].add(conv.service_name)
        if getattr(conv, "traffic_pattern", None):
            entry["traffic_patterns"].add(conv.traffic_pattern)
        if conv.vlan_id:
            entry["vlan_ids"].add(str(conv.vlan_id))
        label = getattr(conv, "diffserv_label", None)
        if label:
            entry["diffserv_labels"].add(label)
        if conv.first_seen and (
            entry["first_seen"] is None or conv.first_seen < entry["first_seen"]
        ):
            entry["first_seen"] = conv.first_seen
        if conv.last_seen and (
            entry["last_seen"] is None or conv.last_seen > entry["last_seen"]
        ):
            entry["last_seen"] = conv.last_seen

    links: list[dict[str, Any]] = []
    for entry in link_agg.values():
        entry["app_protocols"] = sorted(entry["app_protocols"])
        entry["service_names"] = sorted(entry["service_names"])
        entry["traffic_patterns"] = sorted(entry["traffic_patterns"])
        entry["vlan_ids"] = sorted(entry["vlan_ids"])
        entry["diffserv_labels"] = sorted(entry["diffserv_labels"])
        # Compute bandwidth in bytes/sec
        duration = 0.0
        if entry["first_seen"] and entry["last_seen"]:
            duration = max(entry["last_seen"] - entry["first_seen"], 0.001)
        entry["bandwidth_bytes_per_sec"] = round(entry["total_bytes"] / duration, 1) if duration > 0 else 0.0
        # Convert timestamps to ISO strings
        if entry["first_seen"]:
            entry["first_seen"] = datetime.fromtimestamp(entry["first_seen"]).isoformat()
        else:
            entry.pop("first_seen")
        if entry["last_seen"]:
            entry["last_seen"] = datetime.fromtimestamp(entry["last_seen"]).isoformat()
        else:
            entry.pop("last_seen")
        links.append(entry)

    # Populate VLAN membership on nodes
    node_vlans: dict[str, set[str]] = defaultdict(set)
    for link in links:
        for vlan in link.get("vlan_ids", []):
            node_vlans[link["source"]].add(vlan)
            node_vlans[link["target"]].add(vlan)
    for node in nodes:
        mac = node["id"]
        if mac in node_vlans:
            node["vlans"] = sorted(node_vlans[mac])

    return {
        "nodes": nodes,
        "links": links,
        "node_count": len(nodes),
        "link_count": len(links),
    }


# ---------------------------------------------------------------------------
# 4. ANOMALY DETECTION
# ---------------------------------------------------------------------------

# Common well-known ports for "normal" traffic
NORMAL_TCP_PORTS: set[int] = {
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 3389, 5432, 6379, 8080, 8443,
}

NORMAL_UDP_PORTS: set[int] = {
    53, 67, 68, 123, 161, 162, 500, 514, 1194, 5353,
}

SUSPICIOUS_PORTS: dict[int, str] = {
    23: "Telnet (unencrypted remote access)",
    21: "FTP (unencrypted file transfer)",
    6667: "IRC (often used by botnets)",
    4444: "Common backdoor / reverse shell port",
    31337: "Back Orifice / hacker tool",
    8888: "Common proxy / alternate HTTP",
    9999: "Common backdoor port",
    12345: "NetBus trojan",
    27015: "Common game server (may be unauthorized)",
}


def detect_anomalies(
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
    roles: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Detect anomalies in the capture.

    Returns a list of anomaly records with severity and details.
    """
    anomalies: list[dict[str, Any]] = []

    if roles is None:
        roles = {}

    # 1. Suspicious port usage
    for conv in conversation_data.values():
        ports = [
            conv.source_tcp_port,
            conv.target_tcp_port,
            conv.source_udp_port,
            conv.target_udp_port,
        ]
        for port in ports:
            if port and port in SUSPICIOUS_PORTS:
                anomalies.append(
                    {
                        "type": "suspicious_port",
                        "severity": "medium",
                        "description": f"Suspicious port {port}: {SUSPICIOUS_PORTS[port]}",
                        "source": conv.source_ip,
                        "target": conv.target_ip,
                        "source_mac": conv.source_mac,
                        "target_mac": conv.target_mac,
                        "port": port,
                    }
                )

    # 2. Asymmetric traffic (significant imbalance)
    for conv in conversation_data.values():
        total_pkts = conv.packets_a_to_b + conv.packets_b_to_a
        if total_pkts > 100:  # Only flag substantial conversations
            ratio = (
                max(conv.packets_a_to_b, conv.packets_b_to_a)
                / max(min(conv.packets_a_to_b, conv.packets_b_to_a), 1)
            )
            if ratio > 20:
                anomalies.append(
                    {
                        "type": "asymmetric_traffic",
                        "severity": "low",
                        "description": f"Highly asymmetric traffic ({ratio:.0f}:1 ratio, "
                        f"{conv.packets_a_to_b}→ vs {conv.packets_b_to_a}←)",
                        "source": conv.source_ip,
                        "target": conv.target_ip,
                        "source_mac": conv.source_mac,
                        "target_mac": conv.target_mac,
                        "ratio": round(ratio, 1),
                        "protocol": conv.protocol,
                    }
                )

    # 3. Unexpected protocols for device roles
    for mac, role_info in roles.items():
        role = role_info.get("role", "unknown")
        if role == "printer":
            # Printers shouldn't be running SSH or databases
            info = device_info.get(mac)
            if info:
                for ip_info in info.ip_connections.values():
                    tcp = set(getattr(ip_info, "tcp_ports", set()))
                    unexpected = tcp & {22, 3306, 5432, 6379, 27017}
                    if unexpected:
                        anomalies.append(
                            {
                                "type": "unexpected_service",
                                "severity": "medium",
                                "description": f"Printer {mac} has unexpected server ports: {sorted(unexpected)}",
                                "mac": mac,
                                "role": role,
                                "unexpected_ports": sorted(unexpected),
                                "vendor": role_info.get("vendor"),
                            }
                        )

    # 4. Devices with no conversations (orphan MACs)
    all_macs_in_convs: set[str] = set()
    for conv in conversation_data.values():
        if conv.source_mac:
            all_macs_in_convs.add(conv.source_mac)
        if conv.target_mac:
            all_macs_in_convs.add(conv.target_mac)

    for mac, info in device_info.items():
        if mac not in all_macs_in_convs:
            anomalies.append(
                {
                    "type": "orphan_device",
                    "severity": "low",
                    "description": f"Device {mac} has packets but no conversations (may be broadcast-only or truncated capture)",
                    "mac": mac,
                    "packet_count": info.packet_count,
                    "vendor": getattr(info, "vendor", "Unknown"),
                }
            )

    # 5. Unencrypted sensitive protocol usage
    for conv in conversation_data.values():
        if conv.protocol == "TCP":
            clear_ports = {21, 23, 80, 110, 143, 389}
            port_match = any(
                p in clear_ports
                for p in [
                    conv.source_tcp_port,
                    conv.target_tcp_port,
                ]
                if p is not None
            )
            if port_match and conv.app_protocol not in ("TLS", "SSL", "HTTPS"):
                anomalies.append(
                    {
                        "type": "cleartext_protocol",
                        "severity": "low",
                        "description": f"Cleartext connection on port: {conv.source_tcp_port or conv.target_tcp_port}",
                        "source": conv.source_ip,
                        "target": conv.target_ip,
                        "source_mac": conv.source_mac,
                        "target_mac": conv.target_mac,
                        "app_protocol": conv.app_protocol,
                    }
                )

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2}
    anomalies.sort(key=lambda a: severity_order.get(a["severity"], 3))

    return anomalies


# ---------------------------------------------------------------------------
# 5. CONVERSATION TIMELINE
# ---------------------------------------------------------------------------


@dataclass
class TimelineBucket:
    timestamp: float
    label: str
    conversations_active: int
    packets: int
    bytes_total: int
    devices_active: int
    top_talkers: list[tuple[str, int]]


def build_conversation_timeline(
    conversation_data: dict[Any, ConversationSummary],
    device_info: dict[str, DeviceSummary] | None = None,
    bucket_seconds: float = 60.0,
    max_buckets: int = 200,
) -> list[dict[str, Any]]:
    """Build a time-series of conversation activity.

    Buckets all packets into time windows and returns per-bucket stats.
    """
    if not conversation_data:
        return []

    # Find global time range
    all_timestamps: list[float] = []
    for conv in conversation_data.values():
        if conv.first_seen:
            all_timestamps.append(conv.first_seen)
        if conv.last_seen:
            all_timestamps.append(conv.last_seen)

    if not all_timestamps:
        return []

    t_min = min(all_timestamps)
    t_max = max(all_timestamps)
    total_span = t_max - t_min

    if total_span <= 0:
        return []

    # Auto-size buckets to stay within max_buckets
    num_buckets = int(total_span / bucket_seconds) + 1
    if num_buckets > max_buckets:
        bucket_seconds = total_span / max_buckets
        num_buckets = max_buckets

    # Initialize buckets
    buckets: list[dict[str, Any]] = []
    for i in range(num_buckets):
        t_start = t_min + i * bucket_seconds
        buckets.append(
            {
                "timestamp": t_start,
                "label": datetime.fromtimestamp(t_start).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "conversations_active": 0,
                "packets": 0,
                "bytes_total": 0,
                "devices_active": set(),
                "top_talkers": defaultdict(int),
            }
        )

    # Distribute conversations into buckets
    for conv in conversation_data.values():
        if conv.first_seen is None or conv.last_seen is None:
            continue
        pkt_total = conv.packets_a_to_b + conv.packets_b_to_a
        byte_total = conv.bytes_a_to_b + conv.bytes_b_to_a
        duration = max(conv.duration, 0.001)

        # Spread packets/bytes evenly across the conversation's time span
        start_bucket = int((conv.first_seen - t_min) / bucket_seconds)
        end_bucket = int((conv.last_seen - t_min) / bucket_seconds)
        start_bucket = max(0, min(start_bucket, num_buckets - 1))
        end_bucket = max(0, min(end_bucket, num_buckets - 1))

        num_spanned = end_bucket - start_bucket + 1
        pkts_per_bucket = pkt_total / max(num_spanned, 1)
        bytes_per_bucket = byte_total / max(num_spanned, 1)

        for bi in range(start_bucket, end_bucket + 1):
            if bi >= len(buckets):
                break
            b = buckets[bi]
            b["conversations_active"] += 1
            b["packets"] += int(pkts_per_bucket)
            b["bytes_total"] += int(bytes_per_bucket)
            if conv.source_mac:
                b["devices_active"].add(conv.source_mac)
                b["top_talkers"][conv.source_mac] += int(pkts_per_bucket)
            if conv.target_mac:
                b["devices_active"].add(conv.target_mac)
                b["top_talkers"][conv.target_mac] += int(pkts_per_bucket)

    # Finalize: convert sets to counts, sort top talkers
    result: list[dict[str, Any]] = []
    for b in buckets:
        talkers = sorted(b["top_talkers"].items(), key=lambda x: -x[1])[:5]
        result.append(
            {
                "timestamp": b["timestamp"],
                "label": b["label"],
                "conversations_active": b["conversations_active"],
                "packets": b["packets"],
                "bytes_total": b["bytes_total"],
                "devices_active": len(b["devices_active"]),
                "top_talkers": [{"mac": m, "packets": p} for m, p in talkers],
            }
        )

    return result


# ---------------------------------------------------------------------------
# 6. AUTOMATED SUMMARY REPORT
# ---------------------------------------------------------------------------


def build_summary_report(
    pcap_file: str,
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
    roles: dict[str, dict[str, Any]] | None = None,
    segments: dict[str, Any] | None = None,
    anomalies: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    elapsed_seconds: float = 0,
) -> str:
    """Generate an executive summary report as plain text."""

    if roles is None:
        roles = {}
    if anomalies is None:
        anomalies = []

    total_packets = sum(d.packet_count for d in device_info.values())
    total_bytes = sum(
        c.bytes_a_to_b + c.bytes_b_to_a for c in conversation_data.values()
    )
    protocols = set()
    app_protocols = set()
    for c in conversation_data.values():
        if c.protocol:
            protocols.add(c.protocol)
        if c.app_protocol:
            app_protocols.add(c.app_protocol)

    # Role distribution
    role_counts: dict[str, int] = defaultdict(int)
    for mac, r in roles.items():
        role_counts[r.get("role", "unknown")] += 1

    # Top talkers
    top_talkers = sorted(
        [(mac, d.packet_count, getattr(d, "vendor", "Unknown")) for mac, d in device_info.items()],
        key=lambda x: -x[1],
    )[:10]

    # Top conversations
    top_convos = sorted(
        [
            (c, c.packets_a_to_b + c.packets_b_to_a)
            for c in conversation_data.values()
        ],
        key=lambda x: -x[1],
    )[:10]

    # Anomaly counts
    anomaly_by_severity = Counter(a["severity"] for a in anomalies)
    anomaly_by_type = Counter(a["type"] for a in anomalies)

    lines: list[str] = []
    lines.append("=" * 68)
    lines.append("  NETWORK CAPTURE ANALYSIS — EXECUTIVE SUMMARY")
    lines.append("=" * 68)
    lines.append(f"  Capture file:      {Path(pcap_file).name}")
    lines.append(f"  Generated at:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Processing time:   {elapsed_seconds:.2f}s")
    lines.append("-" * 68)
    lines.append("  QUICK STATS")
    lines.append(f"  Total packets:     {total_packets:,}")
    lines.append(f"  Total data:        {total_bytes / (1024*1024):.2f} MB")
    lines.append(f"  Devices found:     {len(device_info)}")
    lines.append(f"  Conversations:     {len(conversation_data)}")
    lines.append(f"  Protocols:         {', '.join(sorted(protocols)) if protocols else 'none'}")
    lines.append(f"  Applications:      {', '.join(sorted(app_protocols)) if app_protocols else 'none'}")

    if role_counts:
        lines.append("-" * 68)
        lines.append("  DEVICE ROLES")
        for role_name in sorted(role_counts):
            count = role_counts[role_name]
            bar = "█" * min(count, 40)
            lines.append(f"  {role_name:20s} {count:5d}  {bar}")

    if segments:
        lines.append("-" * 68)
        lines.append("  NETWORK SEGMENTS")
        lines.append(f"  Subnets discovered: {segments.get('total_subnets', 0)}")
        lines.append(f"  Unique IPs seen:    {segments.get('total_ips', 0)}")
        vlans = segments.get("vlans", [])
        if vlans:
            lines.append(f"  VLANs detected:     {len(vlans)}")
            for v in vlans[:5]:
                lines.append(f"    VLAN {v['vlan_id']}: {v['num_devices']} device(s)")

    lines.append("-" * 68)
    lines.append("  TOP TALKERS (by packets)")
    for i, (mac, pkts, vendor) in enumerate(top_talkers, 1):
        role = roles.get(mac, {}).get("role", "")
        role_str = f" [{role}]" if role else ""
        lines.append(f"  {i:2d}. {mac:20s} {pkts:>8d} pkts  {vendor}{role_str}")

    lines.append("-" * 68)
    lines.append("  TOP CONVERSATIONS")
    for i, (conv, pkts) in enumerate(top_convos, 1):
        src = conv.source_ip or "?"
        tgt = conv.target_ip or "?"
        proto = conv.app_protocol or conv.protocol or "?"
        lines.append(f"  {i:2d}. {src}:{conv.source_tcp_port or '*'}"
                     f" ↔ {tgt}:{conv.target_tcp_port or '*'}"
                     f"  [{proto}]  {pkts} pkts")

    if anomalies:
        lines.append("-" * 68)
        lines.append("  ANOMALIES DETECTED")
        for severity in ("high", "medium", "low"):
            count = anomaly_by_severity.get(severity, 0)
            if count:
                lines.append(f"  {severity.upper()}: {count}")
        lines.append("  Breakdown:")
        for atype, count in anomaly_by_type.most_common():
            lines.append(f"    {atype}: {count}")

    if timeline:
        lines.append("-" * 68)
        lines.append("  TIMELINE OVERVIEW")
        if len(timeline) >= 2:
            first = timeline[0]
            last = timeline[-1]
            lines.append(f"  Start:  {first['label']}")
            lines.append(f"  End:    {last['label']}")
            max_pkts = max(b["packets"] for b in timeline) if timeline else 1
            peak_bucket = max(timeline, key=lambda b: b["packets"])
            lines.append(f"  Peak:   {peak_bucket['label']} ({peak_bucket['packets']} pkts)")

    lines.append("=" * 68)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. GEOIP ENRICHMENT
# ---------------------------------------------------------------------------

# Offline GeoIP stub that uses a simple MaxMind GeoLite2 CSV
# Real implementation requires `geoip2` + GeoLite2-City.mmdb
# This provides CSV-based and MaxMind DB backends.

GEOIP_CACHE: dict[str, dict[str, str]] = {}


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/local/multicast."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except ValueError:
        return True  # Treat unparseable as private


def _parse_geolite2_csv(csv_path: str) -> dict[str, dict[str, str]]:
    """Parse a MaxMind GeoLite2 CSV block file into a lookup table.

    Expected columns: network,geoname_id,...
    We map network CIDR to location info.
    """
    lookup: dict[str, dict[str, str]] = {}
    blocks_path = Path(csv_path)
    if not blocks_path.exists():
        return lookup

    # Try GeoLite2-City-Blocks-IPv4.csv format
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                network = row.get("network", "")
                if not network:
                    continue
                lookup[network] = {
                    "geoname_id": row.get("geoname_id", ""),
                    "latitude": row.get("latitude", ""),
                    "longitude": row.get("longitude", ""),
                }
    except Exception:
        pass

    return lookup


def enrich_geoip(
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
    geoip_db_path: str | None = None,
    geoip_locations_path: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Enrich public IPs with GeoIP location data.

    Uses a MaxMind GeoLite2 CSV or MMDB database if available.
    Returns a dict of IP → {country, city, lat, lon, isp}.
    """
    result: dict[str, dict[str, Any]] = {}

    # Collect all unique public IPs
    public_ips: set[str] = set()
    for mac, info in device_info.items():
        for ip in info.ip_connections.keys():
            if not _is_private_ip(ip):
                public_ips.add(ip)
    for conv in conversation_data.values():
        for ip in (conv.source_ip, conv.target_ip):
            if ip and not _is_private_ip(ip):
                public_ips.add(ip)

    if not public_ips:
        return result

    # Try MaxMind MMDB first (requires geoip2 package)
    if geoip_db_path:
        db_path = _expand_path(geoip_db_path)
        if db_path and db_path.exists():
            try:
                import geoip2.database  # type: ignore[import]

                reader = geoip2.database.Reader(str(db_path))
                for ip in sorted(public_ips):
                    try:
                        response = reader.city(ip)
                        result[ip] = {
                            "country": response.country.name or "",
                            "country_code": response.country.iso_code or "",
                            "city": response.city.name or "",
                            "latitude": round(response.location.latitude or 0, 4),
                            "longitude": round(response.location.longitude or 0, 4),
                            "source": "mmdb",
                        }
                    except Exception:
                        result[ip] = {"country": "", "city": "", "source": "lookup_failed"}
                reader.close()
                return result
            except ImportError:
                pass  # Fall through to CSV

    # Try CSV-based lookup
    if geoip_locations_path:
        blocks_path = _expand_path(geoip_locations_path)
        if blocks_path and blocks_path.exists():
            blocks = _parse_geolite2_csv(str(blocks_path))
            # Match each IP to the most specific subnet
            for ip in sorted(public_ips):
                try:
                    addr = ipaddress.ip_address(ip)
                    best_match = None
                    best_prefix = -1
                    # Limit search to avoid O(n^2)
                    for network_str, info in list(blocks.items())[:100000]:
                        try:
                            net = ipaddress.ip_network(network_str, strict=False)
                            if addr in net and net.prefixlen > best_prefix:
                                best_match = info
                                best_prefix = net.prefixlen
                        except ValueError:
                            continue
                    if best_match:
                        result[ip] = {
                            "latitude": best_match.get("latitude", ""),
                            "longitude": best_match.get("longitude", ""),
                            "source": "csv",
                            "country": "",
                            "city": "",
                        }
                except ValueError:
                    pass

    # Mark unresolvable IPs
    for ip in public_ips:
        if ip not in result:
            result[ip] = {
                "country": "",
                "city": "",
                "latitude": 0,
                "longitude": 0,
                "source": "unknown",
            }

    return result


def _expand_path(path: str | None) -> Path | None:
    if not path:
        return None
    return Path(path).expanduser()


# ---------------------------------------------------------------------------
# 8. PCAP SLICING
# ---------------------------------------------------------------------------


@dataclass
class SliceCriteria:
    """Criteria for slicing a PCAP."""

    start_time: float | None = None  # unix timestamp
    end_time: float | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    protocol: str | None = None  # TCP, UDP, etc.
    port: int | None = None
    app_protocol: str | None = None  # HTTP, DNS, etc.
    max_packets: int | None = None
    vlan_id: int | None = None


def _matches_criteria(
    conv: ConversationSummary, criteria: SliceCriteria
) -> bool:
    """Check if a conversation matches slicing criteria."""
    if criteria.start_time is not None and conv.first_seen is not None:
        if conv.first_seen < criteria.start_time:
            return False
    if criteria.end_time is not None and conv.last_seen is not None:
        if conv.last_seen > criteria.end_time:
            return False
    if criteria.src_ip and conv.source_ip != criteria.src_ip and conv.target_ip != criteria.src_ip:
        return False
    if criteria.dst_ip and conv.source_ip != criteria.dst_ip and conv.target_ip != criteria.dst_ip:
        return False
    if criteria.src_mac and conv.source_mac != criteria.src_mac and conv.target_mac != criteria.src_mac:
        return False
    if criteria.dst_mac and conv.source_mac != criteria.dst_mac and conv.target_mac != criteria.dst_mac:
        return False
    if criteria.protocol and conv.protocol != criteria.protocol:
        return False
    if criteria.port:
        ports = [
            conv.source_tcp_port,
            conv.target_tcp_port,
            conv.source_udp_port,
            conv.target_udp_port,
        ]
        if criteria.port not in ports:
            return False
    if criteria.app_protocol:
        app = (conv.app_protocol or "").upper()
        if criteria.app_protocol.upper() not in app:
            return False
    if criteria.vlan_id is not None and str(conv.vlan_id) != str(criteria.vlan_id):
        return False
    return True


def slice_conversations(
    conversation_data: dict[Any, ConversationSummary],
    criteria: SliceCriteria,
) -> dict[Any, ConversationSummary]:
    """Filter conversations matching the given criteria.

    Returns a new dict with only the matching conversations.
    """
    filtered: dict[Any, ConversationSummary] = {}
    count = 0
    for key, conv in conversation_data.items():
        if _matches_criteria(conv, criteria):
            filtered[key] = conv
            count += 1
            if criteria.max_packets and count >= criteria.max_packets:
                break
    return filtered


def slice_device_info(
    device_info: dict[str, DeviceSummary],
    filtered_conversations: dict[Any, ConversationSummary],
) -> dict[str, DeviceSummary]:
    """Filter device_info to only devices appearing in sliced conversations."""
    active_macs: set[str] = set()
    for conv in filtered_conversations.values():
        if conv.source_mac:
            active_macs.add(conv.source_mac)
        if conv.target_mac:
            active_macs.add(conv.target_mac)

    filtered: dict[str, DeviceSummary] = {}
    for mac in active_macs:
        if mac in device_info:
            filtered[mac] = device_info[mac]
    return filtered


# ---------------------------------------------------------------------------
# Orchestrator: run all analysis in one call
# ---------------------------------------------------------------------------


def run_advanced_analysis(
    pcap_file: str,
    device_info: dict[str, DeviceSummary],
    conversation_data: dict[Any, ConversationSummary],
    *,
    run_roles: bool = True,
    run_segments: bool = True,
    run_topology: bool = True,
    run_anomalies: bool = True,
    run_timeline: bool = True,
    run_summary: bool = True,
    run_geoip: bool = False,
    geoip_db: str | None = None,
    geoip_locations: str | None = None,
    slice_criteria: SliceCriteria | None = None,
    elapsed_seconds: float = 0,
    bucket_seconds: float = 60.0,
) -> dict[str, Any]:
    """Run the requested advanced analysis features and return results."""

    results: dict[str, Any] = {}

    # Device roles (needed by several downstream features)
    roles: dict[str, dict[str, Any]] = {}
    if run_roles:
        roles = infer_device_roles(device_info, conversation_data)
        results["roles"] = roles

    # Network segments
    if run_segments:
        results["segments"] = discover_network_segments(device_info, conversation_data)

    # Topology
    if run_topology:
        results["topology"] = infer_topology(device_info, conversation_data, roles)

    # Anomalies
    anomalies: list[dict[str, Any]] = []
    if run_anomalies:
        anomalies = detect_anomalies(device_info, conversation_data, roles)
        results["anomalies"] = anomalies

    # Conversation timeline
    timeline: list[dict[str, Any]] = []
    if run_timeline:
        timeline = build_conversation_timeline(
            conversation_data, device_info, bucket_seconds=bucket_seconds
        )
        results["timeline"] = timeline

    # Summary report
    if run_summary:
        results["summary"] = build_summary_report(
            pcap_file,
            device_info,
            conversation_data,
            roles=roles,
            segments=results.get("segments"),
            anomalies=anomalies,
            timeline=timeline,
            elapsed_seconds=elapsed_seconds,
        )

    # GeoIP
    if run_geoip:
        results["geoip"] = enrich_geoip(
            device_info, conversation_data, geoip_db, geoip_locations
        )

    # Slicing
    if slice_criteria:
        sliced_convs = slice_conversations(conversation_data, slice_criteria)
        sliced_devs = slice_device_info(device_info, sliced_convs)
        results["slice"] = {
            "criteria": {
                "start_time": slice_criteria.start_time,
                "end_time": slice_criteria.end_time,
                "src_ip": slice_criteria.src_ip,
                "dst_ip": slice_criteria.dst_ip,
                "protocol": slice_criteria.protocol,
                "port": slice_criteria.port,
                "app_protocol": slice_criteria.app_protocol,
            },
            "device_count": len(sliced_devs),
            "conversation_count": len(sliced_convs),
            "devices": sliced_devs,
            "conversations": sliced_convs,
        }

    return results


def write_analysis_json(results: dict[str, Any], output_path: str | Path) -> Path:
    """Write analysis results to a structured JSON file (excluding raw data)."""
    out = Path(output_path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)

    # Filter out raw device/conversation data from slice for JSON size
    output = {}
    for key, value in results.items():
        if key == "slice":
            output[key] = {
                k: v for k, v in value.items() if k not in ("devices", "conversations")
            }
            output[key]["device_macs"] = sorted(value.get("devices", {}).keys())
        else:
            output[key] = value

    with open(out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    return out
