from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pcap_parser


def test_slot_backed_hot_records_behave_like_mappings() -> None:
    device = pcap_parser.DeviceSummary()
    device["vendor"] = "Vendor One"
    device["packet_count"] = 3
    device["first_seen"] = 10.0

    ip_summary = device["ip_connections"]["10.0.0.1"]
    ip_summary["packet_count"] += 1
    ip_summary["tcp_ports"].add(443)

    conv = pcap_parser.ConversationSummary()
    conv["source_ip"] = "10.0.0.1"
    conv["conversation_status"] = "response"
    conv["tcp_flags"].update({"SYN", "ACK"})

    assert device.get("vendor") == "Vendor One"
    assert device["ip_connections"]["10.0.0.1"].packet_count == 1
    assert device["ip_connections"]["10.0.0.1"].tcp_ports == {443}
    assert conv.get("source_ip") == "10.0.0.1"
    assert conv["tcp_flags"] == {"SYN", "ACK"}


def test_vendor_lookup_normalizes_oui_and_uses_cache(monkeypatch: object) -> None:
    monkeypatch.setattr(pcap_parser, "ieee_oui_db", {"AA:BB:CC": "Vendor One"})
    pcap_parser._lookup_vendor_by_oui.cache_clear()

    first = pcap_parser.get_vendor("aa:bb:cc:dd:ee:ff")
    second = pcap_parser.get_vendor("AA-BB-CC-11-22-33")
    missing = pcap_parser.get_vendor("11:22:33:44:55:66")

    assert first == "Vendor One"
    assert second == "Vendor One"
    assert missing is None


def test_output_writers_accept_slot_backed_records(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(pcap_parser, "OUTPUT_DIR", str(tmp_path))

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "Vendor One"
    device.packet_count = 2
    device.first_seen = 10.0
    device.last_seen = 12.0
    ip_summary = device.ip_connections["10.0.0.1"]
    ip_summary.packet_count = 1
    ip_summary.tcp_ports.update({80, 443})
    ip_summary.udp_ports.add(53)

    conversation_data = defaultdict(pcap_parser.ConversationSummary)
    conv = conversation_data[("10.0.0.1", "10.0.0.2", 443, 51515, "TCP")]
    conv.source_ip = "10.0.0.1"
    conv.source_mac = "aa:bb:cc:dd:ee:ff"
    conv.target_ip = "10.0.0.2"
    conv.target_mac = "11:22:33:44:55:66"
    conv.protocol = "TCP"
    conv.app_protocol = "TLS"
    conv.source_tcp_port = 443
    conv.target_tcp_port = 51515
    conv.packets_a_to_b = 4
    conv.packets_b_to_a = 2
    conv.bytes_a_to_b = 600
    conv.bytes_b_to_a = 300
    conv.first_seen = 10.0
    conv.last_seen = 12.0
    conv.duration = 2.0
    conv.conversation_status = "response"
    conv.tcp_flags.update({"SYN", "ACK"})
    conv.stream_id = 7
    conv.frame_protocols.add("eth:ip:tcp")
    conv.vlan_id = 240
    conv.dsfield = 10
    conv.ip_version = 4

    assert pcap_parser.write_csv_report(device_info, "device.csv") is True
    assert pcap_parser.write_conversation_report(conversation_data, "conversation.csv") is True

    device_csv = (tmp_path / "device.csv").read_text(encoding="utf-8")
    conversation_csv = (tmp_path / "conversation.csv").read_text(encoding="utf-8")

    assert "MAC Address,Vendor,IP Address,TCP Ports,UDP Ports,First Seen,Last Seen,Packet Count" in device_csv
    assert "Source IP,Source MAC,Source TCP Port,Source UDP Port,Target IP,Target MAC" in conversation_csv
