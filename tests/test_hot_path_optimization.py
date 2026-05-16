from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import datetime as dt
import json

import pcap_parser


class FakeCapture:
    def __init__(self, packets):
        self.packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self.packets)

    def close(self) -> None:
        self.closed = True


def make_packet(*, transport="TCP", src_port="443", dst_port="51515"):
    flags = SimpleNamespace(syn="1", ack="1", reset="0", fin="0")
    packet = SimpleNamespace(
        sniff_time=dt.datetime.fromtimestamp(10.0),
        ip=SimpleNamespace(src="10.0.0.1", dst="10.0.0.2", dsfield="0x00"),
        eth=SimpleNamespace(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66"),
        length="128",
        transport_layer=transport,
        highest_layer=transport,
        frame_info=SimpleNamespace(protocols=f"eth:ip:{transport.lower()}"),
    )
    if transport == "TCP":
        packet.tcp = SimpleNamespace(srcport=src_port, dstport=dst_port, stream="1", flags=flags)
    elif transport == "UDP":
        packet.udp = SimpleNamespace(srcport=src_port, dstport=dst_port)
    return packet


def test_capture_uses_low_materialization_pyshark_options(monkeypatch: Any) -> None:
    created: dict[str, object] = {}

    def fake_file_capture(pcap_file, **kwargs):
        created["pcap_file"] = pcap_file
        created["kwargs"] = kwargs
        return FakeCapture([])

    monkeypatch.setattr(pcap_parser.pyshark, "FileCapture", fake_file_capture)

    result = pcap_parser.extract_device_info("sample.pcapng", collect_metrics=True)

    assert result is not None
    assert created == {
        "pcap_file": "sample.pcapng",
        "kwargs": {"keep_packets": False, "use_json": True},
    }


def test_extract_device_info_filters_non_tcp_udp_packets_early(monkeypatch: Any) -> None:
    icmp_packet = make_packet(transport="ICMP")
    monkeypatch.setattr(pcap_parser.pyshark, "FileCapture", lambda *args, **kwargs: FakeCapture([icmp_packet]))

    device_info, conversation_data, metrics = pcap_parser.extract_device_info("sample.pcapng", collect_metrics=True)

    assert metrics["packet_count"] == 1
    assert metrics["processed_count"] == 0
    assert device_info == {}
    assert conversation_data == {}


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


def test_service_inference_uses_well_known_ports_and_scores_confidence() -> None:
    service, confidence = pcap_parser.infer_service_name(
        source_tcp_port=443,
        target_tcp_port=51515,
        app_protocol="TLS",
        protocol="TCP",
    )

    assert service == "HTTPS"
    assert confidence >= 0.95

    dns_service, dns_confidence = pcap_parser.infer_service_name(
        source_udp_port=53000,
        target_udp_port=53,
        app_protocol="DNS",
        protocol="UDP",
    )

    assert dns_service == "DNS"
    assert dns_confidence >= 0.95


def test_diffserv_interpretation_labels_common_codepoints() -> None:
    assert pcap_parser.interpret_diffserv_field("0x00") == "CS0 / Not-ECT"
    assert pcap_parser.interpret_diffserv_field("0xb8") == "EF / Not-ECT"
    assert pcap_parser.interpret_diffserv_field("0x03") == "CS0 / CE"
    assert pcap_parser.interpret_diffserv_field("bogus") is None


def test_json_report_includes_diffserv_label(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(pcap_parser, "OUTPUT_DIR", str(tmp_path))

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "Vendor One"
    device.packet_count = 2
    device.first_seen = 10.0
    device.last_seen = 12.0

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
    conv.dsfield = "0xb8"
    conv.ip_version = 4

    assert pcap_parser.write_json_report(device_info, conversation_data, "capture.pcapng", "network.json") is True

    payload = json.loads((tmp_path / "network.json").read_text(encoding="utf-8"))
    assert payload["links"][0]["diffserv_label"] == "EF / Not-ECT"


def test_conversation_writer_enriches_service_label(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(pcap_parser, "OUTPUT_DIR", str(tmp_path))

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
    conv.first_seen = 10.0
    conv.last_seen = 12.0

    assert pcap_parser.write_conversation_report(conversation_data, "conversation.csv") is True

    row = (tmp_path / "conversation.csv").read_text(encoding="utf-8").splitlines()[1]
    assert ",HTTPS," in row
