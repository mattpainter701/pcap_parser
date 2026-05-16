from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import sys

import pcap_parser


def test_main_writes_reports_into_custom_output_dir(monkeypatch: object, tmp_path: Path) -> None:
    output_dir = tmp_path / "analysis-results"

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "Vendor One"
    device.packet_count = 1
    device.first_seen = 1.0
    device.last_seen = 2.0
    device.ip_connections["10.0.0.1"].packet_count = 1
    device.ip_connections["10.0.0.1"].tcp_ports.add(443)

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
    conv.packets_a_to_b = 1
    conv.bytes_a_to_b = 128
    conv.first_seen = 1.0
    conv.last_seen = 2.0
    conv.duration = 1.0
    conv.conversation_status = "response"
    conv.tcp_flags.add("SYN")
    conv.stream_id = 1
    conv.frame_protocols.add("eth:ip:tcp")
    conv.vlan_id = 240
    conv.dsfield = 10
    conv.ip_version = 4

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(
        pcap_parser,
        "extract_device_info",
        lambda *args, **kwargs: (device_info, conversation_data),
    )
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "capture.pcapng",
        "--output-dir",
        str(output_dir),
        "--format",
        "both",
    ])

    pcap_parser.main()

    assert (output_dir / "capture-device_info.csv").exists()
    assert (output_dir / "capture-conversation_info.csv").exists()
    assert (output_dir / "capture-network_data.json").exists()


def test_main_uses_custom_output_dir_for_benchmark_report(monkeypatch: object, tmp_path: Path) -> None:
    output_dir = tmp_path / "benchmarks"
    written: dict[str, Path] = {}

    benchmark_report = pcap_parser.BenchmarkReport(
        pcap_file="capture.pcapng",
        wall_time_seconds=1.0,
        cpu_time_seconds=0.9,
        peak_memory_bytes=4096,
        packet_count=10,
        processed_packets=10,
        device_count=1,
        conversation_count=1,
        packets_per_second=10.0,
        cpu_utilization_percent=90.0,
        top_functions=[],
    )

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(pcap_parser, "collect_benchmark_report", lambda *args, **kwargs: benchmark_report)
    monkeypatch.setattr(
        pcap_parser,
        "write_benchmark_report",
        lambda report, path: written.setdefault("path", Path(path)) or Path(path),
    )
    monkeypatch.setattr(pcap_parser, "render_benchmark_report", lambda report: "Benchmark report\n...")
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "capture.pcapng",
        "--benchmark",
        "--output-dir",
        str(output_dir),
    ])

    pcap_parser.main()

    assert written["path"] == output_dir / "capture-benchmark.json"
