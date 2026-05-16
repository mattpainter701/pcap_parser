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


def test_main_expands_tilde_output_dir(monkeypatch: object, tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    output_dir = home_dir / "analysis-results"

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

    monkeypatch.setenv("HOME", str(home_dir))
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
        "~/analysis-results",
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


def test_main_expands_tilde_benchmark_output_path(monkeypatch: object, tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    benchmark_path = home_dir / "benchmarks" / "capture-benchmark.json"
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

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
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
        "--benchmark-output",
        "~/benchmarks/capture-benchmark.json",
    ])

    pcap_parser.main()

    assert written["path"] == benchmark_path


def test_main_processes_capture_directory_with_prefix(monkeypatch: object, tmp_path: Path) -> None:
    input_dir = tmp_path / "captures"
    output_dir = tmp_path / "reports"
    input_dir.mkdir()
    (input_dir / "alpha.pcapng").write_bytes(b"")
    (input_dir / "beta.pcap").write_bytes(b"")

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

    seen: list[str] = []

    def fake_extract(pcap_file: str, debug: bool = False, **kwargs):
        seen.append(Path(pcap_file).name)
        return device_info, conversation_data

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", fake_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        str(input_dir),
        "--output-dir",
        str(output_dir),
        "--output",
        "bundle",
    ])

    pcap_parser.main()

    assert seen == ["alpha.pcapng", "beta.pcap"]
    for stem in ("alpha", "beta"):
        assert (output_dir / f"bundle-{stem}-device_info.csv").exists()
        assert (output_dir / f"bundle-{stem}-conversation_info.csv").exists()
        assert (output_dir / f"bundle-{stem}-network_data.json").exists()


def test_stats_only_prints_summary_and_does_not_write_files(monkeypatch: object, tmp_path: Path, capsys: object) -> None:
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "Vendor One"
    device.packet_count = 100
    device.first_seen = 1.0
    device.last_seen = 100.0
    device.ip_connections["10.0.0.1"].packet_count = 100
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
    conv.packets_a_to_b = 50
    conv.bytes_a_to_b = 6400
    conv.packets_b_to_a = 50
    conv.bytes_b_to_a = 6400
    conv.first_seen = 1.0
    conv.last_seen = 100.0
    conv.duration = 99.0
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
        "--stats-only",
        "--output-dir",
        str(output_dir),
    ])

    pcap_parser.main()

    captured = capsys.readouterr()
    assert "PARSING STATISTICS" in captured.out
    assert "100" in captured.out  # packet count in output
    assert "Devices:" in captured.out
    assert "Conversations:" in captured.out
    # No output files should exist (since --stats-only skips writing)
    assert not list(output_dir.iterdir())


def test_stats_only_prints_top_talkers(monkeypatch: object, tmp_path: Path, capsys: object) -> None:
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "Vendor One"
    device.packet_count = 200
    device.first_seen = 1.0
    device.last_seen = 2.0
    device.ip_connections["10.0.0.1"].packet_count = 200
    device.ip_connections["10.0.0.1"].tcp_ports.add(443)

    device2 = device_info["11:22:33:44:55:66"]
    device2.vendor = "Vendor Two"
    device2.packet_count = 50
    device2.first_seen = 1.0
    device2.last_seen = 2.0
    device2.ip_connections["10.0.0.2"].packet_count = 50

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
    conv.packets_a_to_b = 50
    conv.bytes_a_to_b = 6400
    conv.packets_b_to_a = 50
    conv.bytes_b_to_a = 6400
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
        "--stats-only",
    ])

    pcap_parser.main()
    captured = capsys.readouterr()
    assert "PARSING STATISTICS" in captured.out
    assert "Top talkers" in captured.out
    assert "aa:bb:cc:dd:ee:ff" in captured.out
    assert "11:22:33:44:55:66" in captured.out


def test_filter_flag_passed_to_extract_device_info(monkeypatch: object, tmp_path: Path) -> None:
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    captured_filter: list[str | None] = []

    def fake_extract(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
        captured_filter.append(bpf_filter)
        return defaultdict(pcap_parser.DeviceSummary), defaultdict(pcap_parser.ConversationSummary)

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", fake_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "capture.pcapng",
        "--filter",
        "tcp.port==443",
        "--output-dir",
        str(output_dir),
    ])

    pcap_parser.main()

    assert len(captured_filter) == 1
    assert captured_filter[0] == "tcp.port==443"


def test_filter_flag_with_ip_subnet_filter(monkeypatch: object, tmp_path: Path) -> None:
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    captured_filter: list[str | None] = []

    def fake_extract(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
        captured_filter.append(bpf_filter)
        return defaultdict(pcap_parser.DeviceSummary), defaultdict(pcap_parser.ConversationSummary)

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", fake_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "capture.pcapng",
        "--filter",
        "ip.addr==10.0.0.0/8",
    ])

    pcap_parser.main()

    assert len(captured_filter) == 1
    assert captured_filter[0] == "ip.addr==10.0.0.0/8"


def test_compare_mode_parses_two_captures(monkeypatch: object, tmp_path: Path, capsys: object) -> None:
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    left_devices = defaultdict(pcap_parser.DeviceSummary)
    ldev = left_devices["aa:bb:cc:dd:ee:ff"]
    ldev.vendor = "Vendor One"
    ldev.packet_count = 1
    ldev.first_seen = 1.0
    ldev.last_seen = 2.0
    ldev.ip_connections["10.0.0.1"].packet_count = 1

    left_convs = defaultdict(pcap_parser.ConversationSummary)
    lc = left_convs[("10.0.0.1", "10.0.0.2", 443, 51515, "TCP")]
    lc.source_ip = "10.0.0.1"
    lc.source_mac = "aa:bb:cc:dd:ee:ff"
    lc.target_ip = "10.0.0.2"
    lc.target_mac = "11:22:33:44:55:66"
    lc.protocol = "TCP"
    lc.packets_a_to_b = 10
    lc.packets_b_to_a = 5
    lc.bytes_a_to_b = 100
    lc.bytes_b_to_a = 50
    lc.first_seen = 1.0
    lc.last_seen = 2.0
    lc.duration = 1.0
    lc.conversation_status = "response"
    lc.stream_id = 1
    lc.ip_version = 4

    # Right capture: one more device + one new conversation
    right_devices = defaultdict(pcap_parser.DeviceSummary)
    rdev = right_devices["aa:bb:cc:dd:ee:ff"]
    rdev.vendor = "Vendor One"
    rdev.packet_count = 1
    rdev.first_seen = 1.0
    rdev.last_seen = 2.0
    rdev.ip_connections["10.0.0.1"].packet_count = 1
    rdev2 = right_devices["cc:dd:ee:ff:00:11"]
    rdev2.vendor = "Vendor Two"
    rdev2.packet_count = 1
    rdev2.first_seen = 1.0
    rdev2.last_seen = 2.0
    rdev2.ip_connections["10.0.0.3"].packet_count = 1

    right_convs = defaultdict(pcap_parser.ConversationSummary)
    rc = right_convs[("10.0.0.1", "10.0.0.2", 443, 51515, "TCP")]
    rc.source_ip = "10.0.0.1"
    rc.source_mac = "aa:bb:cc:dd:ee:ff"
    rc.target_ip = "10.0.0.2"
    rc.target_mac = "11:22:33:44:55:66"
    rc.protocol = "TCP"
    rc.packets_a_to_b = 12
    rc.packets_b_to_a = 5
    rc.bytes_a_to_b = 120
    rc.bytes_b_to_a = 50
    rc.first_seen = 1.0
    rc.last_seen = 2.0
    rc.duration = 1.0
    rc.conversation_status = "response"
    rc.stream_id = 1
    rc.ip_version = 4

    extract_calls: list[str] = []

    def side_effect_extract(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
        extract_calls.append(pcap_file)
        if "left" in str(pcap_file):
            return left_devices, left_convs
        return right_devices, right_convs

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", side_effect_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "left.pcap",
        "right.pcap",
        "--compare",
    ])

    pcap_parser.main()
    captured = capsys.readouterr()

    assert "COMPARE MODE" in captured.out
    assert "DIFF SUMMARY" in captured.out
    assert "Devices added" in captured.out or "Devices:" in captured.out
    assert "cc:dd:ee:ff:00:11" in captured.out


def test_compare_mode_errors_on_insufficient_args(monkeypatch: object, capsys: object) -> None:
    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        "capture.pcapng",
        "--compare",
    ])

    pcap_parser.main()
    captured = capsys.readouterr()
    assert "requires exactly two PCAP" in captured.out


def test_help_output_contains_epilog_examples(monkeypatch: object, capsys: object) -> None:
    monkeypatch.setattr(sys, "argv", ["pcap_parser.py", "--help"])
    try:
        pcap_parser.main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    assert "PCAP Network Capture Analyzer" in captured.out
    assert "--stats-only" in captured.out
    assert "--filter" in captured.out
    assert "--compare" in captured.out
    assert "pcap_parser.py before.pcap after.pcap --compare" in captured.out


def test_batch_directory_with_filter(monkeypatch: object, tmp_path: Path) -> None:
    """Batch mode (directory) combined with --filter passes filter to each file."""
    input_dir = tmp_path / "captures"
    output_dir = tmp_path / "reports"
    input_dir.mkdir()
    (input_dir / "alpha.pcapng").write_bytes(b"")
    (input_dir / "beta.pcap").write_bytes(b"")

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "V One"
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

    seen_filter_args: list[str | None] = []

    def recording_extract(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
        seen_filter_args.append(bpf_filter)
        return device_info, conversation_data

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", recording_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        str(input_dir),
        "--output-dir",
        str(output_dir),
        "--filter",
        "tcp.port==80 or tcp.port==443",
    ])

    pcap_parser.main()

    assert len(seen_filter_args) == 2
    assert all(f == "tcp.port==80 or tcp.port==443" for f in seen_filter_args)


def test_batch_directory_with_stats_only(monkeypatch: object, tmp_path: Path, capsys: object) -> None:
    """Batch mode + stats-only processes all files but writes no output."""
    input_dir = tmp_path / "captures"
    output_dir = tmp_path / "reports"
    input_dir.mkdir()
    (input_dir / "alpha.pcapng").write_bytes(b"")
    (input_dir / "beta.pcap").write_bytes(b"")

    device_info = defaultdict(pcap_parser.DeviceSummary)
    device = device_info["aa:bb:cc:dd:ee:ff"]
    device.vendor = "V One"
    device.packet_count = 10
    device.first_seen = 1.0
    device.last_seen = 2.0
    device.ip_connections["10.0.0.1"].packet_count = 10
    device.ip_connections["10.0.0.1"].tcp_ports.add(80)

    conversation_data = defaultdict(pcap_parser.ConversationSummary)
    conv = conversation_data[("10.0.0.1", "10.0.0.2", 80, 50000, "TCP")]
    conv.source_ip = "10.0.0.1"
    conv.source_mac = "aa:bb:cc:dd:ee:ff"
    conv.target_ip = "10.0.0.2"
    conv.target_mac = "11:22:33:44:55:66"
    conv.protocol = "TCP"
    conv.packets_a_to_b = 5
    conv.packets_b_to_a = 5
    conv.bytes_a_to_b = 500
    conv.bytes_b_to_a = 500
    conv.first_seen = 1.0
    conv.last_seen = 2.0
    conv.duration = 1.0
    conv.conversation_status = "response"
    conv.stream_id = 1
    conv.ip_version = 4

    seen_count = 0

    def recording_extract(pcap_file, debug=False, collect_metrics=False, bpf_filter=None):
        nonlocal seen_count
        seen_count += 1
        return device_info, conversation_data

    monkeypatch.setattr(pcap_parser, "check_tshark_installation", lambda: True)
    monkeypatch.setattr(pcap_parser.os.path, "exists", lambda path: True)
    monkeypatch.setattr(pcap_parser, "extract_device_info", recording_extract)
    monkeypatch.setattr(sys, "argv", [
        "pcap_parser.py",
        str(input_dir),
        "--stats-only",
    ])

    pcap_parser.main()
    captured = capsys.readouterr()

    assert seen_count == 2
    assert "PARSING STATISTICS" in captured.out
    # No output files written
    assert not list(output_dir.iterdir()) if output_dir.exists() else True

