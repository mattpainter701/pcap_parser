from __future__ import annotations

from pathlib import Path
import sys

import pytest

import pcap_parser


def test_collect_benchmark_report_records_standard_metrics(monkeypatch: object) -> None:
    def fake_capture(pcap_file: str | Path, *, debug: bool = False, collect_metrics: bool = False):
        assert str(pcap_file) == "sample.pcapng"
        assert debug is True
        assert collect_metrics is True
        return (
            {"aa:bb:cc:dd:ee:ff": object(), "11:22:33:44:55:66": object()},
            {"conv-a": object()},
            {"packet_count": 25, "processed_count": 24},
        )

    timeline = iter([10.0, 11.5])
    cpu_timeline = iter([5.0, 5.4])
    monkeypatch.setattr(pcap_parser.time, "perf_counter", lambda: next(timeline))
    monkeypatch.setattr(pcap_parser.time, "process_time", lambda: next(cpu_timeline))
    monkeypatch.setattr(pcap_parser.tracemalloc, "start", lambda: None)
    monkeypatch.setattr(pcap_parser.tracemalloc, "get_traced_memory", lambda: (1024, 2048))
    monkeypatch.setattr(pcap_parser.tracemalloc, "stop", lambda: None)

    report = pcap_parser.collect_benchmark_report("sample.pcapng", debug=True, capture_runner=fake_capture)

    assert report.packet_count == 25
    assert report.processed_packets == 24
    assert report.device_count == 2
    assert report.conversation_count == 1
    assert report.wall_time_seconds == 1.5
    assert report.cpu_time_seconds == pytest.approx(0.4)
    assert report.peak_memory_bytes == 2048
    assert report.packets_per_second == pytest.approx(16.0)
    assert report.cpu_utilization_percent == pytest.approx(26.666666666666668)
    assert report.top_functions, "expected profiler output to include at least one function"
    assert any("fake_capture" in item.function for item in report.top_functions)


def test_benchmark_cli_writes_report_and_skips_full_output_generation(monkeypatch: object, tmp_path: Path) -> None:
    written: dict[str, object] = {}
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
        top_functions=[
            pcap_parser.BenchmarkFunctionStat(
                function="pcap_parser.py:1:fake",
                primitive_calls=1,
                total_calls=1,
                total_time_seconds=0.1,
                cumulative_time_seconds=0.1,
            )
        ],
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
    monkeypatch.setattr(sys, "argv", ["pcap_parser.py", "capture.pcapng", "--benchmark"])

    pcap_parser.main()

    assert written["path"] == Path("outputs/capture-benchmark.json")
