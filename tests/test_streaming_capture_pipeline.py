from pathlib import Path

import pcap_parser
from pcap_parser import ParsedData, StreamingProgress, parse_capture_streaming


def test_streaming_progress_to_dict_is_json_ready():
    progress = StreamingProgress(
        pcap_file="sample.pcapng",
        packets_seen=10,
        packets_processed=8,
        malformed_packets=1,
        skipped_packets=1,
        device_count=2,
        conversation_count=3,
        event="complete",
    )

    assert progress.to_dict() == {
        "pcap_file": "sample.pcapng",
        "packets_seen": 10,
        "packets_processed": 8,
        "malformed_packets": 1,
        "skipped_packets": 1,
        "device_count": 2,
        "conversation_count": 3,
        "event": "complete",
    }


def test_parse_capture_streaming_can_emit_progress_records(monkeypatch, tmp_path):
    capture = tmp_path / "tiny.pcapng"
    capture.write_bytes(b"not a real pcap; parser is patched")

    def fake_parse_capture(path, *, debug=False, bpf_filter=None, progress_callback=None, progress_interval=100):
        assert Path(path) == capture
        assert progress_interval == 5
        if progress_callback:
            progress_callback(
                StreamingProgress(
                    pcap_file=str(path),
                    packets_seen=5,
                    packets_processed=5,
                    malformed_packets=0,
                    skipped_packets=0,
                    device_count=1,
                    conversation_count=1,
                    event="complete",
                )
            )
        return ParsedData(
            pcap_file=str(path),
            devices=[],
            conversations=[],
            elapsed_seconds=0.01,
            device_count=0,
            conversation_count=0,
            total_packets=0,
            total_bytes=0,
            protocols_detected=[],
        )

    monkeypatch.setattr(pcap_parser, "parse_capture", fake_parse_capture)

    records = list(parse_capture_streaming(capture, chunk_size=5, include_progress=True))

    assert records[0]["type"] == "progress"
    assert records[0]["packets_seen"] == 5
    assert records[-1]["type"] == "summary"
