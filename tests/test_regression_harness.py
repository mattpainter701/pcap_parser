from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from pcap_regression import (
    compare_conversation_csv,
    compare_device_csv,
    compare_network_json,
    load_regression_manifest,
    run_regression_suite,
    summarize_regression_results,
    validate_conversation_csv,
    validate_device_csv,
    validate_network_json,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "fixtures" / "regression_manifest.json"
DEVICE_FIXTURES = [
    REPO_ROOT / "outputs" / "misc_cap-device_info.csv",
    REPO_ROOT / "outputs" / "vlan-240-device_info.csv",
]


def test_regression_manifest_points_to_existing_fixtures() -> None:
    fixtures = load_regression_manifest(MANIFEST)

    assert [fixture.name for fixture in fixtures] == ["misc_cap_mixed_ipv4", "vlan_240_tagged"]
    for fixture in fixtures:
        assert fixture.pcap.exists(), fixture.pcap
        for golden in fixture.goldens.values():
            assert golden.exists(), golden


def test_regression_suite_passes_for_committed_goldens() -> None:
    results = run_regression_suite(MANIFEST)
    summary = summarize_regression_results(results)

    assert summary["total"] == 6
    assert summary["passed"] == 6
    assert summary["failed"] == 0
    assert summary["failures"] == []


@pytest.mark.parametrize("csv_path", DEVICE_FIXTURES)
def test_device_csv_validation_accepts_committed_outputs(csv_path: Path) -> None:
    assert validate_device_csv(csv_path) == []


def test_device_csv_comparison_allows_timestamp_jitter(tmp_path: Path) -> None:
    golden = tmp_path / "golden-device.csv"
    actual = tmp_path / "actual-device.csv"
    golden.write_text(
        "\n".join(
            [
                "MAC Address,Vendor,IP Address,TCP Ports,UDP Ports,First Seen,Last Seen,Packet Count",
                'aa:bb:cc:dd:ee:ff,Vendor One,10.0.0.1,"80,443",53,100.0001,101.0001,12',
                '11:22:33:44:55:66,Vendor Two,10.0.0.2,,"123,456",200.0,250.0,3',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    actual.write_text(
        "\n".join(
            [
                "MAC Address,Vendor,IP Address,TCP Ports,UDP Ports,First Seen,Last Seen,Packet Count",
                '11:22:33:44:55:66,Vendor Two,10.0.0.2,,"123,456",200.0004,250.0004,3',
                'aa:bb:cc:dd:ee:ff,Vendor One,10.0.0.1,"80,443",53,100.0004,101.0004,12',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert compare_device_csv(golden, actual, timestamp_precision=3) == []


def test_conversation_csv_validation_accepts_expected_shape(tmp_path: Path) -> None:
    path = tmp_path / "conversation.csv"
    path.write_text(
        "\n".join(
            [
                "Source IP,Source MAC,Source TCP Port,Source UDP Port,Target IP,Target MAC,Target TCP Port,Target UDP Port,Protocol,Application Protocol,Service Name,Service Confidence,Traffic Pattern,Packets A->B,Packets B->A,Bytes A->B,Bytes B->A,First Seen,Last Seen,Duration (seconds),Conversation Status,TCP Flags,Stream ID,Frame Protocols,VLAN ID,DiffServ Field,DiffServ Label,IP Version",
                '10.0.0.1,aa:bb:cc:dd:ee:ff,443,,10.0.0.2,11:22:33:44:55:66,51515,,TCP,TLS,HTTPS,0.98,request-response,4,2,600,300,2024-01-01T00:00:00,2024-01-01T00:00:02,2.0,response,SYN,7,eth:ip:tcp,240,10,CS0 / Not-ECT,4',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert validate_conversation_csv(path) == []


def test_conversation_csv_comparison_allows_row_reordering_and_duration_jitter(tmp_path: Path) -> None:
    golden = tmp_path / "golden-conv.csv"
    actual = tmp_path / "actual-conv.csv"
    headers = (
        "Source IP,Source MAC,Source TCP Port,Source UDP Port,Target IP,Target MAC,Target TCP Port,Target UDP Port,Protocol,Application Protocol,Service Name,Service Confidence,Traffic Pattern,Packets A->B,Packets B->A,Bytes A->B,Bytes B->A,First Seen,Last Seen,Duration (seconds),Conversation Status,TCP Flags,Stream ID,Frame Protocols,VLAN ID,DiffServ Field,DiffServ Label,IP Version\n"
    )
    golden.write_text(
        headers
        + "\n".join(
            [
                '10.0.0.1,aa:bb:cc:dd:ee:ff,443,,10.0.0.2,11:22:33:44:55:66,51515,,TCP,TLS,HTTPS,0.98,request-response,4,2,600,300,2024-01-01T00:00:00,2024-01-01T00:00:02,2.0001,response,SYN,7,eth:ip:tcp,240,10,CS0 / Not-ECT,4',
                '10.0.0.3,aa:bb:cc:dd:ee:11,,,10.0.0.4,11:22:33:44:55:77,,,UDP,DNS,DNS,0.98,polling,1,0,100,0,2024-01-01T00:00:03,2024-01-01T00:00:04,1.0,no-response,,8,eth:ip:udp,,,CS0 / Not-ECT,4',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    actual.write_text(
        headers
        + "\n".join(
            [
                '10.0.0.3,aa:bb:cc:dd:ee:11,,,10.0.0.4,11:22:33:44:55:77,,,UDP,DNS,DNS,0.98,polling,1,0,100,0,2024-01-01T00:00:03,2024-01-01T00:00:04,1.0002,no-response,,8,eth:ip:udp,,,CS0 / Not-ECT,4',
                '10.0.0.1,aa:bb:cc:dd:ee:ff,443,,10.0.0.2,11:22:33:44:55:66,51515,,TCP,TLS,HTTPS,0.98,request-response,4,2,600,300,2024-01-01T00:00:00,2024-01-01T00:00:02,2.0002,response,SYN,7,eth:ip:tcp,240,10,CS0 / Not-ECT,4',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert compare_conversation_csv(golden, actual, timestamp_precision=3) == []


def test_network_json_validation_and_compare(tmp_path: Path) -> None:
    golden = tmp_path / "golden.json"
    actual = tmp_path / "actual.json"
    payload = {
        "metadata": {
            "generated_at": "2024-01-01T00:00:00",
            "pcap_file": "capture.pcapng",
            "total_nodes": 1,
            "total_links": 1,
        },
        "nodes": [
            {
                "id": "aa:bb:cc:dd:ee:ff",
                "label": "aa:bb:cc:dd:ee:ff",
                "vendor": "Vendor One",
                "ips": ["10.0.0.1"],
                "tcp_ports": [80, 443],
                "udp_ports": [53],
                "packet_count": 12,
                "first_seen": "2024-01-01T00:00:00",
                "last_seen": "2024-01-01T00:00:02",
            }
        ],
        "links": [
            {
                "source": "aa:bb:cc:dd:ee:ff",
                "target": "11:22:33:44:55:66",
                "source_ip": "10.0.0.1",
                "target_ip": "10.0.0.2",
                "protocol": "TCP",
                "app_protocol": "TLS",
                "source_tcp_port": 443,
                "target_tcp_port": 51515,
                "source_udp_port": None,
                "target_udp_port": None,
                "packets_a_to_b": 4,
                "packets_b_to_a": 2,
                "bytes_a_to_b": 600,
                "bytes_b_to_a": 300,
                "first_seen": "2024-01-01T00:00:00",
                "last_seen": "2024-01-01T00:00:02",
                "duration": 2.0,
                "conversation_status": "response",
                "tcp_flags": ["ACK", "SYN"],
                "stream_id": 7,
                "frame_protocols": "eth:ip:tcp",
                "vlan_id": 240,
                "dsfield": 10,
                "ip_version": 4,
            }
        ],
    }

    golden.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    actual_payload = json.loads(json.dumps(payload))
    actual_payload["metadata"]["generated_at"] = "2024-01-01T00:00:05"
    actual_payload["nodes"][0]["ips"] = ["10.0.0.1"]
    actual_payload["links"][0]["tcp_flags"] = ["SYN", "ACK"]
    actual.write_text(json.dumps(actual_payload, indent=2) + "\n", encoding="utf-8")

    assert validate_network_json(golden) == []
    assert compare_network_json(golden, actual) == []
