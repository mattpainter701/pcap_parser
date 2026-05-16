"""Tests for Sprint 10 advanced analysis features (pcap_analysis.py)."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

# Ensure pcap_parser + pcap_analysis are importable
import conftest  # noqa: F401 — injects ROOT into sys.path

from pcap_analysis import (
    build_conversation_timeline,
    build_summary_report,
    detect_anomalies,
    discover_network_segments,
    infer_device_roles,
    infer_topology,
    slice_conversations,
    slice_device_info,
    SliceCriteria,
)
from pcap_parser import DeviceSummary, ConversationSummary


# ------------------------------------------------------------------
# Test fixtures — build realistic synthetic capture data
# ------------------------------------------------------------------


@pytest.fixture
def sample_devices() -> dict[str, DeviceSummary]:
    """Synthetic 4-device network: server, workstation, printer, IoT cam."""
    devices: dict[str, DeviceSummary] = defaultdict(DeviceSummary)

    # Server — Intel NIC
    srv = devices["aa:bb:cc:11:22:33"]
    srv.vendor = "Intel Corp"
    srv.packet_count = 5000
    srv.first_seen = 1000.0
    srv.last_seen = 2000.0
    srv.ip_connections["10.0.0.1"].tcp_ports.update([22, 80, 443, 3306])
    srv.ip_connections["10.0.0.1"].packet_count = 5000

    # Workstation — Dell
    ws = devices["aa:bb:cc:44:55:66"]
    ws.vendor = "Dell Inc"
    ws.packet_count = 1200
    ws.first_seen = 1000.0
    ws.last_seen = 2000.0
    ws.ip_connections["10.0.0.100"].tcp_ports.update([52341, 52342])
    ws.ip_connections["10.0.0.100"].udp_ports.update([5353])
    ws.ip_connections["10.0.0.100"].packet_count = 1200

    # Printer — HP
    pr = devices["aa:bb:cc:77:88:99"]
    pr.vendor = "HP Inc"
    pr.packet_count = 300
    pr.first_seen = 1100.0
    pr.last_seen = 1900.0
    pr.ip_connections["10.0.0.50"].tcp_ports.update([9100, 631])
    pr.ip_connections["10.0.0.50"].packet_count = 300

    # IoT camera — Arlo
    iot = devices["aa:bb:cc:aa:bb:cc"]
    iot.vendor = "Arlo Technologies"
    iot.packet_count = 800
    iot.first_seen = 1000.0
    iot.last_seen = 2000.0
    iot.ip_connections["10.0.0.200"].tcp_ports.update([443, 554])
    iot.ip_connections["10.0.0.200"].packet_count = 800

    return dict(devices)


@pytest.fixture
def sample_conversations() -> dict:
    """Synthetic conversations: server↔workstation, server↔printer, etc."""
    convs: dict = {}

    def _conv(
        src_ip, dst_ip, src_mac, dst_mac, proto, app, pkts_ab, pkts_ba,
        bytes_ab, bytes_ba, src_port, dst_port, first, last,
    ):
        c = ConversationSummary()
        c.source_ip = src_ip
        c.target_ip = dst_ip
        c.source_mac = src_mac
        c.target_mac = dst_mac
        c.protocol = proto
        c.app_protocol = app
        c.packets_a_to_b = pkts_ab
        c.packets_b_to_a = pkts_ba
        c.bytes_a_to_b = bytes_ab
        c.bytes_b_to_a = bytes_ba
        c.source_tcp_port = src_port if proto == "TCP" else None
        c.target_tcp_port = dst_port if proto == "TCP" else None
        c.source_udp_port = src_port if proto == "UDP" else None
        c.target_udp_port = dst_port if proto == "UDP" else None
        c.first_seen = first
        c.last_seen = last
        c.duration = last - first
        c.conversation_status = "response" if pkts_ba > 0 else "no-response"
        c.ip_version = 4
        return c

    # Workstation → Server: HTTPS (mostly client-initiated)
    k1 = ("10.0.0.100", "10.0.0.1", 52341, 443, "TCP")
    convs[k1] = _conv(
        "10.0.0.100", "10.0.0.1", "aa:bb:cc:44:55:66", "aa:bb:cc:11:22:33",
        "TCP", "TLS", 800, 200, 60000, 120000, 52341, 443, 1000.0, 2000.0,
    )

    # Server → Printer: IPP
    k2 = ("10.0.0.1", "10.0.0.50", 44123, 631, "TCP")
    convs[k2] = _conv(
        "10.0.0.1", "10.0.0.50", "aa:bb:cc:11:22:33", "aa:bb:cc:77:88:99",
        "TCP", "HTTP", 50, 50, 5000, 5000, 44123, 631, 1100.0, 1900.0,
    )

    # Server → IoT camera: RTSP
    k3 = ("10.0.0.1", "10.0.0.200", 44124, 554, "TCP")
    convs[k3] = _conv(
        "10.0.0.1", "10.0.0.200", "aa:bb:cc:11:22:33", "aa:bb:cc:aa:bb:cc",
        "TCP", "RTSP", 300, 300, 25000, 25000, 44124, 554, 1000.0, 2000.0,
    )

    # Workstation → IoT: mDNS
    k4 = ("10.0.0.100", "224.0.0.251", 5353, 5353, "UDP")
    convs[k4] = _conv(
        "10.0.0.100", "224.0.0.251", "aa:bb:cc:44:55:66", "aa:bb:cc:aa:bb:cc",
        "UDP", "MDNS", 20, 0, 2000, 0, 5353, 5353, 1005.0, 1010.0,
    )

    # Server → Workstation: SSH
    k5 = ("10.0.0.1", "10.0.0.100", 22, 52342, "TCP")
    convs[k5] = _conv(
        "10.0.0.1", "10.0.0.100", "aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66",
        "TCP", "SSH", 150, 150, 12000, 8000, 22, 52342, 1200.0, 1800.0,
    )

    # Asymmetric conversation: server → workstation, suspicious port 4444
    k6 = ("10.0.0.1", "10.0.0.100", 4444, 52343, "TCP")
    convs[k6] = _conv(
        "10.0.0.1", "10.0.0.100", "aa:bb:cc:11:22:33", "aa:bb:cc:44:55:66",
        "TCP", None, 500, 5, 40000, 400, 4444, 52343, 1500.0, 1550.0,
    )

    return convs


# ------------------------------------------------------------------
# 1. Device role inference
# ------------------------------------------------------------------


class TestDeviceRoles:
    def test_infers_server_role(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        assert "aa:bb:cc:11:22:33" in roles
        assert roles["aa:bb:cc:11:22:33"]["role"] == "server"

    def test_infers_workstation_role(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        assert "aa:bb:cc:44:55:66" in roles
        # Dell workstation with ephemeral ports should be workstation
        assert roles["aa:bb:cc:44:55:66"]["role"] in ("workstation",)

    def test_infers_printer_role_from_oui(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        assert roles["aa:bb:cc:77:88:99"]["role"] == "printer"

    def test_infers_camera_role_from_oui(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        # Arlo is in CAMERA_OUIS
        assert roles["aa:bb:cc:aa:bb:cc"]["role"] == "camera"

    def test_all_macs_have_roles(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        for mac in sample_devices:
            assert mac in roles, f"Missing role for {mac}"
            assert "role" in roles[mac]
            assert "confidence" in roles[mac]
            assert "evidence" in roles[mac]

    def test_role_confidence_in_range(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        for r in roles.values():
            assert 0.0 <= r["confidence"] <= 1.0


# ------------------------------------------------------------------
# 2. Network segment discovery
# ------------------------------------------------------------------


class TestNetworkSegments:
    def test_discovers_subnet(self, sample_devices, sample_conversations):
        segments = discover_network_segments(sample_devices, sample_conversations)
        assert len(segments["ipv4_segments"]) > 0
        segment = segments["ipv4_segments"][0]
        assert "10.0.0.0/24" in segment["subnet"]
        assert segment["num_ips"] >= 4

    def test_detects_ipv4_not_ipv6(self, sample_devices, sample_conversations):
        segments = discover_network_segments(sample_devices, sample_conversations)
        assert segments["ipv6_present"] is False

    def test_total_ips_matches_devices(self, sample_devices, sample_conversations):
        segments = discover_network_segments(sample_devices, sample_conversations)
        # 4 unique IPs in our test data
        assert segments["total_ips"] == 4


# ------------------------------------------------------------------
# 3. Topology inference
# ------------------------------------------------------------------


class TestTopology:
    def test_builds_graph(self, sample_devices, sample_conversations):
        topo = infer_topology(sample_devices, sample_conversations)
        assert topo["node_count"] == 4
        assert topo["link_count"] >= 3
        assert all("id" in n for n in topo["nodes"])
        assert all("source" in l for l in topo["links"])

    def test_nodes_have_roles_when_provided(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        topo = infer_topology(sample_devices, sample_conversations, roles)
        for node in topo["nodes"]:
            assert "role" in node
            assert node["role"] != "unknown"

    def test_links_have_aggregated_stats(self, sample_devices, sample_conversations):
        topo = infer_topology(sample_devices, sample_conversations)
        for link in topo["links"]:
            assert link["total_packets"] > 0
            assert link["conversation_count"] >= 1


# ------------------------------------------------------------------
# 4. Anomaly detection
# ------------------------------------------------------------------


class TestAnomalies:
    def test_detects_suspicious_port(self, sample_devices, sample_conversations):
        anomalies = detect_anomalies(sample_devices, sample_conversations)
        suspicious = [a for a in anomalies if a["type"] == "suspicious_port"]
        assert len(suspicious) >= 1
        assert any(a["port"] == 4444 for a in suspicious)

    def test_detects_asymmetric_traffic(self, sample_devices, sample_conversations):
        anomalies = detect_anomalies(sample_devices, sample_conversations)
        asymmetric = [a for a in anomalies if a["type"] == "asymmetric_traffic"]
        # Conversation on port 4444 is 50→0
        assert len(asymmetric) >= 1

    def test_anomalies_have_severity(self, sample_devices, sample_conversations):
        anomalies = detect_anomalies(sample_devices, sample_conversations)
        for a in anomalies:
            assert "severity" in a
            assert "type" in a
            assert "description" in a

    def test_no_anomalies_on_clean_data(self):
        # Empty data produces no anomalies
        devices = {}
        convs = {}
        anomalies = detect_anomalies(devices, convs)
        assert anomalies == []


# ------------------------------------------------------------------
# 5. Conversation timeline
# ------------------------------------------------------------------


class TestTimeline:
    def test_builds_timeline(self, sample_conversations, sample_devices):
        timeline = build_conversation_timeline(
            sample_conversations, sample_devices, bucket_seconds=100.0
        )
        assert len(timeline) > 0
        assert all("timestamp" in b for b in timeline)
        assert all("packets" in b for b in timeline)
        assert all("label" in b for b in timeline)

    def test_timeline_covers_time_range(self, sample_conversations):
        timeline = build_conversation_timeline(
            sample_conversations, bucket_seconds=500.0
        )
        assert len(timeline) >= 2  # 1000-2000 range with 500s buckets = 2+ buckets

    def test_empty_timeline(self):
        timeline = build_conversation_timeline({})
        assert timeline == []

    def test_timeline_has_top_talkers(self, sample_conversations, sample_devices):
        timeline = build_conversation_timeline(
            sample_conversations, sample_devices, bucket_seconds=100.0
        )
        for bucket in timeline:
            assert "top_talkers" in bucket
            assert isinstance(bucket["top_talkers"], list)


# ------------------------------------------------------------------
# 6. Summary report
# ------------------------------------------------------------------


class TestSummaryReport:
    def test_generates_report(self, sample_devices, sample_conversations):
        report = build_summary_report(
            "test_capture.pcap", sample_devices, sample_conversations
        )
        assert "EXECUTIVE SUMMARY" in report
        assert "test_capture.pcap" in report
        assert "Devices found" in report
        assert "Conversations" in report

    def test_report_includes_roles(self, sample_devices, sample_conversations):
        roles = infer_device_roles(sample_devices, sample_conversations)
        report = build_summary_report(
            "test.pcap", sample_devices, sample_conversations, roles=roles
        )
        assert "DEVICE ROLES" in report
        # Should contain at least some role labels (case-insensitive)
        assert any(role in report.lower() for role in ["server", "printer", "iot", "camera", "workstation"])

    def test_report_includes_anomalies(self, sample_devices, sample_conversations):
        anomalies = detect_anomalies(sample_devices, sample_conversations)
        report = build_summary_report(
            "test.pcap", sample_devices, sample_conversations,
            anomalies=anomalies,
        )
        assert "ANOMALIES" in report


# ------------------------------------------------------------------
# 7. GeoIP enrichment
# ------------------------------------------------------------------


class TestGeoIP:
    def test_handles_private_ips(self, sample_devices, sample_conversations):
        from pcap_analysis import enrich_geoip as enrich
        result = enrich(sample_devices, sample_conversations)
        # All our test IPs are private (10.x.x.x), so result should be empty
        assert len(result) == 0

    def test_identifies_public_ips(self):
        from pcap_analysis import enrich_geoip, _is_private_ip
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("192.168.1.1") is True
        assert _is_private_ip("8.8.8.8") is False


# ------------------------------------------------------------------
# 8. PCAP slicing
# ------------------------------------------------------------------


class TestSlicing:
    def test_slice_by_protocol(self, sample_conversations):
        criteria = SliceCriteria(protocol="TCP")
        sliced = slice_conversations(sample_conversations, criteria)
        assert len(sliced) >= 4  # 5 TCP convs, maybe one less
        for conv in sliced.values():
            assert conv.protocol == "TCP"

    def test_slice_by_port(self, sample_conversations):
        criteria = SliceCriteria(port=443)
        sliced = slice_conversations(sample_conversations, criteria)
        assert len(sliced) >= 1
        for conv in sliced.values():
            ports = [
                conv.source_tcp_port, conv.target_tcp_port,
                conv.source_udp_port, conv.target_udp_port,
            ]
            assert 443 in ports

    def test_slice_by_time_range(self, sample_conversations):
        criteria = SliceCriteria(start_time=1500.0, end_time=2500.0)
        sliced = slice_conversations(sample_conversations, criteria)
        assert len(sliced) < len(sample_conversations)

    def test_slice_device_info(self, sample_devices, sample_conversations):
        criteria = SliceCriteria(protocol="TCP")
        sliced_convs = slice_conversations(sample_conversations, criteria)
        sliced_devs = slice_device_info(sample_devices, sliced_convs)
        # Server (aa:bb:cc:11:22:33) should be in sliced
        assert "aa:bb:cc:11:22:33" in sliced_devs
        assert len(sliced_devs) <= len(sample_devices)

    def test_slice_by_src_ip(self, sample_conversations):
        criteria = SliceCriteria(src_ip="10.0.0.1")
        sliced = slice_conversations(sample_conversations, criteria)
        # 10.0.0.1 appears as source (k2,k3,k5,k6) or target (k1) → 5 total
        assert len(sliced) == 5
