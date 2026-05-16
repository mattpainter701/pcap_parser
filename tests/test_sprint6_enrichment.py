"""Tests for Sprint 6: Output Quality and Enrichment."""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pcap_parser import (
    ConversationSummary,
    DeviceSummary,
    _classify_traffic_pattern,
    _group_conversations,
    _map_vlan_devices,
    enrich_outputs,
    infer_service_name,
    interpret_diffserv_field,
    _enrich_conversations,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_conv(**overrides) -> ConversationSummary:
    """Create a ConversationSummary with defaults suitable for testing."""
    defaults = {
        "source_ip": "10.0.0.1",
        "source_mac": "aa:bb:cc:dd:ee:01",
        "source_tcp_port": 49152,
        "target_ip": "10.0.0.2",
        "target_mac": "aa:bb:cc:dd:ee:02",
        "target_tcp_port": 443,
        "protocol": "TCP",
        "app_protocol": "HTTPS",
        "packets_a_to_b": 5,
        "packets_b_to_a": 4,
        "bytes_a_to_b": 2000,
        "bytes_b_to_a": 1500,
        "first_seen": 1000.0,
        "last_seen": 1001.0,
        "duration": 1.0,
        "vlan_id": None,
        "dsfield": None,
        "diffserv_label": None,
        "service_name": None,
        "service_confidence": 0.0,
        "traffic_pattern": None,
    }
    defaults.update(overrides)
    conv = ConversationSummary()
    for key, val in defaults.items():
        setattr(conv, key, val)
    return conv


# ---------------------------------------------------------------------------
# Traffic pattern classification
# ---------------------------------------------------------------------------

class TestTrafficPattern:
    def test_request_response(self):
        """Symmetric short exchange → request-response."""
        conv = _make_conv(packets_a_to_b=3, packets_b_to_a=3)
        assert _classify_traffic_pattern(conv) == "request-response"

    def test_streaming_large_bytes_asymmetric(self):
        """Large byte volume + highly asymmetric → streaming."""
        conv = _make_conv(
            packets_a_to_b=1000,
            packets_b_to_a=5,
            bytes_a_to_b=200_000,
            bytes_b_to_a=1000,
            duration=10.0,
        )
        assert _classify_traffic_pattern(conv) == "streaming"

    def test_streaming_long_asymmetric(self):
        """Long duration + highly asymmetric → streaming."""
        conv = _make_conv(
            packets_a_to_b=200,
            packets_b_to_a=2,
            duration=30.0,
        )
        assert _classify_traffic_pattern(conv) == "streaming"

    def test_polling(self):
        """Small, regular symmetric exchanges over time → polling."""
        conv = _make_conv(
            packets_a_to_b=6,
            packets_b_to_a=6,
            bytes_a_to_b=200,
            bytes_b_to_a=200,
            duration=60.0,
        )
        assert _classify_traffic_pattern(conv) == "polling"

    def test_burst(self):
        """Many pkts one-way, few return, short duration → burst."""
        conv = _make_conv(
            packets_a_to_b=50,
            packets_b_to_a=2,
            duration=0.5,
        )
        assert _classify_traffic_pattern(conv) == "burst"

    def test_chatty(self):
        """Lots of small rapid symmetric exchanges → chatty."""
        conv = _make_conv(
            packets_a_to_b=15,
            packets_b_to_a=15,
            bytes_a_to_b=3000,
            bytes_b_to_a=3000,
            duration=0.5,
        )
        assert _classify_traffic_pattern(conv) == "chatty"

    def test_peer_to_peer(self):
        """Highly symmetric with many packets → peer-to-peer."""
        conv = _make_conv(
            packets_a_to_b=50,
            packets_b_to_a=45,
            bytes_a_to_b=10000,
            bytes_b_to_a=9000,
            duration=5.0,
        )
        assert _classify_traffic_pattern(conv) == "peer-to-peer"

    def test_empty(self):
        """Zero packets → unknown."""
        conv = _make_conv(packets_a_to_b=0, packets_b_to_a=0)
        assert _classify_traffic_pattern(conv) == "unknown"

    def test_single_packet(self):
        """Single packet → request-response (default)."""
        conv = _make_conv(packets_a_to_b=1, packets_b_to_a=0)
        assert _classify_traffic_pattern(conv) == "request-response"


# ---------------------------------------------------------------------------
# Service mapping with confidence
# ---------------------------------------------------------------------------

class TestServiceMapping:
    def test_well_known_port(self):
        """HTTPS on port 443 → high confidence."""
        name, conf = infer_service_name(
            source_tcp_port=443,
            app_protocol="HTTPS",
            protocol="TCP",
        )
        assert name == "HTTPS"
        assert conf >= 0.95

    def test_ssh_port(self):
        """SSH on port 22."""
        name, conf = infer_service_name(target_tcp_port=22, protocol="TCP")
        assert name == "SSH"
        assert conf >= 0.80

    def test_dns_udp(self):
        """DNS on UDP/53."""
        name, conf = infer_service_name(source_udp_port=53, protocol="UDP")
        assert name == "DNS"
        assert conf >= 0.80

    def test_app_protocol_overrides_port(self):
        """pyshark detected HTTP on port 8080."""
        name, conf = infer_service_name(
            target_tcp_port=8080,
            app_protocol="HTTP",
            protocol="TCP",
        )
        assert name == "HTTP"
        assert conf >= 0.95

    def test_unknown_port(self):
        """High ephemeral port → no match."""
        name, conf = infer_service_name(source_tcp_port=60000, protocol="TCP")
        assert name is None
        assert conf == 0.0

    def test_no_ports(self):
        """No ports given."""
        name, conf = infer_service_name(protocol="TCP")
        assert conf == 0.0

    def test_tls_maps_to_https(self):
        """TLS app_protocol → HTTPS."""
        name, conf = infer_service_name(
            source_tcp_port=443, app_protocol="TLS", protocol="TCP"
        )
        assert name == "HTTPS"
        assert conf >= 0.70


# ---------------------------------------------------------------------------
# Enrich conversations
# ---------------------------------------------------------------------------

class TestEnrichConversations:
    def test_populates_service_fields(self):
        """_enrich_conversations sets service_name and service_confidence."""
        conv = _make_conv(
            source_tcp_port=443,
            app_protocol="HTTPS",
            protocol="TCP",
            service_name=None,
            service_confidence=0.0,
        )
        convs = {"k": conv}
        _enrich_conversations(convs)
        assert conv.service_name == "HTTPS"
        assert conv.service_confidence >= 0.95

    def test_populates_traffic_pattern(self):
        """_enrich_conversations sets traffic_pattern."""
        conv = _make_conv(traffic_pattern=None)
        convs = {"k": conv}
        _enrich_conversations(convs)
        assert conv.traffic_pattern is not None
        assert conv.traffic_pattern in (
            "request-response", "streaming", "polling",
            "burst", "chatty", "peer-to-peer", "unknown",
        )

    def test_populates_diffserv_label(self):
        """_enrich_conversations sets diffserv_label from dsfield."""
        conv = _make_conv(
            dsfield="0xb8",  # DSCP 46 = EF, ECN 0 = Not-ECT
            diffserv_label=None,
        )
        convs = {"k": conv}
        _enrich_conversations(convs)
        assert conv.diffserv_label is not None
        assert "EF" in conv.diffserv_label

    def test_does_not_overwrite_existing_diffserv_label(self):
        """If diffserv_label is already set, don't overwrite."""
        conv = _make_conv(
            dsfield="0x00",
            diffserv_label="CS0 / Not-ECT",
        )
        convs = {"k": conv}
        _enrich_conversations(convs)
        assert conv.diffserv_label == "CS0 / Not-ECT"


# ---------------------------------------------------------------------------
# Conversation grouping
# ---------------------------------------------------------------------------

class TestConversationGrouping:
    def test_groups_same_mac_pair(self):
        """Two conversations between same MAC pair → grouped."""
        c1 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
        )
        c2 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            source_tcp_port=49153,
            target_tcp_port=80,
            app_protocol="HTTP",
        )
        convs = {("10.0.0.1", "10.0.0.2", 443, 49152, "TCP"): c1,
                 ("10.0.0.1", "10.0.0.2", 80, 49153, "TCP"): c2}
        groups = _group_conversations(convs)
        assert len(groups["mac_pairs"]) >= 1

    def test_groups_client_service_chain(self):
        """Same source MAC → same target IP → grouped."""
        c1 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            source_ip="10.0.0.1",
            target_ip="10.0.0.2",
            target_udp_port=53,
            protocol="UDP",
            app_protocol="DNS",
            service_name="DNS",
        )
        c2 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            source_ip="10.0.0.1",
            target_ip="10.0.0.2",
            target_tcp_port=443,
            protocol="TCP",
            app_protocol="HTTPS",
            service_name="HTTPS",
        )
        convs = {("10.0.0.1", "10.0.0.2", 53, 0, "UDP"): c1,
                 ("10.0.0.1", "10.0.0.2", 443, 49152, "TCP"): c2}
        groups = _group_conversations(convs)
        assert len(groups["client_service_chains"]) >= 1

    def test_groups_service_clusters(self):
        """Same service across different endpoints → grouped."""
        c1 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            target_tcp_port=443,
            app_protocol="HTTPS",
            service_name="HTTPS",
        )
        c2 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:03",
            target_tcp_port=443,
            app_protocol="HTTPS",
            service_name="HTTPS",
        )
        convs = {("10.0.0.1", "10.0.0.2", 443, 49152, "TCP"): c1,
                 ("10.0.0.1", "10.0.0.3", 443, 49153, "TCP"): c2}
        groups = _group_conversations(convs)
        assert "HTTPS" in groups["service_clusters"]

    def test_empty_input(self):
        """Empty conversation dict → empty groups."""
        groups = _group_conversations({})
        assert groups["mac_pairs"] == {}
        assert groups["client_service_chains"] == {}
        assert groups["service_clusters"] == {}


# ---------------------------------------------------------------------------
# VLAN-to-device mapping
# ---------------------------------------------------------------------------

class TestVlanDeviceMapping:
    def test_maps_devices_to_vlans(self):
        """Devices on different VLANs are correctly mapped."""
        c1 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            vlan_id="100",
        )
        c2 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:03",
            target_mac="aa:bb:cc:dd:ee:04",
            vlan_id="200",
        )
        device_info = {
            "aa:bb:cc:dd:ee:01": DeviceSummary(),
            "aa:bb:cc:dd:ee:02": DeviceSummary(),
            "aa:bb:cc:dd:ee:03": DeviceSummary(),
            "aa:bb:cc:dd:ee:04": DeviceSummary(),
        }
        convs = {"k1": c1, "k2": c2}
        mapping = _map_vlan_devices(device_info, convs)
        assert "100" in mapping
        assert "200" in mapping
        assert mapping["100"]["device_count"] == 2
        assert mapping["200"]["device_count"] == 2

    def test_no_vlans(self):
        """No VLAN-tagged conversations → empty mapping."""
        c1 = _make_conv(vlan_id=None)
        convs = {"k1": c1}
        mapping = _map_vlan_devices({}, convs)
        assert mapping == {}

    def test_vlan_stats(self):
        """VLAN mapping includes traffic statistics."""
        c1 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:01",
            target_mac="aa:bb:cc:dd:ee:02",
            vlan_id="100",
            packets_a_to_b=10,
            packets_b_to_a=5,
            bytes_a_to_b=5000,
            bytes_b_to_a=3000,
        )
        convs = {"k1": c1}
        mapping = _map_vlan_devices({}, convs)
        assert mapping["100"]["total_packets"] == 15
        assert mapping["100"]["total_bytes"] == 8000
        assert mapping["100"]["conversation_count"] == 1


# ---------------------------------------------------------------------------
# DiffServ interpretation
# ---------------------------------------------------------------------------

class TestDiffServ:
    def test_ef_class(self):
        """EF (Expedited Forwarding) DSCP 46."""
        label = interpret_diffserv_field("0xb8")  # DSCP 46, ECN 0
        assert "EF" in label

    def test_cs0(self):
        """CS0 (Best Effort)."""
        label = interpret_diffserv_field(0x00)
        assert "CS0" in label

    def test_af31(self):
        """AF31 DSCP 26."""
        label = interpret_diffserv_field(26 << 2)  # DSCP 26, ECN 0
        assert "AF31" in label

    def test_ecn_ce(self):
        """Congestion Experienced ECN."""
        label = interpret_diffserv_field(0x03)  # DSCP 0, ECN 3
        assert "CE" in label

    def test_ecn_ect1(self):
        """ECT(1) ECN."""
        label = interpret_diffserv_field(0x01)
        assert "ECT(1)" in label

    def test_none_input(self):
        """None → None."""
        assert interpret_diffserv_field(None) is None

    def test_empty_string(self):
        """Empty string → None."""
        assert interpret_diffserv_field("") is None

    def test_invalid_input(self):
        """Non-numeric string → None."""
        assert interpret_diffserv_field("not_a_number") is None


# ---------------------------------------------------------------------------
# Enrich outputs (integration)
# ---------------------------------------------------------------------------

class TestEnrichOutputs:
    def test_returns_all_summaries(self):
        """enrich_outputs returns vlan_mapping, conversation_groups, service_summary,
        diffserv_summary, traffic_pattern_summary."""
        c1 = _make_conv(
            vlan_id="100",
            service_name="HTTPS",
            service_confidence=0.98,
            traffic_pattern="request-response",
            diffserv_label="EF / Not-ECT",
        )
        c2 = _make_conv(
            source_mac="aa:bb:cc:dd:ee:03",
            target_mac="aa:bb:cc:dd:ee:04",
            vlan_id="100",
            target_tcp_port=22,
            app_protocol="SSH",
            service_name="SSH",
            service_confidence=0.98,
            traffic_pattern="streaming",
            diffserv_label="CS0 / Not-ECT",
            packets_a_to_b=200,
            packets_b_to_a=5,
            bytes_a_to_b=100000,
        )
        device_info = {
            "aa:bb:cc:dd:ee:01": DeviceSummary(),
            "aa:bb:cc:dd:ee:02": DeviceSummary(),
        }
        convs = {"k1": c1, "k2": c2}
        result = enrich_outputs(device_info, convs)

        assert "vlan_mapping" in result
        assert "conversation_groups" in result
        assert "service_summary" in result
        assert "diffserv_summary" in result
        assert "traffic_pattern_summary" in result

        # Service summary
        svc = result["service_summary"]
        assert "HTTPS" in svc
        assert "SSH" in svc
        assert svc["HTTPS"]["conversation_count"] == 1

        # Traffic pattern summary
        patterns = result["traffic_pattern_summary"]
        assert "request-response" in patterns
        assert "streaming" in patterns

        # DiffServ summary
        dscp = result["diffserv_summary"]
        assert "EF / Not-ECT" in dscp
        assert "CS0 / Not-ECT" in dscp

    def test_empty_input(self):
        """enrich_outputs handles empty input gracefully."""
        result = enrich_outputs({}, {})
        assert result["vlan_mapping"] == {}
        assert result["conversation_groups"] == {
            "mac_pairs": {},
            "client_service_chains": {},
            "service_clusters": {},
        }
        assert result["service_summary"] == {}
        assert result["diffserv_summary"] == {}
        assert result["traffic_pattern_summary"] == {}


# ---------------------------------------------------------------------------
# Topology-friendly link records (via pcap_analysis)
# ---------------------------------------------------------------------------

class TestTopologyEnrichment:
    def test_topology_links_include_enriched_fields(self):
        """infer_topology links include service_names, traffic_patterns, vlan_ids, etc."""
        from pcap_analysis import infer_topology

        c1 = _make_conv(
            vlan_id="100",
            service_name="HTTPS",
            traffic_pattern="request-response",
            diffserv_label="EF / Not-ECT",
        )
        # Need to set service_name etc. on the conv
        c1.service_name = "HTTPS"
        c1.traffic_pattern = "request-response"
        c1.diffserv_label = "EF / Not-ECT"

        device_info = {
            "aa:bb:cc:dd:ee:01": DeviceSummary(
                packet_count=10,
                first_seen=1000.0,
                last_seen=1005.0,
            ),
            "aa:bb:cc:dd:ee:02": DeviceSummary(
                packet_count=8,
                first_seen=1000.0,
                last_seen=1005.0,
            ),
        }
        # Add IP connections so the node builder has data
        from pcap_parser import PortSummary
        device_info["aa:bb:cc:dd:ee:01"].ip_connections["10.0.0.1"] = PortSummary()
        device_info["aa:bb:cc:dd:ee:02"].ip_connections["10.0.0.2"] = PortSummary()
        device_info["aa:bb:cc:dd:ee:02"].ip_connections["10.0.0.2"].tcp_ports.add(443)

        convs = {"k1": c1}
        topo = infer_topology(device_info, convs)

        assert len(topo["links"]) >= 1
        link = topo["links"][0]
        assert "service_names" in link
        assert "traffic_patterns" in link
        assert "vlan_ids" in link
        assert "diffserv_labels" in link
        assert "bandwidth_bytes_per_sec" in link

    def test_topology_nodes_include_services_and_vlans(self):
        """infer_topology nodes include services and vlans fields."""
        from pcap_analysis import infer_topology

        c1 = _make_conv(
            vlan_id="100",
            service_name="HTTPS",
        )
        c1.service_name = "HTTPS"

        device_info = {
            "aa:bb:cc:dd:ee:01": DeviceSummary(
                packet_count=10,
                first_seen=1000.0,
                last_seen=1005.0,
            ),
            "aa:bb:cc:dd:ee:02": DeviceSummary(
                packet_count=8,
                first_seen=1000.0,
                last_seen=1005.0,
            ),
        }
        from pcap_parser import PortSummary
        device_info["aa:bb:cc:dd:ee:01"].ip_connections["10.0.0.1"] = PortSummary()
        device_info["aa:bb:cc:dd:ee:02"].ip_connections["10.0.0.2"] = PortSummary()

        convs = {"k1": c1}
        topo = infer_topology(device_info, convs)

        for node in topo["nodes"]:
            assert "services" in node
            assert "vlans" in node
            assert isinstance(node["services"], list)
            assert isinstance(node["vlans"], list)
