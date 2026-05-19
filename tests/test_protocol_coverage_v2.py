from types import SimpleNamespace

import pcap_parser
from pcap_parser import (
    dns_name_is_safely_decoded,
    extract_tls_client_metadata,
    infer_service_name,
)


class Packet(SimpleNamespace):
    pass


def test_detects_dhcp_from_layer_and_ports():
    packet = Packet(bootp=SimpleNamespace(), highest_layer="DATA")

    assert pcap_parser._detect_application_protocol(
        packet,
        src_udp_port=68,
        dst_udp_port=67,
        highest_layer="DATA",
    ) == "DHCP"
    assert infer_service_name(source_udp_port=68, target_udp_port=67, app_protocol="BOOTP") == (
        "DHCP",
        0.98,
    )


def test_detects_infrastructure_layers_before_generic_highest_layer():
    assert pcap_parser._detect_application_protocol(Packet(arp=SimpleNamespace()), highest_layer="ETH") == "ARP"
    assert pcap_parser._detect_application_protocol(Packet(icmpv6=SimpleNamespace()), highest_layer="IPV6") == "ICMPv6"


def test_extract_tls_sni_and_alpn_defensively():
    packet = Packet(
        tls=SimpleNamespace(
            handshake_extensions_server_name="app.example.test",
            handshake_extensions_alpn_str="h2",
        )
    )

    assert extract_tls_client_metadata(packet) == {"sni": "app.example.test", "alpn": "h2"}
    assert extract_tls_client_metadata(Packet()) == {}


def test_dns_compression_guard_rejects_decoder_error_labels():
    assert dns_name_is_safely_decoded("www.example.com") is True
    assert dns_name_is_safely_decoded("Malformed Packet: compression loop") is False
    assert dns_name_is_safely_decoded("a" * 254) is False
