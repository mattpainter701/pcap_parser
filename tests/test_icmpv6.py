"""Tests for ICMPv6 dissector."""
import struct
import pytest
from dissectors.icmpv6 import (
    dissect_icmpv6,
    ICMPv6Message,
    ICMPV6_NEIGHBOR_SOLICITATION,
    ICMPV6_NEIGHBOR_ADVERTISEMENT,
    ICMPV6_ROUTER_SOLICITATION,
    ICMPV6_ROUTER_ADVERTISEMENT,
    ICMPV6_DEST_UNREACHABLE,
    ICMPV6_TIME_EXCEEDED,
)

def _build_ns_packet(target_addr_bytes, source_lladdr=None):
    """Build a Neighbor Solicitation packet."""
    header = struct.pack('!BBH', 135, 0, 0x0000)  # checksum zero
    reserved = b'\x00\x00\x00\x00'
    target = target_addr_bytes  # 16 bytes
    options = b''
    if source_lladdr:
        opt_type = 1  # Source link-layer address
        opt_len = 1   # 8 bytes total
        lladdr = source_lladdr
        if len(lladdr) != 6:
            raise ValueError("LL address must be 6 bytes")
        options += struct.pack('!BB', opt_type, opt_len) + lladdr
    return header + reserved + target + options

def _build_na_packet(target_addr_bytes, flags=0x60, target_lladdr=None):
    header = struct.pack('!BBH', 136, 0, 0x0000)
    packed_flags = struct.pack('!I', flags)[0:4]  # 4 bytes: flags + reserved
    target = target_addr_bytes
    options = b''
    if target_lladdr:
        opt_type = 2  # Target link-layer address
        opt_len = 1
        options += struct.pack('!BB', opt_type, opt_len) + target_lladdr
    return header + packed_flags + target + options

def _build_rs_packet(source_lladdr=None):
    header = struct.pack('!BBH', 133, 0, 0x0000)
    reserved = b'\x00\x00\x00\x00'
    options = b''
    if source_lladdr:
        opt_type = 1
        opt_len = 1
        options += struct.pack('!BB', opt_type, opt_len) + source_lladdr
    return header + reserved + options

def _build_ra_packet(router_lifetime=1800, source_lladdr=None, mtu=None):
    header = struct.pack('!BBH', 134, 0, 0x0000)
    cur_hop_limit = 64
    flags = 0x00
    lifetime = struct.pack('!H', router_lifetime)
    reachable_time = struct.pack('!I', 0)
    retrans_timer = struct.pack('!I', 0)
    fixed = struct.pack('!BB', cur_hop_limit, flags) + lifetime + reachable_time + retrans_timer
    options = b''
    if source_lladdr:
        opt_type = 1
        opt_len = 1
        options += struct.pack('!BB', opt_type, opt_len) + source_lladdr
    if mtu:
        opt_type = 5
        opt_len = 1
        reserved = b'\x00\x00'
        mtu_bytes = struct.pack('!I', mtu)
        options += struct.pack('!BB', opt_type, opt_len) + reserved + mtu_bytes
    return header + fixed + options

class TestICMPv6Dissector:
    def test_ns_basic(self):
        target = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        pkt = _build_ns_packet(target)
        msg = dissect_icmpv6(pkt)
        assert msg.type == 135
        assert msg.code == 0
        assert msg.target_address is not None
        assert '2001:0db8:0000:0000:0000:0000:0000:0001' in msg.target_address

    def test_ns_with_source_lladdr(self):
        target = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        lladdr = b'\x00\x1a\x2b\x3c\x4d\x5e'
        pkt = _build_ns_packet(target, source_lladdr=lladdr)
        msg = dissect_icmpv6(pkt)
        assert msg.type == 135
        assert len(msg.options) == 1
        assert msg.options[0].type == 1
        assert msg.options[0].data == lladdr

    def test_na_basic(self):
        target = b'\xfe\x80\x00\x00\x00\x00\x00\x00\x12\x34\x56\xff\xfe\x78\x9a\xbc'
        pkt = _build_na_packet(target, target_lladdr=None)
        msg = dissect_icmpv6(pkt)
        assert msg.type == 136
        assert msg.code == 0
        assert msg.target_address is not None

    def test_na_with_target_lladdr(self):
        target = b'\x20\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
        lladdr = b'\x00\x11\x22\x33\x44\x55'
        pkt = _build_na_packet(target, target_lladdr=lladdr)
        msg = dissect_icmpv6(pkt)
        assert len(msg.options) == 1
        assert msg.options[0].type == 2
        assert msg.options[0].data == lladdr

    def test_rs_basic(self):
        pkt = _build_rs_packet()
        msg = dissect_icmpv6(pkt)
        assert msg.type == 133
        assert msg.code == 0

    def test_ra_with_mtu(self):
        pkt = _build_ra_packet(source_lladdr=b'\xaa\xbb\xcc\xdd\xee\xff', mtu=1500)
        msg = dissect_icmpv6(pkt)
        assert msg.type == 134
        assert len(msg.options) == 2
        mtu_opt = [o for o in msg.options if o.type == 5]
        assert len(mtu_opt) == 1
        assert mtu_opt[0].data == 1500

    def test_dest_unreachable(self):
        original = b'\x00' * 40
        pkt = struct.pack('!BBH', 1, 0, 0x0000) + b'\x00\x00\x00\x00' + original
        msg = dissect_icmpv6(pkt)
        assert msg.type == 1
        assert msg.code == 0

    def test_time_exceeded(self):
        pkt = struct.pack('!BBH', 3, 0, 0x0000) + b'\x00\x00\x00\x00' + b'\x11' * 40
        msg = dissect_icmpv6(pkt)
        assert msg.type == 3

    def test_registry_entry(self):
        from dissectors.registry import REGISTRY
        assert 58 in REGISTRY, "ICMPv6 dissector not registered for next header 58"
        assert callable(REGISTRY[58])
