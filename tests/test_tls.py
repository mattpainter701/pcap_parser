"""
Tests for TLS Handshake Metadata Extractor (Sprint 24)
"""
import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dissectors.tls import (
    dissect_tls_handshake,
    TLSHandshakeMetadata,
    TLS_VERSIONS,
    CIPHER_SUITE_NAMES,
)


def _build_client_hello(
    version=0x0303,
    sni="example.com",
    alpn_protos=None,
    cipher_suites=None,
):
    """Build a minimal ClientHello message."""
    if cipher_suites is None:
        cipher_suites = [0xc02f, 0xc030, 0x1301]  # ECDHE_RSA AES128/256 GCM, AES128 GCM

    # Random (32 bytes)
    random_bytes = b'\x00' * 32

    # Session ID (empty)
    session_id = b'\x00'

    # Cipher suites
    cipher_data = b''
    for cs in cipher_suites:
        cipher_data += struct.pack('!H', cs)

    # Compression methods (null compression)
    compression = b'\x00'

    # Build extensions
    extensions = b''

    # SNI extension
    if sni:
        sni_host = sni.encode('ascii')
        sni_ext_data = struct.pack('!H', len(sni_host) + 3) + b'\x00' + struct.pack('!H', len(sni_host)) + sni_host
        extensions += struct.pack('!H', 0x0000) + struct.pack('!H', len(sni_ext_data)) + sni_ext_data

    # ALPN extension
    if alpn_protos:
        alpn_data = b''
        for proto in alpn_protos:
            proto_bytes = proto.encode('ascii') if isinstance(proto, str) else proto
            alpn_data += struct.pack('B', len(proto_bytes)) + proto_bytes
        # Oops, typo above - let me fix
        alpn_data = b''
        for proto in alpn_protos:
            proto_bytes = proto.encode('ascii') if isinstance(proto, str) else proto
            alpn_data += struct.pack('B', len(proto_bytes)) + proto_bytes
        alpn_ext_data = struct.pack('!H', len(alpn_data)) + alpn_data
        extensions += struct.pack('!H', 0x0010) + struct.pack('!H', len(alpn_ext_data)) + alpn_ext_data

    # ClientHello body
    hello_body = (
        struct.pack('!H', version) +
        random_bytes +
        session_id +
        struct.pack('!H', len(cipher_data)) +
        cipher_data +
        compression +
        struct.pack('!H', len(extensions)) +
        extensions
    )

    # Handshake header
    handshake = struct.pack('!B', 1) + struct.pack('!I', len(hello_body))[1:] + hello_body

    # TLS record header
    record = struct.pack('!B', 22) + struct.pack('!H', 0x0303) + struct.pack('!H', len(handshake)) + handshake
    return record


def _build_server_hello(
    version=0x0303,
    selected_cipher=0xc02f,
    sni=None,
    alpn_protos=None,
):
    """Build a minimal ServerHello message."""
    # Random (32 bytes)
    random_bytes = b'\x00' * 32

    # Session ID (empty)
    session_id = b'\x00'

    # Build extensions
    extensions = b''

    # ALPN extension (server selected protocol)
    if alpn_protos:
        alpn_data = b''
        for proto in alpn_protos:
            proto_bytes = proto.encode('ascii') if isinstance(proto, str) else proto
            alpn_data += struct.pack('B', len(proto_bytes)) + proto_bytes
        alpn_ext_data = struct.pack('!H', len(alpn_data)) + alpn_data
        extensions += struct.pack('!H', 0x0010) + struct.pack('!H', len(alpn_ext_data)) + alpn_ext_data

    # ServerHello body
    hello_body = (
        struct.pack('!H', version) +
        random_bytes +
        session_id +
        struct.pack('!H', selected_cipher) +
        b'\x00' +  # compression method
        struct.pack('!H', len(extensions)) +
        extensions
    )

    # Handshake header
    handshake = struct.pack('!B', 2) + struct.pack('!I', len(hello_body))[1:] + hello_body

    # TLS record header
    record = struct.pack('!B', 22) + struct.pack('!H', 0x0303) + struct.pack('!H', len(handshake)) + handshake
    return record


def test_client_hello_basic():
    """Test basic ClientHello parsing."""
    payload = _build_client_hello()
    meta = dissect_tls_handshake(payload)
    assert meta is not None
    assert meta.message_type == "ClientHello"
    assert meta.protocol_version == "TLS 1.2"
    assert len(meta.cipher_suites) == 3
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in meta.cipher_suites


def test_client_hello_sni():
    """Test SNI extraction from ClientHello."""
    payload = _build_client_hello(sni="www.google.com")
    meta = dissect_tls_handshake(payload)
    assert meta is not None
    assert meta.sni == "www.google.com"


def test_client_hello_alpn():
    """Test ALPN extraction from ClientHello."""
    payload = _build_client_hello(alpn_protos=["h2", "http/1.1"])
    meta = dissect_tls_handshake(payload)
    assert meta is not None
    assert len(meta.alpn) == 2
    assert "h2 (HTTP/2)" in meta.alpn
    assert "http/1.1" in meta.alpn


def test_server_hello():
    """Test ServerHello parsing."""
    payload = _build_server_hello(selected_cipher=0xc02f, alpn_protos=["h2"])
    meta = dissect_tls_handshake(payload)
    assert meta is not None
    assert meta.message_type == "ServerHello"
    assert meta.selected_cipher == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert len(meta.alpn) == 1
    assert "h2 (HTTP/2)" in meta.alpn


def test_to_dict():
    """Test to_dict serialization."""
    payload = _build_client_hello(sni="test.com")
    meta = dissect_tls_handshake(payload)
    d = meta.to_dict()
    assert d["message_type"] == "ClientHello"
    assert d["sni"] == "test.com"
    assert "cipher_suites" in d


def test_not_tls():
    """Test that non-TLS data returns None."""
    payload = b'\x00\x01\x02\x03\x04' + b'\x00' * 20
    meta = dissect_tls_handshake(payload)
    assert meta is None


def test_too_short():
    """Test that too-short payload returns None."""
    meta = dissect_tls_handshake(b'\x16\x03\x01')
    assert meta is None


def test_tls13():
    """Test TLS 1.3 version detection."""
    payload = _build_client_hello(version=0x0304)
    meta = dissect_tls_handshake(payload)
    assert meta is not None
    assert meta.protocol_version == "TLS 1.3"
    assert meta.version_raw == 0x0304


if __name__ == "__main__":
    tests = [
        test_client_hello_basic,
        test_client_hello_sni,
        test_client_hello_alpn,
        test_server_hello,
        test_to_dict,
        test_not_tls,
        test_too_short,
        test_tls13,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS: {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
