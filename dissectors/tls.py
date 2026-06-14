"""
TLS Handshake Metadata Extractor (Sprint 24)

Extracts TLS handshake metadata without decryption:
- SNI (Server Name Indication)
- ALPN (Application-Layer Protocol Negotiation)
- Cipher suites offered/selected
- Protocol version
- Parses ClientHello and ServerHello messages

Note: TCP port 443 is the standard TLS port, but TLS can run on any port.
The extractor works on raw payload bytes after TCP/IP headers.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


# TLS record types
TLS_HANDSHAKE = 22
TLS_CHANGE_CIPHER_SPEC = 20

# Handshake message types
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2

# TLS versions
TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Common cipher suite names (subset for readability)
CIPHER_SUITE_NAMES = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

# ALPN protocol identifiers
ALPN_PROTOCOLS = {
    b"h2": "h2 (HTTP/2)",
    b"http/1.1": "http/1.1",
    b"grpc": "grpc",
    b"mqtt": "mqtt",
    b"dns": "dns-over-tls",
}


@dataclass
class TLSHandshakeMetadata:
    """Metadata extracted from a TLS handshake."""
    message_type: str = ""
    protocol_version: str = ""
    version_raw: int = 0
    sni: Optional[str] = None
    alpn: list = field(default_factory=list)
    cipher_suites: list = field(default_factory=list)
    selected_cipher: Optional[str] = None
    extensions: list = field(default_factory=list)
    random_bytes: Optional[bytes] = None

    def to_dict(self):
        result = {
            "message_type": self.message_type,
            "protocol_version": self.protocol_version,
            "version_raw": self.version_raw,
        }
        if self.sni:
            result["sni"] = self.sni
        if self.alpn:
            result["alpn"] = self.alpn
        if self.cipher_suites:
            result["cipher_suites"] = self.cipher_suites
        if self.selected_cipher:
            result["selected_cipher"] = self.selected_cipher
        return result


def _parse_sni_extension(data):
    """Parse SNI extension data (extension type 0x0000)."""
    if len(data) < 5:
        return None
    # SNI extension: 2 bytes list length, 1 byte name type, 2 bytes name length, name
    sni_list_len = struct.unpack('!H', data[0:2])[0]
    if len(data) < 2 + sni_list_len:
        return None
    name_type = data[2]
    if name_type != 0:  # hostname
        return None
    name_len = struct.unpack('!H', data[3:5])[0]
    if len(data) < 5 + name_len:
        return None
    return data[5:5 + name_len].decode('ascii', errors='ignore')


def _parse_alpn_extension(data):
    """Parse ALPN extension data (extension type 0x0010)."""
    protocols = []
    offset = 0
    if len(data) < 2:
        return protocols
    proto_list_len = struct.unpack('!H', data[0:2])[0]
    offset = 2
    while offset < 2 + proto_list_len and offset + 1 < len(data):
        proto_len = data[offset]
        offset += 1
        if offset + proto_len > len(data):
            break
        proto = data[offset:offset + proto_len]
        proto_str = ALPN_PROTOCOLS.get(proto, proto.decode('ascii', errors='ignore'))
        protocols.append(proto_str)
        offset += proto_len
    return protocols


def _parse_extensions(data):
    """Parse TLS extensions and extract SNI and ALPN."""
    sni = None
    alpn = []
    extensions = []
    offset = 0
    while offset + 3 < len(data):
        ext_type = struct.unpack('!H', data[offset:offset+2])[0]
        ext_len = struct.unpack('!H', data[offset+2:offset+4])[0]
        ext_data = data[offset+4:offset+4+ext_len]
        extensions.append(f"0x{ext_type:04x}")
        if ext_type == 0x0000:  # SNI
            sni = _parse_sni_extension(ext_data)
        elif ext_type == 0x0010:  # ALPN
            alpn = _parse_alpn_extension(ext_data)
        offset += 4 + ext_len
    return sni, alpn, extensions


def dissect_tls_handshake(payload):
    """
    Dissect a TLS handshake from raw payload bytes.

    Args:
        payload: bytes starting at the TLS record header.

    Returns:
        TLSHandshakeMetadata or None if not a valid TLS handshake.
    """
    if len(payload) < 5:
        return None

    # TLS record header: content type (1), version (2), length (2)
    content_type = payload[0]
    record_version = struct.unpack('!H', payload[1:3])[0]
    record_length = struct.unpack('!H', payload[3:5])[0]

    if content_type != TLS_HANDSHAKE:
        return None

    if record_version not in TLS_VERSIONS:
        return None

    # Handshake header: type (1), length (3)
    if len(payload) < 9:
        return None
    handshake_type = payload[5]
    handshake_length = (payload[6] << 16) | (payload[7] << 8) | payload[8]

    meta = TLSHandshakeMetadata()
    meta.version_raw = record_version
    meta.protocol_version = TLS_VERSIONS.get(record_version, f"Unknown (0x{record_version:04x})")

    if handshake_type == HANDSHAKE_CLIENT_HELLO:
        meta.message_type = "ClientHello"
        if len(payload) < 14:
            return meta

        # Client version
        client_version = struct.unpack('!H', payload[9:11])[0]
        if client_version in TLS_VERSIONS:
            meta.protocol_version = TLS_VERSIONS[client_version]
            meta.version_raw = client_version

        # Random bytes (32 bytes)
        meta.random_bytes = payload[11:43]

        # Session ID
        if len(payload) > 43:
            session_id_len = payload[43]
            offset = 44 + session_id_len
        else:
            return meta

        # Cipher suites
        if offset + 2 <= len(payload):
            cipher_suites_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            num_suites = cipher_suites_len // 2
            for i in range(num_suites):
                if offset + 2 > len(payload):
                    break
                suite = struct.unpack('!H', payload[offset:offset+2])[0]
                name = CIPHER_SUITE_NAMES.get(suite, f"0x{suite:04x}")
                meta.cipher_suites.append(name)
                offset += 2

        # Compression methods (skip)
        if offset < len(payload):
            comp_len = payload[offset]
            offset += 1 + comp_len

        # Extensions
        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            ext_data = payload[offset:offset+ext_total_len]
            meta.sni, meta.alpn, meta.extensions = _parse_extensions(ext_data)

    elif handshake_type == HANDSHAKE_SERVER_HELLO:
        meta.message_type = "ServerHello"
        if len(payload) < 14:
            return meta

        # Server version
        server_version = struct.unpack('!H', payload[9:11])[0]
        if server_version in TLS_VERSIONS:
            meta.protocol_version = TLS_VERSIONS[server_version]
            meta.version_raw = server_version

        # Random bytes (32 bytes)
        meta.random_bytes = payload[11:43]

        # Session ID
        if len(payload) > 43:
            session_id_len = payload[43]
            offset = 44 + session_id_len
        else:
            return meta

        # Selected cipher suite
        if offset + 2 <= len(payload):
            suite = struct.unpack('!H', payload[offset:offset+2])[0]
            meta.selected_cipher = CIPHER_SUITE_NAMES.get(suite, f"0x{suite:04x}")
            offset += 2

        # Compression method (skip)
        if offset < len(payload):
            offset += 1

        # Extensions
        if offset + 2 <= len(payload):
            ext_total_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            ext_data = payload[offset:offset+ext_total_len]
            meta.sni, meta.alpn, meta.extensions = _parse_extensions(ext_data)
    else:
        return None

    return meta
