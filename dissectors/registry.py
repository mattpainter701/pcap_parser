"""Registry mapping protocol numbers to dissectors."""
from dissectors.icmpv6 import dissect_icmpv6
from dissectors.tls import dissect_tls_handshake

REGISTRY = {
    58: dissect_icmpv6,  # ICMPv6 over IPv6
}
