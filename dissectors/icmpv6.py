"""ICMPv6 dissector for parsing ICMPv6 messages."""
import struct

# ICMPv6 types
ICMPV6_NEIGHBOR_SOLICITATION = 135
ICMPV6_NEIGHBOR_ADVERTISEMENT = 136
ICMPV6_ROUTER_SOLICITATION = 133
ICMPV6_ROUTER_ADVERTISEMENT = 134
ICMPV6_DEST_UNREACHABLE = 1
ICMPV6_TIME_EXCEEDED = 3

# Option types
OPT_SOURCE_LINK_LAYER_ADDRESS = 1
OPT_TARGET_LINK_LAYER_ADDRESS = 2
OPT_MTU = 5

class ICMPv6Message:
    """Representation of an ICMPv6 message."""
    def __init__(self, type, code, checksum, body, options=None, target_address=None):
        self.type = type
        self.code = code
        self.checksum = checksum
        self.body = body
        self.options = options or []
        self.target_address = target_address

    def to_dict(self):
        """Convert to dictionary for easy consumption."""
        d = {
            'type': self.type,
            'code': self.code,
            'checksum': self.checksum,
            'options': [opt.to_dict() for opt in self.options],
        }
        if self.target_address:
            d['target_address'] = self.target_address
        return d

class ICMPv6Option:
    """ICMPv6 option in TLV format."""
    def __init__(self, type, data):
        self.type = type
        self.data = data

    def to_dict(self):
        return {
            'type': self.type,
            'data': self.data.hex() if isinstance(self.data, bytes) else str(self.data)
        }

def _parse_options(data, offset=0):
    """Parse ICMPv6 options from data starting at offset."""
    options = []
    i = offset
    while i < len(data):
        if i + 2 > len(data):
            break
        opt_type = data[i]
        opt_len = data[i+1]  # in units of 8 bytes
        if opt_len == 0:
            break
        opt_len_bytes = opt_len * 8
        if i + opt_len_bytes > len(data):
            break
        opt_data = data[i+2:i+opt_len_bytes]
        if opt_type == OPT_SOURCE_LINK_LAYER_ADDRESS or opt_type == OPT_TARGET_LINK_LAYER_ADDRESS:
            options.append(ICMPv6Option(opt_type, opt_data))
        elif opt_type == OPT_MTU:
            if len(opt_data) >= 6:
                mtu = struct.unpack('!I', opt_data[2:6])[0]
                options.append(ICMPv6Option(opt_type, mtu))
            else:
                options.append(ICMPv6Option(opt_type, opt_data))
        else:
            options.append(ICMPv6Option(opt_type, opt_data))
        i += opt_len_bytes
    return options

def _parse_target_address(data, offset):
    """Parse a 16-byte IPv6 target address from data at offset."""
    if offset + 16 <= len(data):
        addr = data[offset:offset+16]
        # Simple IPv6 address formatting (suppress zero compression for clarity)
        groups = [f"{addr[i*2]:02x}{addr[i*2+1]:02x}" for i in range(8)]
        return ':'.join(groups)
    return None

def dissect_icmpv6(payload):
    """Dissect an ICMPv6 message from raw payload bytes.

    Args:
        payload: bytes containing the ICMPv6 message (starting from type field).

    Returns:
        ICMPv6Message object.
    """
    if len(payload) < 4:
        raise ValueError("ICMPv6 payload too short")

    icmp_type = payload[0]
    icmp_code = payload[1]
    checksum = struct.unpack('!H', payload[2:4])[0]
    body = payload[4:]

    msg = ICMPv6Message(type=icmp_type, code=icmp_code, checksum=checksum, body=body)

    # Parse extension based on type
    if icmp_type == ICMPV6_NEIGHBOR_SOLICITATION:
        if len(body) >= 20:
            target_address = _parse_target_address(body, 4)
            msg.target_address = target_address
            msg.options = _parse_options(body, 20)
    elif icmp_type == ICMPV6_NEIGHBOR_ADVERTISEMENT:
        if len(body) >= 20:
            target_address = _parse_target_address(body, 4)
            msg.target_address = target_address
            msg.options = _parse_options(body, 20)
    elif icmp_type == ICMPV6_ROUTER_SOLICITATION:
        if len(body) >= 4:
            msg.options = _parse_options(body, 4)
    elif icmp_type == ICMPV6_ROUTER_ADVERTISEMENT:
        if len(body) >= 12:
            msg.options = _parse_options(body, 12)
    elif icmp_type == ICMPV6_DEST_UNREACHABLE:
        msg.options = []  # no standard options
    elif icmp_type == ICMPV6_TIME_EXCEEDED:
        msg.options = []

    return msg
