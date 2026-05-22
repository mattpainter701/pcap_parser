"""NTP packet dissector."""
import struct

NTP_PACKET_SIZE = 48


class NTPError(Exception):
    """Base NTP dissector error."""
    pass


class InvalidModeError(NTPError):
    """Raised when the NTP mode is invalid/unsupported."""
    pass


class InvalidLeapIndicatorError(NTPError):
    """Raised for invalid leap indicator values (currently unreachable in 2 bits)."""
    pass


class TruncatedPacketError(NTPError):
    """Raised when the packet is shorter than the minimum NTP header."""
    pass


class KissOfDeathError(NTPError):
    """Raised for stratum 0 (kiss-o'-death) packets."""
    pass


def dissect_ntp(data: bytes) -> dict:
    """Parse an NTP packet and return a dictionary with its fields.

    Args:
        data: Raw NTP payload bytes.

    Returns:
        Dictionary with parsed NTP fields.

    Raises:
        TruncatedPacketError: If less than 48 bytes.
        InvalidLeapIndicatorError: If leap indicator > 3 (not possible with 2 bits).
        InvalidModeError: If mode is 0, 6, or 7 (reserved/unsupported).
        KissOfDeathError: If stratum == 0.
    """
    if len(data) < NTP_PACKET_SIZE:
        raise TruncatedPacketError(
            f"Packet too short: {len(data)} bytes, need at least {NTP_PACKET_SIZE}"
        )

    # First byte layout: LI (2) | VN (3) | Mode (3)
    byte0 = data[0]
    leap_indicator = (byte0 >> 6) & 0x03
    version = (byte0 >> 3) & 0x07
    mode = byte0 & 0x07

    # Leap indicator is 2 bits; nothing >3 is possible, but we guard anyway.
    if leap_indicator > 3:
        raise InvalidLeapIndicatorError(f"Leap indicator out of range: {leap_indicator}")

    # NTP modes 0 (reserved), 6 (control), 7 (private) are treated as invalid here.
    if mode in (0, 6, 7):
        raise InvalidModeError(f"Unsupported NTP mode: {mode}")

    stratum = data[1]
    if stratum == 0:
        # Kiss-o'-death: reference ID is a four-character ASCII string
        ref_id = data[12:16]
        try:
            msg = ref_id.decode("ascii", errors="replace").strip("\x00")
        except UnicodeDecodeError:
            msg = repr(ref_id)
        raise KissOfDeathError(f"Kiss-o'-death: {msg}")

    # Timestamps (64-bit NTP timestamps split into 32-bit seconds + 32-bit fraction)
    timestamps = {}
    for name, offset in [
        ("reference", 16),
        ("origin", 24),
        ("receive", 32),
        ("transmit", 40),
    ]:
        raw = data[offset:offset+8]
        seconds, fraction = struct.unpack("!II", raw)
        timestamps[name] = (seconds, fraction)

    root_delay, = struct.unpack("!I", data[4:8])
    root_dispersion, = struct.unpack("!I", data[8:12])
    ref_id_hex = data[12:16].hex()

    return {
        "leap_indicator": leap_indicator,
        "version": version,
        "mode": mode,
        "stratum": stratum,
        "poll": data[2],
        "precision": data[3],
        "root_delay": root_delay,
        "root_dispersion": root_dispersion,
        "reference_id": ref_id_hex,
        "timestamps": timestamps,
    }
