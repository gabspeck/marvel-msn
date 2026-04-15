"""Transport packets: build, parse, ACK, and transport parameter negotiation.

A packet on the wire is: SeqNo | AckNo | StuffedPayload | MaskedCRC | 0x0D
"""

import struct

from .config import (
    ACK_SEQ_BYTE,
    NACK_SEQ_BYTE,
    PACKET_TERMINATOR,
    TRANSPORT_ACK_BEHIND,
    TRANSPORT_ACK_TIMEOUT_MS,
    TRANSPORT_MAX_BYTES,
    TRANSPORT_PACKET_SIZE,
    TRANSPORT_WINDOW_SIZE,
)
from .models import Packet
from .pipe import build_control_frame, build_pipe_frame
from .wire import (
    byte_stuff,
    byte_unstuff,
    crc32,
    decode_header_byte,
    encode_header_byte,
    mask_crc,
)


def build_packet(seq, ack, raw_payload):
    """Assemble a wire-ready packet from sequence numbers and raw payload."""
    seq_byte = encode_header_byte(seq | 0x80)
    ack_byte = encode_header_byte(ack | 0x80)
    stuffed = byte_stuff(raw_payload)
    wire_data = bytes([seq_byte, ack_byte]) + stuffed
    crc_val = crc32(wire_data)
    crc_bytes = struct.pack("<I", crc_val)
    masked = mask_crc(crc_bytes)
    return wire_data + masked + bytes([PACKET_TERMINATOR])


def build_ack_packet(ack):
    """Build an ACK-only packet (no payload)."""
    ack_byte = encode_header_byte(ack | 0x80)
    wire_data = bytes([ACK_SEQ_BYTE, ack_byte])
    crc_val = crc32(wire_data)
    crc_bytes = struct.pack("<I", crc_val)
    masked = mask_crc(crc_bytes)
    return wire_data + masked + bytes([PACKET_TERMINATOR])


def parse_packet(raw_packet):
    """Parse a raw 0x0D-terminated packet (without the terminator).

    Returns Packet or None if too short.
    """
    if len(raw_packet) < 6:
        return None

    first = raw_packet[0]
    if first == ACK_SEQ_BYTE:
        pkt_type = "ACK"
        seq = None
    elif first == NACK_SEQ_BYTE:
        pkt_type = "NACK"
        seq = None
    else:
        pkt_type = "DATA"
        seq = decode_header_byte(first) & 0x7F

    ack = decode_header_byte(raw_packet[1]) & 0x7F
    stuffed_payload = raw_packet[2:-4]
    wire_crc = raw_packet[-4:]
    computed_crc = crc32(raw_packet[:-4])
    computed_bytes = struct.pack("<I", computed_crc)
    masked_computed = mask_crc(computed_bytes)
    crc_ok = masked_computed == wire_crc
    payload = byte_unstuff(stuffed_payload)

    return Packet(
        type=pkt_type,
        seq=seq,
        ack=ack,
        payload=payload,
        crc_ok=crc_ok,
    )


def build_transport_params():
    """Build the type-3 control frame with transport parameters."""
    params = struct.pack(
        "<IIIII",
        TRANSPORT_PACKET_SIZE,
        TRANSPORT_MAX_BYTES,
        TRANSPORT_WINDOW_SIZE,
        TRANSPORT_ACK_BEHIND,
        TRANSPORT_ACK_TIMEOUT_MS,
    )
    ctrl = build_control_frame(3, params)
    pipe = build_pipe_frame(0, ctrl)
    return build_packet(0, 0, pipe)
