"""Transport packets: build, parse, ACK, and transport parameter negotiation.

Two framings carry the same pipe traffic, matching the two protocol objects
ENGCT.EXE registers as `Select` and `Straight`:

* Select — the serial link. SeqNo | AckNo | StuffedPayload | MaskedCRC | 0x0D,
  with byte stuffing, CRC-32 and a Go-Back-N window.
* Straight — the TCP link. uint16 LE record length (counting itself) | command
  byte | pipe message. TCP already delivers in order, so nothing else is left:
  no sequence numbers, no ACKs, no stuffing, no CRC, no terminator.

The command byte is a copy of the message's own command byte, written by the
same call that puts it in the content: ENGCT's record builder (OSR2
`FUN_05712fd6` @ 0x05712fd6) emits the buffer's flag byte, which the data path
(`FUN_05713793`) zeroes and which `FUN_05713813` sets when it writes a command
into content[2]. Only the pipe close does that, with 0x01, so the byte is 1 on
a close and 0 on everything else. The receiver overwrites its copy from the
content before reading it (`PipeBuf_SetFlagFromContent` @ 0x0571384c), so it
carries no information and never routes anything.

Observed 2026-08-15 on the gateway port: the client's control type-4 arrived as
`06 00 00 ff ff 04` and its 299-byte type-1 declared `2b 01` — the length counts
the length field itself.
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
from .pipe import build_control_frame, build_pipe_frame, parse_pipe_frames
from .wire import (
    byte_stuff,
    byte_unstuff,
    crc32,
    decode_header_byte,
    encode_header_byte,
    mask_crc,
)

STRAIGHT_HEADER_LEN = 3


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


def build_straight_record(content, cmd=0):
    """Frame one whole pipe message as a Straight record.

    `cmd` echoes the message's command byte. Nothing we send has one, so it
    stays 0; the client ignores the field either way.
    """
    return struct.pack("<HB", STRAIGHT_HEADER_LEN + len(content), cmd) + content


def take_straight_records(buf):
    """Pull every whole pipe message off a Straight receive buffer.

    Consumes what it returns, leaving a partial record in place. Byte 2 is
    dropped: it duplicates the message's command byte and names nothing.
    """
    messages = []
    while len(buf) >= STRAIGHT_HEADER_LEN:
        total = struct.unpack_from("<H", buf)[0]
        if total < STRAIGHT_HEADER_LEN:
            # Unrecoverable: the stream carries no marker to resynchronise on.
            del buf[:]
            break
        if len(buf) < total:
            break
        messages.append(bytes(buf[STRAIGHT_HEADER_LEN:total]))
        del buf[:total]
    return messages


def reframe_as_straight(packets):
    """Re-frame Select packets — one builder's output — as Straight records.

    The builders speak Select because the serial path is the tested one. A
    Straight record carries its own length, so a message the Select builder had
    to split across packets goes back together into a single record here.
    """
    pending = {}
    buffers = {}
    records = []
    for pkt in packets:
        for frame in parse_pipe_frames(byte_unstuff(pkt[2:-5]), pending):
            idx = frame.reassembly_index
            buffers.setdefault(idx, bytearray()).extend(frame.content)
            if pending.get(idx, 0) == 0:
                records.append(build_straight_record(bytes(buffers[idx])))
                buffers[idx].clear()
    return records


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
