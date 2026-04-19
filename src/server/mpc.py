"""MPC service protocol: VLI, host blocks, tagged parameters, service packets.

This implements the Marvel Protocol Client (MPC) RPC layer — the message
format that travels inside logical pipes.
"""

import struct

from .config import (
    PIPE_ALWAYS_SET,
    PIPE_CONTINUATION,
    PIPE_INDEX_MASK,
    PIPE_LAST_DATA,
)
from .models import (
    ByteParam,
    DirsrvRequest,
    DwordParam,
    EndMarker,
    ErrorParam,
    HostBlock,
    UnknownParam,
    VarParam,
    WordParam,
)
from .pipe import build_control_frame, build_pipe_frame
from .transport import build_packet
from .wire import encode_header_byte

# --- Variable-Length Integers ---


def encode_vli(value):
    """Encode an integer as a VLI (1/2/4 bytes based on top 2 bits)."""
    if value < 0x40:
        return bytes([value])
    elif value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    elif value < 0x40000000:
        return struct.pack(">I", value | 0xC0000000)
    else:
        raise ValueError(f"VLI value too large: {value}")


def decode_vli(data, pos=0):
    """Decode a VLI at the given position. Returns (value, bytes_consumed)."""
    if pos >= len(data):
        return None, 0
    first = data[pos]
    top2 = first & 0xC0
    if top2 == 0x00 or top2 == 0x40:
        return first & 0x3F, 1
    elif top2 == 0x80:
        if pos + 1 >= len(data):
            return None, 0
        return ((first & 0x3F) << 8) | data[pos + 1], 2
    else:
        if pos + 3 >= len(data):
            return None, 0
        val = struct.unpack(">I", data[pos : pos + 4])[0] & 0x3FFFFFFF
        return val, 4


# --- Host Blocks ---


def build_host_block(msg_class, selector, request_id, payload=b""):
    """Build an MPC host block: msg_class | selector | VLI request_id | payload."""
    return bytes([msg_class, selector]) + encode_vli(request_id) + payload


def build_discovery_host_block(payload, request_id=0):
    """Build a discovery block (selector=0, opcode=0)."""
    return build_host_block(0x00, 0x00, request_id, payload)


def parse_host_block(data):
    """Parse an MPC host block. Returns HostBlock or None."""
    if len(data) < 3:
        return None
    msg_class = data[0]
    selector = data[1]
    req_id, vli_len = decode_vli(data, 2)
    if req_id is None:
        return None
    pos = 2 + vli_len
    return HostBlock(
        msg_class=msg_class,
        selector=selector,
        request_id=req_id,
        payload=data[pos:],
    )


# --- Tagged Parameter Parsing ---


def _decode_var_length(data, pos):
    """Decode a variable-length field size. Returns (length, new_pos) or (None, pos) on truncation."""
    if pos >= len(data):
        return None, pos
    first = data[pos]
    pos += 1
    if first & 0x80:
        return first & 0x7F, pos
    if pos >= len(data):
        return None, pos
    length = (first << 8) | data[pos]
    return length, pos + 1


def parse_request_params(data):
    """Decode send-side tagged parameters from an MPC request payload.

    Send-side tags (bit 7 clear): 0x01=byte, 0x02=word, 0x03=dword,
    0x04=variable, 0x05=dynamic.
    Receive descriptors (bit 7 set): 0x81-0x88, no data attached.
    """
    send_params = []
    recv_descriptors = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        pos += 1

        if tag & 0x80:
            recv_descriptors.append(tag)
            continue

        if tag == 0x01:
            if pos >= len(data):
                break
            send_params.append(ByteParam(tag=tag, value=data[pos]))
            pos += 1
        elif tag == 0x02:
            if pos + 2 > len(data):
                break
            val = struct.unpack("<H", data[pos : pos + 2])[0]
            send_params.append(WordParam(tag=tag, value=val))
            pos += 2
        elif tag == 0x03:
            if pos + 4 > len(data):
                break
            val = struct.unpack("<I", data[pos : pos + 4])[0]
            send_params.append(DwordParam(tag=tag, value=val))
            pos += 4
        elif tag in (0x04, 0x05):
            length, pos = _decode_var_length(data, pos)
            if length is None:
                break
            val = data[pos : pos + length]
            send_params.append(VarParam(tag=tag, data=val))
            pos += length
        else:
            send_params.append(UnknownParam(tag=tag, data=data[pos:]))
            break

    return send_params, recv_descriptors


def decode_dirsrv_request(payload):
    """Decode a DIRSRV GetProperties request into a DirsrvRequest."""
    send_params, recv_descs = parse_request_params(payload)
    req = DirsrvRequest(recv_descriptors=recv_descs)
    var_idx = 0
    dword_idx = 0
    for p in send_params:
        if isinstance(p, VarParam):
            if var_idx == 0:
                # Wire node_id is an 8-byte "_MosLid64": [field_0:u32][field_8:u32].
                # Full 24-byte _MosNodeId is (field_0, pad4, field_8, field_c, field_10[u16]);
                # field_c / field_10 are truncated on the wire.
                # field_0 = service/class index (selects shell extension DLL),
                # field_8 = within-service node sub-id.  Children inherit field_0
                # from parent and get (field_8, field_c) from wire property 'a'.
                d = p.data
                if len(d) >= 8:
                    f0, f8 = struct.unpack("<II", d[:8])
                    req.node_id = f"{f0}:{f8}"
                else:
                    req.node_id = d.hex()
                req.node_id_raw = d
            elif var_idx == 1:
                req.prop_group = p.data.rstrip(b"\x00").decode("ascii", errors="replace")
            elif var_idx == 2:
                req.locale_raw = p.data
                req.locale_str = p.data.rstrip(b"\x00").decode("ascii", errors="replace")
            var_idx += 1
        elif isinstance(p, ByteParam):
            req.flags = p.value
        elif isinstance(p, DwordParam):
            if dword_idx == 0:
                req.dword_0 = p.value
            else:
                req.dword_1 = p.value
            dword_idx += 1
    return req


def parse_tagged_params(data):
    """Best-effort decode of MPC tagged parameters (reply-side)."""
    params = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        pos += 1
        tag_type = tag & 0x0F

        if tag_type == 0x01:
            if pos >= len(data):
                break
            params.append(ByteParam(tag=tag, value=data[pos]))
            pos += 1
        elif tag_type == 0x02:
            if pos + 2 > len(data):
                break
            val = struct.unpack("<H", data[pos : pos + 2])[0]
            params.append(WordParam(tag=tag, value=val))
            pos += 2
        elif tag_type == 0x03:
            if pos + 4 > len(data):
                break
            val = struct.unpack("<I", data[pos : pos + 4])[0]
            params.append(DwordParam(tag=tag, value=val))
            pos += 4
        elif tag_type in (0x04, 0x05, 0x06, 0x08):
            length, pos = _decode_var_length(data, pos)
            if length is None:
                break
            val = data[pos : pos + length]
            params.append(VarParam(tag=tag, data=val))
            pos += length
        elif tag_type == 0x07:
            params.append(EndMarker(tag=tag))
        elif tag_type == 0x0F:
            if pos + 4 > len(data):
                break
            val = struct.unpack("<I", data[pos : pos + 4])[0]
            params.append(ErrorParam(tag=tag, code=val))
            pos += 4
        else:
            params.append(UnknownParam(tag=tag, data=data[pos:]))
            break
    return params


# --- Reply Encoding ---


def encode_reply_var_length(length):
    """Encode a reply-side variable length. Bit 7 = inline (max 127)."""
    if length < 0x80:
        return bytes([length | 0x80])
    return bytes([(length >> 8) & 0x7F, length & 0xFF])


def build_tagged_reply_byte(value):
    """Build a 0x81 tagged byte reply."""
    return b"\x81" + bytes([value & 0xFF])


def build_tagged_reply_word(value):
    """Build a 0x82 tagged word reply."""
    return b"\x82" + struct.pack("<H", value & 0xFFFF)


def build_tagged_reply_dword(value):
    """Build a 0x83 tagged dword reply."""
    return b"\x83" + struct.pack("<I", value & 0xFFFFFFFF)


def build_tagged_reply_var(tag, data):
    """Build a variable-length tagged reply."""
    return bytes([tag]) + encode_reply_var_length(len(data)) + data


# --- Service Packet Assembly ---


def build_service_packet(pipe_idx, host_block, server_seq, client_ack, max_wire_bytes=1024):
    """Wrap a host block for delivery on a logical service pipe.

    Returns a list of wire packets.  When the payload fits in a single
    transport packet (≤ max_wire_bytes on the wire), the list has one
    element.  Larger payloads are split across two packets using MOSCP's
    multi-frame pipe reassembly:

      Packet 1 — continuation frame (no last_data):
        header_byte + uint16_le(total_pipe_data_len) + chunk1

      Packet 2 — continuation frame (last_data):
        header_byte + chunk2   (no size prefix — pipe context already
        allocated from packet 1's prefix)

    MOSCP allocates the pipe buffer from the 2-byte prefix in the first
    frame and preserves the pipe slot across packets when last_data is
    not set.
    """
    routing_prefix = struct.pack("<H", pipe_idx)
    pipe_data = routing_prefix + host_block

    # Try single-packet path
    frame = build_pipe_frame(pipe_idx, pipe_data, last=True)
    pkt = build_packet(server_seq, client_ack, frame)
    if len(pkt) <= max_wire_bytes:
        return [pkt]

    # Split across two packets.
    # Frame 1 overhead: header(1) + size_prefix(2) = 3 bytes in payload.
    # Packet overhead: seq(1) + ack(1) + CRC(4) + terminator(1) = 7 bytes.
    # Leave margin for byte-stuffing expansion.
    size_prefix = struct.pack("<H", len(pipe_data))
    overhead1 = 7 + 1 + 2  # packet framing + frame header + size prefix
    chunk1_max = max_wire_bytes - overhead1 - 20  # 20-byte stuffing margin
    chunk1 = pipe_data[:chunk1_max]
    chunk2 = pipe_data[chunk1_max:]

    frame1 = _build_continuation_frame(pipe_idx, size_prefix + chunk1, last=False)
    pkt1 = build_packet(server_seq, client_ack, frame1)

    seq2 = (server_seq + 1) & 0x7F
    frame2 = _build_continuation_frame(pipe_idx, chunk2, last=True)
    pkt2 = build_packet(seq2, client_ack, frame2)

    return [pkt1, pkt2]


def _build_continuation_frame(pipe_idx, content, last=True):
    """Build a raw continuation-format pipe frame (no size prefix added).

    The content is placed directly after the header byte.  Used by
    multi-frame fragmentation where the caller controls the prefix.
    """
    flags = PIPE_ALWAYS_SET | PIPE_CONTINUATION
    if last:
        flags |= PIPE_LAST_DATA
    hdr = encode_header_byte(flags | (pipe_idx & PIPE_INDEX_MASK))
    return bytes([hdr]) + content


def build_pipe_open_result(client_pipe_idx, server_seq, client_ack):
    """Build Select-protocol pipe-open response."""
    content = struct.pack(
        "<HHHH",
        client_pipe_idx,
        0x0001,  # command: pipe open success
        client_pipe_idx,  # server pipe idx (mirror client's)
        0x0000,  # error: success
    )
    pipe_frame = build_pipe_frame(client_pipe_idx, content)
    return build_packet(server_seq, client_ack, pipe_frame)


def build_control_type1_ack(server_seq, client_ack, payload=b""):
    """Echo a control type-1 payload back to the client."""
    ctrl = build_control_frame(1, payload)
    pipe = build_pipe_frame(0, ctrl)
    return build_packet(server_seq, client_ack, pipe)


def build_discovery_payload(guid_list):
    """Build an IID->selector discovery payload from a list of (guid_bytes_le, selector) pairs."""
    payload = bytearray()
    for guid_bytes, sel in guid_list:
        payload.extend(guid_bytes)
        payload.append(sel)
    return bytes(payload)
