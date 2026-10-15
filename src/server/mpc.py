"""MPC service protocol: VLI, host blocks, tagged parameters, service packets.

This implements the Marvel Protocol Client (MPC) RPC layer — the message
format that travels inside logical pipes.
"""

import struct

from .config import (
    MPC_CHUNKED_REF_LEN,
    MPC_CLASS_ONEWAY_MASK,
    MPC_CONTINUATION_HEADER_LEN,
    MPC_TAG_CHUNKED,
    MPC_TAG_CHUNKED_COMPRESSED,
    MPC_TAG_VARIABLE,
    MPC_TAG_VARIABLE_COMPRESSED,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
    TRANSPORT_PACKET_SIZE,
)
from .models import (
    ByteParam,
    ChunkedParam,
    DirsrvRequest,
    DwordParam,
    EndMarker,
    ErrorParam,
    HostBlock,
    UnknownParam,
    VarParam,
    WordParam,
)
from .pipe import build_control_frame, build_pipe_frame, build_pipe_header
from .transport import build_packet

# --- Variable-Length Integers ---


def encode_vli(value):
    """Encode an integer as a VLI (1/2/4 bytes based on top 2 bits).

    The form boundaries are strict comparisons, matching
    `MPCCL!AllocateRequestIdVliHeader @ 0x046034C6` byte for byte: each form's
    widest value spills into the next form up, so 0x3F is `80 3f` and 0x3FFF is
    `c0 00 3f ff`.  0x3FFFFFFF has no encoding — the client marks the request
    header invalid instead of emitting one.
    """
    if value < 0x3F:
        return bytes([value])
    elif value < 0x3FFF:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    elif value < 0x3FFFFFFF:
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


def is_oneway(msg_class):
    """A one-way continuation frame: all of the 0xE0 class bits set."""
    return (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK


def parse_host_block(data):
    """Parse an MPC host block. Returns HostBlock or None.

    A one-way continuation frame (class bits 0xE0 set) is not a call: it has no
    request id and no selector, only `[class][stream_id][raw bytes]` per
    `MPCCL!AppendChunkedRequestField @ 0x04606CB2`. Decoding a VLI out of its
    body would eat the first payload bytes, so the stream id lands in
    `selector` and `request_id` stays 0.
    """
    if len(data) < 2:
        return None
    msg_class = data[0]
    if is_oneway(msg_class):
        return HostBlock(
            msg_class=msg_class,
            selector=data[1],
            request_id=0,
            payload=data[MPC_CONTINUATION_HEADER_LEN:],
        )
    if len(data) < 3:
        return None
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


# --- MPCCL iterator-cancel control frame ---

# Single-byte payload appended by `MPCCL!AppendRequestTagByte @ 0x0460699E`
# from `MPCCL!FUN_046046e7`, the vtable[+0xc] hook invoked by
# `MVTTL14C!MVAsyncSubscriberUnsubscribe @ 0x7E844FE3` on subscriber teardown
# regardless of the `skipWireUnsubscribe` flag.  Framing layer concern: any
# selector that opened a stream iterator can receive this cancel.
MPCCL_ITERATOR_CANCEL_TAG = 0x0F
ITERATOR_CANCEL_ACK = bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])


def is_iterator_cancel(payload):
    """True iff payload is the MPCCL iterator-cancel control frame.

    Sent on the same `(class, selector, req_id)` triple as the original
    stream-iterator subscribe.  No legitimate tagged-param wire encoding
    produces a bare 1-byte `0x0F` payload — every send-side primitive
    tag (`0x01`–`0x05`) carries data after it, and every receive-side
    descriptor has bit 7 set.  See `docs/MEDVIEW.md` §6d.0.
    """
    return payload == bytes([MPCCL_ITERATOR_CANCEL_TAG])


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


_SCALAR_PARAMS = {
    0x01: (ByteParam, "<B", 1),
    0x02: (WordParam, "<H", 2),
    0x03: (DwordParam, "<I", 4),
}


def _decode_scalar(tag, tag_type, data, pos):
    """Decode a byte/word/dword field. Returns (param, new_pos), or
    (None, pos) when the field is truncated."""
    cls, fmt, size = _SCALAR_PARAMS[tag_type]
    if pos + size > len(data):
        return None, pos
    return cls(tag=tag, value=struct.unpack_from(fmt, data, pos)[0]), pos + size


def _decode_var(tag, data, pos):
    """Decode an inline variable field. Returns (VarParam, new_pos), or
    (None, pos) when the size prefix is truncated."""
    length, pos = _decode_var_length(data, pos)
    if length is None:
        return None, pos
    return VarParam(tag=tag, data=data[pos : pos + length]), pos + length


def parse_request_params(data):
    """Decode send-side tagged parameters from an MPC request payload.

    Send-side tags (bit 7 clear): 0x01=byte, 0x02=word, 0x03=dword,
    0x04/0x44=variable, 0x05/0x45=chunked reference.
    Receive descriptors (bit 7 set): 0x81-0x88, no data attached.

    Bit 0x40 on a variable tag means the content is compressed. The client
    picks it per call site: `AppendSendBufferField @ MPCCL 0x04603C0A` passes
    0x04 and `AppendSendOwnedDwordField @ 0x04603B4F` passes 0x44 (vtable
    0x0460CDB0 slots 13 and 14), and `AppendTaggedRequestField @ 0x046067E2`
    compresses before it decides inline vs chunked. So 0x44 and 0x45 are the
    compressed forms of 0x04 and 0x05, and the length that reaches the wire is
    always the compressed one. The codec is not implemented here — see
    `ChunkedParam.compressed` / `VarParam.compressed`.

    A chunked reference is 6 bytes and carries no inline data — the field rides
    class 0xE6/0xE7 frames instead. It must not go through the variable-field
    branch: `_decode_var_length` would read the stream id as a length byte and
    slice the rest of the request into a bogus value.
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

        if tag in _SCALAR_PARAMS:
            param, pos = _decode_scalar(tag, tag, data, pos)
            if param is None:
                break
            send_params.append(param)
        elif tag in (MPC_TAG_CHUNKED, MPC_TAG_CHUNKED_COMPRESSED):
            if pos + MPC_CHUNKED_REF_LEN > len(data):
                break
            stream_id = data[pos]
            total_length = struct.unpack("<I", data[pos + 1 : pos + 5])[0]
            send_params.append(
                ChunkedParam(tag=tag, stream_id=stream_id, total_length=total_length)
            )
            pos += MPC_CHUNKED_REF_LEN
        elif tag in (MPC_TAG_VARIABLE, MPC_TAG_VARIABLE_COMPRESSED):
            param, pos = _decode_var(tag, data, pos)
            if param is None:
                break
            send_params.append(param)
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
                # An array of 8-byte `_MosLid64` ids, `dword_0` long:
                # [field_0:u32 service/class index][field_8:u32 node sub-id].
                # MOSFIND resolves 20 search hits per call
                # (CFindResultSet_GetNextRow @ 0x7E9B182B); every other caller
                # sends one.
                d = p.data
                req.node_ids = [
                    f"{f0}:{f8}" for f0, f8 in struct.iter_unpack("<II", d[: len(d) - len(d) % 8])
                ] or [d.hex()]
                req.node_id_raw = d
            elif var_idx == 1:
                req.prop_group = p.data.rstrip(b"\x00").decode("ascii", errors="replace")
            elif var_idx == 2:
                req.locale_raw = p.data
                if len(p.data) >= 8:
                    _unknown_locale_dword, locale_lcid = struct.unpack("<II", p.data[:8])
                    req.locale_lcid = locale_lcid
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

        if tag_type in _SCALAR_PARAMS:
            param, pos = _decode_scalar(tag, tag_type, data, pos)
            if param is None:
                break
            params.append(param)
        elif tag_type in (0x04, 0x05, 0x06, 0x08):
            param, pos = _decode_var(tag, data, pos)
            if param is None:
                break
            params.append(param)
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
    """Encode a reply-side variable length. Bit 7 = inline.

    Strict boundaries, matching the inline branch of
    `MPCCL!AppendTaggedRequestField @ 0x046067E2` (`CMP len,0x7f / JNC` at
    0x046068F0, `CMP len,0x7fff / JNC` at 0x04606956) byte for byte: 127 spills
    into the two-byte form as `00 7f`, and 0x7FFF has no inline encoding — the
    client fails the call with 0x80004005 rather than emit one.
    """
    if length < 0x7F:
        return bytes([length | 0x80])
    if length > 0x7FFE:
        raise ValueError(f"variable field too long for an inline size: {length}")
    return bytes([length >> 8, length & 0xFF])


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


def build_static_reply(*tagged_fields):
    """Concatenate tagged primitive fields and append `0x87` end-static.

    Used by selectors whose spec return is a static section with no
    dynamic body — e.g. `0x83 <dword> 0x87`, `0x81 <byte> 0x83 <dword> 0x87`.
    """
    return b"".join(tagged_fields) + b"\x87"


# --- Service Packet Assembly ---


def build_service_packet(
    pipe_idx, host_block, server_seq, client_ack, max_wire_bytes=TRANSPORT_PACKET_SIZE
):
    """Wrap a host block for delivery on a logical service pipe.

    Returns a list of wire packets, each at most `max_wire_bytes`. A message
    that does not fit in one packet is split across continuation frames that
    MOSCP reassembles:

      frame 1      header_byte + u16 total_pipe_data_len + chunk
      frames 2..N  header_byte + chunk; last_data set on frame N

    MOSCP sizes the buffer from frame 1's prefix and appends until last_data.
    Each split point is the largest chunk whose stuffed packet still fits:
    stuffing expansion depends on content, so a fixed margin can overflow
    (GetShabby for default.ico, 25 stuffable bytes in 1078, produced a
    1029-byte frame that MOSCP dropped).
    """
    routing_prefix = struct.pack("<H", pipe_idx)
    pipe_data = routing_prefix + host_block

    frame = build_pipe_frame(pipe_idx, pipe_data, last=True)
    pkt = build_packet(server_seq, client_ack, frame)
    if len(pkt) <= max_wire_bytes:
        return [pkt]

    size_prefix = struct.pack("<H", len(pipe_data))
    packets = []
    pos = 0
    seq = server_seq
    frame_idx = 0

    while pos < len(pipe_data):
        frame_idx += 1
        prefix = size_prefix if frame_idx == 1 else b""
        remaining = len(pipe_data) - pos

        lo, hi = 1, remaining
        while lo < hi:
            mid = (lo + hi + 1) // 2
            is_last = pos + mid == len(pipe_data)
            probe_frame = build_pipe_header(pipe_idx, is_last) + prefix + pipe_data[pos : pos + mid]
            if len(build_packet(seq, client_ack, probe_frame)) <= max_wire_bytes:
                lo = mid
            else:
                hi = mid - 1

        chunk_size = lo
        is_last = pos + chunk_size == len(pipe_data)
        frame = build_pipe_header(pipe_idx, is_last) + prefix + pipe_data[pos : pos + chunk_size]
        packets.append(build_packet(seq, client_ack, frame))
        pos += chunk_size
        seq = (seq + 1) & 0x7F

    return packets


def build_pipe_open_result_content(client_pipe_idx):
    """Body of the pipe-open response, without any routing in front of it."""
    return struct.pack(
        "<HHHH",
        client_pipe_idx,
        0x0001,  # command: pipe open success
        client_pipe_idx,  # server pipe idx (mirror client's)
        0x0000,  # error: success
    )


def build_pipe_open_result(client_pipe_idx, server_seq, client_ack):
    """Build Select-protocol pipe-open response."""
    pipe_frame = build_pipe_frame(client_pipe_idx, build_pipe_open_result_content(client_pipe_idx))
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
