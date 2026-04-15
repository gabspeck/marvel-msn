"""Pipe multiplexing: frame building/parsing, control frames, pipe-0 routing.

Up to 16 logical pipes are multiplexed over a single connection. All traffic
flows through pipe 0 with a 2-byte LE routing prefix.
"""

import struct

from .config import (
    PIPE_ALWAYS_SET,
    PIPE_CONTINUATION,
    PIPE_HAS_LENGTH,
    PIPE_INDEX_MASK,
    PIPE_LAST_DATA,
    ROUTING_CONTROL,
    ROUTING_PIPE_OPEN,
)
from .models import ControlMessage, PipeData, PipeFrame, PipeOpenRequest
from .wire import decode_header_byte, encode_header_byte


def build_pipe_frame(pipe_index, data, last=True):
    """Build a continuation-format pipe frame.

    Continuation format: bit 5 set, all remaining packet bytes belong to
    this pipe. Used for normal data and pipe-open responses.
    """
    flags = PIPE_ALWAYS_SET | PIPE_CONTINUATION
    if last:
        flags |= PIPE_LAST_DATA
    hdr = encode_header_byte(flags | (pipe_index & PIPE_INDEX_MASK))
    content_length = struct.pack("<H", len(data))
    return bytes([hdr]) + content_length + data


def build_pipe_frame_has_length(pipe_index, data, last=True):
    """Build a has_length-format pipe frame.

    Has_length format: bit 4 set, next byte gives the data length.
    Used for pipe-open ACK and multi-frame packets.
    """
    flags = PIPE_ALWAYS_SET | PIPE_HAS_LENGTH
    if last:
        flags |= PIPE_LAST_DATA
    hdr = encode_header_byte(flags | (pipe_index & PIPE_INDEX_MASK))
    data_bytes = struct.pack("<H", len(data)) + data
    length_byte = encode_header_byte(len(data_bytes) | PIPE_ALWAYS_SET)
    return bytes([hdr, length_byte]) + data_bytes


def build_control_frame(ctrl_type, payload):
    """Build a control frame: 0xFFFF marker + type byte + payload."""
    return struct.pack("<HB", ROUTING_CONTROL, ctrl_type) + payload


def parse_pipe_frame(payload):
    """Parse a single pipe frame from unstuffed transport payload.

    Returns (PipeFrame, bytes_consumed) or (None, 0).
    """
    if not payload:
        return None, 0

    hdr = decode_header_byte(payload[0])
    pipe_idx = hdr & PIPE_INDEX_MASK
    has_length = bool(hdr & PIPE_HAS_LENGTH)
    continuation = bool(hdr & PIPE_CONTINUATION)
    last_data = bool(hdr & PIPE_LAST_DATA)

    pos = 1
    if continuation:
        data_bytes = payload[pos:]
        pos = len(payload)
    else:
        if pos >= len(payload):
            return None, 0
        data_len = decode_header_byte(payload[pos]) & 0x7F
        pos += 1
        data_bytes = payload[pos : pos + data_len]
        pos += data_len

    if len(data_bytes) < 2:
        return None, pos
    content_length = struct.unpack("<H", data_bytes[0:2])[0]
    content = data_bytes[2 : 2 + content_length]

    return PipeFrame(
        pipe_idx=pipe_idx,
        has_length=has_length,
        continuation=continuation,
        last_data=last_data,
        content_length=content_length,
        content=content,
    ), pos


def parse_pipe_frames(payload):
    """Parse all pipe frames in a transport payload."""
    frames = []
    pos = 0
    while pos < len(payload):
        pf, consumed = parse_pipe_frame(payload[pos:])
        if pf is None:
            break
        frames.append(pf)
        pos += consumed
    return frames


def parse_pipe0_content(content):
    """Route pipe-0 content by its 2-byte LE routing prefix.

    Returns ControlMessage, PipeOpenRequest, PipeData, or None.
    """
    if len(content) < 2:
        return None

    routing = struct.unpack("<H", content[0:2])[0]

    if routing == ROUTING_CONTROL:
        ctrl_type = content[2] if len(content) > 2 else 0
        return ControlMessage(ctrl_type=ctrl_type, data=content[3:])
    elif routing == ROUTING_PIPE_OPEN:
        if len(content) < 6:
            return None
        _, pipe_idx = struct.unpack("<HH", content[2:6])
        rest = content[6:]
        parts = rest.split(b"\x00", 2)
        svc_name = parts[0].decode("ascii", errors="replace") if parts else ""
        ver_param = parts[1].decode("ascii", errors="replace") if len(parts) > 1 else ""
        tail = parts[2] if len(parts) > 2 else b""
        version = struct.unpack("<I", tail[:4])[0] if len(tail) >= 4 else 0
        return PipeOpenRequest(
            client_pipe_idx=pipe_idx,
            svc_name=svc_name,
            ver_param=ver_param,
            version=version,
        )
    else:
        return PipeData(pipe_idx=routing, data=content[2:])
