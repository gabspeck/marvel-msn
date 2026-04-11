#!/usr/bin/env python3
"""
MSN dial-up server. Accepts TCP connections from 86Box modem emulation.
After CONNECT, speaks the MOSCP/ENGCT transport protocol.

86Box: COM port modem -> dials -> TCP connection to this server.
"""

import os
import socket
import struct
import sys
import time
import uuid
import hashlib
from collections import defaultdict

HOST = "0.0.0.0"
PORT = 2323
LOGSRV_VARIANT = os.environ.get("LOGSRV_VARIANT", "login-bootstrap")
LOGSRV_SELECTOR = int(os.environ.get("LOGSRV_SELECTOR", "1"), 0) & 0xFF

def guid_bytes_le(guid_text):
    """Return GUID bytes in Windows in-memory layout, not RFC 4122 wire order."""
    return uuid.UUID(guid_text).bytes_le


# MPCCL ships with a contiguous LOGSRV interface GUID catalog. For this empirical probe, publish
# the whole family with monotonically increasing selectors in catalog order instead of mapping every
# IID to the same selector. If the service assigns selectors sequentially, GUIDE's requested 28BC2
# should resolve to selector 0x06 rather than 0x01.
#
# GUIDs must be sent in Windows in-memory layout because MPCCL later resolves them with memcmp()
# against in-process GUID constants from GUIDE.EXE/MPCCL.DLL.
LOGSRV_INTERFACE_GUIDS = [
    ("00028BB6-0000-0000-C000-000000000046", 0x01),
    ("00028BB7-0000-0000-C000-000000000046", 0x02),
    ("00028BB8-0000-0000-C000-000000000046", 0x03),
    ("00028BC0-0000-0000-C000-000000000046", 0x04),
    ("00028BC1-0000-0000-C000-000000000046", 0x05),
    ("00028BC2-0000-0000-C000-000000000046", 0x06),
    ("00028BC3-0000-0000-C000-000000000046", 0x07),
    ("00028BC4-0000-0000-C000-000000000046", 0x08),
    ("00028BC5-0000-0000-C000-000000000046", 0x09),
    ("00028BC6-0000-0000-C000-000000000046", 0x0A),
]

# DIRSRV interface GUID — captured at runtime via HW breakpoint on
# ResolveServiceSelectorForInterface. The client requests this IID
# twice (once per DIRSRV pipe).
DIRSRV_INTERFACE_GUIDS = [
    ("00028B27-0000-0000-C000-000000000046", 0x01),
]

# --- CRC-32 (from ENGCT.EXE, §2.4) ---
# Custom polynomial 0x248ef9be, init=0, no final XOR.
# Order: XOR → shift → NOT (from decompile of crc_table_init at VA 0x05712da3).

CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        if _c & 1:
            _c = (~((_c ^ 0x248ef9be) >> 1)) & 0xFFFFFFFF
        else:
            _c >>= 1
    CRC_TABLE.append(_c)


def crc32(data):
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ CRC_TABLE[(b ^ (crc & 0xFF)) & 0xFF]
    return crc


def short_hash(data):
    return hashlib.sha1(data).hexdigest()[:12]


# --- Wire encoding (from ENGCT.EXE disassembly) ---
#
# Three different encodings are used within a single packet:
#   1. Header bytes (SeqNo, AckNo): XOR 0xC0 if value is 0x8D/0x90/0x8B
#   2. Payload bytes: 0x1B escape stuffing (0x1B + digit)
#   3. CRC bytes: OR 0x60 masking
#
# CRC is computed over the WIRE bytes (after encoding), not raw bytes.

ESCAPE_SET = {0x1B, 0x0D, 0x10, 0x0B, 0x8D, 0x90, 0x8B}

STUFF_MAP = {
    0x1B: b'\x1b0',
    0x0D: b'\x1b1',
    0x10: b'\x1b2',
    0x0B: b'\x1b3',
    0x8D: b'\x1b4',
    0x90: b'\x1b5',
    0x8B: b'\x1b6',
}

UNSTUFF_MAP = {
    ord('0'): 0x1B,
    ord('1'): 0x0D,
    ord('2'): 0x10,
    ord('3'): 0x0B,
    ord('4'): 0x8D,
    ord('5'): 0x90,
    ord('6'): 0x8B,
}


def encode_header_byte(val):
    """Encode a SeqNo or AckNo byte for the wire. XOR 0xC0 if in {0x8D, 0x90, 0x8B}."""
    if val in (0x8D, 0x90, 0x8B):
        return val ^ 0xC0
    return val


def decode_header_byte(val):
    """Reverse of encode_header_byte."""
    # XOR 0xC0 reverses: 0x4D->0x8D, 0x50->0x90, 0x4B->0x8B
    if val in (0x4D, 0x50, 0x4B):
        return val ^ 0xC0
    return val


def byte_stuff(data):
    """0x1B escape encoding for payload bytes."""
    out = bytearray()
    for b in data:
        if b in STUFF_MAP:
            out.extend(STUFF_MAP[b])
        else:
            out.append(b)
    return bytes(out)


def byte_unstuff(data):
    """Reverse 0x1B escape encoding."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x1B and i + 1 < len(data):
            out.append(UNSTUFF_MAP.get(data[i + 1], data[i + 1]))
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def mask_crc(crc_bytes):
    """OR 0x60 masking for CRC bytes on the wire."""
    out = bytearray(crc_bytes)
    for i in range(len(out)):
        if out[i] in ESCAPE_SET:
            out[i] |= 0x60
    return bytes(out)


# --- Transport packet building (from ENGCT.EXE FUN_05713a83) ---

def build_packet(seq, ack, raw_payload):
    """Build a wire-ready transport packet.

    Wire format: SeqNo | AckNo | StuffedPayload | MaskedCRC | 0x0D
    CRC is over the wire bytes [SeqNo, AckNo, StuffedPayload].
    """
    seq_wire = encode_header_byte(seq | 0x80)
    ack_wire = encode_header_byte(ack | 0x80)
    payload_wire = byte_stuff(raw_payload)

    # CRC over wire bytes (headers + stuffed payload)
    wire_data = bytes([seq_wire, ack_wire]) + payload_wire
    checksum = crc32(wire_data)
    crc_bytes = mask_crc(struct.pack('<I', checksum))

    return wire_data + crc_bytes + b'\x0d'


def build_ack_packet(ack):
    """Build an ACK-only packet (type 'A'). Uses precomputed CRC table in ENGCT."""
    ack_wire = encode_header_byte(ack | 0x80)
    wire_data = bytes([0x41, ack_wire])
    checksum = crc32(wire_data)
    crc_bytes = mask_crc(struct.pack('<I', checksum))
    return wire_data + crc_bytes + b'\x0d'


# --- Pipe framing (§2.7) ---

def build_pipe_frame(pipe_index, data, last=True):
    """Build a pipe frame using continuation format (like the client).

    Wire format: PipeHdr | PipeData
    PipeData starts with uint16 content_length followed by content.

    PipeHdr uses continuation format (bit 5) instead of has_length (bit 4)
    because has_length + last_data on pipe 0 = 0x50, which collides with
    decode_header_byte's XOR set {0x4D, 0x50, 0x4B} and gets mangled to 0x90.
    """
    flags = (pipe_index & 0x0F) | 0x80  # bit 7 always set
    flags |= 0x20  # continuation: remaining payload is all pipe data
    if last:
        flags |= 0x40  # last_data
    pipe_data = struct.pack('<H', len(data)) + data
    return bytes([flags]) + pipe_data


def build_pipe_frame_has_length(pipe_index, data, last=True):
    """Build a pipe frame using has_length format (bit 4 in PipeHdr).

    Required for pipe-open-ack because PipeBuf_SetFlagFromContent
    (FUN_7f452507) only extracts the flag byte from content[2] when
    puVar12[9] (has_length) is non-zero. Continuation format (bit 5)
    leaves puVar12[9]=0 and the flag is never seen.

    Wire format: PipeHdr | LengthByte | PipeData
    PipeData = uint16_size + data (same content as continuation format).
    The receiver parses the LengthByte to know how many content bytes follow.

    NOTE: has_length on pipe 0 collides with decode_header_byte
    (0xD0 & ~0x80 = 0x50 which is in the XOR set). Safe for pipe >= 1.
    """
    flags = (pipe_index & 0x0F) | 0x80  # bit 7 always set
    flags |= 0x10  # has_length (bit 4)
    if last:
        flags |= 0x40  # last_data
    pipe_data = struct.pack('<H', len(data)) + data
    length_byte = len(pipe_data)
    assert length_byte <= 127, f"has_length content too large: {length_byte}"
    return bytes([flags, length_byte]) + pipe_data


def build_control_frame(ctrl_type, payload):
    """Build a control frame: 0xFFFF marker + type_byte + payload.
    Control type is 1 byte (confirmed from ENGCT FUN_057149bd which writes
    ff, ff, type as 3 single bytes via FUN_057136e5)."""
    return b'\xff\xff' + bytes([ctrl_type]) + payload


# --- Pipe frame parsing ---

def parse_pipe_frame(payload):
    """Parse a pipe frame from unstuffed transport payload.

    PipeHdr byte uses encode_header_byte encoding (survives byte_unstuff).
    Format: PipeHdr | DataLen(if not continuation) | data_bytes
    data_bytes = uint16_content_length | content
    """
    if not payload:
        return None, 0

    hdr = decode_header_byte(payload[0])
    pipe_idx = hdr & 0x0F
    has_length = bool(hdr & 0x10)
    continuation = bool(hdr & 0x20)
    last_data = bool(hdr & 0x40)

    pos = 1
    if continuation:
        data_bytes = payload[pos:]
        pos = len(payload)
    else:
        if pos >= len(payload):
            return None, 0
        data_len = decode_header_byte(payload[pos]) & 0x7F
        pos += 1
        data_bytes = payload[pos:pos + data_len]
        pos += data_len

    # Data starts with uint16 content_length prefix
    if len(data_bytes) < 2:
        return None, pos
    content_length = struct.unpack('<H', data_bytes[0:2])[0]
    content = data_bytes[2:2 + content_length]

    return {
        'pipe_idx': pipe_idx,
        'has_length': has_length,
        'continuation': continuation,
        'last_data': last_data,
        'content_length': content_length,
        'content': content,
    }, pos


def parse_pipe_frames(payload):
    """Parse all pipe frames carried in a single transport payload."""
    frames = []
    pos = 0
    while pos < len(payload):
        pf, consumed = parse_pipe_frame(payload[pos:])
        if not pf or consumed <= 0:
            break
        frames.append(pf)
        pos += consumed
    return frames


def parse_pipe0_content(content):
    """Parse pipe 0 content: routing header determines type.
    0x0000 = new pipe request, 0xFFFF = control frame, other = pipe data."""
    if len(content) < 2:
        return None

    routing = struct.unpack('<H', content[0:2])[0]

    if routing == 0xFFFF:
        if len(content) < 3:
            return {'type': 'control', 'ctrl_type': 0, 'data': b''}
        return {'type': 'control', 'ctrl_type': content[2], 'data': content[3:]}

    if routing == 0x0000:
        # New pipe: [0x0000][0x0000][pipe_idx:2][svc_name\0][ver_param\0][VERSION:4]
        if len(content) < 6:
            return {'type': 'pipe_open', 'client_pipe_idx': 0, 'svc_name': '?', 'ver_param': '', 'version': 0}
        client_pipe_idx = struct.unpack('<H', content[4:6])[0]
        rest = content[6:]
        svc_end = rest.find(0)
        if svc_end >= 0:
            svc_name = rest[:svc_end].decode('ascii', errors='replace')
            rest = rest[svc_end + 1:]
        else:
            svc_name = rest.decode('ascii', errors='replace')
            rest = b''
        ver_end = rest.find(0)
        if ver_end >= 0:
            ver_param = rest[:ver_end].decode('ascii', errors='replace')
            rest = rest[ver_end + 1:]
        else:
            ver_param = ''
            rest = b''
        version = struct.unpack('<I', rest[:4])[0] if len(rest) >= 4 else 0
        return {
            'type': 'pipe_open',
            'client_pipe_idx': client_pipe_idx,
            'svc_name': svc_name,
            'ver_param': ver_param,
            'version': version,
        }

    return {'type': 'pipe_data', 'pipe_idx': routing, 'data': content[2:]}


def decode_vli(data, pos=0):
    """Decode MPCCL's variable-length integer format."""
    if pos >= len(data):
        return None, pos

    b0 = data[pos]
    top = b0 & 0xC0
    if top == 0x00:
        return b0 & 0x3F, pos + 1
    if top == 0x80:
        if pos + 1 >= len(data):
            return None, pos
        value = ((b0 & 0x3F) << 8) | data[pos + 1]
        return value, pos + 2
    if top == 0xC0:
        if pos + 3 >= len(data):
            return None, pos
        value = (
            ((b0 & 0x3F) << 24)
            | (data[pos + 1] << 16)
            | (data[pos + 2] << 8)
            | data[pos + 3]
        )
        return value, pos + 4
    return None, pos


def parse_host_block(data):
    """Decode an MPC host block carried on a service pipe.

    Current MPCCL analysis indicates the outer header is:
      byte 0 = message class
      byte 1 = selector
      VLI    = request id
    """
    if len(data) < 3:
        return None

    req_id, pos = decode_vli(data, 2)
    if req_id is None:
        return None

    return {
        'msg_class': data[0],
        'selector': data[1],
        'request_id': req_id,
        'payload': data[pos:],
    }


def parse_request_params(data):
    """Decode send-side tagged parameters from an MPC request payload.

    Send-side tags use the low nibble for type (no bit 7):
      0x01 = byte, 0x02 = word, 0x03 = dword, 0x04 = variable, 0x05 = dynamic
    Receive descriptors have bit 7 set (0x81-0x88) and carry no data.
    """
    send_params = []
    recv_descriptors = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        pos += 1

        if tag & 0x80:
            # Receive descriptor — no data, just a type indicator
            recv_descriptors.append(tag)
            continue

        # Send parameter
        if tag == 0x01:
            if pos >= len(data):
                break
            send_params.append({'tag': tag, 'type': 'byte', 'value': data[pos]})
            pos += 1
        elif tag == 0x02:
            if pos + 2 > len(data):
                break
            val = struct.unpack('<H', data[pos:pos + 2])[0]
            send_params.append({'tag': tag, 'type': 'word', 'value': val})
            pos += 2
        elif tag == 0x03:
            if pos + 4 > len(data):
                break
            val = struct.unpack('<I', data[pos:pos + 4])[0]
            send_params.append({'tag': tag, 'type': 'dword', 'value': val})
            pos += 4
        elif tag in (0x04, 0x05):
            # Variable-length: length byte uses bit 7 for inline encoding
            if pos >= len(data):
                break
            length = data[pos]
            pos += 1
            if length & 0x80:
                length = length & 0x7F
            else:
                if pos >= len(data):
                    break
                length = (length << 8) | data[pos]
                pos += 1
            val = data[pos:pos + length]
            send_params.append({
                'tag': tag,
                'type': 'variable' if tag == 0x04 else 'dynamic',
                'length': length,
                'data': val,
            })
            pos += length
        else:
            send_params.append({'tag': tag, 'type': 'unknown', 'rest': data[pos:]})
            break

    return send_params, recv_descriptors


def decode_dirsrv_request(payload):
    """Decode a DIRSRV GetProperties request payload into human-readable fields."""
    send_params, recv_descs = parse_request_params(payload)
    info = {}

    # Expected: variable(node_id), byte(flags), dword, dword, variable(prop_group), variable(locale)
    var_idx = 0
    for p in send_params:
        if p['type'] == 'variable':
            if var_idx == 0:
                # First variable = node ID (LARGE_INTEGER, 8 bytes)
                node_id = p['data']
                if len(node_id) >= 8:
                    lo, hi = struct.unpack('<II', node_id[:8])
                    info['node_id'] = f"{lo}:{hi}"
                else:
                    info['node_id'] = node_id.hex()
            elif var_idx == 1:
                # Property group name (NUL-terminated string)
                name = p['data'].rstrip(b'\x00').decode('ascii', errors='replace')
                info['prop_group'] = name
            else:
                info[f'var_{var_idx}'] = p['data'].hex()
            var_idx += 1
        elif p['type'] == 'byte':
            info['flags'] = p['value']
        elif p['type'] == 'dword':
            if 'dword_0' not in info:
                info['dword_0'] = p['value']
            else:
                info['dword_1'] = p['value']

    info['recv_descriptors'] = [f"0x{d:02x}" for d in recv_descs]
    return info


def parse_tagged_params(data):
    """Best-effort decode of MPC tagged parameters."""
    params = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        pos += 1

        if tag == 0x8F:
            if pos + 4 > len(data):
                params.append({'tag': tag, 'truncated': True})
                break
            err = struct.unpack('<I', data[pos:pos + 4])[0]
            params.append({'tag': tag, 'server_error': err})
            pos += 4
            continue

        tag_type = tag & 0x8F
        if tag_type in (0x81, 0x82, 0x83, 0x84):
            size_map = {0x81: 1, 0x82: 2, 0x83: 4}
            if tag_type == 0x84:
                if pos >= len(data):
                    params.append({'tag': tag, 'truncated': True})
                    break
                length = data[pos]
                pos += 1
                if length & 0x80:
                    if pos >= len(data):
                        params.append({'tag': tag, 'truncated': True})
                        break
                    length = ((length & 0x7F) << 8) | data[pos]
                    pos += 1
                value = data[pos:pos + length]
                params.append({'tag': tag, 'length': length, 'data': value})
                pos += len(value)
                continue

            length = size_map.get(tag_type, 0)
            value = data[pos:pos + length]
            params.append({'tag': tag, 'length': length, 'data': value})
            pos += len(value)
            continue

        if tag_type in (0x85, 0x86, 0x87, 0x88):
            if pos >= len(data):
                params.append({'tag': tag, 'truncated': True})
                break
            length = data[pos]
            pos += 1
            if length & 0x80:
                if pos >= len(data):
                    params.append({'tag': tag, 'truncated': True})
                    break
                length = ((length & 0x7F) << 8) | data[pos]
                pos += 1
            value = data[pos:pos + length]
            params.append({'tag': tag, 'length': length, 'data': value})
            pos += len(value)
            continue

        params.append({'tag': tag, 'unknown_tail': data[pos:]})
        break

    return params


# --- Transport parameter negotiation (§2.6) ---

def build_pipe_open_result(client_pipe_idx, server_seq, client_ack):
    """Build the protocol-level pipe-open-response for the "Select" protocol.

    MOSCP's pipe protocol has two transports: "Select" (negotiation) and
    "Straight" (established data).  New pipes start in "Select" mode.

    SelectProtocol_DataCallback (0x7f455de4) routes by flag byte:
      flag 0x01/0x02 → CMD 5 (read_complete) — wrong, won't unblock MOSCL
      flag 0x00      → SelectProtocol_DispatchToHandler (0x7f456071)

    The dispatch reads 4 bytes from the buffer:
      bytes 0-1: routing prefix (skipped by dispatch, used by MOSCP routing)
      bytes 2-3: LE uint16 command index into PipeProtocol_HandlerTable

    Handler 1 = PipeOpen_SendCmd7ToMOSCL (0x7f455cb1) which:
      - Reads server_pipe_index (uint16 LE)
      - Reads error code (uint16 LE)
      - Switches pipe to "Straight" transport
      - Sends CMD 7 (PIPE_OPEN_RESPONSE) to MOSCL via MosSlot
      - CMD 7 triggers SetEvent(pipe+0x5c) in MOSCL, unblocking PipeObj_OpenAndWait

    MUST use continuation frame format (no has_length bit) so that
    PipeBuf_SetFlagFromContent does NOT extract a flag byte.  With has_length,
    content[2] would be the routing prefix byte (= pipe_idx = 0x01) which is
    mistaken for OPEN_ACK flag 0x01 and routes to the CMD 5 path.

    Wire content layout (8 bytes):
      [routing:2LE = pipe_idx]     — MOSCP pipe routing
      [command:2LE = 0x0001]       — Select handler 1
      [server_pipe_idx:2LE]        — server's pipe index
      [error:2LE = 0x0000]         — 0 = success
    """
    server_pipe_idx = client_pipe_idx  # mirror the client's index
    content = struct.pack('<HHHH',
        client_pipe_idx,    # routing prefix
        0x0001,             # command = handler 1 (PipeOpen_SendCmd7ToMOSCL)
        server_pipe_idx,    # server pipe index
        0x0000,             # error = success
    )
    pipe = build_pipe_frame(client_pipe_idx, content)
    return build_packet(server_seq, client_ack, pipe)


def encode_vli(value):
    """Encode an MPC variable-length integer."""
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | ((value >> 8) & 0x3F), value & 0xFF])
    if value < 0x40000000:
        return bytes([
            0xC0 | ((value >> 24) & 0x3F),
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        ])
    raise ValueError(f"VLI value too large: {value}")


def build_host_block(header0, header1, request_id, payload=b''):
    """Build a generic MPC host block prefix + VLI request id + payload."""
    return bytes([header0, header1]) + encode_vli(request_id) + payload


def build_discovery_host_block(payload, request_id=0):
    """Build a class-0 service-discovery block.

    For the current probe, discovery is sent with an explicit 0x00,0x00
    header so it cannot accidentally inherit normal service-frame semantics.
    """
    return b"\x00\x00" + encode_vli(request_id) + payload


def build_service_packet(pipe_idx, host_block, server_seq, client_ack):
    """Wrap a host block for delivery on a logical service pipe.

    ENGCT routes completed non-control pipe messages by the first uint16 in the
    pipe content, not by the outer PipeHdr nibble alone. For service traffic on
    a nonzero pipe, prefix the host block with the client's logical pipe index.
    """
    routed_content = struct.pack('<H', pipe_idx) + host_block
    pipe = build_pipe_frame(pipe_idx, routed_content)
    return build_packet(server_seq, client_ack, pipe)


def encode_reply_var_length(length):
    """Encode MPCCL reply-side variable lengths for tags 0x84..0x88.

    Reply parsing in MPCCL treats lengths with bit 7 set as inline 7-bit lengths.
    Clear bit 7 means a 15-bit big-endian length spread across two bytes.
    """
    if length < 0x80:
        return bytes([0x80 | length])
    if length < 0x8000:
        return bytes([(length >> 8) & 0x7F, length & 0xFF])
    raise ValueError(f"Reply variable field too large: {length}")


def build_tagged_reply_dword(value):
    return b"\x83" + struct.pack("<I", value & 0xFFFFFFFF)


def build_tagged_reply_var(tag, data):
    return bytes([tag]) + encode_reply_var_length(len(data)) + data


def build_logsrv_bootstrap_payload():
    """Build the best-known first LOGSRV reply layout.

    GUIDE/MPCCL register:
      - seven fixed 4-byte reply fields (tag 0x83)
      - one 16-byte variable reply buffer
      - one auto-added completion slot

    The exact semantics of every slot are still under investigation, but the
    first dword is the login result code and must be 0 or 0x0c for success.
    Start with an all-zero success-shaped reply.
    """
    payload = bytearray()

    # Seven fixed reply dwords. Field 0 is the login result code consumed by GUIDE.
    for value in (0, 0, 0, 0, 0, 0, 0):
        payload.extend(build_tagged_reply_dword(value))

    # End of fixed/static section.
    payload.append(0x87)

    # One registered 16-byte dynamic reply buffer.
    payload.extend(build_tagged_reply_var(0x84, b"\x00" * 16))

    # The request builder auto-adds a 0x84 completion-helper slot, but we
    # do NOT include it in the reply.  ProcessTaggedServiceReply triggers
    # completion automatically when data runs out after the 0x87 terminator,
    # so the reply should end here.

    return bytes(payload)


def build_logsrv_service_map_payload(selector):
    """Build the service-registry/discovery payload for LOGSRV.

    MPCCL expects a table of 17-byte records:
      16-byte interface IID + 1-byte selector
    """
    payload = bytearray()
    for guid_text, entry_selector in LOGSRV_INTERFACE_GUIDS:
        payload.extend(guid_bytes_le(guid_text))
        payload.append(entry_selector & 0xFF)
    return bytes(payload)


def build_logsrv_service_map(pipe_idx, server_seq, client_ack, selector):
    """Send the LOGSRV IID->selector registry block.

    The receive dispatcher treats host blocks with first byte 0 as service
    registry updates and uses them to populate the IID->selector lookup.
    """
    host_block = build_discovery_host_block(build_logsrv_service_map_payload(selector), 0)
    return build_service_packet(pipe_idx, host_block, server_seq, client_ack)


def build_dirsrv_service_map_payload():
    """Build the discovery payload for DIRSRV (same 17-byte record format)."""
    payload = bytearray()
    for guid_text, entry_selector in DIRSRV_INTERFACE_GUIDS:
        payload.extend(guid_bytes_le(guid_text))
        payload.append(entry_selector & 0xFF)
    return bytes(payload)


def build_dirsrv_service_map(pipe_idx, server_seq, client_ack):
    """Send the DIRSRV IID->selector discovery block."""
    host_block = build_discovery_host_block(build_dirsrv_service_map_payload(), 0)
    return build_service_packet(pipe_idx, host_block, server_seq, client_ack)


def build_logsrv_greeting(pipe_idx, server_seq, client_ack):
    """Build the first server-initiated LOGSRV block.

    Variants are selected via LOGSRV_VARIANT to speed up iteration:
      - login-bootstrap
      - status-empty
      - status-req1
      - data-empty
      - data-tag81
      - data-tag82
      - data-tag83
      - data-ctag81
      - error-method
      - error-param
    """
    variant = LOGSRV_VARIANT

    if variant == "login-bootstrap":
        host_block = build_host_block(0x01, 0x00, 0, build_logsrv_bootstrap_payload())
    elif variant == "status-empty":
        host_block = build_host_block(0x00, 0x00, 0, b'')
    elif variant == "status-req1":
        host_block = build_host_block(0x00, 0x00, 1, b'')
    elif variant == "data-empty":
        host_block = build_host_block(0x01, 0x00, 0, b'')
    elif variant == "data-tag81":
        host_block = build_host_block(0x01, 0x00, 0, b'\x81\x00')
    elif variant == "data-tag82":
        host_block = build_host_block(0x01, 0x00, 0, b'\x82\x00\x00')
    elif variant == "data-tag83":
        host_block = build_host_block(0x01, 0x00, 0, b'\x83\x00\x00\x00\x00')
    elif variant == "data-ctag81":
        host_block = build_host_block(0x01, 0x00, 0, b'\xc1\x00')
    elif variant == "error-method":
        host_block = build_host_block(0x01, 0x00, 0, b'\x8f\x04\x00\x00\xe0')
    elif variant == "error-param":
        host_block = build_host_block(0x01, 0x00, 0, b'\x8f\x07\x00\x00\xe0')
    else:
        raise ValueError(f"Unknown LOGSRV_VARIANT: {variant}")

    return build_service_packet(pipe_idx, host_block, server_seq, client_ack)


def build_empty_reply_payload():
    """Minimal reply for unimplemented service methods.

    A bare 0x87 (end of static section) triggers the automatic completion
    path in ProcessTaggedServiceReply when data runs out.  Safe regardless
    of how many receive fields the request registered.
    """
    return bytes([0x87])


def build_property_record(properties):
    """Build a SVCPROP property record.

    Format (parsed by FDecompressPropClnt in SVCPROP.DLL @ 0x7f641592):
      [total_size:uint32][prop_count:uint16][properties...]
    Each property:
      [type:byte][name:NUL-terminated string][value_data]

    Property types (DecodePropertyValue @ 0x7f64143a):
      0x01=byte(1), 0x02=word(2), 0x03=dword(4), 0x04=int64(8),
      0x0A=string(compressed), 0x0E=blob([len:4][data])

    properties: list of (type_byte, name_str, value_bytes)
    """
    body = bytearray()
    for ptype, pname, pvalue in properties:
        body.append(ptype)
        body.extend(pname.encode('ascii') + b'\x00')
        body.extend(pvalue)
    total_size = 6 + len(body)
    header = struct.pack('<IH', total_size, len(properties))
    return header + bytes(body)


def build_dirsrv_reply_payload(node_id_str="0:0", request_info=None):
    """Reply for DIRSRV GetProperties calls.

    The request's trailing bytes encode the receive param layout:
      0x83, 0x83, 0x85 = two dwords + dynamic section.

    CTreeNavClient::GetProperties reads:
      dword 1 → local status variable (0 = success)
      dword 2 → node count (passed to iterator constructor at this+0x08)
    Then GetNextNode iterates the dynamic section as property records.

    Dynamic section format (parsed by FDecompressPropClnt in SVCPROP.DLL):
      Each record: [total_size:uint32][prop_count:uint16][properties...]

    Request fields (from wire capture):
      dword_0=0 → get this node's properties
      dword_0=1 → get this node's children
      dword_1   → number of properties requested
      prop_group → NUL-separated list of property names
    """
    info = request_info or {}
    get_children = info.get('dword_0', 0) == 1
    prop_group = info.get('prop_group', 'q')

    # Parse NUL-separated property name list
    if '\x00' in prop_group:
        requested_props = prop_group.split('\x00')
    else:
        requested_props = [prop_group]

    print(f"[DIRSRV] node={node_id_str} children={get_children} "
          f"props={requested_props}", flush=True)

    records = []

    if not get_children:
        # Query for this node's own properties (initial "q" query).
        # Return a single record with whatever properties were requested.
        props = []
        for name in requested_props:
            if name == 'q':
                # "q" seems to be a quick-check property.  Return a dword
                # so the client knows the node exists and proceeds to
                # request children with the full property list.
                props.append((0x03, "q", struct.pack('<I', 1)))
            else:
                # Unknown self-property — return 0
                props.append((0x03, name, struct.pack('<I', 0)))
        records.append(build_property_record(props))

    else:
        # Query for children of this node.
        if node_id_str == "0:0":
            # Root node children — return MSN Central
            # Property names discovered from wire: a,c,h,b,e,g,x,mf,wv,tp,p,w,l,i
            msn_central = []
            for name in requested_props:
                if name == 'p':
                    # Display name
                    msn_central.append((0x0E, "p",
                        struct.pack('<I', 11) + b'MSN Central'))
                elif name == 'c':
                    msn_central.append((0x03, "c", struct.pack('<I', 3)))  # child count
                elif name == 'h':
                    msn_central.append((0x03, "h", struct.pack('<I', 1)))  # has children
                elif name == 'a':
                    msn_central.append((0x03, "a", struct.pack('<I', 0)))  # attributes
                elif name == 'b':
                    msn_central.append((0x03, "b", struct.pack('<I', 0)))
                elif name == 'e':
                    msn_central.append((0x03, "e", struct.pack('<I', 0)))
                elif name == 'g':
                    msn_central.append((0x03, "g", struct.pack('<I', 0)))  # group flag
                elif name == 'x':
                    msn_central.append((0x03, "x", struct.pack('<I', 0)))
                elif name == 'mf':
                    msn_central.append((0x03, "mf", struct.pack('<I', 0)))
                elif name == 'wv':
                    msn_central.append((0x0E, "wv", struct.pack('<I', 0)))  # empty blob
                elif name == 'tp':
                    msn_central.append((0x0E, "tp", struct.pack('<I', 0)))  # empty blob
                elif name == 'w':
                    msn_central.append((0x0E, "w", struct.pack('<I', 0)))   # empty blob
                elif name == 'l':
                    msn_central.append((0x0E, "l", struct.pack('<I', 0)))   # empty blob
                elif name == 'i':
                    msn_central.append((0x03, "i", struct.pack('<I', 0)))   # icon
                else:
                    msn_central.append((0x03, name, struct.pack('<I', 0)))
            records.append(build_property_record(msn_central))
        else:
            # Unknown parent — return empty
            records.append(build_property_record([]))

    node_count = len(records)
    dynamic_data = b''.join(records)

    payload = bytearray()
    payload.extend(build_tagged_reply_dword(0))           # dword 1: status = 0 (success)
    payload.extend(build_tagged_reply_dword(node_count))  # dword 2: node count
    payload.append(0x87)  # end of static section
    # Dynamic data: tag 0x88 = "complete dynamic chunk".
    # FUN_04605809 reads ALL remaining host-block bytes as raw data —
    # do NOT prefix with encode_reply_var_length, it would corrupt the record.
    payload.append(0x88)
    payload.extend(dynamic_data)
    return bytes(payload)


def build_logsrv_reply_for_request(pipe_idx, msg_class, selector, request_id, server_seq, client_ack):
    """Reply to the client's LOGSRV request.

    MPCCL's DispatchMosPipeReadEvent routes by header[0] (service selector)
    to find the registered service handler.  FUN_046035bf then extracts
    the VLI request_id to find the pending request object.  Finally,
    DispatchReplyToRequestObject verifies header[1] == request's stored
    selector byte.

    So: header[0] = msg_class (service selector from discovery map),
        header[1] = selector  (method/opcode byte from request),
        VLI       = request_id matching the pending request.

    Dispatch by selector (byte 1 = method opcode), NOT msg_class (byte 0):
    both login and transfer requests use the same msg_class (0x06) because
    they go through the same service handler (IID 28BC2).

    selector 0x00 = login method → full bootstrap reply.
    selector != 0x00 = enumerator request → do NOT reply.

    Non-login selectors (e.g. opcode 7) create a MosEnumeratorLoop thread
    that blocks on MsgWaitForSingleObject.  Replying with a bare 0x87
    immediately completes the request object, permanently signaling the
    wait event and causing an 80% CPU spin in MPCCL.DLL WaitForMessage.
    Leaving the request pending lets the enumerator block properly.
    """
    if selector == 0x00:
        payload = build_logsrv_bootstrap_payload()
    else:
        return None
    host_block = build_host_block(msg_class, selector, request_id, payload)
    return build_service_packet(pipe_idx, host_block, server_seq, client_ack)


def build_transport_params():
    """Build the type-3 control frame with transport parameters."""
    params = struct.pack('<IIIII',
        256,   # PacketSize
        256,   # MaxBytes
        16,    # WindowSize
        1,     # AckBehind
        600,   # AckTimeout (ms)
    )
    ctrl = build_control_frame(3, params)
    pipe = build_pipe_frame(0, ctrl)
    return build_packet(0, 0, pipe)


def build_control_type1_ack(server_seq, client_ack, payload=b""):
    """Build a reply to the client's control type-1 connection request."""
    ctrl = build_control_frame(1, payload)
    pipe = build_pipe_frame(0, ctrl)
    return build_packet(server_seq, client_ack, pipe)


# --- Telnet IAC handling ---

IAC  = 0xFF
WILL = 0xFB
WONT = 0xFC
DO   = 0xFD
DONT = 0xFE


def strip_telnet(data):
    clean = bytearray()
    responses = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (WILL, WONT, DO, DONT) and i + 2 < len(data):
                opt = data[i + 2]
                if cmd == DO:
                    responses.extend([IAC, WONT, opt])
                elif cmd == WILL:
                    responses.extend([IAC, DONT, opt])
                i += 3
                continue
            elif cmd == IAC:
                clean.append(IAC)
                i += 2
                continue
            else:
                i += 2
                continue
        clean.append(data[i])
        i += 1
    return bytes(clean), bytes(responses)


# --- Packet parsing ---

def parse_packet(raw_packet):
    """Parse a raw 0x0D-terminated packet (wire bytes). Returns dict or None."""
    if len(raw_packet) < 6:
        return None

    # CRC check: compute over wire bytes (before CRC), then mask and compare
    wire_before_crc = raw_packet[:-4]
    wire_crc_bytes = raw_packet[-4:]
    calc_crc = crc32(wire_before_crc)
    calc_crc_masked = mask_crc(struct.pack('<I', calc_crc))

    # Decode header bytes
    seq_byte = decode_header_byte(raw_packet[0])
    ack_byte = decode_header_byte(raw_packet[1])
    # Unstuff payload (between headers and CRC)
    payload = byte_unstuff(raw_packet[2:-4])

    ptype = "DATA"
    if seq_byte == 0x41:
        ptype = "ACK"
    elif seq_byte == 0x42:
        ptype = "NACK"

    return {
        "type": ptype,
        "seq": seq_byte & 0x7F,
        "ack": ack_byte & 0x7F,
        "payload": payload,
        "crc_ok": wire_crc_bytes == calc_crc_masked,
        "wire_crc": wire_crc_bytes.hex(),
        "calc_crc": calc_crc_masked.hex(),
    }


# --- Hex dump ---

def hexdump(data, prefix=""):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{prefix}{i:04x}: {hexpart:<48s} {ascpart}")


# --- Connection handler ---

def handle_connection(conn, addr):
    conn_start = time.monotonic()
    event_no = 0
    rx_pkt_no = 0
    tx_pkt_no = 0

    def ev():
        nonlocal event_no
        event_no += 1
        return f"[{time.monotonic() - conn_start:8.3f} #{event_no:04d}]"

    def log(msg):
        print(f"{ev()} {msg}")

    print(f"[*] Connection from {addr}")
    conn.settimeout(0.5)

    # After modem CONNECT, MOSCP sends 0x0D then enters state 6 waiting for
    # the server's first message. "COM" triggers direct transport mode, which
    # hands off to ENGCT for the binary packet protocol.
    log("[*] Waiting for initial 0x0D from MOSCP...")
    sent_com = False
    sent_params = False

    buf = bytearray()
    server_seq = 1  # next server seq (0 was used for params)
    client_ack = 0  # last client seq we've seen (for ack field in our packets)
    pipe_services = {}
    pipe_buffers = defaultdict(bytearray)
    pipes_closed = set()
    logsrv_discovery_sent = set()
    first_post_discovery_logged = set()
    pending_logsrv_discovery = {}
    logsrv_discovery_time = {}
    logsrv_timeout_logged = set()

    try:
        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                now = time.monotonic()
                for pipe_idx, sent_at in list(logsrv_discovery_time.items()):
                    if (
                        pipe_idx not in first_post_discovery_logged
                        and pipe_idx not in logsrv_timeout_logged
                        and now - sent_at >= 25.0
                    ):
                        svc = pipe_services.get(
                            pipe_idx,
                            {'svc_name': '?', 'ver_param': '', 'version': 0},
                        )
                        log(f"[TRACE] logsrv_no_post_discovery_25s pipe={pipe_idx} "
                            f"service='{svc['svc_name']}'")
                        logsrv_timeout_logged.add(pipe_idx)
                continue
            except ConnectionResetError:
                log("[!] Connection reset")
                return

            if not data:
                log("[!] Connection closed")
                return

            # Handle telnet negotiation only before transport mode.
            # Once ENGCT is running, 0xFF 0xFF is a control frame marker —
            # telnet IAC escaping would corrupt it.
            if not sent_com:
                clean, responses = strip_telnet(data)
                if responses:
                    conn.sendall(responses)
                    log(f"[TELNET] Responded to {len(responses)//3} negotiations")
                if not clean:
                    continue
            else:
                clean = data

            log(f"[RX] Raw ({len(clean)} bytes)")
            hexdump(clean, "[RX] ")

            buf.extend(clean)

            # Split on 0x0D packet terminators
            while b'\x0d' in buf:
                idx = buf.index(0x0D)
                pkt_data = bytes(buf[:idx])
                buf = buf[idx + 1:]

                if not pkt_data:
                    log(f"[RX] Empty terminator (bare 0x0D)")
                    if not sent_com:
                        # MOSCP state 6: send "COM" to trigger direct transport mode
                        log(f"[TX] Sending 'COM' (direct transport trigger)")
                        conn.sendall(b'COM\r')
                        sent_com = True
                        time.sleep(0.3)
                        # Now send ENGCT transport params
                        params_pkt = build_transport_params()
                        tx_pkt_no += 1
                        log(f"[TXPKT {tx_pkt_no:03d}] Sending transport params ({len(params_pkt)} bytes)")
                        hexdump(params_pkt, "[TX] ")
                        conn.sendall(params_pkt)
                        sent_params = True
                    continue

                parsed = parse_packet(pkt_data)
                if parsed:
                    rx_pkt_no += 1
                    crc_str = "OK" if parsed["crc_ok"] else f"FAIL (wire={parsed['wire_crc']} calc={parsed['calc_crc']})"
                    log(f"[RXPKT {rx_pkt_no:03d}] type={parsed['type']} seq={parsed['seq']} "
                        f"ack={parsed['ack']} payload_len={len(parsed['payload'])} crc={crc_str}")
                    if parsed['payload']:
                        hexdump(parsed['payload'], "[PKT]   ")

                    if parsed['type'] == 'ACK' and parsed['crc_ok']:
                        pass  # Discovery is now sent immediately, no deferred ACK trigger

                    # ACK data packets (next-expected semantics: ack = seq + 1)
                    if parsed['type'] == 'DATA' and parsed['crc_ok']:
                        client_ack = (parsed['seq'] + 1) & 0x7F
                        ack_pkt = build_ack_packet(client_ack)
                        conn.sendall(ack_pkt)
                        tx_pkt_no += 1
                        log(f"[TXPKT {tx_pkt_no:03d}] ACK seq={parsed['seq']} ack_field={client_ack}")

                        # Parse pipe frames from payload
                        payload = parsed['payload']
                        if payload:
                            frames = parse_pipe_frames(payload)
                            if not frames:
                                log("[PIPE] Unable to parse pipe frames from payload")

                            for pf in frames:
                                log(f"[PIPE] idx={pf['pipe_idx']} cont={pf['continuation']} "
                                    f"last={pf['last_data']} content_len={pf['content_length']}")
                                if pf['content']:
                                    hexdump(pf['content'], "[PIPE]   ")

                                pipe_buffers[pf['pipe_idx']].extend(pf['content'])
                                if not pf['last_data']:
                                    continue

                                assembled = bytes(pipe_buffers[pf['pipe_idx']])
                                pipe_buffers[pf['pipe_idx']].clear()
                                log(f"[PIPE] MESSAGE pipe={pf['pipe_idx']} assembled_len={len(assembled)}")

                                if pf['pipe_idx'] == 0:
                                    pc = parse_pipe0_content(assembled)
                                    if pc:
                                        if pc['type'] == 'pipe_open':
                                            pipe_services[pc['client_pipe_idx']] = {
                                                'svc_name': pc['svc_name'],
                                                'ver_param': pc['ver_param'],
                                                'version': pc['version'],
                                            }
                                            log(f"[PIPE] OPEN REQUEST: pipe_idx={pc['client_pipe_idx']} "
                                                f"svc='{pc['svc_name']}' ver='{pc['ver_param']}' "
                                                f"version={pc['version']}")

                                            # Send protocol-level pipe-open response.
                                            # Uses continuation format (no has_length)
                                            # so flag stays 0x00, routing to the "Select"
                                            # handler table → handler 1 →
                                            # PipeOpen_SendCmd7ToMOSCL → CMD 7 to MOSCL
                                            # → SetEvent unblocks PipeObj_OpenAndWait.
                                            ack_pkt = build_pipe_open_result(
                                                pc['client_pipe_idx'], server_seq, client_ack)
                                            tx_pkt_no += 1
                                            log(f"[TXPKT {tx_pkt_no:03d}] Pipe open RESPONSE for "
                                                f"pipe {pc['client_pipe_idx']} "
                                                f"svc='{pc['svc_name']}' "
                                                f"(seq={server_seq}, {len(ack_pkt)} bytes)")
                                            hexdump(ack_pkt, "[TX] ")
                                            conn.sendall(ack_pkt)
                                            server_seq = (server_seq + 1) & 0x7F

                                            if pc['svc_name'] == 'LOGSRV':
                                                time.sleep(0.1)
                                                map_pkt = build_logsrv_service_map(
                                                    pc['client_pipe_idx'], server_seq,
                                                    client_ack, LOGSRV_SELECTOR)
                                                map_payload = build_logsrv_service_map_payload(
                                                    LOGSRV_SELECTOR)
                                                tx_pkt_no += 1
                                                log(f"[TXPKT {tx_pkt_no:03d}] LOGSRV discovery for "
                                                    f"pipe {pc['client_pipe_idx']} "
                                                    f"(seq={server_seq}, {len(map_pkt)} bytes)")
                                                log(f"[TRACE] logsrv_discovery pipe="
                                                    f"{pc['client_pipe_idx']} "
                                                    f"entries={len(map_payload) // 17} "
                                                    f"payload_sha1={short_hash(map_payload)}")
                                                hexdump(map_pkt, "[TX] ")
                                                conn.sendall(map_pkt)
                                                logsrv_discovery_sent.add(pc['client_pipe_idx'])
                                                logsrv_discovery_time[pc['client_pipe_idx']] = time.monotonic()
                                                server_seq = (server_seq + 1) & 0x7F

                                            elif pc['svc_name'] == 'DIRSRV':
                                                time.sleep(0.1)
                                                map_pkt = build_dirsrv_service_map(
                                                    pc['client_pipe_idx'], server_seq,
                                                    client_ack)
                                                tx_pkt_no += 1
                                                log(f"[TXPKT {tx_pkt_no:03d}] DIRSRV discovery for "
                                                    f"pipe {pc['client_pipe_idx']} "
                                                    f"(seq={server_seq}, {len(map_pkt)} bytes)")
                                                hexdump(map_pkt, "[TX] ")
                                                conn.sendall(map_pkt)
                                                server_seq = (server_seq + 1) & 0x7F

                                        elif pc['type'] == 'control':
                                            log(f"[PIPE] CONTROL type={pc['ctrl_type']} "
                                                f"data_len={len(pc['data'])}")
                                            if pc['data']:
                                                hexdump(pc['data'], "[CTRL]   ")
                                            if pc['ctrl_type'] == 1:
                                                log(f"[TRACE] ctrl1 sha1={short_hash(pc['data'])} "
                                                    f"head32={pc['data'][:32].hex()}")
                                                time.sleep(0.1)
                                                ctrl_ack = build_control_type1_ack(
                                                    server_seq, client_ack, pc['data'])
                                                tx_pkt_no += 1
                                                log(f"[TXPKT {tx_pkt_no:03d}] Control type-1 echo "
                                                    f"(seq={server_seq}, {len(ctrl_ack)} bytes)")
                                                hexdump(ctrl_ack, "[TX] ")
                                                conn.sendall(ctrl_ack)
                                                server_seq = (server_seq + 1) & 0x7F
                                        elif pc['type'] == 'pipe_data':
                                            log(f"[PIPE] DATA for pipe {pc['pipe_idx']} "
                                                f"data_len={len(pc['data'])}")
                                            # Service traffic comes on pipe 0 with
                                            # a routing prefix.  Process it the same
                                            # way as the non-zero-pipe path.
                                            svc = pipe_services.get(
                                                pc['pipe_idx'],
                                                {'svc_name': '?', 'ver_param': '', 'version': 0},
                                            )
                                            service_payload = pc['data']
                                            log(f"[SVC] pipe={pc['pipe_idx']} service='{svc['svc_name']}' "
                                                f"version={svc['version']} data_len={len(service_payload)}")

                                            # 1-byte 0x01: pipe close / teardown signal
                                            if len(service_payload) == 1 and service_payload[0] == 0x01:
                                                log(f"[SVC] pipe-close 0x01 on pipe {pc['pipe_idx']}")
                                                pipes_closed.add(pc['pipe_idx'])
                                                all_service_pipes = {idx for idx, svc in pipe_services.items() if idx != 0}
                                                if all_service_pipes and pipes_closed >= all_service_pipes:
                                                    log(f"[SVC] All {len(pipes_closed)} pipes closed, dropping connection")
                                                    conn.close()
                                                    raise ConnectionError("clean signout")
                                                continue

                                            hb = parse_host_block(service_payload)
                                            if hb:
                                                log(f"[SVC] host_block class=0x{hb['msg_class']:02x} "
                                                    f"selector=0x{hb['selector']:02x} req_id={hb['request_id']} "
                                                    f"payload_len={len(hb['payload'])}")
                                                if hb['payload']:
                                                    hexdump(hb['payload'], "[SVC]   ")
                                                if svc['svc_name'] == 'LOGSRV':
                                                    time.sleep(0.1)
                                                    reply_pkt = build_logsrv_reply_for_request(
                                                        pc['pipe_idx'],
                                                        hb['msg_class'],
                                                        hb['selector'],
                                                        hb['request_id'],
                                                        server_seq,
                                                        client_ack,
                                                    )
                                                    if reply_pkt is not None:
                                                        tx_pkt_no += 1
                                                        log(f"[TXPKT {tx_pkt_no:03d}] LOGSRV reply for pipe {pc['pipe_idx']} "
                                                            f"class=0x{hb['msg_class']:02x} selector=0x{hb['selector']:02x} "
                                                            f"req_id={hb['request_id']} "
                                                            f"(seq={server_seq}, {len(reply_pkt)} bytes)")
                                                        hexdump(reply_pkt, "[TX] ")
                                                        conn.sendall(reply_pkt)
                                                        server_seq = (server_seq + 1) & 0x7F
                                                    else:
                                                        log(f"[SVC] LOGSRV selector=0x{hb['selector']:02x} "
                                                            f"req_id={hb['request_id']} — enumerator request, no reply")
                                                elif svc['svc_name'] == 'DIRSRV':
                                                    req_info = decode_dirsrv_request(hb['payload'])
                                                    log(f"[SVC] DIRSRV request: {req_info}")
                                                    node_id = req_info.get('node_id', '0:0')
                                                    time.sleep(0.1)
                                                    reply_payload = build_dirsrv_reply_payload(
                                                        node_id_str=node_id, request_info=req_info)
                                                    host_block = build_host_block(
                                                        hb['msg_class'], hb['selector'],
                                                        hb['request_id'], reply_payload)
                                                    reply_pkt = build_service_packet(
                                                        pc['pipe_idx'], host_block,
                                                        server_seq, client_ack)
                                                    tx_pkt_no += 1
                                                    log(f"[TXPKT {tx_pkt_no:03d}] DIRSRV reply for pipe {pc['pipe_idx']} "
                                                        f"class=0x{hb['msg_class']:02x} selector=0x{hb['selector']:02x} "
                                                        f"req_id={hb['request_id']} node={node_id} "
                                                        f"(seq={server_seq}, {len(reply_pkt)} bytes)")
                                                    hexdump(reply_pkt, "[TX] ")
                                                    conn.sendall(reply_pkt)
                                                    server_seq = (server_seq + 1) & 0x7F
                                            else:
                                                log("[SVC] Unable to decode host block")
                                                hexdump(service_payload, "[SVC]   ")
                                else:
                                    svc = pipe_services.get(
                                        pf['pipe_idx'],
                                        {'svc_name': '?', 'ver_param': '', 'version': 0},
                                    )
                                    routed_pipe_idx = None
                                    service_payload = assembled
                                    if len(assembled) >= 2:
                                        routed_pipe_idx = struct.unpack('<H', assembled[:2])[0]
                                        if routed_pipe_idx == pf['pipe_idx']:
                                            service_payload = assembled[2:]
                                    if (
                                        pf['pipe_idx'] in logsrv_discovery_sent
                                        and pf['pipe_idx'] not in first_post_discovery_logged
                                    ):
                                        log(f"[TRACE] first_post_discovery pipe={pf['pipe_idx']} "
                                            f"service='{svc['svc_name']}' raw_sha1={short_hash(assembled)} "
                                            f"raw_len={len(assembled)}")
                                        first_post_discovery_logged.add(pf['pipe_idx'])
                                    if routed_pipe_idx is not None:
                                        log(f"[SVC] pipe={pf['pipe_idx']} routed_pipe={routed_pipe_idx} "
                                            f"payload_len={len(service_payload)}")
                                    log(f"[SVC] pipe={pf['pipe_idx']} service='{svc['svc_name']}' "
                                        f"version={svc['version']} data_len={len(service_payload)}")

                                    # 1-byte 0x01: pipe close / teardown signal
                                    if len(service_payload) == 1 and service_payload[0] == 0x01:
                                        log(f"[SVC] pipe-close 0x01 on pipe {pf['pipe_idx']}")
                                        pipes_closed.add(pf['pipe_idx'])
                                        all_service_pipes = {idx for idx, svc in pipe_services.items() if idx != 0}
                                        if all_service_pipes and pipes_closed >= all_service_pipes:
                                            log(f"[SVC] All {len(pipes_closed)} pipes closed, dropping connection")
                                            conn.close()
                                            raise ConnectionError("clean signout")
                                        continue

                                    hb = parse_host_block(service_payload)
                                    if hb:
                                        log(f"[SVC] host_block class=0x{hb['msg_class']:02x} "
                                            f"selector=0x{hb['selector']:02x} req_id={hb['request_id']} "
                                            f"payload_len={len(hb['payload'])}")
                                        log(f"[TRACE] svc_host_block pipe={pf['pipe_idx']} "
                                            f"class=0x{hb['msg_class']:02x} selector=0x{hb['selector']:02x} "
                                            f"req_id={hb['request_id']} "
                                            f"payload_sha1={short_hash(hb['payload'])}")
                                        if hb['payload']:
                                            hexdump(hb['payload'], "[SVC]   ")
                                            params = parse_tagged_params(hb['payload'])
                                            for idx, param in enumerate(params):
                                                if 'server_error' in param:
                                                    print(f"[SVC]   param[{idx}] tag=0x{param['tag']:02x} "
                                                          f"server_error=0x{param['server_error']:08x}")
                                                elif 'data' in param:
                                                    print(f"[SVC]   param[{idx}] tag=0x{param['tag']:02x} "
                                                          f"len={param['length']}")
                                                elif 'unknown_tail' in param:
                                                    print(f"[SVC]   param[{idx}] tag=0x{param['tag']:02x} "
                                                          f"unknown_tail_len={len(param['unknown_tail'])}")
                                                elif 'truncated' in param:
                                                    print(f"[SVC]   param[{idx}] tag=0x{param['tag']:02x} "
                                                          "truncated")

                                        if svc['svc_name'] == 'LOGSRV':
                                            time.sleep(0.1)
                                            reply_pkt = build_logsrv_reply_for_request(
                                                pf['pipe_idx'],
                                                hb['msg_class'],
                                                hb['selector'],
                                                hb['request_id'],
                                                server_seq,
                                                client_ack,
                                            )
                                            if reply_pkt is not None:
                                                tx_pkt_no += 1
                                                log(f"[TXPKT {tx_pkt_no:03d}] LOGSRV reply for pipe {pf['pipe_idx']} "
                                                    f"class=0x{hb['msg_class']:02x} selector=0x{hb['selector']:02x} "
                                                    f"req_id={hb['request_id']} "
                                                    f"(seq={server_seq}, {len(reply_pkt)} bytes)")
                                                hexdump(reply_pkt, "[TX] ")
                                                conn.sendall(reply_pkt)
                                                server_seq = (server_seq + 1) & 0x7F
                                            else:
                                                log(f"[SVC] LOGSRV selector=0x{hb['selector']:02x} "
                                                    f"req_id={hb['request_id']} — enumerator request, no reply")
                                        elif svc['svc_name'] == 'DIRSRV':
                                            req_info = decode_dirsrv_request(hb['payload'])
                                            log(f"[SVC] DIRSRV request: {req_info}")
                                            node_id = req_info.get('node_id', '0:0')
                                            time.sleep(0.1)
                                            reply_payload = build_dirsrv_reply_payload(
                                                node_id_str=node_id, request_info=req_info)
                                            host_block = build_host_block(
                                                hb['msg_class'], hb['selector'],
                                                hb['request_id'], reply_payload)
                                            reply_pkt = build_service_packet(
                                                pf['pipe_idx'], host_block,
                                                server_seq, client_ack)
                                            tx_pkt_no += 1
                                            log(f"[TXPKT {tx_pkt_no:03d}] DIRSRV reply for pipe {pf['pipe_idx']} "
                                                f"class=0x{hb['msg_class']:02x} selector=0x{hb['selector']:02x} "
                                                f"req_id={hb['request_id']} node={node_id} "
                                                f"(seq={server_seq}, {len(reply_pkt)} bytes)")
                                            hexdump(reply_pkt, "[TX] ")
                                            conn.sendall(reply_pkt)
                                            server_seq = (server_seq + 1) & 0x7F
                                    else:
                                        log("[SVC] Unable to decode host block")
                                        hexdump(service_payload, "[SVC]   ")
                else:
                    log(f"[PKT] Unparseable ({len(pkt_data)} bytes): {pkt_data.hex()}")

    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        log(f"[*] Connection from {addr} closed")


def main():
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
    print(f"[*] MSN dial-up server listening on {HOST}:{PORT}")
    print(f"[*] Waiting for modem connection...")
    print()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)

        while True:
            conn, addr = srv.accept()
            try:
                handle_connection(conn, addr)
            except Exception as e:
                print(f"[!] Error: {e}")
                import traceback
                traceback.print_exc()
            print()


if __name__ == "__main__":
    main()
