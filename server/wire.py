"""Wire encoding: CRC-32, byte-stuffing, header byte encoding.

These are the lowest-level encoding functions for the Marvel transport
protocol. All operate on raw bytes with no protocol knowledge.
"""
from .config import (
    CRC_POLYNOMIAL, CRC_MASK_OR,
    HEADER_XOR_MASK, HEADER_SPECIAL_VALUES, HEADER_ENCODED_VALUES,
    ESCAPE_SET, ESCAPE_CHAR, STUFF_MAP, UNSTUFF_MAP,
)

# --- CRC-32 lookup table ---
# Custom polynomial 0x248EF9BE, init=0, no final XOR.
# NOT-after-XOR on the odd path (from ENGCT.EXE @ 0x05712da3).

CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        if _c & 1:
            _c = (~((_c ^ CRC_POLYNOMIAL) >> 1)) & 0xFFFFFFFF
        else:
            _c >>= 1
    CRC_TABLE.append(_c)


def crc32(data):
    """Compute CRC-32 with custom polynomial over raw bytes."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ CRC_TABLE[(b ^ (crc & 0xFF)) & 0xFF]
    return crc


def encode_header_byte(val):
    """Encode a SeqNo or AckNo byte for the wire. XOR 0xC0 if in {0x8D, 0x90, 0x8B}."""
    if val in HEADER_SPECIAL_VALUES:
        return val ^ HEADER_XOR_MASK
    return val


def decode_header_byte(val):
    """Reverse of encode_header_byte."""
    if val in HEADER_ENCODED_VALUES:
        return val ^ HEADER_XOR_MASK
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
        if data[i] == ESCAPE_CHAR and i + 1 < len(data):
            out.append(UNSTUFF_MAP.get(data[i + 1], data[i + 1]))
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def mask_crc(crc_bytes):
    """OR 0x60 on CRC bytes that are in the escape set."""
    return bytes(b | CRC_MASK_OR if b in ESCAPE_SET else b for b in crc_bytes)
