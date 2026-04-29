"""MEDVIEW wire-format encoders for Blackbird-published content.

Builds the byte-exact containers the MOSVIEW client reads off baggage
selectors `0x1A`/`0x1B`/`0x1C` and the type-0 `0xBF` cache push.

Format derived from RE of `MVCL14N.DLL`:

- Container preamble: `FUN_7e887a40` is the kind=5/6/8 bitmap parser;
  the multi-bitmap container that wraps it is `[u16 reserved][u16
  bitmap_count][u32 offset_to_bitmap[0]]`.
- Kind=5/6 raster header: 2 byte-narrow varints (planes, bpp), 6
  ushort-narrow-or-u32-wide varints (width, height, palette_count,
  reserved, pixel_byte_count, trailer_size), 2 u32 offsets
  (pixel_data_offset, trailer_offset).
- Trailer (`FUN_7e886820` → `FUN_7e886de0`): `[u8 reserved=0][u16
  child_count][u32 tail_size][child_count*15B][tail_size B]`.
- Child record (15 B): `[u8 tag][u8 tag2][u8 flags][i16 x][i16 y][i16
  w][i16 h][u32 va]`. Tag `0x8A` (-0x76) is the text/link path
  (slot tag 7); other tags route to slot tag 4 with `(slot+0x39, +0x3a)
  = (tag, tag2)` keying into the tail.
"""

from __future__ import annotations

import struct


_NARROW_BYTE_MAX = 0x7F
_NARROW_USHORT_MAX = 0x7FFF
_WIDE_U32_MAX = 0x7FFFFFFF


def encode_byte_or_ushort_varint(value: int) -> bytes:
    """Variable-length encoding for the planes/bpp slots in a kind=5
    header. Reader (`FUN_7e887a40` byte-narrow path) peeks the first byte:
    LSB clear → 1-byte form (value <= 127, encoded `value << 1`); LSB
    set → 2-byte form (value <= 32767, encoded as little-endian u16
    `(value << 1) | 1`).
    """
    if value < 0:
        raise ValueError(f"varint must be non-negative: {value}")
    if value <= _NARROW_BYTE_MAX:
        return bytes([(value << 1) & 0xFF])
    if value <= _NARROW_USHORT_MAX:
        return struct.pack("<H", ((value << 1) | 1) & 0xFFFF)
    raise ValueError(f"byte/ushort varint overflow: {value}")


def encode_ushort_or_u32_varint(value: int) -> bytes:
    """Variable-length encoding for the six wide slots in a kind=5 header
    (width, height, palette_count, reserved, pixel_byte_count,
    trailer_size). Reader peeks first u32: LSB clear → 2-byte narrow
    form (value <= 32767, `value << 1` as u16); LSB set → 4-byte wide
    form (value <= 0x7FFFFFFF, `(value << 1) | 1` as u32).
    """
    if value < 0:
        raise ValueError(f"varint must be non-negative: {value}")
    if value <= _NARROW_USHORT_MAX:
        return struct.pack("<H", (value << 1) & 0xFFFF)
    if value <= _WIDE_U32_MAX:
        return struct.pack("<I", ((value << 1) | 1) & 0xFFFFFFFF)
    raise ValueError(f"ushort/u32 varint overflow: {value}")


def build_child_record(
    tag: int,
    tag2: int,
    flags: int,
    x: int,
    y: int,
    w: int,
    h: int,
    va: int,
) -> bytes:
    """Build a 15-byte trailer child record (see docs/MEDVIEW.md §10.3).

    `FUN_7e886de0` reads each record in this layout, applies DPI scaling
    to x/y/w/h, then `FUN_7e894560` materialises it into a `0x47`-byte
    slot at `title+0xf6 + (parent_idx + 1 + child_idx) * 0x47`.
    """
    return struct.pack(
        "<BBBhhhhI",
        tag & 0xFF,
        tag2 & 0xFF,
        flags & 0xFF,
        x,
        y,
        w,
        h,
        va & 0xFFFFFFFF,
    )


def build_trailer(children: list[bytes], tail: bytes) -> bytes:
    """Build the trailer bytes consumed by `FUN_7e886820` →
    `FUN_7e886de0`.

    Layout: `[u8 reserved=0][u16 child_count][u32 tail_size][child_count
    * 15B][tail_size bytes]`. `tail_size` is the byte length of `tail`,
    which non-`0x8A` children index into via their `(slot+0x39,
    slot+0x3a)` = `(tag, tag2)` pair.
    """
    for c in children:
        if len(c) != 15:
            raise ValueError(f"child record must be 15 bytes, got {len(c)}")
    body = b"".join(children)
    return (
        bytes([0])  # reserved
        + struct.pack("<HI", len(children), len(tail))
        + body
        + tail
    )


def build_kind5_raster(
    width: int,
    height: int,
    bpp: int,
    pixel_data: bytes,
    trailer: bytes,
    *,
    planes: int = 1,
    palette: bytes = b"",
    palette_count: int | None = None,
    compression: int = 0,
) -> bytes:
    """Build a kind=5 raster bitmap.

    Layout (assembled in input order — `FUN_7e887a40` parses through
    these positionally):

        +0x00  u8 kind=5
        +0x01  u8 compression (0=raw)
        +X     2x ushort-narrow skip-int = 0 each (4 bytes)
        +X     varint planes (byte/ushort)
        +X     varint bpp    (byte/ushort)
        +X     varint width  (ushort/u32)
        +X     varint height (ushort/u32)
        +X     varint palette_count (ushort/u32)
        +X     varint reserved=0    (ushort/u32)
        +X     varint pixel_byte_count (ushort/u32)
        +X     varint trailer_size  (ushort/u32)
        +X     u32 pixel_data_offset (rel. to bitmap start)
        +X     u32 trailer_offset    (rel. to bitmap start)
        +X     palette_count * 4 bytes palette table
        +pixel_data_offset  pixel_data
        +trailer_offset     trailer

    `pixel_data_offset` and `trailer_offset` are computed from the
    accumulated header length so the parser's `param_1 + offset` reads
    land on the right bytes.
    """
    if palette_count is None:
        palette_count = len(palette) // 4
    if len(palette) != palette_count * 4:
        raise ValueError(
            f"palette length {len(palette)} != palette_count*4 = {palette_count*4}"
        )

    # Build the variable-length header section (everything up to the
    # final two u32 offsets) so we can compute pixel_data_offset.
    header_prefix = bytes([0x05, compression & 0xFF])  # kind, compression
    header_prefix += struct.pack("<HH", 0, 0)  # 2x ushort-narrow skip-ints
    header_prefix += encode_byte_or_ushort_varint(planes)
    header_prefix += encode_byte_or_ushort_varint(bpp)
    header_prefix += encode_ushort_or_u32_varint(width)
    header_prefix += encode_ushort_or_u32_varint(height)
    header_prefix += encode_ushort_or_u32_varint(palette_count)
    header_prefix += encode_ushort_or_u32_varint(0)  # reserved
    header_prefix += encode_ushort_or_u32_varint(len(pixel_data))
    header_prefix += encode_ushort_or_u32_varint(len(trailer))

    # Header total = prefix + 8 bytes for the two u32 offsets.
    header_len = len(header_prefix) + 8
    pixel_data_offset = header_len + len(palette)
    trailer_offset = pixel_data_offset + len(pixel_data)

    return (
        header_prefix
        + struct.pack("<II", pixel_data_offset, trailer_offset)
        + palette
        + pixel_data
        + trailer
    )


def build_baggage_container(bitmap: bytes) -> bytes:
    """Wrap a single bitmap in the multi-bitmap container preamble.

    `FUN_7e886310` reads the container's `+0x04` u32 to find the bitmap
    header start, then forwards the slice to `FUN_7e887a40`. Single-
    bitmap form: `[u16 reserved=0][u16 count=1][u32 offset=8] + bitmap`.
    """
    return struct.pack("<HHI", 0, 1, 8) + bitmap
