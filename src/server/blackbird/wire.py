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
- Type-0 `0xBF` chunk case-1 path (text slot) — preamble parser is
  `FUN_7e897ed0` (1-byte type tag + signed-int varint), TLV parser is
  `FUN_7e897ad0` (signed-int length + u32 presence bitmap + conditional
  sub-fields + variable trailing pair list). The case-1 dispatch
  (`FUN_7e894c50` switch on byte 0 of preamble) emits a tag-1 slot via
  `FUN_7e8915d0` → `FUN_7e891810` → `FUN_7e891f50` → `FUN_7e892200` →
  `FUN_7e8925d0` → `FUN_7e892d30`. Slot fields driving paint:
    slot+0x39 (int) = TLV[0x00] (length field, treated as text byte
                                 offset into chunk content base)
    slot+0x3D (short) = walked text length (NUL- or chunk_end-terminated)
    slot+0x3F (short) = font index (inherited from caller, not from chunk)
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


# --------------------------------------------------------------------------
# Type-0 0xBF cache chunk — case-1 (text slot) wire format.
#
# The case-1 chunk drives `FUN_7e890fd0` → `FUN_7e894c50` (case 1) →
# `FUN_7e8915d0` to emit a slot-tag-1 row that paints via `ExtTextOutA`
# at `FUN_7e893010`. Three byte-encodings show up in this path:
#
#   1. Preamble signed-int varint: narrow 2 B `(value+0x4000)<<1`,
#      wide 4 B `((value+0x40000000)<<1)|1`.
#   2. TLV signed-int varint (same form as #1) for the length field
#      and the conditional field at TLV+0x12.
#   3. TLV signed-short varint (-0x40 / +0xC000 bias) for the
#      conditional fields at TLV+0x16..0x22 and the pair count at
#      TLV+0x27.
# --------------------------------------------------------------------------


_PREAMBLE_NARROW_TYPE_TAG_MAX = 0x10  # `FUN_7e897ed0` reads an extra ushort only when type tag > 0x10


def encode_signed_int_varint(value: int) -> bytes:
    """Encode a `FUN_7e897ad0` length-form varint (signed int).

    Reader paths:
      - narrow (1-bit LSB clear): 2-byte little-endian word, decoded
        `(raw>>1) - 0x4000`. Range `[-0x4000, +0x3FFF]`.
      - wide (LSB set): 4-byte little-endian dword, decoded
        `(raw>>1) + 0xC0000000` (i.e. `(raw>>1) - 0x40000000` after
        treating as signed). Range `[-0x40000000, +0x3FFFFFFF]`.
    """
    if -0x4000 <= value <= 0x3FFF:
        raw = ((value + 0x4000) << 1) & 0xFFFF
        return struct.pack("<H", raw)
    if -0x40000000 <= value <= 0x3FFFFFFF:
        raw = (((value + 0x40000000) << 1) | 1) & 0xFFFFFFFF
        return struct.pack("<I", raw)
    raise ValueError(f"signed-int varint out of range: {value}")


def encode_signed_short_varint(value: int) -> bytes:
    """Encode a `FUN_7e897ad0` short-form varint (signed short).

    Reader paths:
      - narrow (1-bit LSB clear): 1-byte, decoded `(raw>>1) - 0x40`.
        Range `[-0x40, +0x3F]`.
      - wide (LSB set): 2-byte little-endian word, decoded
        `(raw>>1) + 0xC000`. Range `[-0x4000, +0x3FFF]`.
    """
    if -0x40 <= value <= 0x3F:
        raw = ((value + 0x40) << 1) & 0xFF
        return bytes([raw])
    if -0x4000 <= value <= 0x3FFF:
        raw = (((value + 0x4000) << 1) | 1) & 0xFFFF
        return struct.pack("<H", raw)
    raise ValueError(f"signed-short varint out of range: {value}")


def encode_case1_preamble(length_value: int, type_tag: int = 0x01) -> bytes:
    """Encode the per-chunk preamble that prefixes the TLV+text region.

    `FUN_7e897ed0` reads:
      byte 0:    type tag (switched on by `FUN_7e894c50`)
      bytes 1+:  signed-int varint, decoded as `length_value`

    `length_value` is added to `entry+0x26+preamble_size` to compute
    the TEXT BASE pointer (`local_c` in `FUN_7e890fd0`). The TLV is
    consumed at `entry+0x26+preamble_size`, so setting
    `length_value = TLV_size` places the text immediately after the
    TLV. Type tag 0x01 dispatches to the case-1 (text) branch.
    """
    if not (0 <= type_tag <= 0xFF):
        raise ValueError(f"preamble tag out of byte range: {type_tag}")
    if type_tag > _PREAMBLE_NARROW_TYPE_TAG_MAX:
        # `FUN_7e897ed0` reads an additional byte/ushort varint after
        # the length field for tags > 0x10 — not exercised yet.
        raise NotImplementedError(
            f"preamble tag > 0x10 has extra varint field: {type_tag}"
        )
    return bytes([type_tag]) + encode_signed_int_varint(length_value)


def encode_null_tlv() -> bytes:
    """Encode the minimum-viable TLV: length=0, presence bitmap=0.

    `FUN_7e897ad0` consumes 6 bytes total (2-byte narrow length +
    4-byte u32 bitmap) and leaves the output struct zeroed except
    for `[0]=0` (length) and the formula default at `[0x22]=0x0048`.

    With this TLV in front of text bytes, `slot+0x39` (text byte
    offset into chunk content base) = 0 — i.e. text begins at the
    text base pointer.
    """
    return encode_signed_int_varint(0) + struct.pack("<I", 0)


def decode_case1_tlv(buf: bytes) -> tuple[dict, int]:
    """Decode bytes produced by `encode_null_tlv` (or any TLV form
    `FUN_7e897ad0` accepts) and report (struct_dict, bytes_consumed).

    Mirrors `FUN_7e897ad0`'s exact control flow so test cases can
    pin the encoder against the decompiled paths.
    """
    pos = 0
    fields: dict = {}

    # Length field — same varint form as preamble length.
    raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
    if (raw_word & 1) == 0:
        fields[0x00] = ((raw_word >> 1) - 0x4000)
        pos += 2
    else:
        raw_dword = struct.unpack("<I", buf[pos:pos + 4])[0]
        decoded = (raw_dword >> 1) + 0xC0000000
        if decoded >= 0x80000000:
            decoded -= 0x100000000
        fields[0x00] = decoded
        pos += 4

    # Presence bitmap u32 + four unconditional flag fields.
    bitmap = struct.unpack("<I", buf[pos:pos + 4])[0]
    pos += 4
    fields[0x04] = bitmap & 0x1
    fields[0x08] = (bitmap >> 16) & 0x1
    fields[0x0A] = (bitmap >> 24) & 0x1
    fields[0x0C] = (bitmap >> 26) & 0x3  # 2-bit field
    fields[0x0E] = (bitmap >> 28) & 0x1

    # Conditional signed-int field at +0x12 (gated by bit 0x10000;
    # same gate also drives the unconditional flag at +0x08).
    if bitmap & 0x10000:
        raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
        if (raw_word & 1) == 0:
            fields[0x12] = ((raw_word >> 1) - 0x4000)
            pos += 2
        else:
            raw_dword = struct.unpack("<I", buf[pos:pos + 4])[0]
            decoded = (raw_dword >> 1) + 0xC0000000
            if decoded >= 0x80000000:
                decoded -= 0x100000000
            fields[0x12] = decoded
            pos += 4
    else:
        fields[0x12] = 0

    # Conditional signed-short fields at +0x16..+0x20.
    for offset, bit_mask in (
        (0x16, 0x20000),
        (0x18, 0x40000),
        (0x1A, 0x80000),
        (0x1C, 0x100000),
        (0x1E, 0x200000),
        (0x20, 0x400000),
    ):
        if bitmap & bit_mask:
            raw_byte = buf[pos]
            if (raw_byte & 1) == 0:
                fields[offset] = (raw_byte >> 1) - 0x40
                pos += 1
            else:
                raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
                decoded = (raw_word >> 1) + 0xC000
                if decoded >= 0x8000:
                    decoded -= 0x10000
                fields[offset] = decoded
                pos += 2
        else:
            fields[offset] = 0

    # +0x22 — same form, with formula default when absent.
    if bitmap & 0x800000:
        raw_byte = buf[pos]
        if (raw_byte & 1) == 0:
            fields[0x22] = (raw_byte >> 1) - 0x40
            pos += 1
        else:
            raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
            decoded = (raw_word >> 1) + 0xC000
            if decoded >= 0x8000:
                decoded -= 0x10000
            fields[0x22] = decoded
            pos += 2
    else:
        fields[0x22] = 0x0048 if (fields[0x12] & 1) == 0 else 0x02C6

    # +0x24 — 3-byte read, low 2 bytes stored. Parser advances 3 bytes
    # but writes only the low 2 to the struct (third byte discarded).
    if bitmap & 0x1000000:
        fields[0x24] = struct.unpack("<H", buf[pos:pos + 2])[0]
        pos += 3
    else:
        fields[0x24] = 0

    # +0x27 — count of trailing pairs.
    if bitmap & 0x2000000:
        raw_byte = buf[pos]
        if (raw_byte & 1) == 0:
            fields[0x27] = (raw_byte >> 1) - 0x40
            pos += 1
        else:
            raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
            decoded = (raw_word >> 1) + 0xC000
            if decoded >= 0x8000:
                decoded -= 0x10000
            fields[0x27] = decoded
            pos += 2
    else:
        fields[0x27] = 0

    # Trailing pair list — each pair is two unbiased varints.
    pairs: list[tuple[int, int]] = []
    for _ in range(max(0, fields[0x27])):
        raw_byte = buf[pos]
        if (raw_byte & 1) == 0:
            first = raw_byte >> 1
            pos += 1
        else:
            raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
            first = raw_word >> 1
            pos += 2
        if first & 0x4000:
            raw_byte = buf[pos]
            if (raw_byte & 1) == 0:
                second = raw_byte >> 1
                pos += 1
            else:
                raw_word = struct.unpack("<H", buf[pos:pos + 2])[0]
                second = raw_word >> 1
                pos += 2
        else:
            second = 0
        first &= ~0x4000  # parser clears bit 14 post-read
        pairs.append((first, second))
    fields["pairs"] = pairs

    return (fields, pos)


# In-name_buf text region: bytes name_buf[0x29..0x40) = 0x17 = 23 bytes
# total available before the content block. The minimum case-1 chunk
# spends 3 (preamble) + 6 (null TLV) + 1 (0xFF end-of-chunk control
# byte) = 10 bytes, leaving 13 bytes for ASCII text + NUL terminator.
#
# The 0xFF byte sits at end_of_TLV (= name_buf[0x29 + 6] = name_buf[0x2F])
# so the control walker (`template[+0x14]` in FUN_7e891810, initialised
# to end_of_TLV by FUN_7e8915d0) finds an end-of-chunk marker once the
# text walker hits the NUL terminator. Without it, FUN_7e894ec0's
# default case treats 'M' (or whatever first text byte) as a link tag
# and reads `*(ushort *)('M'+1)` = 'SN' = 0x4E53 = 20051, advancing the
# walker out of bounds and triggering the "service is not available"
# dialog. Live SoftIce trace 2026-04-29 at FUN_7e892d30 confirmed.
_CASE1_NAME_BUF_TEXT_BUDGET = 0x40 - 0x29 - 3 - 6 - 1


def build_case1_bf_chunk(text: str, title_byte: int, key: int) -> bytes:
    """Build a 128-byte type-0 0xBF chunk that drives the case-1 path.

    Wire layout (all offsets are within the chunk; the first 4 bytes
    are stripped before the cache stores `name_buf` + content_block at
    `entry+0x00`):

        +0x00  0xBF                                cache opcode
        +0x01  title_byte                          per-title routing
        +0x02  name_size = 0x40 (LE u16)           memcpy length into entry
        +0x04..0x0B  zero padding                  name_buf[0..7]
        +0x0C  key (LE u32)                        FUN_7e8452d3 reads here
        +0x10..0x29  zero padding                  name_buf[12..0x25]
        +0x2A  0x01                                name_buf[0x26] — case-1 dispatch
        +0x2B..0x2C  preamble length raw           narrow varint, decoded = 7
        +0x2D..0x32  null TLV (6 bytes)            length=0, bitmap=0
        +0x33  0xFF                                end-of-chunk control byte (FUN_7e894ec0 case 0xFF)
        +0x34..      ASCII text + NUL              up to 13 bytes (incl. NUL)
        +...         zero padding to 0x44
        +0x44..0x7F  60-byte content block         zeros (HGLOBAL slots NULL)

    With preamble length = 7, TLV length field = 0, 0xFF at end_of_TLV:
      - control walker (template[+0x14]) starts at end_of_TLV =
        entry+0x2F = chunk[0x33] = the 0xFF byte
      - text base = entry + 0x26 + 3 + 7 = entry + 0x30 = chunk[0x34]
      - slot+0x39 = TLV[0x00] = 0 (text byte offset within text base)
      - text walk (`FUN_7e8925d0`) reads from text_base[0] until NUL →
        text length = len(text); emits slot tag 1
      - next loop iteration: text byte at idx N is NUL → `FUN_7e892200`
        calls `FUN_7e894ec0`, which reads 0xFF at control walker → case
        0xFF → return 5 → loop exits cleanly
      - paint loop's `FUN_7e893010` calls `ExtTextOutA(hdc, x, y, …,
        text, len, …)` with the bytes shipped here.
    """
    if not text:
        # FUN_7e891810's pre-test treats first text byte == 0 (with
        # end-of-TLV byte == 0xFF) as "skip this row" → return 5 →
        # caller's do-while loop terminates without emitting tag 1.
        raise ValueError("case-1 chunk requires non-empty text")

    text_bytes = text.encode("ascii", errors="replace") + b"\x00"
    if len(text_bytes) > _CASE1_NAME_BUF_TEXT_BUDGET:
        raise ValueError(
            f"text + NUL = {len(text_bytes)} bytes; in-name_buf form caps "
            f"at {_CASE1_NAME_BUF_TEXT_BUDGET} bytes"
        )

    name_size = 0x40
    chunk = bytearray(4 + name_size + 60)  # 128 bytes total
    chunk[0] = 0xBF
    chunk[1] = title_byte & 0xFF
    chunk[2:4] = struct.pack("<H", name_size)
    chunk[12:16] = struct.pack("<I", key & 0xFFFFFFFF)

    case_offset = 4 + 0x26  # = 0x2A
    chunk[case_offset] = 0x01

    preamble = encode_case1_preamble(length_value=7, type_tag=0x01)
    if len(preamble) != 3:
        raise AssertionError(f"narrow case-1 preamble must be 3 bytes, got {len(preamble)}")
    # Preamble already wrote `0x01` at byte 0; copy bytes 1-2 (length raw).
    chunk[case_offset + 1:case_offset + 3] = preamble[1:3]

    tlv = encode_null_tlv()
    if len(tlv) != 6:
        raise AssertionError(f"null TLV must be 6 bytes, got {len(tlv)}")
    chunk[case_offset + 3:case_offset + 3 + 6] = tlv

    # 0xFF end-of-chunk control byte at end_of_TLV — read by FUN_7e894ec0
    # via control walker (template[+0x14]) when text walker hits NUL.
    chunk[case_offset + 3 + 6] = 0xFF

    text_offset = case_offset + 3 + 6 + 1  # = 0x34
    chunk[text_offset:text_offset + len(text_bytes)] = text_bytes

    return bytes(chunk)
