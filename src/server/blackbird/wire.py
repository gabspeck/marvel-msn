"""MEDVIEW wire-format encoders for Blackbird-published content.

Builds the byte-exact containers the MOSVIEW client reads off baggage
selectors `0x1A`/`0x1B`/`0x1C` and the type-0 `0xBF` cache push.

Format derived from RE of `MVCL14N.DLL`:

- Container preamble: `MVDecodeBitmapBaggage` is the kind=5/6/8 bitmap parser;
  the multi-bitmap container that wraps it is `[u16 reserved][u16
  bitmap_count][u32 offset_to_bitmap[0]]`.
- Kind=5/6 raster header: 2 byte-narrow varints (planes, bpp), 6
  ushort-narrow-or-u32-wide varints (width, height, palette_count,
  reserved, pixel_byte_count, trailer_size), 2 u32 offsets
  (pixel_data_offset, trailer_offset).
- Trailer (`MVCloneBaggageBytes` → `MVScaleBaggageHotspots`): `[u8 reserved=0][u16
  child_count][u32 tail_size][child_count*15B][tail_size B]`.
- Child record (15 B): `[u8 tag][u8 tag2][u8 flags][i16 x][i16 y][i16
  w][i16 h][u32 va]`. Tag `0x8A` (-0x76) is the text/link path
  (slot tag 7); other tags route to slot tag 4 with `(slot+0x39, +0x3a)
  = (tag, tag2)` keying into the tail.
- Type-0 `0xBF` chunk case-1 path (text slot) — preamble parser is
  `MVDecodeTopicItemPrefix` (1-byte type tag + signed-int varint), TLV parser is
  `MVDecodePackedTextHeader` (signed-int length + u32 presence bitmap + conditional
  sub-fields + variable trailing pair list). The case-1 dispatch
  (`MVWalkLayoutSlots` switch on byte 0 of preamble) emits a tag-1 slot via
  `MVBuildTextItem` → `MVTextLayoutFSM` → `MVLayoutTextLine` → `MVLayoutTextRunStream` →
  `MVFitPlainTextRun` → `MVEmitTextRunSlot`. Slot fields driving paint:
    slot+0x39 (int) = TLV[0x00] (length field, treated as text byte
                                 offset into chunk content base)
    slot+0x3D (short) = walked text length (NUL- or chunk_end-terminated)
    slot+0x3F (short) = font index (primed by a leading 0x80 control by default)
"""

from __future__ import annotations

import struct

_NARROW_BYTE_MAX = 0x7F
_NARROW_USHORT_MAX = 0x7FFF
_WIDE_U32_MAX = 0x7FFFFFFF


def encode_byte_or_ushort_varint(value: int) -> bytes:
    """Variable-length encoding for the planes/bpp slots in a kind=5
    header. Reader (`MVDecodeBitmapBaggage` byte-narrow path) peeks the first byte:
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

    `MVScaleBaggageHotspots` reads each record in this layout, applies DPI scaling
    to x/y/w/h, then `MVBuildLayoutLine` materialises it into a `0x47`-byte
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
    """Build the trailer bytes consumed by `MVCloneBaggageBytes` →
    `MVScaleBaggageHotspots`.

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

    Layout (assembled in input order — `MVDecodeBitmapBaggage` parses through
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

    `MVResolveBitmapForRun` reads the container's `+0x04` u32 to find the bitmap
    header start, then forwards the slice to `MVDecodeBitmapBaggage`. Single-
    bitmap form: `[u16 reserved=0][u16 count=1][u32 offset=8] + bitmap`.
    """
    return struct.pack("<HHI", 0, 1, 8) + bitmap


# --------------------------------------------------------------------------
# Win32 metafile (.WMF) — kind=8 baggage carries arbitrary GDI records
# (TextOut, font select, etc.) that PlayMetaFile renders at the parent
# slot's origin. This is the wire primitive for absolute-positioned text:
# `MVCL14N!MVPaintBitmapRecord @ 0x7E887180` SetViewportOrgEx → SetMapMode
# → PlayMetaFile; `MVCL14N!MVCreateHmetafileFromBaggage @ 0x7E8870A0` calls
# SetMetaFileBitsEx on the bytes at parsed_baggage+0x1e.
# --------------------------------------------------------------------------

# WMF function codes (META_*) used by `build_text_metafile`.
_META_EOF = 0x0000
_META_SETBKMODE = 0x0102
_META_SELECTOBJECT = 0x012D
_META_DELETEOBJECT = 0x01F0
_META_TEXTOUT = 0x0521
_META_CREATEFONTINDIRECT = 0x02FB

_BKMODE_TRANSPARENT = 1


def _wmf_record(rd_function: int, params: bytes) -> bytes:
    """Encode one WMF record. `rdSize` = total record size in WORDs
    (including rdSize and rdFunction). `params` must be even-length.
    """
    if len(params) & 1:
        raise ValueError("WMF record params must be even-byte length")
    rd_size_words = (4 + 2 + len(params)) // 2  # rdSize(4) + rdFunction(2) + params
    return struct.pack("<IH", rd_size_words, rd_function & 0xFFFF) + params


def _wmf_setbkmode(mode: int) -> bytes:
    return _wmf_record(_META_SETBKMODE, struct.pack("<H", mode & 0xFFFF))


def _wmf_selectobject(idx: int) -> bytes:
    return _wmf_record(_META_SELECTOBJECT, struct.pack("<H", idx & 0xFFFF))


def _wmf_deleteobject(idx: int) -> bytes:
    return _wmf_record(_META_DELETEOBJECT, struct.pack("<H", idx & 0xFFFF))


def _wmf_eof() -> bytes:
    return _wmf_record(_META_EOF, b"")


def _wmf_textout(x: int, y: int, text: str) -> bytes:
    """META_TEXTOUT record. WMF order is: count, string_bytes (padded to
    even), Y, X (note: Y *before* X — opposite of typical GDI calls).
    """
    text_bytes = text.encode("ascii", errors="replace")
    if len(text_bytes) & 1:
        text_bytes += b"\x00"  # pad to even
    params = struct.pack("<H", len(text)) + text_bytes + struct.pack("<hh", y, x)
    return _wmf_record(_META_TEXTOUT, params)


def _wmf_createfontindirect(
    *,
    height: int,
    weight: int = 400,
    italic: bool = False,
    underline: bool = False,
    strikeout: bool = False,
    face_name: str = "MS Sans Serif",
) -> bytes:
    """META_CREATEFONTINDIRECT record carrying a packed LOGFONTA.

    Layout per MS-WMF: 18-byte LOGFONT prefix (Height, Width, Escapement,
    Orientation, Weight as i16; Italic, Underline, StrikeOut, CharSet,
    OutPrecision, ClipPrecision, Quality, PitchAndFamily as u8) followed
    by a NUL-terminated ASCII face name. Record padded to even bytes.
    """
    face_bytes = face_name.encode("ascii", errors="replace") + b"\x00"
    if len(face_bytes) & 1:
        face_bytes += b"\x00"
    logfont = struct.pack(
        "<hhhhhBBBBBBBB",
        height,
        0,                  # Width (= 0 → matched on aspect ratio)
        0,                  # Escapement
        0,                  # Orientation
        weight,
        1 if italic else 0,
        1 if underline else 0,
        1 if strikeout else 0,
        0,                  # CharSet (ANSI_CHARSET)
        0,                  # OutPrecision (default)
        0,                  # ClipPrecision (default)
        0,                  # Quality (default)
        0,                  # PitchAndFamily (default)
    )
    return _wmf_record(_META_CREATEFONTINDIRECT, logfont + face_bytes)


def build_text_metafile(
    items: list[tuple[int, int, str]],
    *,
    font_face: str = "MS Sans Serif",
    font_height: int = -12,
    font_weight: int = 400,
) -> bytes:
    """Build a Win32 .WMF rendering text strings at absolute (x, y).

    `items` is a list of `(x_pixels, y_pixels, text)` tuples in the
    coordinate system MOSVIEW will set up before `PlayMetaFile`. Caller
    chooses the mapping mode via the kind=8 baggage `mapmode` byte —
    for MM_TEXT (=1), x/y are device pixels.

    All items share one font (created at start, deleted at end). Text
    color and text alignment come from the engine's pre-PlayMetaFile
    `SetTextColor` (= title+0x8c) — the metafile doesn't override.
    BkMode is set TRANSPARENT so text doesn't fill its bounding box
    with the system window color.
    """
    records = bytearray()
    records += _wmf_setbkmode(_BKMODE_TRANSPARENT)
    records += _wmf_createfontindirect(
        height=font_height,
        weight=font_weight,
        face_name=font_face,
    )
    records += _wmf_selectobject(0)
    for x, y, text in items:
        records += _wmf_textout(int(x), int(y), text)
    records += _wmf_deleteobject(0)
    records += _wmf_eof()

    # METAHEADER (18 bytes = 9 WORDs):
    #   Type (1=memory), HeaderSize (=9), Version (=0x0300),
    #   Size (in WORDs), NumberOfObjects, MaxRecord, NumberOfMembers (=0)
    record_word_sizes = []
    pos = 0
    while pos < len(records):
        rd_size = struct.unpack_from("<I", records, pos)[0]
        record_word_sizes.append(rd_size)
        pos += rd_size * 2
    max_record = max(record_word_sizes) if record_word_sizes else 0
    total_words = 9 + len(records) // 2  # header + body
    header = struct.pack(
        "<HHHIHIH",
        1,                  # Type (memory)
        9,                  # HeaderSize (WORDs)
        0x0300,             # Version
        total_words,        # Size (WORDs)
        1,                  # NumberOfObjects (font slot)
        max_record,         # MaxRecord (WORDs)
        0,                  # NumberOfMembers
    )
    return bytes(header) + bytes(records)


def build_kind8_baggage(
    metafile_bytes: bytes,
    *,
    mapmode: int = 1,
    viewport_w: int = 0,
    viewport_h: int = 0,
) -> bytes:
    """Wrap a Win32 metafile in a kind=8 baggage container.

    Layout consumed by `MVCL14N!MVDecodeBitmapBaggage` (kind=8 branch):
      +0      u8     kind = 0x08
      +1      u8     compression (0 = raw)
      +2..    varint mapmode (narrow byte if mapmode <= 0x7F)
      +...    u16    viewport_w (raw, used for SetViewportExtEx when mapmode == 7|8)
      +...    u16    viewport_h
      +...    varint decompressed_metafile_size
      +...    varint compressed_metafile_size
      +...    varint trailer_size = 0
      +...    u32    metafile_data_offset (rel. baggage start)
      +...    u32    trailer_offset
      +...    metafile bytes (raw)

    For `mapmode = 1` (MM_TEXT), `viewport_w/h` are unused — engine
    skips both `SetWindowExtEx` and `SetViewportExtEx`. Logical units
    in the metafile = device pixels.
    """
    mapmode_varint = encode_byte_or_ushort_varint(mapmode)
    decompressed_size = len(metafile_bytes)
    compressed_size = len(metafile_bytes)
    trailer_size = 0

    size_varints = (
        encode_ushort_or_u32_varint(decompressed_size)
        + encode_ushort_or_u32_varint(compressed_size)
        + encode_ushort_or_u32_varint(trailer_size)
    )
    header_prefix = (
        bytes([0x08, 0x00])                                    # kind, compression
        + mapmode_varint
        + struct.pack("<HH", viewport_w & 0xFFFF, viewport_h & 0xFFFF)
        + size_varints
    )
    header_len = len(header_prefix) + 8                        # + 2 u32 offsets
    metafile_data_offset = header_len
    trailer_offset = metafile_data_offset + len(metafile_bytes)
    return (
        header_prefix
        + struct.pack("<II", metafile_data_offset, trailer_offset)
        + metafile_bytes
    )


def build_case3_bf_chunk(
    title_byte: int,
    key: int,
    *,
    name_size: int = 0x40,
) -> bytes:
    """Build a type-0 0xBF chunk that drives the case-3 bitmap cell path.

    Case 3 (`MVBuildLayoutLine`) materialises a parent cell whose bitmap is
    loaded from baggage (`bm0` for the current zeroed descriptor fields).
    This is the plain bitmap/background path, complementary to
    `build_case1_bf_chunk`'s text-row path.
    """
    if not (0x40 <= name_size <= 0xFFFF):
        raise ValueError(
            f"name_size out of range [0x40..0xFFFF]: 0x{name_size:x}"
        )

    chunk = bytearray(4 + name_size + 60)
    chunk[0] = 0xBF
    chunk[1] = title_byte & 0xFF
    chunk[2:4] = struct.pack("<H", name_size)
    chunk[12:16] = struct.pack("<I", key & 0xFFFFFFFF)
    chunk[4 + 0x26] = 0x03
    return bytes(chunk)


# --------------------------------------------------------------------------
# Type-0 0xBF cache chunk — case-1 (text slot) wire format.
#
# The case-1 chunk drives `MVParseLayoutChunk` → `MVWalkLayoutSlots` (case 1) →
# `MVBuildTextItem` to emit a slot-tag-1 row that paints via `ExtTextOutA`
# at `DrawTextSlot`. Three byte-encodings show up in this path:
#
#   1. Preamble signed-int varint: narrow 2 B `(value+0x4000)<<1`,
#      wide 4 B `((value+0x40000000)<<1)|1`.
#   2. TLV signed-int varint (same form as #1) for the length field
#      and the conditional field at TLV+0x12.
#   3. TLV signed-short varint (-0x40 / +0xC000 bias) for the
#      conditional fields at TLV+0x16..0x22 and the pair count at
#      TLV+0x27.
# --------------------------------------------------------------------------


_PREAMBLE_NARROW_TYPE_TAG_MAX = 0x10  # `MVDecodeTopicItemPrefix` reads an extra ushort only when type tag > 0x10


def encode_signed_int_varint(value: int) -> bytes:
    """Encode a `MVDecodePackedTextHeader` length-form varint (signed int).

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
    """Encode a `MVDecodePackedTextHeader` short-form varint (signed short).

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

    `MVDecodeTopicItemPrefix` reads:
      byte 0:    type tag (switched on by `MVWalkLayoutSlots`)
      bytes 1+:  signed-int varint, decoded as `length_value`

    `length_value` is added to `entry+0x26+preamble_size` to compute
    the TEXT BASE pointer (`local_c` in `MVParseLayoutChunk`). The TLV is
    consumed at `entry+0x26+preamble_size`, so setting
    `length_value = TLV_size` places the text immediately after the
    TLV. Type tag 0x01 dispatches to the case-1 (text) branch.
    """
    if not (0 <= type_tag <= 0xFF):
        raise ValueError(f"preamble tag out of byte range: {type_tag}")
    if type_tag > _PREAMBLE_NARROW_TYPE_TAG_MAX:
        # `MVDecodeTopicItemPrefix` reads an additional byte/ushort varint after
        # the length field for tags > 0x10 — not exercised yet.
        raise NotImplementedError(
            f"preamble tag > 0x10 has extra varint field: {type_tag}"
        )
    return bytes([type_tag]) + encode_signed_int_varint(length_value)


def build_type0_status_record(title_byte: int, status: int, contents_token: int) -> bytes:
    """Build a type-0 `0xa5` HfcStatusRecord (8 bytes, no payload).

    Pushed on the type-0 notification subscription as a status-only
    response to selector 0x16 (`HfcNextPrevHfc`) when no adjacent topic
    body is available. Layout per `docs/mosview-mediaview-format.md`
    "Type 0 TopicCacheStream":

        +0x00 u8  0xa5                  record opcode
        +0x01 u8  title_byte            cache key (title slot)
        +0x02 u16 status                opaque status word
        +0x04 u32 contents_token        cache key (request's current_token)

    Status semantics aren't pinned in the doc — `0` is treated as
    success-but-empty by the recovered code path; `0xffff` would be
    interpreted as "no data" by the wrappers' fail-on-zero patterns.
    The cache entry is keyed by `(title_byte, contents_token)` so the
    client's `HfcNextPrevHfc` retry loop can match the request and
    short-circuit instead of polling the full 30 s timeout.
    """
    return struct.pack("<BBHI", 0xA5, title_byte & 0xFF, status & 0xFFFF, contents_token & 0xFFFFFFFF)


def build_type3_op4_frame(title_byte: int, kind: int, key: int, va: int, addr: int) -> bytes:
    """Build a type-3 op-code 4 cache-insert frame (18 bytes).

    Pushed on the type-3 notification subscription in response to
    selectors 0x05 (`vaConvertAddr`) / 0x06 (`vaConvertHash`) /
    0x07 (`vaConvertTopicNumber`). Layout per
    `docs/medview-service-contract.md` §"Type 3 MixedAsyncStream /
    subtype 4 AddressConversionResult":

        +0x00 u16 op_code = 4
        +0x02 u16 length  = 18
        +0x04 u8  title_byte
        +0x05 u8  kind     (0=topic→va+addr, 1=hash→va, 2=va→addr)
        +0x06 u32 key      (input key being converted)
        +0x0A u32 va       (va result)
        +0x0E u32 addr     (secondary token / addr result)
    """
    return struct.pack(
        "<HHBBIII",
        4, 18,
        title_byte & 0xFF,
        kind & 0xFF,
        key & 0xFFFFFFFF,
        va & 0xFFFFFFFF,
        addr & 0xFFFFFFFF,
    )


def encode_null_tlv() -> bytes:
    """Encode the minimum-viable TLV: length=0, presence bitmap=0.

    `MVDecodePackedTextHeader` consumes 6 bytes total (2-byte narrow length +
    4-byte u32 bitmap) and leaves the output struct zeroed except
    for `[0]=0` (length) and the formula default at `[0x22]=0x0048`.

    With this TLV in front of text bytes, `slot+0x39` (text byte
    offset into chunk content base) = 0 — i.e. text begins at the
    text base pointer.

    Equivalent to `encode_text_item_tlv({0x00: 0})`.
    """
    return encode_signed_int_varint(0) + struct.pack("<I", 0)


# `encode_text_item_tlv` field map per `docs/mosview-authored-text-and-font-re.md`
# §"Text Header Grammar". Keys match the decoded struct's offsets so
# `decode_case1_tlv(encode_text_item_tlv(x))` round-trips.
_TLV_OPTIONAL_INT_FIELDS = (
    # offset, bitmap_mask
    (0x12, 0x10000),       # text_base_or_mode (signed-int varint)
)
_TLV_OPTIONAL_SHORT_FIELDS = (
    (0x16, 0x20000),       # space_before
    (0x18, 0x40000),       # space_after
    (0x1A, 0x80000),       # min_line_extent
    (0x1C, 0x100000),      # left_indent
    (0x1E, 0x200000),      # right_indent
    (0x20, 0x400000),      # first_line_indent
    (0x22, 0x800000),      # tab_interval
)


def encode_text_item_tlv(fields: dict[int, int] | None = None) -> bytes:
    """Encode a `MVDecodePackedTextHeader`-shaped TLV from a field dict.

    Inverse of `decode_case1_tlv`. Field semantics per
    `docs/mosview-authored-text-and-font-re.md` §"Text Header Grammar":

      0x00  text_start_index        i32  starting char index (length field)
      0x04  text_base_present       u16  flag, packed into bitmap bit 0
      0x08  header_flag_16_0        u16  flag, packed into bitmap bit 16
      0x0A  edge_metrics_enabled    u16  flag, packed into bitmap bit 24
      0x0C  alignment_mode          u16  2-bit field, packed bits 26-27
      0x0E  header_flag_28          u16  flag, packed into bitmap bit 28
      0x12  text_base_or_mode       i32  optional, gated by bitmap bit 0x10000
      0x16  space_before            i16  optional, gated by bitmap bit 0x20000
      0x18  space_after             i16  optional, gated by bitmap bit 0x40000
      0x1A  min_line_extent         i16  optional, gated by bitmap bit 0x80000
      0x1C  left_indent             i16  optional, gated by bitmap bit 0x100000
      0x1E  right_indent            i16  optional, gated by bitmap bit 0x200000
      0x20  first_line_indent       i16  optional, gated by bitmap bit 0x400000
      0x22  tab_interval            i16  optional, gated by bitmap bit 0x800000
      0x24  edge_metric_flags       u16  optional, gated by bitmap bit 0x1000000
      0x27  inline_run_count        i16  optional, gated by bitmap bit 0x2000000

    Optional fields are emitted when their key is present in `fields`
    (regardless of value — explicit zero still shows up on the wire).
    Inline-run pair list is not yet supported (set inline_run_count = 0
    or omit). Unknown keys raise `ValueError`.
    """
    f = dict(fields or {})
    length_value = f.pop(0x00, 0)

    bitmap = 0
    # Bitmap-packed flag fields (no separate payload bytes).
    if f.pop(0x04, 0):
        bitmap |= 0x1
    if f.pop(0x08, 0):
        bitmap |= 0x10000
    if f.pop(0x0A, 0):
        bitmap |= 0x1000000
    align = f.pop(0x0C, 0) & 0x3
    bitmap |= align << 26
    if f.pop(0x0E, 0):
        bitmap |= 0x10000000

    optional_payload = bytearray()

    # Optional signed-int field at +0x12.
    if 0x12 in f:
        bitmap |= 0x10000
        optional_payload += encode_signed_int_varint(f.pop(0x12))

    # Optional signed-short fields at +0x16..+0x22.
    for offset, bit_mask in _TLV_OPTIONAL_SHORT_FIELDS:
        if offset in f:
            bitmap |= bit_mask
            optional_payload += encode_signed_short_varint(f.pop(offset))

    # Optional `edge_metric_flags` u16 — parser reads 3 bytes but only
    # stores low 2; emit value LE-packed + a trailing zero.
    if 0x24 in f:
        bitmap |= 0x1000000
        optional_payload += struct.pack("<H", f.pop(0x24) & 0xFFFF) + b"\x00"

    # Optional inline_run_count + pair list.
    if 0x27 in f:
        bitmap |= 0x2000000
        run_count = f.pop(0x27)
        optional_payload += encode_signed_short_varint(run_count)
        if run_count != 0:
            raise NotImplementedError(
                "non-zero inline_run_count requires pair-list encoding "
                "which has not been implemented yet"
            )

    if f:
        raise ValueError(f"unknown TLV field keys: {sorted(f)}")

    return (
        encode_signed_int_varint(length_value)
        + struct.pack("<I", bitmap)
        + bytes(optional_payload)
    )


def decode_case1_tlv(buf: bytes) -> tuple[dict, int]:
    """Decode bytes produced by `encode_null_tlv` (or any TLV form
    `MVDecodePackedTextHeader` accepts) and report (struct_dict, bytes_consumed).

    Mirrors `MVDecodePackedTextHeader`'s exact control flow so test cases can
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


# Default name_size for the case-1 chunk. The original RE pinned the
# minimum-viable shape at name_size=0x40 (16-byte text region after
# the case-1 dispatch + preamble + null TLV + 0xFF control byte).
# Authored stories on the reference .ttl exceed that — Homepage.bdf
# alone is 119 bytes — so the wire-mode default grows name_size to
# 0x100 (256 B), giving room for ASCII text + NUL well past 200 B.
# Per `docs/MEDVIEW.md` §10.5, the engine memcpy's `name_size` bytes
# from the chunk into the cache entry's name_buf; larger values are
# accepted up to u16 capacity.
_CASE1_DEFAULT_NAME_SIZE = 0x100

def case1_text_budget(
    name_size: int = _CASE1_DEFAULT_NAME_SIZE,
    tlv_size: int = 6,
    initial_font_style: int | None = 0,
) -> int:
    """Maximum text+NUL bytes that fit in a case-1 chunk's name_buf.

    Formula: `name_size - 0x29 (skipped pad) - 3 (preamble) -
    tlv_size - len(control stream) - len(text prefix)`. The default
    primes style 0 with a `0x80 <u16 style>` control before the first
    printable byte, so `text_prefix` is one leading NUL that forces the
    control walker to run before the text run is emitted. Pass
    `initial_font_style=None` for the old `0xFF`-only stream.

    Within the chunk, name_buf starts at offset +0x04 and the case-1
    dispatch byte sits at name_buf+0x26 = chunk+0x2A. The 0xFF byte
    sits at end_of_TLV (= name_buf[0x29 + tlv_size]) so the control
    walker (`template[+0x14]` in MVTextLayoutFSM, initialised to end_of_TLV
    by MVBuildTextItem) finds an end-of-chunk marker once the text
    walker hits the NUL terminator. Without it, MVDispatchControlRun's
    default case treats the first text byte as a link tag and reads
    `*(ushort *)(first+1)`, advancing the walker out of bounds and
    triggering the "service is not available" dialog. Live SoftIce
    trace 2026-04-29 at MVEmitTextRunSlot confirmed.
    """
    control_len = 1 if initial_font_style is None else 4
    text_prefix_len = 0 if initial_font_style is None else 1
    return name_size - 0x29 - 3 - tlv_size - control_len - text_prefix_len


# Legacy constant retained for the existing 0x40-shape tests. New
# callers should use `case1_text_budget(name_size)`.
_CASE1_NAME_BUF_TEXT_BUDGET = case1_text_budget(0x40, initial_font_style=None)


def build_case1_bf_chunk(
    text: str,
    title_byte: int,
    key: int,
    *,
    name_size: int = _CASE1_DEFAULT_NAME_SIZE,
    tlv_fields: dict[int, int] | None = None,
    initial_font_style: int | None = 0,
) -> bytes:
    """Build a 128-byte type-0 0xBF chunk that drives the case-1 path.

    Wire layout (all offsets are within the chunk; the first 4 bytes
    are stripped before the cache stores `name_buf` + content_block at
    `entry+0x00`):

        +0x00  0xBF                                cache opcode
        +0x01  title_byte                          per-title routing
        +0x02  name_size = 0x40 (LE u16)           memcpy length into entry
        +0x04..0x0B  zero padding                  name_buf[0..7]
        +0x0C  key (LE u32)                        HfcCache_DispatchContentNotification reads here
        +0x10..0x29  zero padding                  name_buf[12..0x25]
        +0x2A  0x01                                name_buf[0x26] — case-1 dispatch
        +0x2B..0x2C  preamble length raw           narrow varint, decoded = 10 by default
        +0x2D..0x32  null TLV (6 bytes)            length=0, bitmap=0
        +0x33..      control stream                default: 0x80, style u16, 0xFF
        +...         text prefix                   default: leading NUL to run 0x80 before text
        +...         ASCII text + NUL
        +...         zero padding to 0x44
        +0x44..0x7F  60-byte content block         zeros (HGLOBAL slots NULL)

    With the default font-control stream:
      - control walker starts at end_of_TLV and reads 0x80, style 0, then 0xFF
      - text base starts after the control stream
      - text_base[0] is NUL so `MVDispatchControlRun` applies style 0 before the first
        printable run
      - text walk then reads from text_base[1] until NUL and emits slot tag 1
      - next loop iteration: text byte at idx N is NUL → `MVLayoutTextRunStream`
        calls `MVDispatchControlRun`, which reads 0xFF at control walker → case
        0xFF → return 5 → loop exits cleanly
      - paint loop's `DrawTextSlot` calls `ExtTextOutA(hdc, x, y, …,
        text, len, …)` with the bytes shipped here.
    """
    # Empty text is intentional for the "no authored content" fallback:
    # `MVTextLayoutFSM`'s pre-test treats first text byte == 0 (with
    # end-of-TLV byte == 0xFF) as "skip this row" → return 5 → caller's
    # do-while loop terminates without emitting tag 1. The chunk still
    # populates HfcNear's per-title cache (so `fMVSetAddress` completes
    # and the client clears its hourglass) without producing a visible
    # slot. Used by `services/medview._push_case1_text` when the title
    # has no topic-source entries.

    if not (0x40 <= name_size <= 0xFFFF):
        raise ValueError(
            f"name_size out of range [0x40..0xFFFF]: 0x{name_size:x}"
        )

    tlv = encode_null_tlv() if tlv_fields is None else encode_text_item_tlv(tlv_fields)
    if len(tlv) < 6:
        raise AssertionError(f"TLV must be >= 6 bytes, got {len(tlv)}")

    if initial_font_style is not None and not -0x8000 <= initial_font_style <= 0xFFFF:
        raise ValueError(f"initial_font_style out of int16/u16 range: {initial_font_style}")

    control_stream = b"\xFF"
    text_prefix = b""
    if initial_font_style is not None:
        control_stream = b"\x80" + struct.pack("<H", initial_font_style & 0xFFFF) + b"\xFF"
        text_prefix = b"\x00"

    text_bytes = text_prefix + text.encode("ascii", errors="replace") + b"\x00"
    budget = case1_text_budget(
        name_size,
        tlv_size=len(tlv),
        initial_font_style=initial_font_style,
    )
    if len(text_bytes) > budget:
        raise ValueError(
            f"text payload = {len(text_bytes)} bytes; in-name_buf form caps "
            f"at {budget} bytes (name_size=0x{name_size:x}, "
            f"tlv_size={len(tlv)})"
        )

    # Preamble length value skips past TLV + control stream so text_base lands
    # on the leading NUL (default) or the first text byte (legacy).
    preamble_length_value = len(tlv) + len(control_stream)

    chunk = bytearray(4 + name_size + 60)  # 4-byte header + name_buf + content_block
    chunk[0] = 0xBF
    chunk[1] = title_byte & 0xFF
    chunk[2:4] = struct.pack("<H", name_size)
    chunk[12:16] = struct.pack("<I", key & 0xFFFFFFFF)

    case_offset = 4 + 0x26  # = 0x2A
    chunk[case_offset] = 0x01

    preamble = encode_case1_preamble(length_value=preamble_length_value, type_tag=0x01)
    if len(preamble) != 3:
        raise AssertionError(
            f"non-narrow case-1 preamble not implemented for length_value={preamble_length_value}"
        )
    chunk[case_offset + 1:case_offset + 3] = preamble[1:3]

    chunk[case_offset + 3:case_offset + 3 + len(tlv)] = tlv

    # Control stream at end_of_TLV — read by MVDispatchControlRun when the text
    # walker sees NUL. The default stream selects style 0 before text.
    control_offset = case_offset + 3 + len(tlv)
    chunk[control_offset:control_offset + len(control_stream)] = control_stream

    text_offset = case_offset + 3 + len(tlv) + len(control_stream)
    chunk[text_offset:text_offset + len(text_bytes)] = text_bytes

    return bytes(chunk)
