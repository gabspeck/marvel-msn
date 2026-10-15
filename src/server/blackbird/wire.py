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
        raise ValueError(f"palette length {len(palette)} != palette_count*4 = {palette_count * 4}")

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


# contentsToken for a BF chunk's prev/next link fields when it has no
# neighbour. It must be nonzero, not 0xFFFFFFFF, and lower than every valid
# TOPICPOS: HfcCache_FindEntryAndPromote also treats the next-token field as
# the cached record's upper range during near lookups. `MVTTL14C!HfcNextPrevHfc
# @ 0x7e845abb` reads wire+0x8 (prev) for leading probes and wire+0x10 (next)
# for trailing ones; with 0 there the probe hits the requesting chunk's own
# key 0, re-parses it and appends a duplicate slot, so the scrollbar range
# grows with every scroll click. With 1 the probe misses, the client sends
# selector 0x16, and the `0xA5` status 0x3F3 reply ends the seek loop.
CHAIN_TERMINATOR_TOKEN = 1


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


_PREAMBLE_NARROW_TYPE_TAG_MAX = (
    0x10  # `MVDecodeTopicItemPrefix` reads an extra ushort only when type tag > 0x10
)


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


def encode_case1_preamble(
    length_value: int,
    type_tag: int = 0x01,
    *,
    prefix_u16: int | None = None,
) -> bytes:
    """Encode the per-chunk preamble that prefixes the TLV+text region.

    `MVDecodeTopicItemPrefix @ 0x7e897ed0` reads:
      byte 0:    type tag (switched on by `MVWalkLayoutSlots`)
      bytes 1+:  PackedWideScalar (signed-int varint), decoded as `length_value`
      bytes N+:  PackedUnsignedSmall (u8/u16) — present only when type_tag > 0x10

    Tag inventory (per `docs/mosview-authored-text-and-font-re.md`
    §"Text Item Prefix"):

      0x01 / 0x20 → MVBuildTextItem            (narrow / widened text)
      0x03 / 0x22 → MVBuildLayoutLine          (narrow / widened image-row)
      0x04 / 0x23 → MVBuildColumnLayoutItem    (narrow / widened column)
      0x05 / 0x24 → MVBuildEmbeddedWindowItem  (narrow / widened embed)

    `length_value` is added to `entry+0x26+preamble_size` to compute the
    TEXT BASE pointer (`local_c` in `MVParseLayoutChunk @ 0x7e890fd0`).
    The TLV is consumed at `entry+0x26+preamble_size`, so setting
    `length_value = TLV_size` (+ control-stream size) places the text
    immediately after both.

    Wide tag (0x20..0x24): the extra PackedUnsignedSmall is stored at
    the parsed slot's `+0x1e`. `MVFindSlotForY` excludes slots where
    this value is zero, so interactive native displays must preserve
    their nonzero TopicLength here. Narrow type `0x01` remains suitable
    for synthetic, noninteractive text. Narrow vs wide TAG is
    independent of narrow vs wide SIGNED-INT VARINT — text bodies
    larger than 0x3FFF bytes use the wide signed-int form and need not
    change item type for that reason.

    Raw-pair tags 0x02 / 0x21 (short-circuit branch of MVDecodeTopicItemPrefix
    — verbatim u32 + optional u16 copy with no varint decode) are not
    used by any case-1 path observed in the wire so far; they remain
    unimplemented.
    """
    if not (0 <= type_tag <= 0xFF):
        raise ValueError(f"preamble tag out of byte range: {type_tag}")
    if type_tag in (0x02, 0x21):
        raise NotImplementedError(
            f"raw-pair short-circuit tag {type_tag:#x} not implemented "
            "(MVDecodeTopicItemPrefix's verbatim-copy branch)"
        )
    if type_tag > _PREAMBLE_NARROW_TYPE_TAG_MAX:
        effective_prefix = 0 if prefix_u16 is None else prefix_u16
        if not (0 <= effective_prefix <= 0x7FFF):
            raise ValueError(
                f"prefix_u16 out of PackedUnsignedSmall range [0, 0x7FFF]: {effective_prefix}"
            )
        return (
            bytes([type_tag])
            + encode_signed_int_varint(length_value)
            + encode_byte_or_ushort_varint(effective_prefix)
        )
    if prefix_u16 not in (None, 0):
        raise ValueError(
            f"narrow tag {type_tag:#x} has no prefix_u16 slot; "
            f"use a wide tag (0x20/0x22/0x23/0x24) to carry prefix_u16={prefix_u16}"
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
    return struct.pack(
        "<BBHI", 0xA5, title_byte & 0xFF, status & 0xFFFF, contents_token & 0xFFFFFFFF
    )


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
        4,
        18,
        title_byte & 0xFF,
        kind & 0xFF,
        key & 0xFFFFFFFF,
        va & 0xFFFFFFFF,
        addr & 0xFFFFFFFF,
    )


def build_type3_transfer_status_frame(
    transfer_id: int,
    target_size: int,
    *,
    state_kind: int = 0,
    metric0: int = 0,
    metric1: int = 0,
    metric_divisor: int = 0,
    aux_status: int = 0,
) -> bytes:
    """Build a type-3 subtype-1 transfer-status frame (30 bytes).

    ``PictureDownload_StartOrRefresh`` polls notification type 3 until
    ``NotificationType3_ApplyObjectStatus`` finds the transfer id and marks
    its object valid. The same record establishes the target byte count used
    to detect completion of the type-4 chunk stream.
    """
    return struct.pack(
        "<HHIHIIIII",
        1,
        30,
        target_size & 0xFFFFFFFF,
        state_kind & 0xFFFF,
        metric0 & 0xFFFFFFFF,
        metric1 & 0xFFFFFFFF,
        metric_divisor & 0xFFFFFFFF,
        aux_status & 0xFFFFFFFF,
        transfer_id & 0xFFFFFFFF,
    )


def build_type4_transfer_chunk_frame(
    transfer_id: int,
    chunk_offset: int,
    chunk_data: bytes,
) -> bytes:
    """Build one type-4 opcode-3 contiguous transfer chunk."""
    frame_size = 12 + len(chunk_data)
    if frame_size > 0xFFFF:
        raise ValueError(f"type-4 transfer frame exceeds u16 size: {frame_size}")
    return (
        struct.pack(
            "<HHII",
            3,
            frame_size,
            transfer_id & 0xFFFFFFFF,
            chunk_offset & 0xFFFFFFFF,
        )
        + chunk_data
    )


# Optional signed-short TLV fields `(struct offset, presence bit)`, per
# `docs/mosview-authored-text-and-font-re.md` §"Text Header Grammar". Keys
# match the decoded struct's offsets so `decode_case1_tlv` round-trips.
_TLV_OPTIONAL_SHORT_FIELDS = (
    (0x16, 0x20000),  # space_before
    (0x18, 0x40000),  # space_after
    (0x1A, 0x80000),  # min_line_extent
    (0x1C, 0x100000),  # left_indent
    (0x1E, 0x200000),  # right_indent
    (0x20, 0x400000),  # first_line_indent
    (0x22, 0x800000),  # tab_interval
)


_TAB_STOP_SECOND_FLAG = 0x4000  # bit 14 of `stop_x` signals "stop_payload follows"


def encode_text_item_tlv(
    fields: dict | None = None,
    *,
    tab_stops: list[tuple[int, int]] | None = None,
) -> bytes:
    """Encode a `MVDecodePackedTextHeader`-shaped TLV from a field dict.

    Inverse of `decode_case1_tlv`. Field semantics per
    `MVDecodePackedTextHeader @ 0x7e897ad0` and consumers in
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
      0x27  tab_stop_count          i16  optional, gated by bitmap bit 0x2000000

    The bit-0x2000000 pair list is **tab stops**, consumed by
    `MVResolveNextTabStop @ 0x7e895620` as `(stop_x, stop_payload)`
    shorts at decoded-header offset +0x29 stride 4. Multi-run text
    styling is *not* encoded here — it happens via the `0x80` control
    byte in the case-1 control stream (see §5 of
    `docs/MEDVIEW-TEXT-ENCODING.md`).

    Tab-stop pair wire form per `MVDecodePackedTextHeader`:
      - First short: PackedUnsignedSmall (u8/u16, value range
        [0, 0x7FFF]). Bit 14 of the decoded value flags whether a
        second short follows; bit 14 is cleared after the read.
      - Optional second short: PackedUnsignedSmall.

    The decoded `stop_x` (bit-14 cleared) thus has range [0, 0x3FFF].
    `stop_payload == 0` is the engine's default-alignment sentinel and
    is omitted from the wire (no second short emitted, bit 14 of
    `stop_x` left clear).

    Args:
      fields: dict keyed by struct offset.
      tab_stops: list of `(stop_x, stop_payload)` pairs; when present,
        sets bitmap bit 0x2000000 and `tab_stop_count = len(stops)`.

    Optional fields are emitted when their key is present in `fields`
    (regardless of value — explicit zero still shows up on the wire).
    Unknown keys raise `ValueError`.
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

    if tab_stops is not None:
        bitmap |= 0x2000000
        optional_payload += encode_signed_short_varint(len(tab_stops))
        for stop_x, stop_payload in tab_stops:
            if not (0 <= stop_x <= 0x3FFF):
                raise ValueError(f"stop_x out of range [0, 0x3FFF] (bit 14 reserved): {stop_x}")
            if not (0 <= stop_payload <= 0x7FFF):
                raise ValueError(
                    f"stop_payload out of PackedUnsignedSmall range [0, 0x7FFF]: {stop_payload}"
                )
            if stop_payload == 0:
                optional_payload += encode_byte_or_ushort_varint(stop_x)
            else:
                optional_payload += encode_byte_or_ushort_varint(stop_x | _TAB_STOP_SECOND_FLAG)
                optional_payload += encode_byte_or_ushort_varint(stop_payload)

    if f:
        raise ValueError(f"unknown TLV field keys: {sorted(f)}")

    return (
        encode_signed_int_varint(length_value) + struct.pack("<I", bitmap) + bytes(optional_payload)
    )


def _decode_signed_int(buf: bytes, pos: int) -> tuple[int, int]:
    """Inverse of `encode_signed_int_varint`. Returns `(value, new_pos)`."""
    raw_word = struct.unpack_from("<H", buf, pos)[0]
    if (raw_word & 1) == 0:
        return (raw_word >> 1) - 0x4000, pos + 2
    raw_dword = struct.unpack_from("<I", buf, pos)[0]
    return (raw_dword >> 1) - 0x40000000, pos + 4


def _decode_signed_short(buf: bytes, pos: int) -> tuple[int, int]:
    """Inverse of `encode_signed_short_varint`. Returns `(value, new_pos)`."""
    if (buf[pos] & 1) == 0:
        return (buf[pos] >> 1) - 0x40, pos + 1
    raw_word = struct.unpack_from("<H", buf, pos)[0]
    return (raw_word >> 1) - 0x4000, pos + 2


def _decode_unsigned_small(buf: bytes, pos: int) -> tuple[int, int]:
    """Inverse of `encode_byte_or_ushort_varint`. Returns `(value, new_pos)`."""
    if (buf[pos] & 1) == 0:
        return buf[pos] >> 1, pos + 1
    return struct.unpack_from("<H", buf, pos)[0] >> 1, pos + 2


def decode_case1_tlv(buf: bytes) -> tuple[dict, int]:
    """Decode a `MVDecodePackedTextHeader` TLV and report
    `(struct_dict, bytes_consumed)`, following its control flow so tests can
    pin the encoder against the decompiled paths."""
    fields: dict = {}
    fields[0x00], pos = _decode_signed_int(buf, 0)

    # Presence bitmap u32 + the flag fields packed into it.
    bitmap = struct.unpack_from("<I", buf, pos)[0]
    pos += 4
    fields[0x04] = bitmap & 0x1
    fields[0x08] = (bitmap >> 16) & 0x1
    fields[0x0A] = (bitmap >> 24) & 0x1
    fields[0x0C] = (bitmap >> 26) & 0x3
    fields[0x0E] = (bitmap >> 28) & 0x1

    # +0x12 shares bit 0x10000 with the flag at +0x08.
    fields[0x12] = 0
    if bitmap & 0x10000:
        fields[0x12], pos = _decode_signed_int(buf, pos)

    for offset, bit_mask in _TLV_OPTIONAL_SHORT_FIELDS:
        if bitmap & bit_mask:
            fields[offset], pos = _decode_signed_short(buf, pos)
        elif offset == 0x22:
            fields[0x22] = 0x0048 if (fields[0x12] & 1) == 0 else 0x02C6
        else:
            fields[offset] = 0

    # +0x24: the parser reads 3 bytes and stores the low 2.
    fields[0x24] = 0
    if bitmap & 0x1000000:
        fields[0x24] = struct.unpack_from("<H", buf, pos)[0]
        pos += 3

    fields[0x27] = 0
    if bitmap & 0x2000000:
        fields[0x27], pos = _decode_signed_short(buf, pos)

    # Tab stops at +0x29, stride 4: bit 14 of the raw `stop_x` flags a
    # following `stop_payload`, and the parser clears it after the read.
    tab_stops: list[tuple[int, int]] = []
    for _ in range(max(0, fields[0x27])):
        stop_x, pos = _decode_unsigned_small(buf, pos)
        stop_payload = 0
        if stop_x & _TAB_STOP_SECOND_FLAG:
            stop_payload, pos = _decode_unsigned_small(buf, pos)
        tab_stops.append((stop_x & ~_TAB_STOP_SECOND_FLAG, stop_payload))
    fields["tab_stops"] = tab_stops

    return (fields, pos)


def build_case1_bf_chunk(
    control_stream: bytes,
    text_data: bytes,
    title_byte: int,
    key: int,
    *,
    topic_length: int | None = None,
    tlv_fields: dict[int, int] | None = None,
    tab_stops: list[tuple[int, int]] | None = None,
    name_size: int | None = None,
    non_scroll: int = -1,
    scroll: int = -1,
    previous: int = CHAIN_TERMINATOR_TOKEN,
    following: int = CHAIN_TERMINATOR_TOKEN,
) -> bytes:
    """Wrap one Media View display record in a type-0 0xBF chunk.

    Layout: `[0xBF][title_byte][u16 name_size]`, then `name_size` bytes of
    name buffer and a 60-byte companion block. In the name buffer, +0x04 and
    +0x0C carry the previous and following contentsTokens, +0x08 the key,
    and +0x26 the item prefix (`MVDecodeTopicItemPrefix`), followed by the
    TLV, the control stream and the text. The companion block's +0x14/+0x18
    hold the non-scroll and scroll bounds; `HfcNear @ 0x7e84589f` copies it
    to viewer+0x38, so a non-scroll value of -1 lands on viewer+0x4c and
    `fMVHasNSR @ 0x7e8835b0` reports no NSR pane.

    Compiled titles already store the bytecode `MVDispatchControlRun`
    consumes: LinkData1 ends with the control stream and LinkData2 holds its
    NUL-separated strings. Only the paragraph header is re-encoded, as the
    TLV. With `topic_length` the item prefix is the widened tag 0x20, which
    carries the TopicLength the client needs to admit the slot to point
    hit-testing; without it the prefix is the narrow text tag 0x01.
    `name_size` defaults to the smallest 4-aligned buffer that fits.
    """
    if not control_stream or control_stream[-1] != 0xFF:
        raise ValueError("Media View control stream must end with 0xFF")
    if not text_data:
        text_data = b"\x00"

    tlv = encode_text_item_tlv(tlv_fields, tab_stops=tab_stops)
    preamble_length_value = len(tlv) + len(control_stream)
    if topic_length is None:
        preamble = encode_case1_preamble(length_value=preamble_length_value, type_tag=0x01)
    else:
        preamble = encode_case1_preamble(
            length_value=preamble_length_value,
            type_tag=0x20,
            prefix_u16=topic_length,
        )

    required_name_size = 0x26 + len(preamble) + len(tlv) + len(control_stream) + len(text_data)
    if name_size is None:
        name_size = max(0x40, (required_name_size + 3) & ~3)
    elif name_size < required_name_size:
        raise ValueError(f"name_size 0x{name_size:x} cannot hold 0x{required_name_size:x} bytes")
    if name_size > 0xFFFF:
        raise ValueError(f"Media View display record exceeds 0xFFFF-byte name buffer: {name_size}")

    chunk = bytearray(4 + name_size + 60)
    chunk[0] = 0xBF
    chunk[1] = title_byte & 0xFF
    chunk[2:4] = struct.pack("<H", name_size)
    chunk[12:16] = struct.pack("<I", key & 0xFFFFFFFF)

    case_offset = 4 + 0x26
    chunk[case_offset : case_offset + len(preamble)] = preamble
    tlv_offset = case_offset + len(preamble)
    chunk[tlv_offset : tlv_offset + len(tlv)] = tlv
    control_offset = tlv_offset + len(tlv)
    chunk[control_offset : control_offset + len(control_stream)] = control_stream
    text_offset = control_offset + len(control_stream)
    chunk[text_offset : text_offset + len(text_data)] = text_data

    chunk[8:12] = struct.pack("<I", previous & 0xFFFFFFFF)
    chunk[16:20] = struct.pack("<I", following & 0xFFFFFFFF)
    nsr_offset = 4 + name_size + 0x14
    chunk[nsr_offset : nsr_offset + 8] = struct.pack(
        "<II",
        non_scroll & 0xFFFFFFFF,
        scroll & 0xFFFFFFFF,
    )
    return bytes(chunk)
