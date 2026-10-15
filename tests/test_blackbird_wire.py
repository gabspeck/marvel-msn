"""Tests for `server.blackbird.wire`: the kind=5 raster, trailer and
container encoders, the case-1 chunk and the notification frames.

Pin every byte against the format derived from RE of `MVCL14N.DLL`:

- Container preamble: `MVResolveBitmapForRun` reads `+0x04` u32 to find the
  bitmap start.
- Kind=5 header: `MVDecodeBitmapBaggage` parses through the positional varints.
- Trailer: `MVCloneBaggageBytes` extracts `[u8 reserved][u16 count][u32
  tail_size][N*15B children][tail bytes]`.
"""

import struct
import unittest

from server.blackbird.wire import (
    build_baggage_container,
    build_case1_bf_chunk,
    build_kind5_raster,
    build_trailer,
    build_type0_status_record,
    build_type3_transfer_status_frame,
    build_type4_transfer_chunk_frame,
    decode_case1_tlv,
    encode_byte_or_ushort_varint,
    encode_case1_preamble,
    encode_signed_int_varint,
    encode_signed_short_varint,
    encode_text_item_tlv,
    encode_ushort_or_u32_varint,
)


class TestVarintEncoding(unittest.TestCase):
    def test_byte_or_ushort_narrow_byte_low_values(self):
        # value <= 127 fits the byte-narrow form; 1 byte, low bit clear.
        self.assertEqual(encode_byte_or_ushort_varint(0), bytes([0x00]))
        self.assertEqual(encode_byte_or_ushort_varint(1), bytes([0x02]))
        self.assertEqual(encode_byte_or_ushort_varint(127), bytes([0xFE]))

    def test_byte_or_ushort_narrow_ushort_high_values(self):
        # 128..32767 spills to ushort form; 2 bytes, low bit set.
        self.assertEqual(encode_byte_or_ushort_varint(128), bytes.fromhex("0101"))
        self.assertEqual(encode_byte_or_ushort_varint(32767), bytes.fromhex("ffff"))

    def test_byte_or_ushort_overflow_rejected(self):
        with self.assertRaises(ValueError):
            encode_byte_or_ushort_varint(32768)
        with self.assertRaises(ValueError):
            encode_byte_or_ushort_varint(-1)

    def test_ushort_or_u32_narrow_short_values(self):
        # value <= 32767 fits the ushort-narrow form; 2 bytes, low bit
        # clear (LE u16 = value << 1).
        self.assertEqual(encode_ushort_or_u32_varint(0), bytes.fromhex("0000"))
        self.assertEqual(encode_ushort_or_u32_varint(1), bytes.fromhex("0200"))
        self.assertEqual(encode_ushort_or_u32_varint(640), bytes.fromhex("0005"))
        self.assertEqual(encode_ushort_or_u32_varint(32767), bytes.fromhex("feff"))

    def test_ushort_or_u32_wide_high_values(self):
        # 32768..0x7FFFFFFF needs the u32-wide form; 4 bytes, low bit
        # set ((value << 1) | 1 as LE u32).
        self.assertEqual(encode_ushort_or_u32_varint(32768), bytes.fromhex("01000100"))
        # 38400 = 640*60 = 1bpp pixel-byte-count for a 640×480 bitmap.
        # Encoded as wide form: (38400 << 1) | 1 = 0x12C01.
        self.assertEqual(encode_ushort_or_u32_varint(38400), bytes.fromhex("012c0100"))

    def test_ushort_or_u32_overflow_rejected(self):
        with self.assertRaises(ValueError):
            encode_ushort_or_u32_varint(0x80000000)


def _child_record(tag, tag2, flags, x, y, w, h, va):
    """A 15-byte trailer child record (docs/MEDVIEW.md §10.3)."""
    return struct.pack("<BBBhhhhI", tag, tag2, flags, x, y, w, h, va)


class TestTrailer(unittest.TestCase):
    def test_empty_trailer(self):
        # No children, no tail: 1B reserved + 2B count + 4B tail_size = 7 B.
        t = build_trailer([], b"")
        self.assertEqual(t, bytes.fromhex("00 0000 00000000".replace(" ", "")))

    def test_trailer_with_one_child_no_tail(self):
        rec = _child_record(0x8A, 0, 0, 10, 20, 50, 18, 0xFFFFFFFF)
        t = build_trailer([rec], b"")
        # 1B reserved + 2B count=1 + 4B tail=0 + 15B child = 22 B
        self.assertEqual(len(t), 22)
        self.assertEqual(t[0], 0)
        self.assertEqual(struct.unpack("<H", t[1:3])[0], 1)
        self.assertEqual(struct.unpack("<I", t[3:7])[0], 0)
        self.assertEqual(t[7:22], rec)

    def test_trailer_with_tail_bytes(self):
        rec = _child_record(0x07, 0x01, 0x00, 0, 0, 100, 18, 0)
        tail = b"MSN Today\x00"
        t = build_trailer([rec], tail)
        # 7B header + 15B child + 10B tail = 32 B
        self.assertEqual(len(t), 32)
        self.assertEqual(struct.unpack("<I", t[3:7])[0], len(tail))
        self.assertEqual(t[22:], tail)

    def test_trailer_rejects_wrong_record_size(self):
        with self.assertRaises(ValueError):
            build_trailer([b"\x00" * 14], b"")


class TestKind5Raster(unittest.TestCase):
    def test_minimum_viable_1x1_monochrome(self):
        # 1×1 mono with empty trailer. Pixel data starts at offset 28
        # (right after the all-narrow header). Trailer offset points to
        # the byte after pixel data (30) — `MVDecodeBitmapBaggage` reads the
        # field but performs a 0-byte memcpy when trailer_size=0, so
        # any value is acceptable; the encoder picks `pixel_offset +
        # len(pixel_data)` for self-consistency.
        raster = build_kind5_raster(
            width=1,
            height=1,
            bpp=1,
            pixel_data=b"\x00\x00",  # 1×1 mono + WORD pad
            trailer=b"",
        )
        self.assertEqual(
            raster,
            bytes.fromhex(
                "0500"  # kind=5, compression=raw
                "00000000"  # 2x narrow skip-ints
                "0202"  # planes=1, bpp=1
                "02000200"  # width=1, height=1 (narrow ushort)
                "00000000"  # palette=0, reserved=0
                "04000000"  # pixel_byte_count=2, trailer_size=0
                "1c000000"  # pixel_data_offset = 28
                "1e000000"  # trailer_offset = 30 (after pixels)
                "0000"  # pixel data
            ),
        )

    def test_640x480_uses_wide_pixel_byte_count(self):
        # 640×480 1bpp → pixel_byte_count = 38400, doesn't fit in a
        # narrow ushort. Encoder must spill to wide form. Header gains
        # 2 bytes (4-byte wide vs 2-byte narrow), shifting the offset
        # fields. pixel_data_offset = header_with_wide_field = 30 B.
        raster = build_kind5_raster(
            width=640,
            height=480,
            bpp=1,
            pixel_data=b"\xff" * 38400,
            trailer=b"",
        )
        # Expected size: 30 B header + 38400 B pixel data = 38430 B.
        self.assertEqual(len(raster), 30 + 38400)
        # Pixel-byte-count field should be 4-byte wide form.
        # Header position 0x10 carries the pixel-byte-count varint.
        self.assertEqual(raster[0x10:0x14], bytes.fromhex("012c0100"))
        # pixel_data_offset at position 0x16 = 30
        self.assertEqual(struct.unpack("<I", raster[0x16:0x1A])[0], 30)
        # trailer_offset = 30 + 38400 = 38430 = 0x961E
        self.assertEqual(struct.unpack("<I", raster[0x1A:0x1E])[0], 38430)

    def test_pixel_data_at_declared_offset(self):
        # The parser's `memcpy(output + pixel_offset_in_output,
        # input + pixel_data_offset, pixel_byte_count)` step requires
        # pixel_data_offset to point to the actual pixel bytes.
        pix = bytes(range(64)) * 4  # 256 bytes
        raster = build_kind5_raster(
            width=8,
            height=32,
            bpp=8,
            pixel_data=pix,
            trailer=b"",
        )
        offset = struct.unpack("<I", raster[0x14:0x18])[0]
        self.assertEqual(raster[offset : offset + 256], pix)

    def test_trailer_at_declared_offset(self):
        trailer = build_trailer(
            [_child_record(0x8A, 0, 0, 5, 5, 50, 18, 0xFFFFFFFF)],
            b"caption\x00",
        )
        raster = build_kind5_raster(
            width=2,
            height=2,
            bpp=1,
            pixel_data=b"\x00\x00",  # 2×2 mono
            trailer=trailer,
        )
        # Read trailer offset and verify the trailer bytes match.
        trailer_offset = struct.unpack("<I", raster[0x18:0x1C])[0]
        self.assertEqual(raster[trailer_offset:], trailer)


class TestBaggageContainer(unittest.TestCase):
    def test_container_preamble(self):
        bitmap = b"\x05\x00" + b"\x00" * 26  # 28-byte minimum kind-5 stub
        container = build_baggage_container(bitmap)
        # 8-byte preamble: u16 reserved=0, u16 count=1, u32 offset=8.
        self.assertEqual(container[0:8], bytes.fromhex("00000100 08000000".replace(" ", "")))
        # Bitmap follows.
        self.assertEqual(container[8:], bitmap)


class TestSignedIntVarint(unittest.TestCase):
    """Length-form varint used by `MVDecodePackedTextHeader` / `MVDecodeTopicItemPrefix`.

    Narrow form: 2 B, low bit clear, decoded `(raw>>1) - 0x4000`.
    Wide form:   4 B, low bit set,   decoded `(raw>>1) - 0x40000000`.
    """

    def test_narrow_zero_encodes_to_0080(self):
        # raw word = (0 + 0x4000) << 1 = 0x8000 → LE bytes `00 80`.
        self.assertEqual(encode_signed_int_varint(0), bytes.fromhex("0080"))

    def test_narrow_negative_extreme(self):
        # value = -0x4000 → raw = 0x0000 → LE `00 00`.
        self.assertEqual(encode_signed_int_varint(-0x4000), bytes.fromhex("0000"))

    def test_narrow_positive_extreme(self):
        # value = 0x3FFF → raw = 0xFFFE → LE `fe ff`.
        self.assertEqual(encode_signed_int_varint(0x3FFF), bytes.fromhex("feff"))

    def test_wide_when_value_overflows_narrow(self):
        # 0x4000 needs wide form; raw = ((0x4000 + 0x40000000) << 1) | 1
        # = 0x80008001 → LE `01 80 00 80`.
        self.assertEqual(encode_signed_int_varint(0x4000), bytes.fromhex("01800080"))

    def test_overflow_rejected(self):
        with self.assertRaises(ValueError):
            encode_signed_int_varint(0x40000000)
        with self.assertRaises(ValueError):
            encode_signed_int_varint(-0x40000001)


class TestSignedShortVarint(unittest.TestCase):
    """Short-form varint used by `MVDecodePackedTextHeader` for fields TLV+0x16..+0x22.

    Narrow form: 1 B, low bit clear, decoded `(raw>>1) - 0x40`.
    Wide form:   2 B, low bit set,   decoded `(raw>>1) - 0x4000`.
    """

    def test_narrow_zero(self):
        self.assertEqual(encode_signed_short_varint(0), bytes([0x80]))

    def test_narrow_negative_extreme(self):
        self.assertEqual(encode_signed_short_varint(-0x40), bytes([0x00]))

    def test_narrow_positive_extreme(self):
        self.assertEqual(encode_signed_short_varint(0x3F), bytes([0xFE]))

    def test_wide_when_value_overflows_narrow(self):
        # value=0x40 → raw=((0x40+0x4000)<<1)|1=0x8081 → LE `81 80`.
        self.assertEqual(encode_signed_short_varint(0x40), bytes.fromhex("8180"))

    def test_overflow_rejected(self):
        with self.assertRaises(ValueError):
            encode_signed_short_varint(0x4000)
        with self.assertRaises(ValueError):
            encode_signed_short_varint(-0x4001)


class TestCase1Preamble(unittest.TestCase):
    """Per-chunk preamble (`MVDecodeTopicItemPrefix`).

    Layout for type tag in [0x03..0x10]: `[tag][signed-int varint]`.
    The varint value is added to `entry+0x26 + preamble_size` to find
    the text base pointer.
    """

    def test_case1_zero_length_value(self):
        # type=0x01, length_value=0: 3 bytes `01 00 80`.
        self.assertEqual(encode_case1_preamble(0, 0x01), bytes.fromhex("010080"))

    def test_case1_length_value_seven(self):
        # length_value=7 → raw=(7+0x4000)<<1=0x800E → bytes `0E 80`.
        # Used to put text after a 6-byte null TLV + 1-byte 0xFF control
        # byte (TEXT_BASE one byte past end_of_TLV).
        self.assertEqual(encode_case1_preamble(7, 0x01), bytes.fromhex("010e80"))

    def test_wide_tag_with_default_prefix_u16(self):
        # type=0x20 (widened text), length=0, prefix_u16 defaults to 0
        # → encoded as PackedUnsignedSmall narrow (1 byte = 0x00).
        # Wire: `20` + signed-int-narrow(0)=`0080` + PackedUnsignedSmall(0)=`00`.
        self.assertEqual(
            encode_case1_preamble(0, 0x20),
            bytes.fromhex("20008000"),
        )

    def test_wide_tag_with_nonzero_prefix_u16(self):
        # prefix_u16 = 1 fits the PackedUnsignedSmall byte-narrow form (value<<1).
        self.assertEqual(
            encode_case1_preamble(0, 0x20, prefix_u16=1),
            bytes.fromhex("20008002"),
        )
        # prefix_u16 = 128 spills to the u16-wide form ((128<<1)|1 = 0x101).
        self.assertEqual(
            encode_case1_preamble(0, 0x20, prefix_u16=128),
            bytes.fromhex("2000800101"),
        )

    def test_wide_tag_prefix_u16_overflow(self):
        with self.assertRaises(ValueError):
            encode_case1_preamble(0, 0x20, prefix_u16=0x8000)
        with self.assertRaises(ValueError):
            encode_case1_preamble(0, 0x20, prefix_u16=-1)

    def test_narrow_tag_rejects_prefix_u16(self):
        # Narrow tags (≤ 0x10) have no slot for prefix_u16; caller must
        # use a wide tag (0x20+) to carry one.
        with self.assertRaises(ValueError):
            encode_case1_preamble(0, 0x01, prefix_u16=1)
        # prefix_u16=0 / None on narrow tag stays valid (no-op).
        self.assertEqual(
            encode_case1_preamble(0, 0x01, prefix_u16=0),
            bytes.fromhex("010080"),
        )

    def test_raw_pair_tags_rejected(self):
        # 0x02 / 0x21 take the verbatim-copy short-circuit branch of
        # MVDecodeTopicItemPrefix (no varint decode); not implemented.
        with self.assertRaises(NotImplementedError):
            encode_case1_preamble(0, 0x02)
        with self.assertRaises(NotImplementedError):
            encode_case1_preamble(0, 0x21)

    def test_wide_signed_int_varint_in_narrow_tag(self):
        # Text bodies > 0x3FFF need wide SIGNED-INT VARINT (4 byte
        # length), NOT a wide tag. Decoder pinned at MVDecodeTopicItemPrefix
        # — narrow tag 0x01 + wide varint works.
        encoded = encode_case1_preamble(0x4000, 0x01)
        self.assertEqual(encoded[0], 0x01)
        # Wide signed-int varint: ((0x4000+0x40000000)<<1)|1 = 0x80008001.
        self.assertEqual(encoded[1:5], bytes.fromhex("01800080"))

    def test_tag_byte_range(self):
        with self.assertRaises(ValueError):
            encode_case1_preamble(0, 256)


class TestCase1BfChunk(unittest.TestCase):
    def test_empty_cache_fill_layout(self):
        # MEDVIEW's cache fill for a key with no display record.
        chunk = build_case1_bf_chunk(b"\xff", b"\x00", 0x02, 0x1234, name_size=0x100, scroll=0)
        self.assertEqual(len(chunk), 4 + 0x100 + 60)
        self.assertEqual(chunk[:4], b"\xbf\x02\x00\x01")
        self.assertEqual(struct.unpack_from("<III", chunk, 8), (1, 0x1234, 1))
        # Narrow text tag, preamble length 7 = 6-byte TLV + 0xFF control.
        self.assertEqual(chunk[0x2A:0x2D], b"\x01" + encode_signed_int_varint(7))
        self.assertEqual(chunk[0x2D:0x35], encode_text_item_tlv() + b"\xff\x00")
        self.assertEqual(struct.unpack_from("<iI", chunk, 4 + 0x100 + 0x14), (-1, 0))

    def test_topic_length_selects_the_widened_tag(self):
        chunk = build_case1_bf_chunk(b"\xff", b"\x00", 0x02, 0, topic_length=5)
        self.assertEqual(chunk[0x2A], 0x20)

    def test_name_size_too_small_is_rejected(self):
        with self.assertRaises(ValueError):
            build_case1_bf_chunk(b"\xff", b"x" * 64, 0x02, 0, name_size=0x40)


class TestCase1Tlv(unittest.TestCase):
    """TLV produced by `MVDecodePackedTextHeader` — the case-1 layout descriptor."""

    def test_null_tlv_is_six_bytes(self):
        # Length=0 narrow (`00 80`) + bitmap u32 = 0 (`00 00 00 00`).
        self.assertEqual(encode_text_item_tlv(), bytes.fromhex("008000000000"))

    def test_decode_null_tlv_round_trip(self):
        fields, consumed = decode_case1_tlv(encode_text_item_tlv())
        self.assertEqual(consumed, 6)
        self.assertEqual(fields[0x00], 0)
        # All flag fields are zero.
        for offset in (0x04, 0x08, 0x0A, 0x0C, 0x0E):
            self.assertEqual(fields[offset], 0, f"flag {offset:#x}")
        # Conditional fields zero by absence.
        for offset in (0x12, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 0x20, 0x24, 0x27):
            self.assertEqual(fields[offset], 0, f"field {offset:#x}")
        # Default for absent +0x22: depends on (TLV[0x12] & 1).
        self.assertEqual(fields[0x22], 0x0048)
        # No trailing tab stops.
        self.assertEqual(fields["tab_stops"], [])

    def test_decode_consumes_only_narrow_length_plus_bitmap(self):
        # Trailing bytes after the 6-byte null TLV must NOT be read.
        suffix = b"\xca\xfe\xba\xbe"
        fields, consumed = decode_case1_tlv(encode_text_item_tlv() + suffix)
        self.assertEqual(consumed, 6)


class TestTextItemTlvEncoder(unittest.TestCase):
    """`encode_text_item_tlv` — encoder counterpart of `decode_case1_tlv`.

    Round-trip coverage: any field set the decoder produces should round
    back through the encoder identically (modulo parser-default fill-in).
    """

    def test_alignment_mode_packs_into_bitmap_bits_26_27(self):
        # alignment_mode = 1 (right) → bitmap = (1 << 26) = 0x04000000.
        # Length=0 narrow (`00 80`) + bitmap LE (`00 00 00 04`) = 6 B total.
        encoded = encode_text_item_tlv({0x0C: 1})
        self.assertEqual(encoded, bytes.fromhex("008000000004"))

    def test_text_start_index_emitted_as_length_field(self):
        # text_start_index = 16 → length raw = (16 + 0x4000) << 1 = 0x8020 → "20 80"
        # bitmap = 0 → "00 00 00 00"
        encoded = encode_text_item_tlv({0x00: 16})
        self.assertEqual(encoded, bytes.fromhex("208000000000"))

    def test_optional_fields_emit_only_when_present(self):
        # space_before = 5 → bitmap |= 0x20000; payload = encode_signed_short_varint(5)
        # = ((5+0x40)<<1) = 0x8A → 1-byte narrow.
        # Length(2) + bitmap_LE(4) + payload(1) = 7 B.
        encoded = encode_text_item_tlv({0x16: 5})
        self.assertEqual(encoded, bytes.fromhex("0080000002008a"))

    def test_round_trip_with_real_authored_defaults(self):
        # Recipe-derived field set: left-aligned text with non-zero spacing.
        # text_start_index=0, alignment_mode=0 (left), space_before=12,
        # space_after=12, left_indent=0x40, first_line_indent=0x80.
        fields = {
            0x00: 0,
            0x0C: 0,
            0x16: 12,
            0x18: 12,
            0x1C: 0x40,
            0x20: 0x80,
        }
        encoded = encode_text_item_tlv(fields)
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        for k, v in fields.items():
            self.assertEqual(decoded[k], v, f"field 0x{k:02x}")

    def test_round_trip_with_alignment_and_empty_tab_stops(self):
        # An empty stop list still sets bit 0x2000000 and encodes count 0.
        encoded = encode_text_item_tlv({0x00: 0, 0x0C: 2}, tab_stops=[])
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(decoded[0x0C], 2)
        self.assertEqual(decoded[0x27], 0)
        self.assertEqual(decoded["tab_stops"], [])

    def test_unknown_key_raises(self):
        with self.assertRaises(ValueError):
            encode_text_item_tlv({0x99: 1})

    def test_tab_stops_single_no_payload(self):
        # One stop at x=100 with default payload (0): emitted as just
        # `PackedUnsignedSmall(100)` (1 byte = 100<<1 = 200 = 0xC8).
        # Length(2) + bitmap_LE(4) + count_varint(1) + stop_x(1) = 8 B.
        encoded = encode_text_item_tlv({0x00: 0}, tab_stops=[(100, 0)])
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(decoded[0x27], 1)
        self.assertEqual(decoded["tab_stops"], [(100, 0)])

    def test_tab_stops_with_payload(self):
        # Stop at x=50 with payload=7. stop_x bit 14 set → second short
        # follows. encoded as PackedUnsignedSmall((50|0x4000)) wide form
        # then PackedUnsignedSmall(7) narrow.
        encoded = encode_text_item_tlv({0x00: 0}, tab_stops=[(50, 7)])
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(decoded["tab_stops"], [(50, 7)])

    def test_tab_stops_multiple_mixed(self):
        # 8 stops, mixed payloads — exercises the multi-pair path the
        # plan called out for inline-run encoding (which is in fact tab
        # stops, not style runs).
        stops = [
            (10, 0),
            (50, 0),
            (100, 1),
            (150, 0),
            (200, 7),
            (500, 0),
            (1000, 3),
            (0x3FFF, 0),
        ]
        encoded = encode_text_item_tlv({0x00: 0}, tab_stops=stops)
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(decoded[0x27], len(stops))
        self.assertEqual(decoded["tab_stops"], stops)

    def test_tab_stops_x_overflow(self):
        # stop_x must fit in [0, 0x3FFF] — bit 14 is the flag and bit
        # 15 / wide-form bit are reserved by the varint encoding.
        with self.assertRaises(ValueError):
            encode_text_item_tlv({0x00: 0}, tab_stops=[(0x4000, 0)])

    def test_tab_stops_legacy_count_mismatch_rejected(self):
        # Passing both fields[0x27] and tab_stops must agree.
        with self.assertRaises(ValueError):
            encode_text_item_tlv({0x00: 0, 0x27: 2}, tab_stops=[(10, 0)])

    def test_tab_stops_legacy_nonzero_count_without_list_rejected(self):
        # Old positional API only supports count=0 (no list). Non-zero
        # count without an explicit `tab_stops=` raises.
        with self.assertRaises(ValueError):
            encode_text_item_tlv({0x27: 1})


class TestType0StatusRecord(unittest.TestCase):
    """`0xA5` HfcStatusRecord on the type-0 subscription channel.

    Layout per `docs/mosview-mediaview-format.md` "Type 0
    TopicCacheStream": `u8 0xa5, u8 title_byte, u16 status, u32 contents_token`.
    """

    def test_record_is_eight_bytes(self):
        rec = build_type0_status_record(title_byte=1, status=0, contents_token=0)
        self.assertEqual(len(rec), 8)

    def test_layout_matches_spec(self):
        rec = build_type0_status_record(
            title_byte=0x42,
            status=0xCAFE,
            contents_token=0xDEADBEEF,
        )
        self.assertEqual(rec[0], 0xA5)  # opcode
        self.assertEqual(rec[1], 0x42)  # title_byte
        self.assertEqual(rec[2:4], bytes.fromhex("feca"))  # status u16 LE
        self.assertEqual(rec[4:8], bytes.fromhex("efbeadde"))  # contents_token u32 LE

    def test_zero_status_for_empty_no_data(self):
        # Used by `MEDVIEW.FetchAdjacentTopic` to short-circuit the
        # 30 s wait loop when no adjacent body is available.
        rec = build_type0_status_record(title_byte=1, status=0, contents_token=0x1000)
        self.assertEqual(rec, bytes.fromhex("a501000000100000"))


class TestPictureTransferFrames(unittest.TestCase):
    def test_type3_status_marks_transfer_valid_and_sets_target_size(self):
        frame = build_type3_transfer_status_frame(
            transfer_id=0x12345678,
            target_size=0x2F44,
            state_kind=1,
            metric0=113,
            metric1=95,
        )
        self.assertEqual(len(frame), 30)
        self.assertEqual(
            struct.unpack("<HHIHIIIII", frame),
            (1, 30, 0x2F44, 1, 113, 95, 0, 0, 0x12345678),
        )

    def test_type4_chunk_carries_transfer_id_offset_and_bytes(self):
        frame = build_type4_transfer_chunk_frame(
            transfer_id=0x12345678,
            chunk_offset=0x400,
            chunk_data=b"bitmap",
        )
        self.assertEqual(
            struct.unpack("<HHII", frame[:12]),
            (3, len(frame), 0x12345678, 0x400),
        )
        self.assertEqual(frame[12:], b"bitmap")

    def test_type4_chunk_rejects_oversized_frame(self):
        with self.assertRaises(ValueError):
            build_type4_transfer_chunk_frame(1, 0, b"\x00" * 0xFFF4)


if __name__ == "__main__":
    unittest.main()
