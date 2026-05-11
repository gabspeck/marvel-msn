"""Tests for `src.server.blackbird.wire` — the kind=5 raster + trailer +
container encoders.

Pin every byte against the format derived from RE of `MVCL14N.DLL`:

- Container preamble: `MVResolveBitmapForRun` reads `+0x04` u32 to find the
  bitmap start.
- Kind=5 header: `MVDecodeBitmapBaggage` parses through the positional varints.
- Trailer: `MVCloneBaggageBytes` extracts `[u8 reserved][u16 count][u32
  tail_size][N*15B children][tail bytes]`.
"""

import struct
import unittest

from src.server.blackbird.wire import (
    build_baggage_container,
    build_case1_bf_chunk,
    build_case3_bf_chunk,
    build_child_record,
    build_kind5_raster,
    build_trailer,
    build_type0_status_record,
    decode_case1_tlv,
    encode_byte_or_ushort_varint,
    encode_case1_preamble,
    encode_null_tlv,
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
        self.assertEqual(
            encode_ushort_or_u32_varint(32768), bytes.fromhex("01000100")
        )
        # 38400 = 640*60 = 1bpp pixel-byte-count for a 640×480 bitmap.
        # Encoded as wide form: (38400 << 1) | 1 = 0x12C01.
        self.assertEqual(
            encode_ushort_or_u32_varint(38400), bytes.fromhex("012c0100")
        )

    def test_ushort_or_u32_overflow_rejected(self):
        with self.assertRaises(ValueError):
            encode_ushort_or_u32_varint(0x80000000)


class TestChildRecord(unittest.TestCase):
    def test_child_record_byte_layout(self):
        # 15 B: tag(1) tag2(1) flags(1) x(2) y(2) w(2) h(2) va(4)
        rec = build_child_record(
            tag=0x8A,
            tag2=0x00,
            flags=0x00,
            x=10,
            y=20,
            w=100,
            h=18,
            va=0x12345678,
        )
        self.assertEqual(len(rec), 15)
        self.assertEqual(
            rec,
            bytes.fromhex("8a 00 00 0a 00 14 00 64 00 12 00 78 56 34 12".replace(" ", ""))
        )

    def test_child_record_signed_position(self):
        # x/y/w/h are signed shorts — negative values must round-trip.
        rec = build_child_record(0x07, 0x01, 0x00, -1, -1, 0, 0, 0)
        self.assertEqual(rec[3:7], struct.pack("<hh", -1, -1))


class TestTrailer(unittest.TestCase):
    def test_empty_trailer(self):
        # No children, no tail: 1B reserved + 2B count + 4B tail_size = 7 B.
        t = build_trailer([], b"")
        self.assertEqual(t, bytes.fromhex("00 0000 00000000".replace(" ", "")))

    def test_trailer_with_one_child_no_tail(self):
        rec = build_child_record(0x8A, 0, 0, 10, 20, 50, 18, 0xFFFFFFFF)
        t = build_trailer([rec], b"")
        # 1B reserved + 2B count=1 + 4B tail=0 + 15B child = 22 B
        self.assertEqual(len(t), 22)
        self.assertEqual(t[0], 0)
        self.assertEqual(struct.unpack("<H", t[1:3])[0], 1)
        self.assertEqual(struct.unpack("<I", t[3:7])[0], 0)
        self.assertEqual(t[7:22], rec)

    def test_trailer_with_tail_bytes(self):
        rec = build_child_record(0x07, 0x01, 0x00, 0, 0, 100, 18, 0)
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
                "0500"               # kind=5, compression=raw
                "00000000"           # 2x narrow skip-ints
                "0202"               # planes=1, bpp=1
                "02000200"           # width=1, height=1 (narrow ushort)
                "00000000"           # palette=0, reserved=0
                "04000000"           # pixel_byte_count=2, trailer_size=0
                "1c000000"           # pixel_data_offset = 28
                "1e000000"           # trailer_offset = 30 (after pixels)
                "0000"               # pixel data
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
            pixel_data=b"\xFF" * 38400,
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
            [build_child_record(0x8A, 0, 0, 5, 5, 50, 18, 0xFFFFFFFF)],
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

    def test_tag_above_0x10_rejected(self):
        # MVDecodeTopicItemPrefix's `if (0x10 < bVar1)` branch reads an extra
        # varint we don't yet generate.
        with self.assertRaises(NotImplementedError):
            encode_case1_preamble(0, 0x11)

    def test_tag_byte_range(self):
        with self.assertRaises(ValueError):
            encode_case1_preamble(0, 256)


class TestCase1Tlv(unittest.TestCase):
    """TLV produced by `MVDecodePackedTextHeader` — the case-1 layout descriptor."""

    def test_null_tlv_is_six_bytes(self):
        # Length=0 narrow (`00 80`) + bitmap u32 = 0 (`00 00 00 00`).
        self.assertEqual(encode_null_tlv(), bytes.fromhex("008000000000"))

    def test_decode_null_tlv_round_trip(self):
        fields, consumed = decode_case1_tlv(encode_null_tlv())
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
        # No trailing pairs.
        self.assertEqual(fields["pairs"], [])

    def test_decode_consumes_only_narrow_length_plus_bitmap(self):
        # Trailing bytes after the 6-byte null TLV must NOT be read.
        suffix = b"\xCA\xFE\xBA\xBE"
        fields, consumed = decode_case1_tlv(encode_null_tlv() + suffix)
        self.assertEqual(consumed, 6)


class TestTextItemTlvEncoder(unittest.TestCase):
    """`encode_text_item_tlv` — encoder counterpart of `decode_case1_tlv`.

    Round-trip coverage: any field set the decoder produces should round
    back through the encoder identically (modulo parser-default fill-in).
    """

    def test_empty_dict_matches_null_tlv(self):
        self.assertEqual(encode_text_item_tlv({}), encode_null_tlv())
        self.assertEqual(encode_text_item_tlv(None), encode_null_tlv())

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

    def test_round_trip_with_alignment_and_inline_runs_zero(self):
        fields = {
            0x00: 0,
            0x0C: 2,        # alignment_mode = center
            0x27: 0,        # inline_run_count = 0 (encoded but no payload)
        }
        encoded = encode_text_item_tlv(fields)
        decoded, consumed = decode_case1_tlv(encoded)
        self.assertEqual(consumed, len(encoded))
        self.assertEqual(decoded[0x0C], 2)
        self.assertEqual(decoded[0x27], 0)

    def test_unknown_key_raises(self):
        with self.assertRaises(ValueError):
            encode_text_item_tlv({0x99: 1})

    def test_inline_run_count_nonzero_not_implemented(self):
        with self.assertRaises(NotImplementedError):
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
            title_byte=0x42, status=0xCAFE, contents_token=0xDEADBEEF,
        )
        self.assertEqual(rec[0], 0xA5)                   # opcode
        self.assertEqual(rec[1], 0x42)                   # title_byte
        self.assertEqual(rec[2:4], bytes.fromhex("feca"))    # status u16 LE
        self.assertEqual(rec[4:8], bytes.fromhex("efbeadde"))  # contents_token u32 LE

    def test_zero_status_for_empty_no_data(self):
        # Used by `MEDVIEW.FetchAdjacentTopic` to short-circuit the
        # 30 s wait loop when no adjacent body is available.
        rec = build_type0_status_record(title_byte=1, status=0, contents_token=0x1000)
        self.assertEqual(rec, bytes.fromhex("a501000000100000"))


class TestCase1BfChunkLegacy0x40(unittest.TestCase):
    """Byte-pinned case-1 chunk in the original RE form (name_size=0x40)."""

    def _chunk(self, text="MSN Today", title_byte=0x01, key=0):
        return build_case1_bf_chunk(
            text,
            title_byte=title_byte,
            key=key,
            name_size=0x40,
            initial_font_style=None,
        )

    def test_chunk_is_128_bytes(self):
        chunk = self._chunk(key=0xCAFEBABE)
        self.assertEqual(len(chunk), 4 + 0x40 + 60)

    def test_chunk_header_and_key_placement(self):
        chunk = self._chunk(key=0xCAFEBABE)
        self.assertEqual(chunk[0], 0xBF)        # type-0 cache opcode
        self.assertEqual(chunk[1], 0x01)        # title byte
        self.assertEqual(chunk[2:4], bytes.fromhex("4000"))  # name_size = 0x40
        self.assertEqual(chunk[12:16], struct.pack("<I", 0xCAFEBABE))  # key

    def test_chunk_dispatch_byte_is_case1(self):
        chunk = self._chunk()
        # name_buf[0x26] = 0x01 → case-1 dispatch in MVWalkLayoutSlots.
        self.assertEqual(chunk[4 + 0x26], 0x01)

    def test_chunk_preamble_drives_text_base_to_entry_0x30(self):
        # Preamble at name_buf[0x26..0x28]:
        #   byte 0x26: 0x01 (tag)
        #   bytes 0x27-0x28: signed-int varint, value = 7 (TLV size + 1).
        # text_base = entry + 0x26 + 3 + 7 = entry + 0x30.
        chunk = self._chunk()
        self.assertEqual(chunk[4 + 0x26:4 + 0x29], bytes.fromhex("010e80"))

    def test_chunk_tlv_is_null(self):
        chunk = self._chunk()
        # TLV at name_buf[0x29..0x2E] = 6-byte null TLV.
        self.assertEqual(chunk[4 + 0x29:4 + 0x2F], bytes.fromhex("008000000000"))

    def test_chunk_end_of_chunk_marker_at_end_of_tlv(self):
        # 0xFF at name_buf[0x2F] = end_of_TLV. Read by MVDispatchControlRun
        # via control walker (template[+0x14]) when text walker hits NUL.
        chunk = self._chunk()
        self.assertEqual(chunk[4 + 0x2F], 0xFF)

    def test_chunk_text_at_entry_0x30_with_nul_terminator(self):
        chunk = self._chunk()
        # Text at name_buf[0x30..0x39] = 9 ASCII + NUL.
        self.assertEqual(
            chunk[4 + 0x30:4 + 0x30 + 10],
            b"MSN Today\x00",
        )

    def test_chunk_full_byte_layout_for_msn_today(self):
        # Pin the entire 128-byte sequence so any encoder drift is caught.
        chunk = self._chunk(key=0xCAFEBABE)
        expected = bytearray(128)
        expected[0] = 0xBF
        expected[1] = 0x01
        expected[2:4] = bytes.fromhex("4000")
        expected[12:16] = struct.pack("<I", 0xCAFEBABE)
        expected[4 + 0x26:4 + 0x29] = bytes.fromhex("010e80")
        expected[4 + 0x29:4 + 0x2F] = bytes.fromhex("008000000000")
        expected[4 + 0x2F] = 0xFF
        expected[4 + 0x30:4 + 0x3A] = b"MSN Today\x00"
        # Bytes 0x3A..0x43 in name_buf and 0x44..0x7F in content block
        # remain zero.
        self.assertEqual(chunk, bytes(expected))

    def test_chunk_content_block_is_zero(self):
        chunk = self._chunk()
        # Content block = chunk[0x44..0x7F]; bytes +0x2C / +0x34 of the
        # block are HGLOBAL slots, kept NULL by zeros.
        self.assertEqual(chunk[0x44:], b"\x00" * 60)

    def test_empty_text_skip_row_chunk(self):
        # Empty text is intentional for the no-content fallback:
        # `MVTextLayoutFSM`'s pre-test treats first text byte == NUL with
        # end-of-TLV byte == 0xFF as "skip this row" → return 5 → no
        # slot emitted, but HfcNear's per-title cache is still populated
        # (so `fMVSetAddress` completes and the client clears its
        # hourglass). Verify the chunk has the exact byte pattern the
        # pre-test matches.
        chunk = build_case1_bf_chunk(
            "", title_byte=0x01, key=0, name_size=0x40, initial_font_style=None,
        )
        # name_size=0x40 → name_buf occupies chunk[4..0x44].
        # chunk[0x33] = end-of-TLV byte (control_stream); chunk[0x34] = first text byte.
        self.assertEqual(chunk[0x33], 0xFF, "end-of-TLV must be 0xFF for skip-row")
        self.assertEqual(chunk[0x34], 0x00, "first text byte must be NUL for skip-row")

    def test_text_too_long_for_in_name_buf_form_rejected(self):
        # 13 bytes of text + NUL = 14 bytes, exceeds 13-byte budget at name_size=0x40.
        with self.assertRaises(ValueError):
            build_case1_bf_chunk("X" * 13, title_byte=0x01, key=0, name_size=0x40, initial_font_style=None)


class TestCase1BfChunkExtended(unittest.TestCase):
    """Default name_size=0x100 chunk fits the full 119-byte authored
    Homepage.bdf TextRuns body; legacy 0x40 form still accepted via
    explicit `name_size=` kwarg for byte-pin coverage."""

    def test_default_chunk_is_320_bytes(self):
        chunk = build_case1_bf_chunk("MSN Today", title_byte=0x01, key=0)
        # 4-byte header + 0x100 name_buf + 60-byte content block = 320 B.
        self.assertEqual(len(chunk), 4 + 0x100 + 60)
        self.assertEqual(chunk[2:4], bytes.fromhex("0001"))  # name_size = 0x100 LE

    def test_default_chunk_fits_authored_text_119_bytes(self):
        # 119 B (Homepage.bdf TextRuns body length) + NUL fits with the
        # 0x100 default; the 0x40 form would reject this.
        text = "T" * 119
        chunk = build_case1_bf_chunk(text, title_byte=0x01, key=0)
        # The default form primes style 0 first, so real text starts at
        # name_buf[0x34] after a leading NUL at text_base[0].
        self.assertEqual(chunk[4 + 0x33], 0)
        # With a 0x100 buffer there's room through name_buf[0x100 - 1] = 0xFF.
        self.assertEqual(
            chunk[4 + 0x34:4 + 0x34 + 120],
            text.encode("ascii") + b"\x00",
        )

    def test_dispatch_and_preamble_unchanged_at_extended_size(self):
        # The case-1 dispatch / preamble / TLV / control stream / text
        # offsets are all measured from name_buf[0x26] — they don't shift
        # when name_size grows.
        chunk = build_case1_bf_chunk("hello", title_byte=0x01, key=0xDEADBEEF)
        self.assertEqual(chunk[4 + 0x26], 0x01)              # case-1 dispatch
        self.assertEqual(chunk[4 + 0x26:4 + 0x29], bytes.fromhex("011480"))  # preamble
        self.assertEqual(chunk[4 + 0x29:4 + 0x2F], bytes.fromhex("008000000000"))  # null TLV
        self.assertEqual(chunk[4 + 0x2F:4 + 0x33], bytes.fromhex("800000ff"))  # style 0, then end
        self.assertEqual(chunk[4 + 0x33], 0)                 # leading NUL runs the style control
        self.assertEqual(chunk[4 + 0x34:4 + 0x3A], b"hello\x00")
        # Content block is appended at the end (after the larger name_buf).
        self.assertEqual(chunk[-60:], b"\x00" * 60)
        # Key still in the canonical name_buf+0x08 slot (= chunk[12..16]).
        self.assertEqual(chunk[12:16], struct.pack("<I", 0xDEADBEEF))


class TestCase3BfChunk(unittest.TestCase):
    def test_chunk_dispatches_to_bitmap_cell_path(self):
        chunk = build_case3_bf_chunk(title_byte=0x01, key=0xCAFEBABE)
        self.assertEqual(len(chunk), 4 + 0x40 + 60)
        self.assertEqual(chunk[0], 0xBF)
        self.assertEqual(chunk[1], 0x01)
        self.assertEqual(chunk[2:4], bytes.fromhex("4000"))
        self.assertEqual(struct.unpack("<I", chunk[12:16])[0], 0xCAFEBABE)
        self.assertEqual(chunk[4 + 0x26], 0x03)
        self.assertEqual(chunk[4 + 0x27:4 + 0x40], b"\x00" * 0x19)
        self.assertEqual(chunk[0x44:], b"\x00" * 60)


if __name__ == "__main__":
    unittest.main()
