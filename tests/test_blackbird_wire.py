"""Tests for `src.server.blackbird.wire` — the kind=5 raster + trailer +
container encoders.

Pin every byte against the format derived from RE of `MVCL14N.DLL`:

- Container preamble: `FUN_7e886310` reads `+0x04` u32 to find the
  bitmap start.
- Kind=5 header: `FUN_7e887a40` parses through the positional varints.
- Trailer: `FUN_7e886820` extracts `[u8 reserved][u16 count][u32
  tail_size][N*15B children][tail bytes]`.
"""

import struct
import unittest

from src.server.blackbird.wire import (
    build_baggage_container,
    build_child_record,
    build_kind5_raster,
    build_trailer,
    encode_byte_or_ushort_varint,
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
        # the byte after pixel data (30) — `FUN_7e887a40` reads the
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


if __name__ == "__main__":
    unittest.main()
