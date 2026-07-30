"""Tests for compiled Microsoft Media View 1.4 title fixtures."""

import hashlib
import pathlib
import struct
import unittest

from server.blackbird.wire import (
    build_case1_stream_bf_chunk,
    decode_case1_tlv,
)
from server.services.medview.m14_loader import load_m14, lower_m14_to_payload

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_HANDBOOK = _REPO_ROOT / "resources" / "titles" / "HANDBOOK.M14"
_FRANCE = _REPO_ROOT / "resources" / "titles" / "FRANCE.M14"


def _read_blob(payload: bytes, offset: int) -> tuple[bytes, int]:
    size = struct.unpack_from("<H", payload, offset)[0]
    offset += 2
    return payload[offset : offset + size], offset + size


class TestM14Loader(unittest.TestCase):
    def test_fixtures_are_the_media_view_samples(self):
        self.assertEqual(len(_HANDBOOK.read_bytes()), 472_917)
        self.assertEqual(
            hashlib.sha256(_HANDBOOK.read_bytes()).hexdigest(),
            "fc6acfd7a38d6a0f12ac6dec68a5e4b0121185c6e69d148fa0c60e659a3a9d11",
        )
        self.assertEqual(len(_FRANCE.read_bytes()), 972_835)
        self.assertEqual(
            hashlib.sha256(_FRANCE.read_bytes()).hexdigest(),
            "f39c8fa37c881ade153f4af8e6c8d9c098c6309d378ed27e5331fd8a8fe98060",
        )

    def test_handbook_home_topic_contains_native_mediaview_image_command(self):
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        self.assertEqual(title.title, "Employee Handbook Example")
        self.assertEqual(
            title.copyright,
            "© 1996 Centric Development, Inc.",
        )
        self.assertEqual(title.topic_count, 22)
        self.assertEqual(
            sum(bool(topic.displays) for topic in title.topics),
            22,
        )
        self.assertEqual(
            title.font_faces,
            ("Times New Roman", "Arial", "Helv", "Wingdings"),
        )
        self.assertTrue(all(len(descriptor) == 0x2A for descriptor in title.font_descriptors))
        self.assertEqual(title.dll_maps[2].alias, "MVIMG")
        self.assertEqual(title.dll_maps[2].win32_retail, "MVMG14N")

        display = title.home_display
        self.assertEqual(display.topic_pos, 0xA7)
        self.assertEqual(display.tlv_fields, ((0x0C, 2), (0x12, 1)))
        self.assertEqual(
            display.control_stream,
            b"\x80\x01\x00"
            b"\x87\x05\x40\x80\x00\x00\x00\x00\x00\x00"
            b"MVIMG,MVIMAGE, !homed.SHG\x00"
            b"\xff",
        )
        self.assertTrue(title.baggage_map()["homed.shg"].startswith(b"\x6c\x70\x01\x00"))
        self.assertEqual(
            title.baggage_map()["handbook.m14"],
            _HANDBOOK.read_bytes(),
        )

    def test_france_compressed_topic_stream_and_baggage_are_decoded(self):
        title = load_m14(_FRANCE)
        self.assertIsNotNone(title)
        self.assertEqual(title.contents_offset, 0x18699)
        self.assertEqual(title.topic_count, 30)
        self.assertEqual(
            sum(bool(topic.displays) for topic in title.topics),
            30,
        )
        self.assertEqual(title.home_topic.title, "Home Page")
        self.assertEqual(title.home_display.topic_pos, 0xC930)
        self.assertEqual(title.pane_backgrounds, (0x00C0FFFF, 0x00FFFFFF))
        self.assertIn(
            b"MVIMG,MVIMAGE, !homem.SHG\x00",
            title.home_display.control_stream,
        )
        self.assertTrue(title.baggage_map()["homem.shg"].startswith(b"\x6c\x70\x01\x00"))

    def test_context_hashes_resolve_to_native_topic_positions(self):
        france = load_m14(_FRANCE)
        handbook = load_m14(_HANDBOOK)
        self.assertIsNotNone(france)
        self.assertIsNotNone(handbook)
        self.assertEqual(
            france.context_at(0x6348),
            (0x4696, 0x8338),
        )
        self.assertEqual(
            france.context_at(0x10ACC4),
            (0xCF0A, 0x186C1),
        )
        self.assertEqual(
            handbook.context_at(0x2CD6150),
            (0x1A6, 0x4),
        )

    def test_title_open_payload_uses_m14_system_and_font_data(self):
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        payload = lower_m14_to_payload(title, "4")

        font_blob, offset = _read_blob(payload, 0)
        reserved, descriptor_count = struct.unpack_from("<HH", font_blob, 0)
        self.assertEqual(reserved, 0)
        self.assertEqual(descriptor_count, 12)
        self.assertIn(b"Times New Roman\x00", font_blob)
        self.assertIn(b"Wingdings\x00", font_blob)

        for _record_size in (0x2B, 0x1F):
            section, offset = _read_blob(payload, offset)
            self.assertEqual(section, b"")
        windows, offset = _read_blob(payload, offset)
        self.assertEqual(len(windows), 0x98)
        self.assertEqual(struct.unpack_from("<I", windows, 0x78)[0], 0x00C0FFFF)
        self.assertEqual(struct.unpack_from("<I", windows, 0x7C)[0], 0x00FFFFFF)
        title_text, offset = _read_blob(payload, offset)
        copyright_text, offset = _read_blob(payload, offset)
        title_id, offset = _read_blob(payload, offset)
        self.assertEqual(title_text, b"Employee Handbook Example\x00")
        self.assertEqual(
            copyright_text,
            "© 1996 Centric Development, Inc.\x00".encode("cp1252"),
        )
        self.assertEqual(title_id, b"4\x00")

        entry_bytes = struct.unpack_from("<H", payload, offset)[0]
        entry_count = struct.unpack_from("<H", payload, offset + 2)[0]
        entries_end = offset + 4 + entry_bytes
        self.assertEqual(entry_count, 6)
        entries = []
        offset += 4
        for _ in range(entry_count):
            entry_size = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            entries.append(payload[offset : offset + entry_size])
            offset += entry_size
        self.assertEqual(offset, entries_end)
        self.assertIn(
            b"MVIMG\x00MVMG14W\x00MVMG14W\x00MVPR14N\x00MVMG14N\x00",
            entries,
        )
        self.assertEqual(payload[offset:], b"\x00\x00")

    def test_native_display_stream_is_preserved_in_case1_cache_record(self):
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        display = title.home_display
        chunk = build_case1_stream_bf_chunk(
            display.control_stream,
            display.text_data,
            title_byte=1,
            key=display.topic_pos,
            tlv_fields=display.fields_dict(),
            tab_stops=list(display.tab_stops),
            non_scroll=display.non_scroll,
        )

        self.assertEqual(chunk[:2], b"\xbf\x01")
        self.assertEqual(struct.unpack_from("<I", chunk, 12)[0], 0xA7)
        self.assertEqual(struct.unpack_from("<I", chunk, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", chunk, 16)[0], 1)
        self.assertEqual(chunk[0x2A], 1)
        fields, tlv_size = decode_case1_tlv(chunk[0x2D:])
        self.assertEqual(fields[0x0C], 2)
        control_offset = 0x2D + tlv_size
        self.assertEqual(
            chunk[control_offset : control_offset + len(display.control_stream)],
            display.control_stream,
        )
        name_size = struct.unpack_from("<H", chunk, 2)[0]
        self.assertEqual(
            struct.unpack_from("<I", chunk, 4 + name_size + 0x14)[0],
            0xFFFFFFFF,
        )

    def test_cathar_display_chain_preserves_nsr_and_scroll_regions(self):
        title = load_m14(_FRANCE)
        self.assertIsNotNone(title)
        non_scroll = title.display_at(0x4696)
        scroll = title.display_at(0x46D3)
        self.assertIsNotNone(non_scroll)
        self.assertIsNotNone(scroll)
        self.assertEqual((non_scroll.non_scroll, non_scroll.scroll), (0x4696, 0x46D3))
        self.assertEqual(title.display_neighbors(0x4696), (1, 0x46D3))
        self.assertEqual(title.display_neighbors(0x46D3), (0x4696, 0x4968))
        self.assertEqual(title.display_neighbors(0x4A17), (0x4968, 1))
        self.assertEqual(
            non_scroll.fields_dict(),
            {
                0x12: 1,
                0x16: 240,
                0x18: 60,
                0x1C: 72,
                0x1E: 72,
            },
        )

        chunk = build_case1_stream_bf_chunk(
            non_scroll.control_stream,
            non_scroll.text_data,
            title_byte=1,
            key=non_scroll.topic_pos,
            tlv_fields=non_scroll.fields_dict(),
            tab_stops=list(non_scroll.tab_stops),
            non_scroll=non_scroll.non_scroll,
            scroll=non_scroll.scroll,
        )
        fields, _tlv_size = decode_case1_tlv(chunk[0x2D:])
        self.assertEqual(fields[0x12], 1)
        self.assertEqual(fields[0x16], 240)
        self.assertEqual(fields[0x18], 60)
        self.assertEqual(fields[0x1C], 72)
        self.assertEqual(fields[0x1E], 72)
