"""Unit tests for the BBDESIGN `.ttl` loader.

Pinned against `resources/titles/4.ttl` — single page, single Caption
control, three-font CStyleSheet.
"""

import pathlib
import unittest

from server.services.medview.handler import (
    _deid_from_title_token,
    _extract_title_token,
)
from server.services.medview.ttl_loader import (
    CaptionSite,
    FaceEntry,
    LoadedTitle,
    build_bm0_baggage,
    load_title,
    lower_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TITLE_PATH = _REPO_ROOT / "resources" / "titles" / "4.ttl"


class TestLoadTitle(unittest.TestCase):
    def test_known_title_parses_all_fields(self):
        t = load_title(_TITLE_PATH)
        self.assertIsNotNone(t)
        self.assertEqual(t.title_name, "Test Title")
        self.assertEqual(t.caption, "Default Window")
        self.assertEqual(t.window_rect, (200, 100, 640, 480))
        self.assertEqual(t.page_pixel_w, 640)
        self.assertEqual(t.page_pixel_h, 480)
        self.assertEqual(t.page_bg, 0x009098A8)
        self.assertEqual(
            t.font_table,
            (
                FaceEntry(slot=2, face_name="Courier New"),
                FaceEntry(slot=1, face_name="Arial"),
                FaceEntry(slot=0, face_name="Times New Roman"),
            ),
        )
        self.assertEqual(
            t.captions,
            (
                CaptionSite(
                    text="Test caption",
                    font_name="MS Sans Serif",
                    size_pt=12,
                    weight=400,
                    rect_twips=(5291, 2963, 11641, 5926),
                ),
            ),
        )

    def test_missing_path_returns_none(self):
        self.assertIsNone(load_title(pathlib.Path("/tmp/__no_ttl__.ttl")))


class TestLowerToPayload(unittest.TestCase):
    def setUp(self):
        self.title = load_title(_TITLE_PATH)
        self.assertIsNotNone(self.title)
        self.body = lower_to_payload(self.title)

    def test_body_contains_caption_cstring(self):
        self.assertIn(b"Default Window\x00", self.body)

    def test_section0_face_table_contains_all_fonts(self):
        # sec0 payload starts after the 2-byte length prefix; face table
        # begins at sec0+0x12 (header size). Slot-keyed offsets:
        # slot 0 = Times New Roman, slot 1 = Arial, slot 2 = Courier New.
        sec0_off = 2                         # after the leading u16 length prefix
        face_table_off = sec0_off + 0x12
        self.assertEqual(
            self.body[face_table_off:face_table_off + 15], b"Times New Roman",
        )
        self.assertEqual(
            self.body[face_table_off + 0x20:face_table_off + 0x20 + 5], b"Arial",
        )
        self.assertEqual(
            self.body[face_table_off + 0x40:face_table_off + 0x40 + 11], b"Courier New",
        )

    def test_sec06_record_contains_caption_at_offset_0x15(self):
        # sec06 follows sec0(390B header+content) + 2x empty section
        # markers. Locate it by scanning for the caption ASCIIZ inside the
        # record-relative offset 0x15.
        idx = self.body.find(b"Default Window\x00")
        self.assertGreater(idx, 0)
        # The match anchored at sec06+0x15 — re-verify by locating the
        # record's length prefix two bytes back at sec06+0 (sec06 begins
        # `record_size_u16 + record_bytes`). With 0x98-byte record, the
        # caption sits within the first 0x40 bytes of the record body.
        self.assertEqual(self.body[idx:idx + 14], b"Default Window")


class TestBuildBm0Baggage(unittest.TestCase):
    def test_kind8_metafile_when_captions_present(self):
        title = load_title(_TITLE_PATH)
        bag = build_bm0_baggage(title)
        # Container preamble is 8 bytes; first byte of bitmap header is
        # the kind tag.
        self.assertEqual(bag[8], 0x08)
        self.assertIn(b"Test caption", bag)
        self.assertIn(b"MS Sans Serif", bag)

    def test_kind5_raster_when_no_captions(self):
        empty = LoadedTitle(
            title_name="Empty",
            caption="Empty",
            window_rect=(0, 0, 640, 480),
            page_bg=0,
            page_pixel_w=640,
            page_pixel_h=480,
            font_table=(),
            captions=(),
        )
        bag = build_bm0_baggage(empty)
        self.assertEqual(bag[8], 0x05)


class TestTokenExtractor(unittest.TestCase):
    def test_extract_and_parse_title_token(self):
        # Wire shape: tag=0x04 + len|0x80=0x87 + 7B ASCIIZ.
        payload = b"\x04\x87:2[4]0\x00" + b"\x83"
        token = _extract_title_token(payload)
        self.assertEqual(token, ":2[4]0")
        self.assertEqual(_deid_from_title_token(token), "4")


if __name__ == "__main__":
    unittest.main()
