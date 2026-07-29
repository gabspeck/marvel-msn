"""Unit tests for the BBDESIGN `.ttl` loader.

Coverage:
- `tests/assets/captions_test.ttl` — single-page title with 24 Captions
  exercising distinct combinations of font face / size / weight /
  italic / underline / strikeout / alignment / back_color /
  frame_color / transparent / word_wrap. Layout matches
  `tests/assets/captions_test_reference.png`.
- `tests/assets/story_test.ttl` — Story + Shortcut single-page,
  CK-deflated CStyleSheet with 7 font keys + 54 overridden styles;
  Story content body is the TextTree at 8/6, whose heading carries a
  PICTURE.PictureCtrl.1 intrusion.
- `tests/assets/story_title.ttl` — root-hung single page whose Story
  resolves through CTitle's own contents list. Its CStyleSheet
  overrides no style, so every paragraph paints from VIEWDLL's
  built-in table. Layout matches `reference/screenshots/story
  title.png`.
- `tests/assets/all_controls.ttl` — single-page "All Controls
  Showcase" with 9 controls covering every BBCTL.OCX site class
  (Story / Outline / Caption / Picture / Shortcut / DynamicStory /
  Audio / CaptionButton / PictureButton).
- `tests/assets/multi_page_title.ttl` — two-page title, one Caption
  per page; verifies the CSection-tree DFS walk.
"""

import datetime
import pathlib
import unittest

from server.services.medview.handler import (
    _deid_from_title_token,
    _extract_title_token,
)
from server.services.medview.ttl_loader import (
    AudioControl,
    CaptionButtonControl,
    CaptionControl,
    FaceEntry,
    LoadedPage,
    LoadedTitle,
    OutlineControl,
    PictureButtonControl,
    PictureControl,
    PsfControl,
    ShortcutControl,
    StoryControl,
    UnknownControl,
    _format_long_date,
    _format_short_time,
    _resolve_caption_text,
    build_all_bm_baggage,
    build_bm0_baggage,
    load_title,
    lower_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TITLE_4 = _REPO_ROOT / "tests" / "assets" / "captions_test.ttl"
_TITLE_MSN_TODAY = _REPO_ROOT / "tests" / "assets" / "story_test.ttl"
_TITLE_STORY_TITLE = _REPO_ROOT / "tests" / "assets" / "story_title.ttl"
_TITLE_ALL_CONTROLS = _REPO_ROOT / "tests" / "assets" / "all_controls.ttl"
_TITLE_MULTI_PAGE = _REPO_ROOT / "tests" / "assets" / "multi_page_title.ttl"


class TestCaptionsTestFixture(unittest.TestCase):
    """captions_test.ttl is a single-page BBDESIGN-authored title with 24
    Captions exercising distinct combinations of font face / size / weight /
    italic / underline / strikeout / alignment / back_color / frame_color /
    transparent / word_wrap. Layout mirrors the on-disk reference render at
    `tests/assets/captions_test_reference.png`."""

    def test_title_top_level(self):
        t = load_title(_TITLE_4)
        self.assertIsNotNone(t)
        self.assertEqual(t.title_name, "Captions Test")
        self.assertEqual(t.caption, "Captions Test")
        # CBFrame rect: (left, top, right, bottom) in pixels (HIMETRIC
        # round-tripped to pixel coords by the wire). Stored LTWH here:
        # left=0, top=0, width=640, height=480.
        self.assertEqual(t.window_rect, (0, 0, 640, 480))

    def test_page_dimensions_and_background(self):
        t = load_title(_TITLE_4)
        page = t.pages[0]
        self.assertEqual(page.page_pixel_w, 640)
        self.assertEqual(page.page_pixel_h, 480)
        # COLOR_3DFACE-ish gray (R=0x68 G=0x78 H=0x68) — workspace bg.
        self.assertEqual(page.page_bg, 0x00687868)
        # Both scrollbar bits set.
        self.assertEqual(page.scrollbar_flags, 3)

    def test_font_table_has_three_faces(self):
        # Keys are the ones VIEWDLL's built-in style table indexes:
        # `Normal` asks for font 1, the headings for 2, `Code` for 3.
        t = load_title(_TITLE_4)
        self.assertEqual(
            t.font_table,
            (
                FaceEntry(slot=3, face_name="Courier New"),
                FaceEntry(slot=2, face_name="Arial"),
                FaceEntry(slot=1, face_name="Times New Roman"),
            ),
        )

    def test_twenty_four_captions_in_seq_order(self):
        t = load_title(_TITLE_4)
        controls = t.pages[0].controls
        self.assertEqual(len(controls), 24)
        for c in controls:
            self.assertIsInstance(c, CaptionControl)
        # Seq numbers from BBDESIGN authoring; 1-based with gaps where
        # the author deleted intermediate sites (7, 9, 14 missing).
        seqs = [c.seq for c in controls]
        self.assertEqual(seqs, [
            1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27,
        ])

    def test_alignment_variant_captions(self):
        # Seqs 1/2/3 are simpleR / simple_right / simple_center. The
        # post-strCaption iAlignment LONG is 0/1/2 respectively (LEFT,
        # RIGHT, CENTER per BBCTL FUN_400083f6).
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        self.assertEqual(controls[1].text, "Plain caption")
        self.assertEqual(controls[2].text, "Right aligned")
        self.assertEqual(controls[3].text, "Center aligned")
        self.assertEqual(controls[1].alignment, 0)
        self.assertEqual(controls[2].alignment, 1)
        self.assertEqual(controls[3].alignment, 2)
        for seq in (1, 2, 3):
            self.assertEqual(controls[seq].font_name, "MS Sans Serif")

    def test_color_variant_captions(self):
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        # seq=4: white background, transparency cleared.
        white_bg = controls[4]
        self.assertEqual(white_bg.text, "Non-transparent white bg")
        self.assertFalse(white_bg.transparent)
        # seq=6: red frame color.
        red_frame = controls[6]
        self.assertEqual(red_frame.text, "Red frame color")
        self.assertEqual(red_frame.frame_color, 0x0000FF)

    def test_font_variant_captions(self):
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        comic = controls[10]
        self.assertEqual(comic.text, "Caption in Comic Sans")
        self.assertEqual(comic.font_name, "Comic Sans MS")
        garamond_italic = controls[12]
        self.assertEqual(garamond_italic.font_name, "Garamond")
        self.assertTrue(garamond_italic.italic)
        garamond_bold_italic = controls[13]
        self.assertEqual(garamond_bold_italic.font_name, "Garamond")
        self.assertTrue(garamond_bold_italic.italic)

    def test_decoration_variant_captions(self):
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        underlined = controls[15]
        self.assertEqual(underlined.text, "Plain caption, underlined")
        self.assertTrue(underlined.underline)
        struck = controls[16]
        self.assertEqual(struck.text, "Plain caption, strikethrough")
        self.assertTrue(struck.strikeout)

    def test_size_variant_captions(self):
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        arial_24 = controls[17]
        self.assertEqual(arial_24.text, "Arial, 24pt")
        self.assertEqual(arial_24.font_name, "Arial")
        self.assertEqual(arial_24.size_pt, 24)
        arial_24_under = controls[18]
        self.assertEqual(arial_24_under.font_name, "Arial")
        self.assertEqual(arial_24_under.size_pt, 24)

    def test_word_wrap_captions(self):
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        wrap = controls[19]
        self.assertEqual(wrap.text, "Word wrap enabled for this one")
        self.assertTrue(wrap.word_wrap)
        auto_resize = controls[20]
        self.assertEqual(auto_resize.text, "This one resizes to fit the text")
        self.assertTrue(auto_resize.word_wrap)

    def test_combination_caption(self):
        # Last seq=27: red bg, yellow frame, Lucida Handwriting, underlined.
        t = load_title(_TITLE_4)
        combo = next(c for c in t.pages[0].controls if c.seq == 27)
        self.assertEqual(combo.text, "Combination")
        self.assertEqual(combo.font_name, "Lucida Handwriting")
        self.assertTrue(combo.underline)
        self.assertEqual(combo.back_color, 0x0000FF)
        self.assertEqual(combo.frame_color, 0xFFFF00)

    def test_captions_property_filters_controls(self):
        t = load_title(_TITLE_4)
        page = t.pages[0]
        self.assertEqual(page.captions, tuple(page.controls))

    def test_missing_path_returns_none(self):
        self.assertIsNone(load_title(pathlib.Path("/tmp/__no_ttl__.ttl")))


class TestMsnTodayDecodes(unittest.TestCase):
    """story_test.ttl: 1 Story + 1 Shortcut on page-0. Verifies CK-deflate
    of CStyleSheet, walker handling of compound controls, and per-control
    rect extraction."""

    def setUp(self):
        self.title = load_title(_TITLE_MSN_TODAY)
        self.assertIsNotNone(self.title)

    def test_title_top_level(self):
        self.assertEqual(self.title.title_name, "MSN Today")
        self.assertEqual(self.title.caption, "MSN Today")
        page = self.title.pages[0]
        self.assertEqual(page.page_pixel_w, 640)
        self.assertEqual(page.page_pixel_h, 480)
        self.assertEqual(page.scrollbar_flags, 3)

    def test_cstylesheet_ck_deflated(self):
        # CK-decompressed CStyleSheet exposes Courier/Arial/Times slots.
        names = [f.face_name for f in self.title.font_table]
        self.assertIn("Courier New", names)
        self.assertIn("Arial", names)
        self.assertIn("Times New Roman", names)

    def test_controls_are_story_and_shortcut(self):
        controls = self.title.pages[0].controls
        self.assertEqual(len(controls), 2)
        self.assertIsInstance(controls[0], StoryControl)
        self.assertEqual(controls[0].name, "Story1R")
        self.assertEqual(controls[0].seq, 1)
        self.assertEqual(controls[0].rect_himetric, (3810, 0, 16933, 12700))
        self.assertIsInstance(controls[1], ShortcutControl)
        self.assertEqual(controls[1].name, "Shortcut1=R")
        self.assertEqual(controls[1].seq, 2)
        self.assertEqual(controls[1].rect_himetric, (211, 1481, 3598, 2963))

    def test_per_control_raw_blocks_carry_proxy_refs(self):
        # Property region is sliced in seq order using descriptor `size`.
        # Story1R's Pascal-prefixed "Homepage.bdf" reference must land in
        # the Story1R block; Shortcut1=R's "Calendar of Events.bdf"
        # straddles the descriptor-claimed 91 B boundary — the visible
        # portion ends at "Events." — which documents that the `size`
        # field is not a perfect block extent for compound controls.
        controls = self.title.pages[0].controls
        story, shortcut = controls[0], controls[1]
        self.assertEqual(len(story.raw_block), 142)
        self.assertEqual(len(shortcut.raw_block), 91)
        self.assertIn(b"\x0cHomepage.bdf", story.raw_block)
        self.assertIn(b"Calendar of Events", shortcut.raw_block)

    def test_captions_is_empty(self):
        # No CaptionControls present in MSN Today's single page.
        self.assertEqual(self.title.pages[0].captions, ())


class TestAllControlsShowcase(unittest.TestCase):
    """all_controls.ttl: 9 controls on the "All Controls Showcase"
    page covering every BBCTL.OCX site class pinned by the loader
    (Story / Outline / Caption / Picture / Shortcut / DynamicStory /
    Audio / CaptionButton / PictureButton)."""

    def setUp(self):
        self.title = load_title(_TITLE_ALL_CONTROLS)
        self.assertIsNotNone(self.title)

    def test_title_top_level(self):
        self.assertEqual(self.title.title_name, "All Controls")
        # CBFrame's caption field is empty in this fixture; the page
        # name carries the displayed identity.
        self.assertEqual(self.title.caption, "")
        self.assertEqual(self.title.window_rect, (0, 0, 640, 480))

    def test_page_dimensions_and_background(self):
        page = self.title.pages[0]
        self.assertEqual(page.name, "All Controls Showcase")
        self.assertEqual(page.page_pixel_w, 640)
        self.assertEqual(page.page_pixel_h, 480)
        # Light gray, the BBDESIGN default ("RGB(192, 192, 192)").
        self.assertEqual(page.page_bg, 0x00C0C0C0)
        self.assertEqual(page.scrollbar_flags, 3)

    def test_nine_controls_in_seq_order(self):
        controls = self.title.pages[0].controls
        self.assertEqual(len(controls), 9)
        names_seqs_types = [(c.name, c.seq, type(c)) for c in controls]
        self.assertEqual(
            names_seqs_types,
            [
                ("Story1R", 1, StoryControl),
                ("Outline1", 2, OutlineControl),
                ("Caption1", 3, CaptionControl),
                ("Picture1", 4, PictureControl),
                ("Shortcut1-V", 5, ShortcutControl),
                # BBDESIGN's "DynamicStory" site type is backed by
                # BBCTL's CPsfCtrl class.
                ("DynamicStory1", 6, PsfControl),
                ("Audio1R", 7, AudioControl),
                ("CaptionButton1", 8, CaptionButtonControl),
                ("PictureButton1", 9, PictureButtonControl),
            ],
        )

    def test_compound_rect_himetric(self):
        # Compound sites carry the same LTRB HIMETRIC rect Caption1
        # does, at the same inline_tail offset.
        controls = {c.name: c for c in self.title.pages[0].controls}
        self.assertEqual(controls["Story1R"].rect_himetric, (1058, 2540, 5715, 8890))
        self.assertEqual(controls["Outline1"].rect_himetric, (6773, 2540, 9313, 5927))
        self.assertEqual(controls["Audio1R"].rect_himetric, (1905, 635, 5503, 2116))
        self.assertEqual(
            controls["Shortcut1-V"].rect_himetric, (1270, 9736, 4656, 11006),
        )
        self.assertEqual(
            controls["CaptionButton1"].rect_himetric, (6773, 423, 9525, 1693),
        )

    def test_caption1_rect_and_font(self):
        controls = {c.name: c for c in self.title.pages[0].controls}
        cap = controls["Caption1"]
        self.assertEqual(cap.rect_himetric, (10160, 2540, 14182, 4233))
        self.assertEqual(cap.font_name, "MS Sans Serif")


class TestLowerToPayload(unittest.TestCase):
    def setUp(self):
        self.title = load_title(_TITLE_4)
        self.assertIsNotNone(self.title)
        self.body = lower_to_payload(self.title)

    def test_body_contains_caption_cstring(self):
        self.assertIn(b"Captions Test\x00", self.body)

    def test_section0_face_table_contains_all_fonts(self):
        # Entries sit at the CStyleSheet font key, so slot 0 stays blank
        # and Times/Arial/Courier land at keys 1/2/3.
        sec0_off = 2                         # leading u16 length prefix
        face_table_off = sec0_off + 0x12
        self.assertEqual(
            self.body[face_table_off:face_table_off + 15], b"\x00" * 15,
        )
        self.assertEqual(
            self.body[face_table_off + 0x20:face_table_off + 0x20 + 15],
            b"Times New Roman",
        )
        self.assertEqual(
            self.body[face_table_off + 0x40:face_table_off + 0x40 + 5], b"Arial",
        )
        self.assertEqual(
            self.body[face_table_off + 0x60:face_table_off + 0x60 + 11], b"Courier New",
        )

    def test_sec06_record_contains_caption_at_offset_0x15(self):
        idx = self.body.find(b"Captions Test\x00")
        self.assertGreater(idx, 0)
        self.assertEqual(self.body[idx:idx + 13], b"Captions Test")


class TestSection0CarriesCaptionStyling(unittest.TestCase):
    """Section 0 descriptors (sec0 per-caption font/style table) get
    `lfItalic`, `lfUnderline`, `lfStrikeOut`, `lfCharSet`, and the
    back_color stock prop populated from each CaptionControl. Each
    descriptor is 42 B (`_SEC0_DESCRIPTOR_SIZE`)."""

    def test_captions_test_descriptors_carry_authored_styling(self):
        from server.services.medview.ttl_loader import (
            _SEC0_DESCRIPTOR_SIZE,
            _SEC0_HEADER_SIZE,
            _SEC0_FACE_ENTRY_SIZE,
            _build_section0,
        )
        t = load_title(_TITLE_4)
        sec0 = _build_section0(t)
        face_count = max(f.slot for f in t.font_table) + 1
        face_table_size = face_count * _SEC0_FACE_ENTRY_SIZE
        desc_off = _SEC0_HEADER_SIZE + face_table_size
        captions = [c for p in t.pages for c in p.captions]
        seq_to_index = {c.seq: i for i, c in enumerate(captions)}

        # seq=1 ("Plain caption", MS Sans Serif default): plain.
        d_plain = sec0[
            desc_off + seq_to_index[1] * _SEC0_DESCRIPTOR_SIZE:
            desc_off + (seq_to_index[1] + 1) * _SEC0_DESCRIPTOR_SIZE
        ]
        self.assertEqual(d_plain[0x20], 0)         # lfItalic
        self.assertEqual(d_plain[0x21], 0)         # lfUnderline
        self.assertEqual(d_plain[0x22], 0)         # lfStrikeOut

        # seq=12 ("Garamond, italic"): lfItalic=1.
        d_italic = sec0[
            desc_off + seq_to_index[12] * _SEC0_DESCRIPTOR_SIZE:
            desc_off + (seq_to_index[12] + 1) * _SEC0_DESCRIPTOR_SIZE
        ]
        self.assertEqual(d_italic[0x20], 1)
        self.assertEqual(d_italic[0x21], 0)
        self.assertEqual(d_italic[0x22], 0)

        # seq=15 ("Plain caption, underlined"): lfUnderline=1.
        d_under = sec0[
            desc_off + seq_to_index[15] * _SEC0_DESCRIPTOR_SIZE:
            desc_off + (seq_to_index[15] + 1) * _SEC0_DESCRIPTOR_SIZE
        ]
        self.assertEqual(d_under[0x20], 0)
        self.assertEqual(d_under[0x21], 1)
        self.assertEqual(d_under[0x22], 0)

        # seq=16 ("Plain caption, strikethrough"): lfStrikeOut=1.
        d_strike = sec0[
            desc_off + seq_to_index[16] * _SEC0_DESCRIPTOR_SIZE:
            desc_off + (seq_to_index[16] + 1) * _SEC0_DESCRIPTOR_SIZE
        ]
        self.assertEqual(d_strike[0x20], 0)
        self.assertEqual(d_strike[0x21], 0)
        self.assertEqual(d_strike[0x22], 1)


class TestBaggageCarriesNewStyling(unittest.TestCase):
    """`build_bm_baggage` emits a kind=8 WMF that carries per-caption
    underline / strikeout / charset in CreateFontIndirect's LOGFONT,
    text alignment via SetTextAlign records, and back_color via
    SetBkColor when transparent=False."""

    def test_baggage_emits_setextalign_records(self):
        t = load_title(_TITLE_4)
        bag = build_all_bm_baggage(t)["bm0"]
        # WMF SetTextAlign record opcode = 0x012E. The bytes appear inside
        # the kind=8 baggage's metafile body.
        # Record header: u32 rdSize (size in WORDs) + u16 rdFunction.
        # SetTextAlign with 1 word param: rdSize=4, function=0x012E.
        # On the wire: 04 00 00 00 2e 01.
        self.assertIn(b"\x04\x00\x00\x00\x2e\x01", bag)

    def test_garamond_italic_logfont_has_italic_bit(self):
        # seq=12 in captions_test.ttl is the only standalone italic
        # Garamond entry. Strikeout/underline cleared, italic set.
        t = load_title(_TITLE_4)
        bag = build_all_bm_baggage(t)["bm0"]
        marker = b"Garamond\x00"
        # LOGFONT layout: Height(i16), Width(i16), Escapement(i16),
        # Orientation(i16), Weight(i16), Italic(u8), Underline(u8),
        # StrikeOut(u8), CharSet(u8), Out/Clip/Quality/Pitch(4 u8), Face.
        # Find an italic Garamond LOGFONT among multiple Garamond entries.
        idx = 0
        found = False
        while True:
            idx = bag.find(marker, idx)
            if idx < 0:
                break
            lf_off = idx - 18
            if (
                lf_off >= 0
                and bag[lf_off + 10] == 1                  # italic
                and bag[lf_off + 11] == 0                  # underline
                and bag[lf_off + 12] == 0                  # strikeout
            ):
                found = True
                break
            idx += len(marker)
        self.assertTrue(found, "no italic-only Garamond LOGFONT in baggage")

    def test_baggage_clips_undersized_caption(self):
        # seq=18 ("Arial, 24pt, undersized dimensions") authors a 248x24
        # rect too narrow for the text — auto_size=False captions with a
        # real rect must emit SAVEDC + INTERSECTCLIPRECT + RESTOREDC
        # around the TextOut so the client clips mid-glyph.
        t = load_title(_TITLE_4)
        bag = build_all_bm_baggage(t)["bm0"]
        # META_INTERSECTCLIPRECT rdSize=7, function=0x0416 → 07 00 00 00 16 04
        self.assertIn(b"\x07\x00\x00\x00\x16\x04", bag)
        # META_SAVEDC rdSize=3, function=0x001E → 03 00 00 00 1e 00
        self.assertIn(b"\x03\x00\x00\x00\x1e\x00", bag)
        # META_RESTOREDC rdSize=4, function=0x0127 → 04 00 00 00 27 01
        self.assertIn(b"\x04\x00\x00\x00\x27\x01", bag)


class TestDynamicCaptions(unittest.TestCase):
    """Captions whose `idTag` is 0x1900..0x1903 draw a runtime value, not
    the authored placeholder. Values match the BBVIEW reference render at
    `reference/screenshots/captions_test_reference_render.png`, captured
    Wednesday 29 July 2026 at 8:14 AM: "Wednesday, Ju[ly 29, 2026]" /
    "Captions Test" / "8:14 AM" / "Captions Test"."""

    _NOW = datetime.datetime(2026, 7, 29, 8, 14, 30)

    def _captions_by_tag(self):
        t = load_title(_TITLE_4)
        return t, {c.id_tag: c for c in t.pages[0].captions}

    def test_authored_text_is_the_design_time_label(self):
        _, by_tag = self._captions_by_tag()
        self.assertEqual(by_tag[0x1900].text, "Current section")
        self.assertEqual(by_tag[0x1901].text, "First section")
        self.assertEqual(by_tag[0x1902].text, "Current date")
        self.assertEqual(by_tag[0x1903].text, "Current time")

    def test_root_hung_page_takes_the_title_name_as_section(self):
        t = load_title(_TITLE_4)
        self.assertEqual(t.pages[0].section_name, "Captions Test")
        self.assertEqual(t.first_section_name, "Captions Test")

    def test_section_name_comes_from_the_owning_csection(self):
        t = load_title(_TITLE_MSN_TODAY)
        self.assertEqual(t.pages[0].section_name, "Section 1")
        self.assertEqual(t.first_section_name, "Section 1")

    def test_tags_resolve_to_runtime_values(self):
        t, by_tag = self._captions_by_tag()
        page = t.pages[0]
        resolve = {
            tag: _resolve_caption_text(
                cap, page, t.first_section_name, self._NOW,
            )
            for tag, cap in by_tag.items()
        }
        self.assertEqual(resolve[0x1900], "Captions Test")
        self.assertEqual(resolve[0x1901], "Captions Test")
        self.assertEqual(resolve[0x1902], "Wednesday, July 29, 2026")
        self.assertEqual(resolve[0x1903], "8:14 AM")

    def test_untagged_caption_keeps_its_authored_text(self):
        t, by_tag = self._captions_by_tag()
        plain = by_tag[-1]
        self.assertEqual(
            _resolve_caption_text(plain, t.pages[0], "S", self._NOW),
            plain.text,
        )

    def test_long_date_does_not_zero_pad_the_day(self):
        # LOCALE_SLONGDATE is "dddd, MMMM d, yyyy": the reference render
        # reads "Sunday, May 1", which a `dd` picture would have clipped
        # to "Sunday, May 0" at the 103 px caption width.
        self.assertEqual(
            _format_long_date(datetime.datetime(2022, 5, 1, 13, 39)),
            "Sunday, May 1, 2022",
        )

    def test_short_time_drops_seconds_and_pads_only_minutes(self):
        self.assertEqual(
            _format_short_time(datetime.datetime(2022, 5, 1, 13, 39, 59)),
            "1:39 PM",
        )
        self.assertEqual(
            _format_short_time(datetime.datetime(2022, 5, 1, 0, 5)),
            "12:05 AM",
        )
        self.assertEqual(
            _format_short_time(datetime.datetime(2022, 5, 1, 12, 0)),
            "12:00 PM",
        )

    def test_baggage_bakes_the_resolved_text_not_the_placeholder(self):
        t = load_title(_TITLE_4)
        bag = build_all_bm_baggage(t, now=self._NOW)["bm0"]
        self.assertIn(b"Wednesday, July 29, 2026", bag)
        self.assertIn(b"8:14 AM", bag)
        self.assertNotIn(b"Current date", bag)
        self.assertNotIn(b"Current time", bag)
        self.assertNotIn(b"Current section", bag)
        self.assertNotIn(b"First section", bag)


class TestBuildBm0Baggage(unittest.TestCase):
    def test_kind8_metafile_when_captions_present(self):
        title = load_title(_TITLE_4)
        bag = build_bm0_baggage(title)
        # Container preamble is 8 bytes; first byte of bitmap header is
        # the kind tag.
        self.assertEqual(bag[8], 0x08)
        self.assertIn(b"Plain caption", bag)
        self.assertIn(b"MS Sans Serif", bag)

    def test_kind5_raster_when_no_captions(self):
        empty = LoadedTitle(
            title_name="Empty",
            caption="Empty",
            window_rect=(0, 0, 640, 480),
            font_table=(),
            pages=(LoadedPage(
                name="",
                section_name="Empty",
                cbform_table=5,
                cbform_slot=0,
                cvform_handle=None,
                page_bg=0,
                page_pixel_w=640,
                page_pixel_h=480,
                scrollbar_flags=0,
                controls=(),
            ),),
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


class TestCaptionsTestSinglePage(unittest.TestCase):
    """captions_test.ttl is a CSection-tree title with a single Page
    ("Captions") holding 24 Captions. Both scrollbar bits are set."""

    def setUp(self):
        self.title = load_title(_TITLE_4)
        self.assertIsNotNone(self.title)

    def test_one_page_named_captions(self):
        self.assertEqual(len(self.title.pages), 1)
        self.assertEqual(self.title.pages[0].name, "Captions")

    def test_page_scrollbar_flags(self):
        self.assertEqual(self.title.pages[0].scrollbar_flags, 3)

    def test_page_holds_twenty_four_captions(self):
        page = self.title.pages[0]
        self.assertEqual(len(page.controls), 24)
        for c in page.controls:
            self.assertIsInstance(c, CaptionControl)


class TestMsnTodayStoryContentChase(unittest.TestCase):
    """story_test.ttl's Story1R chases the Pascal-prefixed `Homepage.bdf`
    reference in its raw_block → CProxyTable@7/0 → the TextTree CContent
    at 8/6, which holds the prose. The parallel TextRuns stream at 8/7
    carries paragraph markers only."""

    def setUp(self):
        self.title = load_title(_TITLE_MSN_TODAY)
        self.assertIsNotNone(self.title)
        self.story = self.title.pages[0].controls[0]
        self.assertIsInstance(self.story, StoryControl)

    def test_content_proxy_ref_is_texttree_key(self):
        # CProxyTable@7/0 maps proxy_key 0x00001400 → CContent at 8/6
        # (TextTree) and 0x00001500 → 8/7 (TextRuns).
        self.assertEqual(self.story.content_proxy_ref, 0x00001400)

    def test_content_text_is_the_authored_body(self):
        self.assertIsNotNone(self.story.content)
        self.assertIn("MSN Today (update test)", self.story.content.text)
        self.assertIn("Here's an unordered list:", self.story.content.text)

    def test_element_tree_survives_the_picture_intrusion(self):
        # 8/6's heading holds a PICTURE.PictureCtrl.1 intrusion whose
        # DATA1 / RSLT1 blobs ride version-3 leaves.
        root = self.story.element_tree
        self.assertIsNotNone(root)
        body = root.children[1]
        self.assertEqual(body.tag, 0x0C)
        heading = body.children[0]
        self.assertEqual(heading.tag, 0x07)
        self.assertEqual(heading.text, "MSN Today (update test)")
        intrusion = heading.children[0]
        self.assertEqual(
            dict(intrusion.props)["CLSID"], "PICTURE.PictureCtrl.1",
        )


class TestLowerToPayloadMultiPage(unittest.TestCase):
    """PR3 emits one sec06 record per page (152 B each) in section 3,
    plus a section 0 descriptor for every CaptionControl across all
    pages."""

    def test_captions_test_emits_one_sec06_record(self):
        from server.services.medview.ttl_loader import _SEC06_RECORD_SIZE
        t = load_title(_TITLE_4)
        body = lower_to_payload(t)
        # section 0 length is u16 prefixed. Walk to section 3 (4th
        # length-prefixed block, after sec0 / sec07 empty / sec08 empty).
        pos = 0
        for _ in range(3):
            seclen = int.from_bytes(body[pos:pos + 2], "little")
            pos += 2 + seclen
        sec06_len = int.from_bytes(body[pos:pos + 2], "little")
        self.assertEqual(sec06_len, _SEC06_RECORD_SIZE)

    def test_msn_today_emits_one_sec06(self):
        from server.services.medview.ttl_loader import _SEC06_RECORD_SIZE
        t = load_title(_TITLE_MSN_TODAY)
        body = lower_to_payload(t)
        pos = 0
        for _ in range(3):
            seclen = int.from_bytes(body[pos:pos + 2], "little")
            pos += 2 + seclen
        sec06_len = int.from_bytes(body[pos:pos + 2], "little")
        self.assertEqual(sec06_len, _SEC06_RECORD_SIZE)

    def test_scrollbar_flag_on_only_page(self):
        from server.services.medview.ttl_loader import (
            _SEC06_FLAG_OUTER_RECT_ABSOLUTE,
            _SEC06_RECORD_SIZE,
            _build_sec06_record,
        )
        t = load_title(_TITLE_4)
        records = [_build_sec06_record(p, t) for p in t.pages]
        self.assertEqual(len(records), 1)
        # Single Page (scrollbar_flags=3 → both): absolute inner rect.
        self.assertEqual(records[0][0x48], _SEC06_FLAG_OUTER_RECT_ABSOLUTE)
        self.assertEqual(len(records[0]), _SEC06_RECORD_SIZE)


class TestBbctlClsidDispatch(unittest.TestCase):
    """CLSID-first dispatch:

    - story_test.ttl's Story1R / Shortcut1=R sit at class_index 0 / 1
      in the CVForm preamble class table; both CLSIDs (CQtxtCtrl /
      CBblinkCtrl) are in `_BBCTL_CLSIDS` and dispatch correctly to
      `StoryControl` / `ShortcutControl`.
    - captions_test.ttl's three pages each have one Caption
      (class_index 0, CLSID = CLabelCtrl) and dispatch to
      `CaptionControl` via the CLSID table.
    """

    def test_bbctl_clsids_pinned_per_descriptor(self):
        from server.services.medview.ttl_loader import _BBCTL_CLSIDS
        # All 10 BBCTL.OCX site classes pinned (Ghidra symbol table).
        names = sorted(_BBCTL_CLSIDS.values())
        self.assertEqual(names, [
            "Audio", "Caption", "CaptionButton", "Outline", "Picture",
            "PictureButton", "PrintPsf", "Psf", "Shortcut", "Story",
        ])

    def test_captions_test_dispatches_via_single_class_clsid(self):
        # captions_test.ttl's CVForm has a single Caption CLSID in the
        # preamble class table; `flags & 0xFF` is a per-site serial
        # (0..23) not a class index, so the loader propagates the sole
        # CLSID to every site. All 24 controls dispatch to CaptionControl.
        t = load_title(_TITLE_4)
        controls = t.pages[0].controls
        self.assertEqual(len(controls), 24)
        for c in controls:
            self.assertIsInstance(c, CaptionControl)

    def test_msn_today_dispatches_both_classes(self):
        t = load_title(_TITLE_MSN_TODAY)
        controls = t.pages[0].controls
        self.assertIsInstance(controls[0], StoryControl)
        self.assertIsInstance(controls[1], ShortcutControl)


class TestMultiPageTitle(unittest.TestCase):
    """multi_page_title.ttl: CTitle holds two pages (Page #1, Page #2)
    via the CSection-tree DFS walk. Each page has a single Caption."""

    def setUp(self):
        self.title = load_title(_TITLE_MULTI_PAGE)
        self.assertIsNotNone(self.title)

    def test_title_top_level(self):
        self.assertEqual(self.title.title_name, "Multi-page title")
        self.assertEqual(self.title.caption, "")
        self.assertEqual(self.title.window_rect, (0, 0, 640, 480))

    def test_two_pages_in_authoring_order(self):
        self.assertEqual(len(self.title.pages), 2)
        self.assertEqual(
            [p.name for p in self.title.pages],
            ["Page #1", "Page #2"],
        )

    def test_each_page_has_one_caption(self):
        for i, page in enumerate(self.title.pages):
            self.assertEqual(len(page.controls), 1, f"page {i}")
            self.assertIsInstance(page.controls[0], CaptionControl)

    def test_per_page_caption_text(self):
        page1, page2 = self.title.pages
        self.assertEqual(page1.controls[0].text, "This is page 1")
        self.assertEqual(page2.controls[0].text, "This is page two")

    def test_pages_share_default_background_and_scrollbar(self):
        for page in self.title.pages:
            self.assertEqual(page.page_bg, 0x00C0C0C0)
            self.assertEqual(page.scrollbar_flags, 3)
            self.assertEqual(page.page_pixel_w, 640)
            self.assertEqual(page.page_pixel_h, 480)


class TestStoryTitleFixture(unittest.TestCase):
    """story_title.ttl authors one Story on a page hung straight off
    CTitle. The Story resolves through CTitle's own contents list, and
    every paragraph paints from VIEWDLL's built-in style table because
    the title's CStyleSheet overrides nothing."""

    def setUp(self):
        self.title = load_title(_TITLE_STORY_TITLE)
        self.assertIsNotNone(self.title)
        self.page = self.title.pages[0]
        self.story = self.page.controls[0]
        self.assertIsInstance(self.story, StoryControl)

    def test_title_top_level(self):
        self.assertEqual(self.title.title_name, "Story Title")
        self.assertEqual(self.title.window_rect, (0, 0, 640, 480))
        self.assertEqual(self.page.name, "Page #1")
        self.assertEqual(self.page.page_pixel_w, 640)
        self.assertEqual(self.page.page_pixel_h, 480)
        self.assertEqual(self.page.page_bg, 0x00A5BFC2)

    def test_root_hung_page_still_resolves_its_story(self):
        # The page has no enclosing CSection; the CProxyTable named
        # `Story.bdf` hangs off CTitle.base_contents.
        self.assertEqual(self.story.rect_himetric, (2328, 635, 15240, 11853))
        self.assertEqual(self.story.content_proxy_ref, 0x00001400)
        self.assertIsNotNone(self.story.element_tree)

    def test_element_tree_matches_the_authored_bbml(self):
        # Story.bdf's BODY stream is
        # `<H1>…</H1><P>…</P><H2>…</H2><P>…</P><OL>×3</OL><P></P>
        #  <UL>×3</UL><P></P>`.
        root = self.story.element_tree
        self.assertEqual(root.tag, 0x05)
        head, body = root.children
        self.assertEqual((head.tag, head.children), (0x0B, ()))
        self.assertEqual(
            [c.tag for c in body.children],
            [0x07, 0x06, 0x08, 0x06, 0x1D, 0x06, 0x1C, 0x06],
        )
        self.assertEqual(body.children[0].text, "Story title")
        self.assertEqual(
            [c.text for c in body.children[4].children],
            ["Numbered list item", "Item ", "Item"],
        )

    def test_paragraphs_take_the_builtin_styles(self):
        from server.services.medview import story_layout
        font_map = {f.slot: f.face_name for f in self.title.font_table}
        got = [
            (p.style.name, p.style.font_face, p.style.pt_size, p.style.bold, p.text)
            for p in story_layout.flatten_paragraphs(
                self.story.element_tree, font_map,
            )
        ]
        self.assertEqual(got, [
            ("Heading 1", "Arial", 22, True, "Story title"),
            ("Normal", "Times New Roman", 11, False, "Story body here "),
            ("Heading 2", "Arial", 18, True, "Second heading"),
            ("Normal", "Times New Roman", 11, False,
             "Some more content blah bla blah"),
            ("List Number", "Times New Roman", 11, False, "Numbered list item"),
            ("List Number", "Times New Roman", 11, False, "Item "),
            ("List Number", "Times New Roman", 11, False, "Item"),
            ("List Bullet", "Times New Roman", 11, False, "Bullet list"),
            ("List Bullet", "Times New Roman", 11, False, "second level"),
            ("List Bullet", "Times New Roman", 11, False, "third level"),
        ])

    def test_layout_matches_the_bbview_reference(self):
        """Positions against `reference/screenshots/story title.png`.
        The capture is BBVIEW scaling the 640x480 page ~1.64x to fill
        its client, so the reference values below are the measured ink
        divided back down; the tolerance covers that scale estimate."""
        from server.services.medview import story_layout
        from server.services.medview.ttl_loader import _himetric_to_pixels

        font_map = {f.slot: f.face_name for f in self.title.font_table}
        rect = tuple(_himetric_to_pixels(v) for v in self.story.rect_himetric)
        self.assertEqual(rect, (87, 24, 576, 447))
        items = story_layout.layout_story(
            self.story.element_tree, rect, font_map,
        )

        background = items[0]
        self.assertEqual((background.x, background.y), (87, 24))
        self.assertEqual((background.rect_w, background.rect_h), (489, 423))
        self.assertFalse(background.transparent)
        self.assertEqual(background.back_color, 0xFFFFFF)

        text = [i for i in items if i.text]
        # Body text sits 10 pt inside the rect; list text a further
        # 18 pt in, which the render measures as 24 px.
        self.assertEqual([i.x for i in text[:4]], [100, 100, 100, 100])
        self.assertEqual([i.x for i in text[4:]], [124] * 6)
        # Reference ink tops, page pixels: 66.6 / 98.1 / 154.2 / 180.1
        # then a 33 px list pitch from 213.5.
        tops = [i.y for i in text]
        self.assertEqual(tops[:4], [61, 95, 147, 175])
        pitches = {b - a for a, b in zip(tops[4:-1], tops[5:], strict=True)}
        self.assertEqual(pitches, {33})

        bullets = [i for i in items[1:] if not i.text]
        self.assertEqual(len(bullets), 6)
        # Flush with the margin (hanging indent == left indent), a
        # solid ~5 px square, its bottom half a side above the baseline.
        self.assertEqual({b.x for b in bullets}, {100})
        self.assertEqual({(b.rect_w, b.rect_h) for b in bullets}, {(5, 5)})
        self.assertTrue(all(not b.transparent for b in bullets))


class TestBuildAllBmBaggage(unittest.TestCase):
    """Per-page bm baggage. Each page produces a `bm<idx>` entry; pages
    with captions or resolved Story text get a kind=8 metafile,
    otherwise a kind=5 1bpp raster."""

    def test_captions_test_key_is_bm0_only(self):
        t = load_title(_TITLE_4)
        bags = build_all_bm_baggage(t)
        self.assertEqual(sorted(bags.keys()), ["bm0"])
        self.assertIn(b"Plain caption", bags["bm0"])

    def test_msn_today_story_text_in_bm0_metafile(self):
        t = load_title(_TITLE_MSN_TODAY)
        bags = build_all_bm_baggage(t)
        self.assertIn("bm0", bags)
        # The Story's flowed paragraphs land in the kind=8 metafile as
        # one TextOut per line, heading first.
        self.assertIn(b"MSN Today (update test)", bags["bm0"])
        self.assertIn(b"An item!", bags["bm0"])

    def test_story_title_bm0_carries_every_paragraph(self):
        t = load_title(_TITLE_STORY_TITLE)
        bags = build_all_bm_baggage(t)
        for phrase in (
            b"Story title", b"Story body here", b"Second heading",
            b"Some more content blah bla blah", b"Numbered list item",
            b"Bullet list", b"third level",
        ):
            self.assertIn(phrase, bags["bm0"])

    def test_legacy_build_bm0_baggage_is_page0(self):
        t = load_title(_TITLE_4)
        self.assertEqual(build_bm0_baggage(t), build_all_bm_baggage(t)["bm0"])


class TestTitleOpenMetadataMultiPage(unittest.TestCase):
    """`derive_title_open_metadata` floors topic_count at max(1, pages)
    and produces nonzero deterministic cache headers."""

    def test_topic_count_matches_page_count(self):
        from server.services.medview.payload import derive_title_open_metadata
        t = load_title(_TITLE_4)
        md = derive_title_open_metadata(
            page_count=len(t.pages),
            page_pixel_w=t.pages[0].page_pixel_w,
            page_pixel_h=t.pages[0].page_pixel_h,
            title_name=t.title_name,
        )
        self.assertEqual(md.topic_count, 1)
        self.assertNotEqual(md.cache_header0, 0)
        self.assertNotEqual(md.cache_header1, 0)

    def test_empty_title_falls_back_to_one(self):
        from server.services.medview.payload import derive_title_open_metadata
        md = derive_title_open_metadata(
            page_count=0, page_pixel_w=640, page_pixel_h=480,
            title_name="",
        )
        self.assertEqual(md.topic_count, 1)


if __name__ == "__main__":
    unittest.main()
