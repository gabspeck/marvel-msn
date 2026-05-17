"""Unit tests for the BBDESIGN `.ttl` loader.

Coverage:
- `tests/assets/captions_test.ttl` — single-page title with 24 Captions
  exercising distinct combinations of font face / size / weight /
  italic / underline / strikeout / alignment / back_color /
  frame_color / transparent / word_wrap. Layout matches
  `tests/assets/captions_test_reference.png`.
- `tests/assets/story_test.ttl` — Story + Shortcut single-page,
  CK-deflated CStyleSheet with 7 font slots + 54 styles; Story content
  body is TextRuns at 8/7 ("This is an example of content...").
- `tests/assets/all_controls.ttl` — single-page "All Controls
  Showcase" with 9 controls covering every BBCTL.OCX site class
  (Story / Outline / Caption / Picture / Shortcut / DynamicStory /
  Audio / CaptionButton / PictureButton).
- `tests/assets/multi_page_title.ttl` — two-page title, one Caption
  per page; verifies the CSection-tree DFS walk.
"""

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
    build_all_bm_baggage,
    build_bm0_baggage,
    load_title,
    lower_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TITLE_4 = _REPO_ROOT / "tests" / "assets" / "captions_test.ttl"
_TITLE_MSN_TODAY = _REPO_ROOT / "tests" / "assets" / "story_test.ttl"
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
        t = load_title(_TITLE_4)
        self.assertEqual(
            t.font_table,
            (
                FaceEntry(slot=2, face_name="Courier New"),
                FaceEntry(slot=1, face_name="Arial"),
                FaceEntry(slot=0, face_name="Times New Roman"),
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
        # Seqs 1/2/3 are "Plain caption"/"Right aligned"/"Center aligned"
        # — same font, different rect positions. Alignment property is
        # not yet split out from the post-strCaption block on this
        # fixture; the visual difference comes from rect positioning
        # in the reference PNG.
        t = load_title(_TITLE_4)
        controls = {c.seq: c for c in t.pages[0].controls}
        self.assertEqual(controls[1].text, "Plain caption")
        self.assertEqual(controls[2].text, "Right aligned")
        self.assertEqual(controls[3].text, "Center aligned")
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
        self.assertEqual(controls[0].xy_twips, (3810, 0))
        self.assertIsInstance(controls[1], ShortcutControl)
        self.assertEqual(controls[1].name, "Shortcut1=R")
        self.assertEqual(controls[1].seq, 2)
        self.assertEqual(controls[1].xy_twips, (211, 1481))

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

    def test_compound_xy_twips(self):
        controls = {c.name: c for c in self.title.pages[0].controls}
        self.assertEqual(controls["Story1R"].xy_twips, (1058, 2540))
        self.assertEqual(controls["Outline1"].xy_twips, (6773, 2540))
        self.assertEqual(controls["Audio1R"].xy_twips, (1905, 635))
        self.assertEqual(controls["Shortcut1-V"].xy_twips, (1270, 9736))
        self.assertEqual(controls["CaptionButton1"].xy_twips, (6773, 423))

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
        sec0_off = 2                         # leading u16 length prefix
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
    reference in its raw_block → CProxyTable@7/0 → TextRuns CContent
    at 8/7 ("This is an example of content..."). The leading 'S' before
    the prose body is unexplained empirical noise (PR2 BBCTL.OCX RE will
    pin it); the chase still succeeds and exposes content_proxy_ref."""

    def setUp(self):
        self.title = load_title(_TITLE_MSN_TODAY)
        self.assertIsNotNone(self.title)
        self.story = self.title.pages[0].controls[0]
        self.assertIsInstance(self.story, StoryControl)

    def test_content_proxy_ref_is_textruns_key(self):
        # CProxyTable@7/0 maps proxy_key 0x00001500 → CContent at 8/7
        # (TextRuns) and 0x00001400 → 8/6 (TextTree); the chase picks
        # the TextRuns target.
        self.assertEqual(self.story.content_proxy_ref, 0x00001500)

    def test_content_text_starts_with_authored_body(self):
        self.assertIsNotNone(self.story.content)
        self.assertIn("This is an example of content", self.story.content.text)

    def test_textruns_header_pinned(self):
        # 8/7 first two bytes are `02 00`; the rest is the prose run.
        self.assertEqual(self.story.content.header_version, 0x02)
        self.assertEqual(self.story.content.header_byte_1, 0x00)


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
            _SEC06_FLAG_INNER_RECT_ABSOLUTE,
            _SEC06_RECORD_SIZE,
            _build_sec06_record,
        )
        t = load_title(_TITLE_4)
        records = [_build_sec06_record(p, t) for p in t.pages]
        self.assertEqual(len(records), 1)
        # Single Page (scrollbar_flags=3 → both): absolute inner rect.
        self.assertEqual(records[0][0x48], _SEC06_FLAG_INNER_RECT_ABSOLUTE)
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
        # Resolved TextRuns body's prose substring lands inside the
        # kind=8 metafile's TextOut payload.
        self.assertIn(b"This is an example of content", bags["bm0"])

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
