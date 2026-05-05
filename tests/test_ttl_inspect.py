"""Tests for the Blackbird .ttl inspector — focused on the CStyleSheet
style-record parse RE'd from VIEWDLL.DLL `?Serialize@CStyle@@…` and
peers (`docs/blackbird-title-format.md` §"CStyle/CParaProps/CCharProps"
+ `docs/mosview-authored-text-and-font-re.md` §"Section-0 Header
Schema").
"""

from __future__ import annotations

import unittest
from pathlib import Path

from server.blackbird.ttl_inspect import (
    CSTYLE_DEFAULT_PROPS,
    CSTYLE_NAME_DICTIONARY,
    INTRUSION_CODE_TO_NAME_INDEX,
    decode_handle,
    encode_handle,
    inspect_blackbird_title,
    parse_cstylesheet,
    parse_text_runs_paragraphs,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_TTL = REPO_ROOT / "resources" / "titles" / "4.ttl"


class CStyleSheetParseTests(unittest.TestCase):
    """Pin the on-disk CStyleSheet grammar against the reference TTL.

    `resources/titles/4.ttl` is `MSN Today` (sha256 4a6e884f…) — the
    only TTL the synthesizer fully supports today. CStyleSheet has 7
    fonts (keys 0–6, including one empty entry) and 54 styles."""

    @classmethod
    def setUpClass(cls):
        inspection = inspect_blackbird_title(SAMPLE_TTL)
        cls.stylesheet = next(
            o for o in inspection["object_streams"]
            if o["class_name"] == "CStyleSheet"
        )
        cls.parsed = cls.stylesheet["parsed"]

    def test_parser_consumes_full_payload(self):
        # `parse_cstylesheet` raises on trailing bytes — re-running it
        # directly proves there's nothing left after the style map.
        result = parse_cstylesheet(self.stylesheet["payload"])
        self.assertEqual(len(result["styles"]), result["style_count"])
        self.assertEqual(result["style_count"], 54)
        self.assertEqual(result["linked_stylesheet_present"], 0)
        self.assertIsNone(result["linked_stylesheet_swizzle"])

    def test_styles_have_expected_count_and_dense_ids(self):
        styles = self.parsed["styles"]
        self.assertEqual(len(styles), 54)
        self.assertEqual([s["style_id"] for s in styles], list(range(54)))

    def test_name_index_matches_style_id(self):
        # In this TTL the packed selector's high-6-bit `name_index`
        # always equals the style_id — ensures the bit-shift decode is
        # right (selector >> 2).
        for s in self.parsed["styles"]:
            self.assertEqual(s["name_index"], s["style_id"])

    def test_root_style_has_no_based_on(self):
        root = self.parsed["styles"][0]
        self.assertFalse(root["is_intrusion"])
        self.assertIsNone(root["based_on"])  # 0xff sentinel decoded to None
        self.assertIsNotNone(root["para_props"])
        self.assertIsNotNone(root["char_props"])

    def test_inheritance_chain_walks_back_to_root(self):
        # Walk each non-intrusion style's based_on chain to make sure
        # it terminates at the root and doesn't loop.
        styles_by_id = {s["style_id"]: s for s in self.parsed["styles"]}
        for s in self.parsed["styles"]:
            if s["is_intrusion"]:
                continue
            seen = set()
            cursor = s
            while cursor["based_on"] is not None:
                self.assertNotIn(cursor["style_id"], seen,
                                 f"based_on cycle through sid {cursor['style_id']}")
                seen.add(cursor["style_id"])
                cursor = styles_by_id[cursor["based_on"]]
            self.assertIsNone(cursor["based_on"])

    def test_intrusion_styles_match_wrap_dictionary_entries(self):
        # The 7 "Wrap: …" entries in CSTYLE_NAME_DICTIONARY (indices
        # 0x2f..0x35) are the intrusion styles — VIEWDLL exposes
        # `CStyle::GetIntrusion` reading the secondary byte from this
        # offset. In the reference TTL these are exactly sid 47..53.
        intrusion_styles = [s for s in self.parsed["styles"] if s["is_intrusion"]]
        self.assertEqual([s["style_id"] for s in intrusion_styles], list(range(47, 54)))
        for s in intrusion_styles:
            self.assertEqual(s["intrusion_index"], 0)
            self.assertIsNone(s["para_props"])
            self.assertIsNone(s["char_props"])
            self.assertTrue(s["name"].startswith("Wrap:"),
                            f"intrusion sid {s['style_id']} resolves to {s['name']!r}")

    def test_intrusion_index_within_published_range(self):
        # BBDESIGN validator "Intrusion argument is invalid. Valid
        # values are 0 to 8." pins the on-disk range. Any future TTL
        # we add must respect this so the engine's GetIntrusion
        # consumer doesn't reject the style.
        for s in self.parsed["styles"]:
            if not s["is_intrusion"]:
                continue
            self.assertIsNotNone(s["intrusion_index"])
            self.assertGreaterEqual(s["intrusion_index"], 0)
            self.assertLessEqual(s["intrusion_index"], 8,
                                 f"sid {s['style_id']} intrusion_index "
                                 f"{s['intrusion_index']} > 8 (BBDESIGN max)")

    def test_style_1_has_authored_text_color(self):
        # Style 1's CCharProps is the only one with an explicit color
        # in this TTL — the masks decode to bit-3-set, yielding
        # text_color = 0x80 = 128 (RGB(128,0,0) dark red, COLORREF LE).
        s1 = self.parsed["styles"][1]
        self.assertEqual(s1["char_props"]["fields"].get("text_color"), 128)

    def test_styles_7_through_15_carry_tab_stops_increasing_by_18(self):
        # The first tab-bearing run (style ids 7–15) places one tab per
        # style at positions 18, 36, 54, … — confirms CParaProps tab
        # bit (mask_explicit bit 12) and per-tab encoding (u16 pos +
        # u8 type) parse correctly.
        for offset, s in enumerate(self.parsed["styles"][7:16]):
            tabs = s["para_props"]["tabs"]
            self.assertEqual(len(tabs), 1)
            self.assertEqual(tabs[0]["position"], 18 * (offset + 1))
            self.assertEqual(tabs[0]["type"], 0)

    def test_font_ids_resolve_against_font_table(self):
        # No style in this TTL ships an explicit font_id (CCharProps
        # mask bit 1 is clear everywhere — every style inherits its
        # font from the parent or stylesheet default). The check
        # nonetheless pins the invariant the wire-side lowering will
        # rely on: any explicit `font_id` must match a `fonts[].key`.
        font_keys = {f["key"] for f in self.parsed["fonts"]}
        for s in self.parsed["styles"]:
            char_props = s["char_props"]
            if char_props is None:
                continue
            font_id = char_props["fields"].get("font_id")
            if font_id is None:
                continue
            self.assertIn(font_id, font_keys,
                          f"sid {s['style_id']} font_id {font_id} not in font table")

    def test_size_distribution_matches_phase_a_buckets(self):
        # Phase A enumeration found 5 distinct record byte-widths. Pin
        # the expected counts so future TTLs that change the mix get
        # caught early.
        # Sizes after stripping (style_id u16 + class tag): 3 bytes
        # (intrusion), 6 bytes (char-props-only), 11 bytes (small
        # CParaProps + minimal CCharProps), 16 bytes (CParaProps + tab
        # list + minimal CCharProps), and the special wrapper-prefixed
        # record 0.
        styles = self.parsed["styles"]
        intrusion_count = sum(1 for s in styles if s["is_intrusion"])
        char_only_count = sum(1 for s in styles if s["char_props_only"]
                              and not s["is_intrusion"])
        with_tabs_count = sum(1 for s in styles
                              if s["para_props"]
                              and s["para_props"]["tabs"])
        self.assertEqual(intrusion_count, 7)   # sids 47–53
        self.assertEqual(char_only_count, 14)  # 6-byte records
        self.assertEqual(with_tabs_count, 18)  # sids 7–24

    def test_name_index_resolves_to_dictionary_entry(self):
        # `name_index` looks up the predefined 54-entry dictionary
        # from VIEWDLL.DLL (CSTYLE_NAME_DICTIONARY). The reference TTL
        # uses dense ids 0..53 so each `name` round-trips against the
        # dictionary entry of the same index.
        for s in self.parsed["styles"]:
            self.assertEqual(s["name"], CSTYLE_NAME_DICTIONARY[s["name_index"]])

    def test_dictionary_pin_known_entries(self):
        # Lock the dictionary to the names recovered from VIEWDLL —
        # any future regression that mis-derives the table fails here.
        self.assertEqual(CSTYLE_NAME_DICTIONARY[0], "Normal")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[1], "Heading 1")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[16], "Section 1")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[30], "Hyperlink")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[34], "Strikethrough")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[47], "Wrap: Design feature")
        self.assertEqual(CSTYLE_NAME_DICTIONARY[53], "Wrap: Custom 2")
        self.assertEqual(len(CSTYLE_NAME_DICTIONARY), 54)

    def test_default_props_pin_known_entries(self):
        # Lock the per-style defaults baked into VIEWDLL @ 0x40770e00.
        # Spot-checks across the table — full pin is the verbatim
        # literal in CSTYLE_DEFAULT_PROPS.
        normal = CSTYLE_DEFAULT_PROPS[0]
        self.assertEqual(normal["based_on"], 0xffff)  # root style
        self.assertEqual(normal["flags_word"], 0x0000)
        self.assertEqual(normal["font_id"], 1)
        self.assertEqual(normal["pt_size"], 11)

        h1 = CSTYLE_DEFAULT_PROPS[1]
        self.assertEqual(h1["based_on"], 0)  # inherits from Normal
        self.assertEqual(h1["flags_word"], 0x7e02)  # bold ON, others absent
        self.assertEqual(h1["font_id"], 2)  # Arial
        self.assertEqual(h1["pt_size"], 22)
        self.assertEqual(h1["space_before"], 18)

        # Hyperlink, Strikethrough, Underline all share the same
        # CCharProps payload (underline ON / 0x7b08). Hyperlink adds
        # a blue text_color; the strike effect is name-special-cased
        # in the renderer, not encoded as a flag bit.
        hyperlink = CSTYLE_DEFAULT_PROPS[30]
        underline = CSTYLE_DEFAULT_PROPS[38]
        strike = CSTYLE_DEFAULT_PROPS[34]
        self.assertEqual(hyperlink["flags_word"], 0x7b08)
        self.assertEqual(underline["flags_word"], 0x7b08)
        self.assertEqual(strike["flags_word"], 0x7b08)
        self.assertEqual(hyperlink["text_color"], 0x00ff0000)  # COLORREF blue
        self.assertEqual(strike["text_color"], 0xffffffff)  # no_change
        self.assertEqual(underline["text_color"], 0xffffffff)

        # All three "char-props-only" style classes
        # (char_props_only=1) — engine constructs CStyle without a
        # CParaProps in defaults.
        self.assertEqual(hyperlink["char_props_only"], 1)
        self.assertEqual(strike["char_props_only"], 1)

        # TOC indents grow by 18 per level (TOC 1 at 18, TOC 2 at 36,
        # …, TOC 9 at 162).
        for n in range(9):
            self.assertEqual(
                CSTYLE_DEFAULT_PROPS[7 + n]["left_indent"], 18 * (n + 1))

        # Preformatted/Code/Fixed Width pin font_id=3 (Courier in
        # standard TTL conventions).
        self.assertEqual(CSTYLE_DEFAULT_PROPS[35]["font_id"], 3)
        self.assertEqual(CSTYLE_DEFAULT_PROPS[40]["font_id"], 3)
        self.assertEqual(CSTYLE_DEFAULT_PROPS[44]["font_id"], 3)

        # Abstract Heading is the only style that pins justify=2
        # (centered) in defaults — confirms `justify` byte is a
        # MFC-style enum (0=left, 1=right, 2=center, ...).
        self.assertEqual(CSTYLE_DEFAULT_PROPS[25]["justify"], 2)

        self.assertEqual(len(CSTYLE_DEFAULT_PROPS), 47)


class HandleEncodingTests(unittest.TestCase):
    """Pin the CDPO object-handle bit format.

    Verified against every handle in `resources/titles/4.ttl` and
    in `/var/share/drop/first title.ttl` — 36/36 round-trip cleanly.
    """

    def test_encode_decode_roundtrip(self):
        for tid in (0, 1, 4, 10, 0x1f, 0x3ff):
            for slot in (0, 1, 7, 0x100, 0x1FFFFF):
                self.assertEqual(decode_handle(encode_handle(tid, slot)),
                                 (tid, slot))

    def test_known_pins(self):
        # Pinned values from `resources/titles/4.ttl` and the older
        # Blackbird sample.
        # CTitle slot 0 = first instance of CTitle in this TTL.
        # In 4.ttl CTitle's table_id is 2 → handle 0x00400000.
        self.assertEqual(encode_handle(2, 0), 0x00400000)
        # The "first title.ttl" 4/1 linked-stylesheet swizzle pin:
        # tid=4 (CStyleSheet) slot=0 → 0x00800000 → 4/0 (the base).
        self.assertEqual(encode_handle(4, 0), 0x00800000)
        # CContent slot 7 → 0x01400007 (the Canyon.mid in the sample).
        self.assertEqual(encode_handle(10, 7), 0x01400007)

    def test_slot_field_caps_at_21_bits(self):
        # Slot exceeding 21 bits must reject. The format leaves 11
        # bits for table_id (which matches the observed maximum
        # level_specifier `0xa = 10` in TTLs surveyed).
        with self.assertRaises(ValueError):
            encode_handle(1, 1 << 21)


class FirstTitleSampleTests(unittest.TestCase):
    """End-to-end smoke test for `/var/share/drop/first title.ttl`.

    Older Blackbird title that ships without `\\x03TitleProps`, uses
    HEX storage names (`a/1`, `a/7`), and has TWO stylesheets with
    the section-local one linking to the title-level one. Skipped
    if the sample isn't present on the filesystem.
    """

    SAMPLE_PATH = Path("/var/share/drop/first title.ttl")

    @classmethod
    def setUpClass(cls):
        if not cls.SAMPLE_PATH.is_file():
            raise unittest.SkipTest(f"sample not present at {cls.SAMPLE_PATH}")
        cls.r = inspect_blackbird_title(cls.SAMPLE_PATH)

    def test_class_inventory(self):
        counts = {}
        for o in self.r['object_streams']:
            counts[o['class_name']] = counts.get(o['class_name'], 0) + 1
        # CMagnet, AudioProxy via CProxyTable, two CStyleSheets,
        # nested sections — features absent from the Marvel reference.
        self.assertEqual(counts['CTitle'], 1)
        self.assertEqual(counts['CSection'], 2)
        self.assertEqual(counts['CStyleSheet'], 2)
        self.assertEqual(counts['CMagnet'], 1)
        # Sample mix: BMP image content (Houndstooth + 2× Sandstone),
        # Audio MIDI, plus TextTree + TextRuns = 6 contents and 4
        # proxies (the Sandstone proxy carries 0x0600 + 0x0601 wrap-
        # variant entries).
        self.assertEqual(counts['CContent'], 6)
        self.assertEqual(counts['CProxyTable'], 4)

    def test_linked_stylesheet_swizzle_resolves_to_base(self):
        # Section-local `4/1` with linked_stylesheet_present=1 should
        # have its swizzle resolve via its own handle table to `4/0`.
        roots = {o['object_root']: o for o in self.r['object_streams']}
        local = roots['4/1']
        self.assertEqual(local['parsed']['linked_stylesheet_present'], 1)
        self.assertEqual(local['parsed']['linked_stylesheet_swizzle'], 0)
        target_handle = local['handles'][0]
        tid, slot = decode_handle(target_handle)
        self.assertEqual(self.r['table_names'][tid], 'CStyleSheet')
        self.assertEqual(slot, 0)
        # The linked-to base really is 4/0 — empty styles, more
        # constrained font list (no Garamond).
        base = roots[f"{tid:x}/{slot:x}"]
        self.assertEqual(base['object_root'], '4/0')
        self.assertEqual(base['parsed']['style_count'], 0)
        self.assertEqual(base['parsed']['linked_stylesheet_present'], 0)

    def test_section_local_stylesheet_overrides_heading_1(self):
        # 4/1 customizes Heading 1 with Garamond 26pt (font key 4 in
        # 4/1's font map, NOT in 4/0's).
        roots = {o['object_root']: o for o in self.r['object_streams']}
        local = roots['4/1']
        h1 = next(s for s in local['parsed']['styles'] if s['name'] == 'Heading 1')
        self.assertEqual(h1['char_props']['fields']['font_id'], 4)
        self.assertEqual(h1['char_props']['fields']['pt_size'], 26)
        # Garamond is the new font this stylesheet adds.
        local_fonts = {f['key']: f['name'] for f in local['parsed']['fonts']}
        self.assertEqual(local_fonts[4], 'Garamond')

    def test_all_handles_decode_to_existing_storage(self):
        roots = {o['object_root'] for o in self.r['object_streams']}
        for o in self.r['object_streams']:
            for h in o['handles']:
                tid, slot = decode_handle(h)
                self.assertIn(f"{tid:x}/{slot:x}", roots,
                              f"handle 0x{h:08x} from {o['object_root']} "
                              f"does not resolve to a stored object")

    def test_text_tree_carries_intrude_property(self):
        # The current sample exercises the intrusion mechanism via an
        # embedded picture control with property INTRUDE=ad — the
        # length-prefixed bytes `\x07INTRUDE\x02ad` appear verbatim in
        # the (decompressed) TextTree payload at a/b. BBCTL.OCX
        # FUN_4001b534 maps `ad` → name_index 0x33 = "Wrap:
        # Advertisement".
        tree = next(o for o in self.r['object_streams']
                    if o['object_root'] == 'a/b')
        self.assertIn(b'\x07INTRUDE\x02ad', tree['payload'])

    def test_intrusion_code_table(self):
        # Pin the full code → name_index mapping recovered from
        # BBCTL.OCX FUN_4001b534 @ 0x4001b534. Each of the 7 wrap
        # styles (CSTYLE_NAME_DICTIONARY indices 0x2f..0x35) has a
        # short ASCII code that picture-control authors use in the
        # TextTree's INTRUDE property.
        self.assertEqual(INTRUSION_CODE_TO_NAME_INDEX, {
            "feature": 0x2f,
            "support": 0x30,
            "related": 0x31,
            "sidebar": 0x32,
            "ad":      0x33,
            "custom1": 0x34,
            "custom2": 0x35,
        })
        # Each value must point into the Wrap: … cluster of the
        # predefined dictionary.
        for code, idx in INTRUSION_CODE_TO_NAME_INDEX.items():
            self.assertTrue(CSTYLE_NAME_DICTIONARY[idx].startswith("Wrap:"),
                            f"code {code!r} → idx {idx} = {CSTYLE_NAME_DICTIONARY[idx]!r} not a wrap style")


class TypographyLoweringTests(unittest.TestCase):
    """End-to-end pins for the multi-face / multi-descriptor section-0
    builder in `server.blackbird.m14_payload`. Walks a parsed
    `CStyleSheet` through the lowering pipeline and asserts the resulting
    descriptors carry the merged LOGFONTA bytes documented in
    `docs/typography-lowering-plan.md` §"Verification".

    These tests exercise `_resolve_style_attrs` + `_descriptor_from_resolved`
    on the reference `resources/titles/4.ttl` stylesheet — the same blob
    `_build_section0_for_stylesheet` ships on the wire."""

    @classmethod
    def setUpClass(cls):
        from server.blackbird import m14_payload
        cls.m14_payload = m14_payload
        inspection = inspect_blackbird_title(SAMPLE_TTL)
        ss = next(
            o for o in inspection["object_streams"]
            if o["class_name"] == "CStyleSheet"
        )
        cls.stylesheet = ss["parsed"]
        cls.parsed_by_id = {
            s["style_id"]: s for s in cls.stylesheet["styles"]
        }

    def _resolve(self, style_id):
        return self.m14_payload._resolve_style_attrs(style_id, self.parsed_by_id)

    def _build(self):
        return self.m14_payload._build_section0_for_stylesheet(self.stylesheet)

    def test_normal_style_resolves_to_times_new_roman_11pt(self):
        # Normal (0x00) is the root style. CSTYLE_DEFAULT_PROPS[0] pins
        # font_id=1 (Times New Roman), pt_size=11, flags_word=0x0000
        # (everything explicit OFF). Authored CCharProps in 4.ttl is
        # empty for sid 0 → defaults are the final answer.
        attrs = self._resolve(0)
        self.assertEqual(attrs["font_id"], 1)
        self.assertEqual(attrs["pt_size"], 11)
        self.assertFalse(attrs["bold"])
        self.assertFalse(attrs["italic"])
        self.assertFalse(attrs["underline"])
        self.assertFalse(attrs["strikeout"])
        self.assertEqual(attrs["text_color"], 0x00000000)
        self.assertEqual(attrs["back_color"], 0x00FFFFFF)

    def test_heading_1_inherits_bold_from_defaults_and_keeps_authored_color(self):
        # Heading 1 (0x01): defaults set font_id=2 (Arial), pt_size=22,
        # flags_word=0x7e02 (bold ON, italic/underline/super/sub absent
        # → inherited from Normal=OFF). Authored CCharProps in 4.ttl
        # adds text_color=128 (dark red) — only mutation across all
        # 54 styles.
        attrs = self._resolve(1)
        self.assertEqual(attrs["font_id"], 2)
        self.assertEqual(attrs["pt_size"], 22)
        self.assertTrue(attrs["bold"])
        self.assertFalse(attrs["italic"])
        self.assertFalse(attrs["underline"])
        self.assertEqual(attrs["text_color"], 128)
        # back_color inherits from Normal default (white).
        self.assertEqual(attrs["back_color"], 0x00FFFFFF)

    def test_hyperlink_inherits_blue_underline_from_defaults(self):
        # Hyperlink (0x1e): defaults flags_word=0x7b08 (underline ON,
        # bold/italic/super/sub absent), text_color=0x00ff0000 (blue).
        attrs = self._resolve(0x1E)
        self.assertTrue(attrs["underline"])
        self.assertFalse(attrs["bold"])
        self.assertFalse(attrs["italic"])
        self.assertEqual(attrs["text_color"], 0x00FF0000)

    def test_strikethrough_special_cased_by_name(self):
        # Strikethrough (0x22): flags_word identical to Hyperlink/Underline
        # (0x7b08) — underline ON, no flag bit for strike. The renderer
        # name-special-cases sid 0x22 and sets lfStrikeOut, so the
        # lowering must mirror that.
        attrs = self._resolve(0x22)
        self.assertTrue(attrs["strikeout"])
        # Underline still ON because flags_word matches Hyperlink.
        self.assertTrue(attrs["underline"])

    def test_preformatted_resolves_to_courier(self):
        # Preformatted (0x23): font_id=3 in defaults (Courier in standard
        # TTL conventions). 4.ttl maps font key 3 → "Courier New".
        attrs = self._resolve(0x23)
        self.assertEqual(attrs["font_id"], 3)

    def test_keyboard_inherits_bold_and_italic(self):
        # Keyboard (0x29): defaults flags_word=0x7c06 — bold ON +
        # italic ON, underline/super/sub absent. Both attributes
        # explicit, no inheritance for them.
        attrs = self._resolve(0x29)
        self.assertTrue(attrs["bold"])
        self.assertTrue(attrs["italic"])
        self.assertFalse(attrs["underline"])

    def test_heading_2_pt_size_and_font_inherit_through_chain(self):
        # Heading 2 (0x02): defaults font_id=0 (inherit), pt_size=18 explicit,
        # based_on=1 (Heading 1). Inheritance must walk back to Heading 1
        # (font_id=2 / Arial) for the font_id resolution.
        attrs = self._resolve(0x02)
        self.assertEqual(attrs["font_id"], 2)
        self.assertEqual(attrs["pt_size"], 18)
        self.assertTrue(attrs["bold"])

    def test_section_3_inherits_font_through_two_levels(self):
        # Section 3 (0x12): defaults font_id=0, based_on=Section 2 (0x11).
        # Section 2 also has font_id=0 inheriting from Section 1 (0x10).
        # Section 1 has font_id=2 (Arial). Resolution must reach back
        # two levels.
        attrs = self._resolve(0x12)
        self.assertEqual(attrs["font_id"], 2)
        self.assertEqual(attrs["pt_size"], 10)

    def test_section0_blob_round_trips_through_m14_parse(self):
        # Wire-bytes round-trip: lower the stylesheet, embed in a fake
        # 9-section payload, parse back, assert face/descriptor counts
        # and per-descriptor LOGFONTA bytes match expectations.
        import struct

        from server.blackbird.m14_parse import parse_payload

        blob = self._build()
        # Stitch a minimal valid 9-section envelope so parse_payload
        # accepts the whole thing.
        payload = (
            struct.pack("<H", len(blob)) + blob +  # sec0
            b"\x00\x00" * 3 +                      # sec07/08/06 empty
            b"\x00\x00" * 3 +                      # sec01/02/6a empty
            b"\x00\x00" +                          # sec13 entry_bytes=0
            b"\x00\x00"                            # sec04 count=0
        )
        parsed = parse_payload(payload)
        self.assertEqual(parsed.font_blob.length, len(blob))
        # 7 fonts × 0x20 = 0xE0; 54 descriptors × 0x2A = 0x8DC.
        face_off, desc_off = struct.unpack_from(
            "<HH", parsed.font_blob.data, 0x04,
        )
        self.assertEqual(face_off, 0x12)
        self.assertEqual(desc_off, 0x12 + 7 * 0x20)
        self.assertEqual(
            struct.unpack_from("<H", parsed.font_blob.data, 0x02)[0],
            54,
        )
        # Spot-check: face[1] = Times New Roman, face[2] = Arial.
        self.assertEqual(
            parsed.font_blob.data[face_off + 0x20:face_off + 0x40].rstrip(b"\x00"),
            b"Times New Roman",
        )
        self.assertEqual(
            parsed.font_blob.data[face_off + 0x40:face_off + 0x60].rstrip(b"\x00"),
            b"Arial",
        )
        # Per-style LOGFONTA pins from
        # `docs/typography-lowering-plan.md` §"Verification".
        def descriptor_bytes(sid: int) -> bytes:
            return parsed.font_blob.data[
                desc_off + sid * 0x2A:desc_off + (sid + 1) * 0x2A
            ]
        normal = descriptor_bytes(0x00)
        self.assertEqual(struct.unpack_from("<H", normal, 0x00)[0], 1)
        self.assertEqual(struct.unpack_from("<i", normal, 0x0C)[0], -220)
        self.assertEqual(struct.unpack_from("<i", normal, 0x1C)[0], 400)
        h1 = descriptor_bytes(0x01)
        self.assertEqual(struct.unpack_from("<H", h1, 0x00)[0], 2)
        self.assertEqual(struct.unpack_from("<i", h1, 0x0C)[0], -440)
        self.assertEqual(struct.unpack_from("<i", h1, 0x1C)[0], 700)
        hyper = descriptor_bytes(0x1E)
        self.assertEqual(hyper[0x21], 1)  # lfUnderline
        self.assertEqual(hyper[0x06:0x09], b"\x00\x00\xFF")  # blue
        strike = descriptor_bytes(0x22)
        self.assertEqual(strike[0x22], 1)  # lfStrikeOut
        pre = descriptor_bytes(0x23)
        self.assertEqual(struct.unpack_from("<H", pre, 0x00)[0], 3)

    def test_face_table_keys_zero_slot_when_font_name_empty(self):
        # 4.ttl reserves font key 0 with an empty name. The face table
        # must still have a slot at index 0 (so face_slot indexing stays
        # consistent) but it should be all-NUL — `hMVSetFontTable` reads
        # up to first NUL and gets an empty face string.
        blob = self._build()
        face_off = 0x12
        self.assertEqual(blob[face_off:face_off + 0x20], b"\x00" * 0x20)

    def test_descriptor_count_field_matches_actual_records(self):
        # When every authored style_id has a real descriptor, the field
        # is the dense count and the FUN_7e896610 clamp passes any sid
        # < count through to its real descriptor (not 0).
        import struct
        blob = self._build()
        descriptor_count = struct.unpack_from("<H", blob, 0x02)[0]
        self.assertEqual(descriptor_count, 54)


class TextRunsParagraphsTests(unittest.TestCase):
    """Pin the TextRuns body parser used by the case-1 lowering path.

    Reference samples come from `resources/titles/4.ttl`. The format is
    `[u16 schema_prefix][ANSI body]` with paragraphs separated by `'#'`
    and a leading `'S'` marker; both sentinels are RE-deferred but
    consistent across observed samples."""

    @classmethod
    def setUpClass(cls):
        inspection = inspect_blackbird_title(SAMPLE_TTL)
        cls.text_runs_payloads = {
            o["object_root"]: o["payload"]
            for o in inspection["object_streams"]
            if o["class_name"] == "CContent"
        }

    def test_homepage_splits_into_two_paragraphs(self):
        # Homepage.bdf TextRuns is at object root `8/7` in 4.ttl:
        # 122-byte body with one `'#'` boundary between intro and tail.
        payload = self.text_runs_payloads["8/7"]
        paragraphs = parse_text_runs_paragraphs(payload)
        self.assertEqual(len(paragraphs), 2)
        self.assertTrue(paragraphs[0].startswith("This is an example"))
        self.assertTrue(paragraphs[1].startswith("Ordered list"))

    def test_calendar_empty_text_runs_yields_no_paragraphs(self):
        # Calendar of Events.bdf TextRuns is `00 00` — empty body. The
        # authored text lives in TextTree instead; lowering falls back
        # to the title caption when paragraphs is empty.
        for payload in self.text_runs_payloads.values():
            if payload == b"\x00\x00":
                self.assertEqual(parse_text_runs_paragraphs(payload), [])
                break
        else:
            self.fail("expected at least one empty TextRuns payload in 4.ttl")

    def test_short_payload_yields_no_paragraphs(self):
        # < 3 bytes → no body to parse.
        self.assertEqual(parse_text_runs_paragraphs(b""), [])
        self.assertEqual(parse_text_runs_paragraphs(b"\x00"), [])
        self.assertEqual(parse_text_runs_paragraphs(b"\x00\x00"), [])

    def test_synthetic_payload_strips_S_marker_and_splits(self):
        # `02 00` prefix + 'S' marker + "A#B" body → ["A", "B"].
        payload = b"\x02\x00SA#B"
        self.assertEqual(parse_text_runs_paragraphs(payload), ["A", "B"])

    def test_payload_without_S_marker_still_splits(self):
        # Defensive: if a future authored TextRuns omits the 'S', the
        # body should still split on '#' rather than refusing to parse.
        payload = b"\x02\x00first#second"
        self.assertEqual(parse_text_runs_paragraphs(payload), ["first", "second"])

    def test_payload_truncates_at_first_nul(self):
        # Per the doc, NUL terminates the body. Anything after is
        # ignored.
        payload = b"\x02\x00Sone#two\x00three#four"
        self.assertEqual(parse_text_runs_paragraphs(payload), ["one", "two"])

    def test_paragraphs_strip_surrounding_whitespace(self):
        # Authored bodies often have a trailing space before the next
        # `#`; the parser strips so heuristic style assignment doesn't
        # ship leading/trailing whitespace into the case-1 chunk.
        payload = b"\x02\x00S  hello  #  world  "
        self.assertEqual(parse_text_runs_paragraphs(payload), ["hello", "world"])


if __name__ == "__main__":
    unittest.main()
