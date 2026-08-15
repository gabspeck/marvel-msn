"""Tests for compiled Microsoft Media View 1.4 title fixtures."""

import hashlib
import pathlib
import re
import struct
import unittest

from server.blackbird.wire import (
    build_case1_stream_bf_chunk,
    decode_case1_tlv,
    encode_case1_preamble,
    encode_text_item_tlv,
)
from server.services.medview.m14_loader import (
    build_m14_mvpfile,
    load_m14,
    lower_m14_to_osr2_payload,
    lower_m14_to_payload,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_HANDBOOK = _REPO_ROOT / "resources" / "titles" / "HANDBOOK.M14"
_FRANCE = _REPO_ROOT / "resources" / "titles" / "FRANCE.M14"
_MVDOC = _REPO_ROOT / "resources" / "titles" / "MVDOC.M14"


def _mvp_sections(mvpfile: bytes) -> dict[str, list[str]]:
    """Split MVP text into `{section: [line, ...]}`, as ParseMvpText does."""
    sections: dict[str, list[str]] = {}
    current: list[str] = []
    for line in mvpfile.decode("cp1252").splitlines():
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], [])
        elif line:
            current.append(line)
    return sections


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
        self.assertEqual(len(_MVDOC.read_bytes()), 3_584_999)
        self.assertEqual(
            hashlib.sha256(_MVDOC.read_bytes()).hexdigest(),
            "227144ca05fae687d1190dfd62010add711e953bf318aa69848af51423fd7123",
        )

    def test_mvdoc_needs_a_two_level_directory_and_the_phrase_table(self):
        """MVDOC.M14 exercises two loader paths the other two fixtures skip.

        Its HFS directory is a two-level B-tree, so the reader must descend
        to the leftmost leaf before walking the leaf chain. Its LinkData2 is
        phrase-compressed against `|Phrases`, so every record expands to the
        size its TOPICLINK declares.
        """
        title = load_m14(_MVDOC)
        self.assertIsNotNone(title)
        self.assertEqual(title.title, "MediaView Online Documentation")
        self.assertEqual(len(title.internal_files), 199)
        self.assertEqual(title.topic_count, 968)
        self.assertEqual(len(title.topics), 969)
        self.assertEqual(
            title.home_topic.title,
            "MediaView Kit Documentation Contents",
        )
        # Phrase expansion feeds the text; a literal-only reader loses these.
        self.assertIn(
            "Author’s Reference:  MediaView Authoring Tools and Commands",
            [topic.title for topic in title.topics],
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

        child_panes, offset = _read_blob(payload, offset)
        self.assertEqual(child_panes, b"")
        # One PopupPaneRecord carrying the authored BackColorPopup. The
        # rect stays -1 so MOSVIEW defaults it to the container client
        # area, and the name is the authoring window id ("0" when the
        # property carries no window prefix).
        popups, offset = _read_blob(payload, offset)
        self.assertEqual(len(popups), 0x1F)
        self.assertEqual(popups[0x02:0x0B], b"0\x00\x00\x00\x00\x00\x00\x00\x00")
        self.assertEqual(struct.unpack_from("<iiii", popups, 0x0B), (-1, -1, -1, -1))
        self.assertEqual(struct.unpack_from("<I", popups, 0x1B)[0], 0x00FFFFFF)
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

    def test_osr2_title_payload_moves_layout_to_mvpfile(self):
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        payload = lower_m14_to_osr2_payload(title, "4")

        font_blob, offset = _read_blob(payload, 0)
        self.assertIn(b"Times New Roman\x00", font_blob)
        self.assertEqual(payload[offset : offset + 2], b"4\x00")
        offset += 2

        title_text, offset = _read_blob(payload, offset)
        copyright_text, offset = _read_blob(payload, offset)
        self.assertEqual(title_text, b"Employee Handbook Example\x00")
        self.assertEqual(
            copyright_text,
            "© 1996 Centric Development, Inc.\x00".encode("cp1252"),
        )
        entry_bytes, entry_count = struct.unpack_from("<HH", payload, offset)
        self.assertEqual(entry_count, 6)
        self.assertEqual(offset + 4 + entry_bytes, len(payload))

        sections = _mvp_sections(build_m14_mvpfile(title))
        self.assertEqual(list(sections), ["CONFIG", "PANES", "POPUPS", "WINDOWS"])
        self.assertEqual(sections["CONFIG"], [])
        self.assertEqual(sections["PANES"], [])
        self.assertEqual(
            sections["WINDOWS"],
            [
                'main="Employee Handbook Example",(0,0,640,480,1),,,'
                "(255,255,255),(255,255,192)"
            ],
        )

    def test_mvpfile_carries_the_same_records_as_the_rtm_body(self):
        """`[WINDOWS]` and `[POPUPS]` restate sections 6 and 8.

        The two window colours are authored scrolling-first — the reverse
        of the `+0x78`/`+0x7C` order `_build_sec06` writes — because
        `MOSVIEW!ParseMvpWindowLine @ 0x7F3C8B6C` stores field 5 at
        `+0x7C` and field 6 at `+0x78`.
        """
        title = load_m14(_FRANCE)
        non_scroll, scroll = title.pane_backgrounds
        popup_background, popup_window = title.popup_pane

        def rgb(value: int) -> str:
            return f"{value & 0xff},{value >> 8 & 0xff},{value >> 16 & 0xff}"

        sections = _mvp_sections(build_m14_mvpfile(title))
        window = sections["WINDOWS"][0]
        self.assertEqual(
            re.findall(r"\(([^)]*)\)", window)[-2:],
            [rgb(scroll), rgb(non_scroll)],
        )
        self.assertEqual(
            sections["POPUPS"],
            [f"{popup_window}=,({rgb(popup_background)})"],
        )

        body = lower_m14_to_payload(title, "4")
        offset = 2 + struct.unpack_from("<H", body, 0)[0] + 2
        sec08, offset = _read_blob(body, offset)
        sec06, _ = _read_blob(body, offset)
        self.assertEqual(
            struct.unpack_from("<II", sec06, 0x78),
            (non_scroll, scroll),
        )
        self.assertEqual(
            sec08[0x02:0x0B].rstrip(b"\x00").decode(),
            popup_window,
        )
        self.assertEqual(
            struct.unpack_from("<I", sec08, 0x1B)[0],
            popup_background,
        )

    def test_native_display_stream_is_preserved_in_case1_cache_record(self):
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        display = title.home_display
        chunk = build_case1_stream_bf_chunk(
            display.control_stream,
            display.text_data,
            title_byte=1,
            key=display.topic_pos,
            topic_length=display.topic_length,
            tlv_fields=display.fields_dict(),
            tab_stops=list(display.tab_stops),
            non_scroll=display.non_scroll,
        )

        self.assertEqual(chunk[:2], b"\xbf\x01")
        self.assertEqual(struct.unpack_from("<I", chunk, 12)[0], 0xA7)
        self.assertEqual(struct.unpack_from("<I", chunk, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", chunk, 16)[0], 1)
        tlv = encode_text_item_tlv(
            display.fields_dict(),
            tab_stops=list(display.tab_stops),
        )
        preamble = encode_case1_preamble(
            len(tlv) + len(display.control_stream),
            type_tag=0x20,
            prefix_u16=display.topic_length,
        )
        self.assertEqual(
            chunk[0x2A : 0x2A + len(preamble)],
            preamble,
        )
        tlv_offset = 0x2A + len(preamble)
        fields, tlv_size = decode_case1_tlv(chunk[tlv_offset:])
        self.assertEqual(fields[0x0C], 2)
        control_offset = tlv_offset + tlv_size
        self.assertEqual(
            chunk[control_offset : control_offset + len(display.control_stream)],
            display.control_stream,
        )
        name_size = struct.unpack_from("<H", chunk, 2)[0]
        self.assertEqual(
            struct.unpack_from("<I", chunk, 4 + name_size + 0x14)[0],
            0xFFFFFFFF,
        )

    def test_popup_background_is_parsed_from_topic_properties(self):
        """`BackColorPopup` is a distinct property from the pane colours.

        France declares it per authoring window (`12.BackColorPopup=`),
        Handbook without a prefix. Both author white, which is also what
        MOSVIEW's synthetic default popup resolves to, so this changes
        no pixels today — it stops the value being dropped.
        """
        france = load_m14(_FRANCE)
        handbook = load_m14(_HANDBOOK)
        self.assertEqual(france.pane_backgrounds, (0x00C0FFFF, 0x00FFFFFF))
        self.assertEqual(france.popup_pane, (0x00FFFFFF, "12"))
        self.assertEqual(handbook.popup_pane, (0x00FFFFFF, ""))
        # The popup colour must not be confused with the NSR yellow.
        self.assertNotEqual(france.popup_pane[0], france.pane_backgrounds[0])

    def test_edge_tokens_never_span_a_real_display(self):
        """Topic-edge cache tokens must sit adjacent to their own record.

        `HfcNear` treats a cached record as covering everything from its
        own key up to the next cached key, so an end-of-content token
        shared across topics claims the whole range beneath the lowest
        record cached so far. That hid the France popup topic at
        `va=0x49`, the title's lowest display.
        """
        title = load_m14(_FRANCE)
        self.assertIsNotNone(title)
        positions = sorted(
            display.topic_pos
            for topic in title.topics
            for display in topic.displays
        )
        occupied = set(positions)
        for topic_pos in positions:
            previous, following = title.display_neighbors(topic_pos)
            for token in (previous, following):
                if token in occupied:
                    continue
                # A synthesised token spans only up to the next real
                # record, so it must not sit below one it does not abut.
                self.assertIn(
                    token,
                    (topic_pos - 1, topic_pos + 1),
                    f"display 0x{topic_pos:x} names non-adjacent edge "
                    f"token 0x{token:x}",
                )
        # The lowest display in the title is the popup target; its
        # leading token must not reach down past it.
        self.assertEqual(title.display_neighbors(positions[0])[0], positions[0] - 1)

    def test_cathar_display_chain_preserves_nsr_and_scroll_regions(self):
        title = load_m14(_FRANCE)
        self.assertIsNotNone(title)
        non_scroll = title.display_at(0x4696)
        scroll = title.display_at(0x46D3)
        self.assertIsNotNone(non_scroll)
        self.assertIsNotNone(scroll)
        self.assertEqual((non_scroll.non_scroll, non_scroll.scroll), (0x4696, 0x46D3))
        self.assertEqual(title.display_neighbors(0x4696), (0x4695, 0x46D3))
        self.assertEqual(title.display_neighbors(0x46D3), (0x4696, 0x4968))
        self.assertEqual(title.display_neighbors(0x4A17), (0x4968, 0x4A18))
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
            topic_length=non_scroll.topic_length,
            tlv_fields=non_scroll.fields_dict(),
            tab_stops=list(non_scroll.tab_stops),
            non_scroll=non_scroll.non_scroll,
            scroll=non_scroll.scroll,
        )
        preamble = encode_case1_preamble(
            len(encode_text_item_tlv(
                non_scroll.fields_dict(),
                tab_stops=list(non_scroll.tab_stops),
            )) + len(non_scroll.control_stream),
            type_tag=0x20,
            prefix_u16=non_scroll.topic_length,
        )
        fields, _tlv_size = decode_case1_tlv(
            chunk[0x2A + len(preamble):],
        )
        self.assertEqual(fields[0x12], 1)
        self.assertEqual(fields[0x16], 240)
        self.assertEqual(fields[0x18], 60)
        self.assertEqual(fields[0x1C], 72)
        self.assertEqual(fields[0x1E], 72)

    def test_other_castles_popup_serves_its_table_rows(self):
        """The popup's bullet list is seven table records, not displays.

        Media View compiles each bullet as a one-column table whose cell
        holds the Wingdings bullet, a tab and the castle name. Skipping
        record type 0x23 leaves the popup with only its heading and lead
        sentence, which is what MOSVIEW painted.
        """
        title = load_m14(_FRANCE)
        self.assertIsNotNone(title)
        popup = [
            title.display_at(topic_pos)
            for topic_pos in (0x3E1, 0x41D, 0x487, 0x4D3, 0x537, 0x599, 0x5FA, 0x65F, 0x6C1)
        ]
        self.assertNotIn(None, popup)
        self.assertEqual(
            [row.text_data for row in popup[2:]],
            [
                b"\x00n\x00\x00Queribus\x00\x00",
                b"\x00n\x00\x00Monts\xe9gur\x00\x00",
                b"\x00n\x00\x00Aguilar\x00\x00",
                b"\x00n\x00\x00Termes\x00\x00",
                b"\x00n\x00\x00Puylaurens\x00\x00",
                b"\x00n\x00\x00Puivert\x00\x00",
                b"\x00n\x00\x00Carcassonne\x00\x00",
            ],
        )

        # Bullet font, tab, body font, end of paragraph. The row after
        # the first drops the leading do-nothing cell instead of ending
        # its empty paragraph, so both rows reach the wire identically.
        for row in popup[2:]:
            self.assertEqual(row.control_stream, bytes.fromhex("8004008380020082ff"))
            self.assertEqual(
                row.fields_dict(),
                {0x12: 1, 0x16: 120, 0x1C: 432, 0x1E: 72, 0x20: -360},
            )

        # The rows join the topic's chain between the lead sentence and
        # the trailing display, so HfcNextPrevHfc walks the whole popup.
        self.assertEqual(title.display_neighbors(0x41D), (0x3E1, 0x487))
        self.assertEqual(title.display_neighbors(0x487), (0x41D, 0x4D3))
        self.assertEqual(title.display_neighbors(0x6C1), (0x65F, 0x727))

    def test_table_cells_join_as_paragraphs_of_one_item(self):
        """A row's later cells become paragraphs of the same text item.

        One chunk carries one `MVDecodeTopicItemPrefix` tag, so a row's
        cells share it. Each non-final cell's `0xFF` becomes `0x82`,
        which ends the paragraph and consumes the one text run the
        `0xFF` it replaces consumed — this record's two cells (`80 06 00
        81 82 ff` and `82 ff`) still spend all six of its runs.
        """
        title = load_m14(_HANDBOOK)
        self.assertIsNotNone(title)
        row = title.display_at(0x8E1B)
        self.assertIsNotNone(row)
        self.assertEqual(row.control_stream, bytes.fromhex("800600818282" "82ff"))
        self.assertEqual(row.text_data.count(b"\x00"), 6)
        self.assertEqual(row.fields_dict(), {0x12: 1})
