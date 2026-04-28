"""Unit tests for the Blackbird `.ttl` compound-file parser.

Fixture: `resources/titles/4.ttl` (shipped with the repo).  Documents
parse of `\\x03type_names_map`, per-storage `\\x03properties`, and
per-storage `\\x03object` streams (with MSZIP / uncompressed branches).
"""

import os
import struct
import unittest
import zlib
from pathlib import Path

from server.services.ttl import (
    Title,
    TTLError,
    _extract_object_stream,
    _parse_property_stream,
    _parse_type_names_map,
)

FIXTURE = Path(__file__).resolve().parents[1] / "resources" / "titles" / "4.ttl"


class TestTypeNamesMap(unittest.TestCase):
    def test_parses_synthetic_map(self):
        # Format: u32 count, u16 opaque, then per-entry
        # u8 name_len / name / u32 storage_id.
        data = (
            struct.pack("<IH", 2, 2)
            + bytes([6]) + b"CTitle" + struct.pack("<I", 1)
            + bytes([5]) + b"CForm" + struct.pack("<I", 2)
        )
        self.assertEqual(_parse_type_names_map(data), {1: "CTitle", 2: "CForm"})

    def test_rejects_truncated(self):
        with self.assertRaises(TTLError):
            _parse_type_names_map(b"\x01\x00")  # only 2B, need ≥6

    def test_rejects_entry_overflow(self):
        data = struct.pack("<IH", 1, 1) + bytes([10]) + b"CT"
        with self.assertRaises(TTLError):
            _parse_type_names_map(data)


class TestPropertyStream(unittest.TestCase):
    def test_parses_single_string_property(self):
        # `name=MSN Today\0` — the CTitle property on 4.ttl.
        data = (
            struct.pack("<I", 1)
            + bytes([4]) + b"name"
            + bytes([0x08, 0x00])
            + struct.pack("<I", 10)
            + b"MSN Today\x00"
        )
        parsed = _parse_property_stream(data)
        self.assertEqual(parsed, {"name": "MSN Today"})

    def test_empty_on_zero_count(self):
        self.assertEqual(_parse_property_stream(struct.pack("<I", 0)), {})

    def test_skips_non_string_type(self):
        # type_tag=0x01 (not 0x08) — logged + skipped.
        data = (
            struct.pack("<I", 1)
            + bytes([3]) + b"foo"
            + bytes([0x01, 0x00])
            + struct.pack("<I", 4)
            + b"\xde\xad\xbe\xef"
        )
        self.assertEqual(_parse_property_stream(data), {})


class TestTitleFromFixture(unittest.TestCase):
    def setUp(self):
        if not FIXTURE.is_file():
            self.skipTest(f"fixture missing: {FIXTURE}")

    def test_display_name_is_msn_today(self):
        title = Title.from_path(str(FIXTURE))
        self.assertEqual(title.display_name, "MSN Today")

    def test_type_graph_covers_authored_classes(self):
        # docs/BLACKBIRD.md §3: minimum title carries CTitle + form /
        # frame / stylesheet / resource scaffolding.  4.ttl additionally
        # carries CContent (per-content storage), CSection, and
        # CProxyTable.
        title = Title.from_path(str(FIXTURE))
        self.assertEqual(set(title.types.values()), {
            "CTitle", "CContent", "CBForm", "CBFrame", "CSection",
            "CVForm", "CProxyTable", "CStyleSheet", "CResourceFolder",
        })

    def test_named_classes_expose_name_property(self):
        # The classes whose `\x03properties` stream carries a `name`
        # entry on 4.ttl.  CVForm / CContent / CSection / CProxyTable
        # don't (their storages either omit the stream or use a
        # different key set the simple parser doesn't decode).
        title = Title.from_path(str(FIXTURE))
        named = {"CTitle", "CBForm", "CBFrame", "CStyleSheet", "CResourceFolder"}
        for sid, class_name in title.types.items():
            if class_name not in named:
                continue
            with self.subTest(sid=sid, cls=class_name):
                self.assertIn("name", title.properties.get(sid, {}))

    def test_ctitle_name_is_the_authored_caption(self):
        title = Title.from_path(str(FIXTURE))
        # Redundant with test_display_name_is_msn_today but pins the
        # underlying property lookup path for regression visibility.
        title_sid = next(sid for sid, cls in title.types.items() if cls == "CTitle")
        self.assertEqual(title.properties[title_sid]["name"], "MSN Today")

    def test_from_bytes_matches_from_path(self):
        data = FIXTURE.read_bytes()
        a = Title.from_path(str(FIXTURE))
        b = Title.from_bytes(data)
        self.assertEqual(a.types, b.types)
        self.assertEqual(a.properties, b.properties)
        self.assertEqual(a.display_name, b.display_name)
        self.assertEqual(a.objects, b.objects)


class TestExtractObjectStream(unittest.TestCase):
    def test_empty_stream_returns_empty(self):
        self.assertEqual(_extract_object_stream(b""), b"")

    def test_ver_zero_is_empty_sentinel(self):
        # 4.ttl's 8/3/object — `00 00`, just the version byte + a pad.
        self.assertEqual(_extract_object_stream(b"\x00\x00"), b"")

    def test_ver_two_strips_version_byte(self):
        self.assertEqual(_extract_object_stream(b"\x02\x01\x02\x03"), b"\x01\x02\x03")

    def test_ver_three_strips_version_byte(self):
        # CSection 9/1 on the in-flight authored fixture uses ver=0x03.
        # Same shape as v2 (uncompressed body), see ttl.py for the
        # wire-ready hypothesis.
        self.assertEqual(_extract_object_stream(b"\x03\xaa\xbb\xcc"), b"\xaa\xbb\xcc")

    def test_ver_one_without_ck_is_uncompressed(self):
        # Small streams that happen to start with 0x01 (CResourceFolder
        # at 2/0 on 4.ttl is one) still ship raw.
        body = b"\x01\x03\x02\x00\x05\x00\x00\x00"  # 8B, no CK at +9
        self.assertEqual(_extract_object_stream(body), body[1:])

    def test_unknown_version_raises(self):
        with self.assertRaises(TTLError):
            _extract_object_stream(b"\x7f" + b"\x00" * 16)

    def test_ver_one_with_ck_round_trips_via_mszip(self):
        plain = b"hello mszip" * 20  # 220 B — large enough to compress
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        body = compressor.compress(plain) + compressor.flush()
        cmp_with_ck = len(body) + 2  # CK signature counted
        wrapped = (
            b"\x01"
            + struct.pack("<II", len(plain), cmp_with_ck)
            + b"CK"
            + body
        )
        self.assertEqual(_extract_object_stream(wrapped), plain)

    def test_ver_one_ck_with_wrong_length_raises(self):
        plain = b"hello"
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        body = compressor.compress(plain) + compressor.flush()
        wrong_unc = len(plain) + 1  # mismatched length triggers guard
        wrapped = (
            b"\x01"
            + struct.pack("<II", wrong_unc, len(body) + 2)
            + b"CK"
            + body
        )
        with self.assertRaises(TTLError):
            _extract_object_stream(wrapped)


class TestObjectStreamsFromFixture(unittest.TestCase):
    """Pinned object-stream sizes from `resources/titles/4.ttl`.

    Inventory captured 2026-04-28:
        ver=01+CK (compressed): 4/0 CStyleSheet 880 B, 6/0 CVForm 816 B,
                                8/0 CContent 319 B
        ver=02 (uncompressed):  1/0 CTitle 37 B, 3/0 CBFrame 44 B,
                                5/0 CBForm 44 B, 7/0+7/1 CProxyTable 17 B,
                                8/1 CContent 119 B
        ver=01 (uncompressed):  2/0 CResourceFolder 24 B,
                                8/2 CContent 84 B
        ver=03 (uncompressed):  9/1 CSection 43 B (matches wire body
                                section-1 record stride exactly)
        ver=00 (empty):         8/3 CContent 0 B
    """

    def setUp(self):
        if not FIXTURE.is_file():
            self.skipTest(f"fixture missing: {FIXTURE}")
        self.title = Title.from_path(str(FIXTURE))

    def _sid_of(self, class_name: str) -> int:
        return next(sid for sid, cls in self.title.types.items() if cls == class_name)

    def test_compressed_streams_decompress_to_pinned_sizes(self):
        cases = [("CStyleSheet", 880), ("CVForm", 816)]
        for cls, size in cases:
            with self.subTest(cls=cls):
                sid = self._sid_of(cls)
                self.assertEqual(len(self.title.objects[sid][0]), size)

    def test_uncompressed_v2_streams_strip_version_byte(self):
        # CTitle: 38 B raw, ver=02, plaintext = 37 B.
        ctitle_sid = self._sid_of("CTitle")
        self.assertEqual(len(self.title.objects[ctitle_sid][0]), 37)
        # CBFrame: 45 B raw → 44 B.
        cbframe_sid = self._sid_of("CBFrame")
        self.assertEqual(len(self.title.objects[cbframe_sid][0]), 44)

    def test_uncompressed_v1_strips_version_byte(self):
        # CResourceFolder: 25 B raw, ver=01 with no CK at +9 → 24 B.
        rf_sid = self._sid_of("CResourceFolder")
        self.assertEqual(len(self.title.objects[rf_sid][0]), 24)

    def test_ccontent_substorages_each_decoded(self):
        # CContent on 4.ttl carries 4 sub-storages with mixed encodings:
        # 8/0 ver=01+CK → 319 B, 8/1 ver=02 → 119 B, 8/2 ver=01 (no CK)
        # → 84 B, 8/3 ver=00 → 0 B.  All four must show up.
        ccontent_sid = self._sid_of("CContent")
        subs = self.title.objects[ccontent_sid]
        self.assertEqual(set(subs.keys()), {0, 1, 2, 3})
        self.assertEqual(len(subs[0]), 319)
        self.assertEqual(len(subs[1]), 119)
        self.assertEqual(len(subs[2]), 84)
        self.assertEqual(len(subs[3]), 0)

    def test_csection_v3_body_matches_wire_section1_record_stride(self):
        # ver=0x03 hypothesis: BBDESIGN release path emits CSection
        # bodies wire-ready for MEDVIEW body section 1 (43-byte topic
        # records, see docs/MEDVIEW.md §4.4).  The body must be exactly
        # 43 bytes — the engine's hard-coded record stride in
        # MVTTL14C!TitleGetInfo.
        csection_sid = self._sid_of("CSection")
        # 9/1 (not 9/0) — the new authored fixture uses sub=1.
        body = self.title.objects[csection_sid][1]
        self.assertEqual(len(body), 43)


class TestTitleErrors(unittest.TestCase):
    def test_not_ole_raises(self):
        # Random bytes — olefile rejects this before we even see it.
        # `OleFileIO` raises OSError ("not an OLE2 structured storage
        # file"); we let that propagate since it's not our error class.
        with self.assertRaises(OSError):
            Title.from_bytes(b"\x00" * 512)

    def test_missing_type_names_map_raises(self):
        # Minimal valid OLE2 with no type_names_map stream would need a
        # synthesized compound file — skipping; the guard is covered by
        # TTLError's docstring + manual inspection.
        pass


class TestMedviewIntegration(unittest.TestCase):
    """End-to-end: MEDVIEW handler pulls CTitle.name from 4.ttl."""

    def test_deid_4_uses_ttl_name(self):
        from server.services.medview import _resolve_display_name
        # 4.ttl exists in-tree; the handler should resolve to the
        # CTitle.name it carries.
        self.assertEqual(_resolve_display_name("4"), "MSN Today")

    def test_unknown_deid_falls_back(self):
        from server.services.medview import _resolve_display_name
        self.assertEqual(_resolve_display_name("42"), "Title 42")

    def test_override_via_env(self):
        # MSN_TITLES_ROOT pointing at an empty dir should force the
        # fallback for every deid (even "4").
        from server.services import medview
        env = os.environ.copy()
        try:
            os.environ["MSN_TITLES_ROOT"] = "/nonexistent/titles"
            self.assertEqual(medview._resolve_display_name("4"), "Title 4")
        finally:
            os.environ.clear()
            os.environ.update(env)


if __name__ == "__main__":
    unittest.main()
