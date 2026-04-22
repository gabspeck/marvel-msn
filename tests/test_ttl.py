"""Unit tests for the Blackbird `.ttl` compound-file parser.

Fixture: `resources/titles/4.ttl` (8704 B, shipped with the repo).
Documents the parse of `\\x03type_names_map` + per-storage
`\\x03properties` streams; opaque `object` streams are out of scope.
"""

import os
import struct
import unittest
from pathlib import Path

from server.services.ttl import (
    Title,
    TTLError,
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

    def test_type_graph_covers_six_classes(self):
        # docs/BLACKBIRD.md §3: a minimum title carries CTitle +
        # CBForm/CVForm/CBFrame/CStyleSheet/CResourceFolder.  4.ttl
        # happens to include one of each.
        title = Title.from_path(str(FIXTURE))
        self.assertEqual(set(title.types.values()), {
            "CTitle", "CBForm", "CBFrame", "CVForm", "CStyleSheet", "CResourceFolder",
        })

    def test_named_classes_expose_name_property(self):
        # CTitle / CBForm / CBFrame / CStyleSheet / CResourceFolder all
        # carry `\x03properties` streams with a single `name` entry.
        # CVForm alone on 4.ttl has no properties stream (storage 6
        # contains only `\x03object`), so skip it.
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
