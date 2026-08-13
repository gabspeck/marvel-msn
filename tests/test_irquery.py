"""Tests for `src.server.blackbird.irquery` — the IQuerySpec decoder.

The fixture is the first BBIRService query ever captured (2026-08-13): a search
for "search term!" issued from the Blackbird Find UI against the published
title, streamed as a chunked field on selector 0x05.

Pin every field against the layout IRUT.DLL's own reader enforces
(`BuildQuerySpec` @ 0x1000d14d and the Build* family it calls), and reject
what that reader would have thrown on.
"""

import pathlib
import struct
import unittest
import uuid

from server.blackbird.irquery import (
    AIR_MAX_COUNT_COMBINER,
    AIR_STRING_CONTEXT_TERM,
    AIR_TIME_TERM,
    AirCombiner,
    AirTerm,
    IRQueryError,
    parse_query_spec,
)

_FIXTURE = pathlib.Path(__file__).resolve().parent / "assets" / "bbir_queryspec.bin"


def _spec():
    return parse_query_spec(_FIXTURE.read_bytes())


class TestCapturedQuerySpec(unittest.TestCase):
    def test_fixture_is_the_captured_length(self):
        # parse_query_spec rejects trailing bytes, so a clean parse of the
        # whole file is itself the proof that every record size is right.
        self.assertEqual(len(_FIXTURE.read_bytes()), 541)

    def test_max_results(self):
        self.assertEqual(_spec().max_results, 100)

    def test_requested_document_properties(self):
        props = _spec().properties
        self.assertEqual(
            [str(p.guid) for p in props],
            [
                "ec9f69c5-7bf7-11ce-b577-00aa0060fa9a",
                "ec9f69c6-7bf7-11ce-b577-00aa0060fa9a",
                "ec9f69bd-7bf7-11ce-b577-00aa0060fa9a",
                "ec9f69be-7bf7-11ce-b577-00aa0060fa9a",
            ],
        )
        self.assertTrue(all(p.direction == 0 and p.extra == b"" for p in props))

    def test_no_sort_properties(self):
        # QuerySpec child count is 2, so BuildQuerySpec skips the sort list.
        self.assertEqual(_spec().sort_properties, [])

    def test_single_criterion_scoped_to_the_published_title(self):
        criteria = _spec().criteria
        self.assertEqual(len(criteria), 1)
        spec = criteria[0]
        self.assertEqual(spec.value, 1000)
        # docs/BLACKBIRD.md §4.4.3 — the root object GUID `bbix +0x04` carries.
        self.assertEqual(
            [str(s.guid) for s in spec.sources],
            ["d439ef41-51f5-11f1-b405-000c875355c8"],
        )

    def test_query_tree_shape(self):
        root = _spec().criteria[0].criteria
        self.assertIsInstance(root, AirCombiner)
        self.assertEqual(root.tag, AIR_MAX_COUNT_COMBINER)
        self.assertEqual(root.op, 3)
        self.assertEqual(len(root.children), 2)

        time_term, inner = root.children
        self.assertIsInstance(time_term, AirTerm)
        self.assertEqual(time_term.tag, AIR_TIME_TERM)
        # The Find UI's date filter left at "any time".
        self.assertEqual((time_term.time_from, time_term.time_to), (0, 0x7FFFFFFF))
        self.assertEqual(str(time_term.guid), "ec9f69be-7bf7-11ce-b577-00aa0060fa9a")

        self.assertIsInstance(inner, AirCombiner)
        self.assertEqual(len(inner.children), 2)

    def test_terms_are_the_typed_tokens(self):
        # CQueryExprParser::Parse split "search term!" on whitespace and made
        # one term per token.
        self.assertEqual(_spec().terms(), ["search", "term!"])

    def test_time_properties_names_the_date_column(self):
        # The property a time term filters on must be served as a date; the
        # Find UI reads that column with the type-0x17 getter and faults on
        # anything else (IRFIND.DLL:0x1000e425).
        self.assertEqual(
            [str(g) for g in _spec().time_properties()],
            ["ec9f69be-7bf7-11ce-b577-00aa0060fa9a"],
        )

    def test_time_properties_empty_without_a_time_term(self):
        spec = _spec()
        spec.criteria[0].criteria.children = spec.criteria[0].criteria.children[1:]
        self.assertEqual(spec.time_properties(), set())

    def test_each_string_term_carries_eight_context_guids(self):
        inner = _spec().criteria[0].criteria.children[1]
        for term in inner.children:
            self.assertEqual(term.tag, AIR_STRING_CONTEXT_TERM)
            self.assertEqual(len(term.contexts), 8)
        self.assertEqual(
            [str(g) for g in inner.children[0].contexts],
            [
                f"ec9f69{xx:02x}-7bf7-11ce-b577-00aa0060fa9a"
                for xx in (0xB9, 0xBD, 0xC2, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC)
            ],
        )


class TestRejectsWhatTheClientRejects(unittest.TestCase):
    def test_wrong_root_tag(self):
        # IRUT throws 0xF0000351 on a tag mismatch.
        data = bytearray(_FIXTURE.read_bytes())
        struct.pack_into("<H", data, 0, 0x00C1)
        with self.assertRaises(IRQueryError):
            parse_query_spec(bytes(data))

    def test_root_child_count_out_of_range(self):
        # BuildQuerySpec throws 0xF0000352 unless 1 < count < 4.
        data = bytearray(_FIXTURE.read_bytes())
        struct.pack_into("<H", data, 2, 4)
        with self.assertRaises(IRQueryError):
            parse_query_spec(bytes(data))

    def test_doc_property_marker_must_be_eight(self):
        # BuildSortDocProperty throws 0xF0000353 when +22 is not 8. The first
        # property sits at 12: 8 for the QuerySpec header, 4 for the list's.
        data = bytearray(_FIXTURE.read_bytes())
        struct.pack_into("<H", data, 12 + 22, 9)
        with self.assertRaises(IRQueryError):
            parse_query_spec(bytes(data))

    def test_empty_property_list(self):
        data = bytearray(_FIXTURE.read_bytes())
        struct.pack_into("<H", data, 10, 0)
        with self.assertRaises(IRQueryError):
            parse_query_spec(bytes(data))

    def test_truncated_buffer(self):
        with self.assertRaises(IRQueryError):
            parse_query_spec(_FIXTURE.read_bytes()[:-1])

    def test_trailing_bytes(self):
        with self.assertRaises(IRQueryError):
            parse_query_spec(_FIXTURE.read_bytes() + b"\x00")

    def test_empty_buffer(self):
        with self.assertRaises(IRQueryError):
            parse_query_spec(b"")


class TestSyntheticShapes(unittest.TestCase):
    """Paths the one capture does not exercise."""

    _PROP_GUID = uuid.UUID("ec9f69c5-7bf7-11ce-b577-00aa0060fa9a")

    def _doc_property(self, extra=b""):
        return (
            struct.pack("<HH", 0x000A, 0)
            + self._PROP_GUID.bytes_le
            + struct.pack("<HHH", 0, 8, len(extra))
            + extra
        )

    def _spec_bytes(self, n_children=2, criteria_body=b"", sort_list=b""):
        return (
            struct.pack("<HHI", 0x00C0, n_children, 50)
            + struct.pack("<HH", 0x0080, 1)
            + self._doc_property()
            + struct.pack("<HH", 0x00A0, 1)
            + struct.pack("<HHI", 0x0090, 0 if not criteria_body else 2, 7)
            + self._PROP_GUID.bytes_le
            + struct.pack("<I", 0)
            + criteria_body
            + sort_list
        )

    def test_criteria_spec_with_no_children_stops_after_its_header(self):
        spec = parse_query_spec(self._spec_bytes())
        self.assertEqual(spec.criteria[0].sources, [])
        self.assertIsNone(spec.criteria[0].criteria)

    def test_sort_property_list_read_when_child_count_is_three(self):
        sort_list = struct.pack("<HH", 0x00B0, 1) + self._doc_property()
        spec = parse_query_spec(self._spec_bytes(n_children=3, sort_list=sort_list))
        self.assertEqual(len(spec.sort_properties), 1)
        self.assertEqual(spec.sort_properties[0].guid, self._PROP_GUID)

    def test_doc_property_extra_bytes_extend_the_record(self):
        # BuildSortDocProperty sizes the record 26 + the WORD at +24.
        sort_list = struct.pack("<HH", 0x00B0, 1) + self._doc_property(extra=b"\xde\xad\xbe\xef")
        spec = parse_query_spec(self._spec_bytes(n_children=3, sort_list=sort_list))
        self.assertEqual(spec.sort_properties[0].extra, b"\xde\xad\xbe\xef")

    def test_dword_valued_string_term(self):
        # BuildCriteria admits value type 3 alongside 8.
        term = (
            struct.pack("<H", 0x0002)
            + self._PROP_GUID.bytes_le
            + struct.pack("<HH", 3, 4)
            + struct.pack("<I", 0x2A)
            + b"\x01\x00"
        )
        body = struct.pack("<HH", 0x0070, 0) + term
        spec = parse_query_spec(self._spec_bytes(criteria_body=body))
        self.assertEqual(spec.criteria[0].criteria.value, 0x2A)
        self.assertEqual(spec.criteria[0].criteria.flag, 1)

    def test_unknown_value_type_rejected(self):
        term = (
            struct.pack("<H", 0x0002)
            + self._PROP_GUID.bytes_le
            + struct.pack("<HH", 4, 4)
            + struct.pack("<I", 0)
            + b"\x00\x00"
        )
        body = struct.pack("<HH", 0x0070, 0) + term
        with self.assertRaises(IRQueryError):
            parse_query_spec(self._spec_bytes(criteria_body=body))

    def test_unknown_air_tag_rejected(self):
        body = struct.pack("<HH", 0x0070, 0) + struct.pack("<H", 0x00FF)
        with self.assertRaises(IRQueryError):
            parse_query_spec(self._spec_bytes(criteria_body=body))


if __name__ == "__main__":
    unittest.main()
