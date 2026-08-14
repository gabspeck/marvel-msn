"""Tests for `src.server.blackbird.irresults` — the IR result-stream encoder.

Pin every byte against the serializers the client reads them back with:

    CIRClientRcvInfo::PeekHeader  IRUT.DLL:0x1000bcdd  record header
    CPropInfos::Serialize         IRUT.DLL:0x100177d0
    CPropInfo::Serialize          IRUT.DLL:0x10016ef1
    CSortInfos::Serialize         IRUT.DLL:0x10014d70
    CSortInfo::Serialize          IRUT.DLL:0x10014542
    CResultRow::Serialize         IRUT.DLL:0x1001a93c
    CBetterByteArray::Serialize   IRUT.DLL:0x1001b3c6
    CResultRow column access      IRUT.DLL:0x1001a105 / 0x1001a250 / 0x1001a208
"""

import datetime
import struct
import unittest
import uuid

from server.blackbird.irresults import (
    PROP_TYPE_DWORD,
    PROP_TYPE_GUID,
    PROP_TYPE_STRING,
    PROP_TYPE_TIME,
    TAG_CMD_COMPLETED,
    TAG_CONTEXT_INFO,
    TAG_PROP_INFOS,
    TAG_RESULT_ROW,
    TAG_SORT_INFOS,
    Context,
    IRResultError,
    PropInfo,
    ResultRow,
    SortInfo,
    decode_bbir_time,
    encode_bbir_time,
    encode_cmd_completed,
    encode_context,
    encode_prop_infos,
    encode_result_row,
    encode_result_stream,
    encode_sort_infos,
    ir_record,
)

_GUID_A = uuid.UUID("ec9f69c5-7bf7-11ce-b577-00aa0060fa9a")
_GUID_B = uuid.UUID("ec9f69c6-7bf7-11ce-b577-00aa0060fa9a")


def _split_records(stream):
    """Walk the stream the way CCmdExec::MoreData drains GetObj."""
    records = []
    pos = 0
    while pos < len(stream):
        tag, length = struct.unpack_from("<HI", stream, pos)
        body = stream[pos + 6 : pos + 6 + length]
        if len(body) != length:
            raise AssertionError(f"record at {pos} is short: {len(body)} of {length}")
        records.append((tag, body))
        pos += 6 + length
    return records


class TestRecordFraming(unittest.TestCase):
    def test_header_is_word_tag_then_dword_length(self):
        self.assertEqual(ir_record(0x23, b"\xaa\xbb"), b"\x23\x00\x02\x00\x00\x00\xaa\xbb")

    def test_length_covers_the_body_alone(self):
        # PeekHeader requires pos + cbBody <= avail, with the 6 header bytes
        # already consumed, so the count must exclude them.
        record = ir_record(0x01, b"x" * 40)
        _tag, length = struct.unpack_from("<HI", record)
        self.assertEqual(length, 40)
        self.assertEqual(len(record), 46)


class TestPropInfos(unittest.TestCase):
    def test_layout(self):
        record = encode_prop_infos([PropInfo(_GUID_A, "Title", PROP_TYPE_STRING, 0x11)])
        tag, body = _split_records(record)[0]
        self.assertEqual(tag, TAG_PROP_INFOS)
        self.assertEqual(
            body,
            struct.pack("<I", 1)
            + _GUID_A.bytes_le
            + struct.pack("<I", 5)
            + b"Title"
            + struct.pack("<H", PROP_TYPE_STRING)
            + struct.pack("<I", 0x11),
        )

    def test_string_has_no_nul_terminator(self):
        # operator<<(CFile&, CString&) at 0x1001c8f0 writes the length then
        # exactly that many chars, so the type WORD abuts the last one.
        _tag, body = _split_records(encode_prop_infos([PropInfo(_GUID_A, "ab")]))[0]
        self.assertIn(
            struct.pack("<I", 2) + b"ab" + struct.pack("<H", PROP_TYPE_STRING),
            body,
        )

    def test_empty_schema(self):
        _tag, body = _split_records(encode_prop_infos([]))[0]
        self.assertEqual(body, struct.pack("<I", 0))


class TestSortInfos(unittest.TestCase):
    def test_layout(self):
        record = encode_sort_infos([SortInfo(_GUID_A, 1), SortInfo(_GUID_B, 0)])
        tag, body = _split_records(record)[0]
        self.assertEqual(tag, TAG_SORT_INFOS)
        self.assertEqual(
            body,
            struct.pack("<I", 2)
            + _GUID_A.bytes_le
            + struct.pack("<H", 1)
            + _GUID_B.bytes_le
            + struct.pack("<H", 0),
        )

    def test_empty_list_still_emits_a_count(self):
        _tag, body = _split_records(encode_sort_infos([]))[0]
        self.assertEqual(body, struct.pack("<I", 0))


class TestResultRow(unittest.TestCase):
    def test_header_is_two_dwords_then_the_byte_array(self):
        columns = [PropInfo(_GUID_A, "n", PROP_TYPE_DWORD)]
        tag, body = _split_records(encode_result_row(ResultRow(7, 42, [0xABCD]), columns))[0]
        self.assertEqual(tag, TAG_RESULT_ROW)
        doc_id, rank, array_len = struct.unpack_from("<III", body)
        self.assertEqual((doc_id, rank), (7, 42))
        # One slot plus the DWORD it points at.
        self.assertEqual(array_len, 8)
        self.assertEqual(len(body), 12 + array_len)

    def test_numeric_slots_are_offsets_not_values(self):
        """Regression for the abort at IRUT.DLL:0x1001b52a.

        FUN_1001a14e reads slot[col] then calls AtDWORD with it, so a value
        written inline gets dereferenced as an offset. AssureGet throws
        0x800401BF, nothing catches it, and the CRT aborts with "abnormal
        program termination". Confirmed live under SoftICE.
        """
        columns = [
            PropInfo(_GUID_A, "a", PROP_TYPE_DWORD),
            PropInfo(_GUID_B, "b", PROP_TYPE_TIME),
        ]
        _tag, body = _split_records(encode_result_row(ResultRow(1, 0, [5, 9]), columns))[0]
        array = body[12:]
        first, second = struct.unpack_from("<II", array)
        # Offsets past the 8-byte slot table, not the values 5 and 9.
        self.assertEqual((first, second), (8, 12))
        self.assertEqual(struct.unpack_from("<I", array, first)[0], 5)
        self.assertEqual(struct.unpack_from("<I", array, second)[0], 9)
        self.assertEqual(len(array), 16)

    def test_every_slot_points_inside_the_array(self):
        # The invariant AssureGet enforces: offset + size <= len(array).
        columns = [
            PropInfo(_GUID_A, "n", PROP_TYPE_TIME),
            PropInfo(_GUID_B, "s", PROP_TYPE_STRING),
            PropInfo(_GUID_A, "g", PROP_TYPE_GUID),
        ]
        row = ResultRow(1, 0, [1214041928, "hi", _GUID_B])
        _tag, body = _split_records(encode_result_row(row, columns))[0]
        array = body[12:]
        sizes = [4, len("hi") + 1, 16]
        for index, size in enumerate(sizes):
            offset = struct.unpack_from("<I", array, index * 4)[0]
            self.assertLessEqual(offset + size, len(array))

    def test_string_slot_holds_an_offset_to_a_nul_terminated_string(self):
        # GetString does AtDWORD(col * 4) then GetAt(offset), and GetAt stops
        # at the NUL, so the payload must carry one.
        columns = [
            PropInfo(_GUID_A, "a", PROP_TYPE_STRING),
            PropInfo(_GUID_B, "b", PROP_TYPE_STRING),
        ]
        _tag, body = _split_records(
            encode_result_row(ResultRow(1, 0, ["one", "two"]), columns)
        )[0]
        array = body[12:]
        first, second = struct.unpack_from("<II", array)
        # The slot table is 4 bytes per column, so payloads start after it.
        self.assertEqual(first, 8)
        self.assertEqual(second, 12)
        self.assertEqual(array[first : array.index(b"\0", first)], b"one")
        self.assertEqual(array[second : array.index(b"\0", second)], b"two")

    def test_guid_slot_holds_an_offset_to_sixteen_raw_bytes(self):
        columns = [PropInfo(_GUID_A, "id", PROP_TYPE_GUID)]
        _tag, body = _split_records(encode_result_row(ResultRow(1, 0, [_GUID_B]), columns))[0]
        array = body[12:]
        (offset,) = struct.unpack_from("<I", array)
        self.assertEqual(offset, 4)
        self.assertEqual(array[offset : offset + 16], _GUID_B.bytes_le)

    def test_mixed_columns_offset_past_the_whole_slot_table(self):
        columns = [
            PropInfo(_GUID_A, "n", PROP_TYPE_DWORD),
            PropInfo(_GUID_B, "s", PROP_TYPE_STRING),
            PropInfo(_GUID_A, "g", PROP_TYPE_GUID),
        ]
        _tag, body = _split_records(
            encode_result_row(ResultRow(1, 0, [3, "hi", _GUID_B]), columns)
        )[0]
        array = body[12:]
        number_at, string_at, guid_at = struct.unpack_from("<III", array)
        self.assertEqual((number_at, string_at, guid_at), (12, 16, 19))
        self.assertEqual(struct.unpack_from("<I", array, number_at)[0], 3)
        self.assertEqual(array[string_at : string_at + 3], b"hi\0")
        self.assertEqual(array[guid_at : guid_at + 16], _GUID_B.bytes_le)

    def test_value_count_must_match_the_schema(self):
        columns = [PropInfo(_GUID_A, "a", PROP_TYPE_DWORD)]
        with self.assertRaises(IRResultError):
            encode_result_row(ResultRow(1, 0, [1, 2]), columns)

    def test_unreadable_column_type_rejected(self):
        # FUN_1001a420 admits 2, 3, 8, 0x12, 0x13, 0x17 and 0x48; a column
        # typed anything else cannot be read back at all.
        columns = [PropInfo(_GUID_A, "a", 0x99)]
        with self.assertRaises(IRResultError):
            encode_result_row(ResultRow(1, 0, ["x"]), columns)


class TestBBIRTime(unittest.TestCase):
    """CTimeToBBIRTime IRUT.DLL:0x1001b7f3 / BBIRTimeToCTime 0x1001b76b."""

    def test_formula(self):
        when = datetime.datetime(2026, 8, 12, 16, 8)
        expected = (2026 * 13 + 8) * 46080 + 12 * 1440 + 16 * 60 + 8
        self.assertEqual(encode_bbir_time(when), expected)

    def test_round_trip(self):
        for when in (
            datetime.datetime(1995, 8, 24, 0, 0),
            datetime.datetime(2026, 1, 1, 0, 0),
            datetime.datetime(2026, 12, 31, 23, 59),
        ):
            with self.subTest(when=when):
                packed = encode_bbir_time(when)
                self.assertEqual(
                    decode_bbir_time(packed),
                    (when.year, when.month, when.day, when.hour, when.minute),
                )

    def test_fits_a_dword(self):
        # The observed query bounded its time term at 0x7FFFFFFF, so a real
        # date has to land under that as well as inside a DWORD.
        self.assertLess(encode_bbir_time(datetime.datetime(2038, 12, 31, 23, 59)), 0x7FFFFFFF)

    def test_seconds_are_dropped(self):
        # BBIRTimeToCTime passes 0 for seconds; resolution is one minute.
        base = datetime.datetime(2026, 8, 12, 16, 8)
        self.assertEqual(encode_bbir_time(base), encode_bbir_time(base.replace(second=59)))


class TestContexts(unittest.TestCase):
    """CContexts::Serialize 0x10013123 / CContext::Serialize 0x10012751."""

    def test_body_is_one_context_with_no_count_prefix(self):
        # Tag 4 builds a single CContext (CLSID {AE97A530-...}), not the
        # CContexts collection. A count prefix desyncs the whole stream.
        record = encode_context(Context(guid_04=_GUID_A, value=7))
        tag, body = _split_records(record)[0]
        self.assertEqual(tag, TAG_CONTEXT_INFO)
        self.assertEqual(
            body, struct.pack("<H", 0x4) + struct.pack("<I", 7) + _GUID_A.bytes_le
        )

    def test_flags_report_which_guids_are_present(self):
        self.assertEqual(Context().flags, 0)
        self.assertEqual(Context(guid_24=_GUID_A).flags, 0x1)
        self.assertEqual(Context(guid_14=_GUID_A).flags, 0x2)
        self.assertEqual(Context(guid_04=_GUID_A).flags, 0x4)
        self.assertEqual(Context(_GUID_A, _GUID_B, _GUID_A).flags, 0x7)

    def test_guids_are_written_in_serialize_order(self):
        # CContext::Serialize reads +0x24, then +0x14, then +0x04.
        ctx = Context(guid_04=_GUID_A, guid_14=_GUID_B, guid_24=_GUID_A)
        _tag, body = _split_records(encode_context(ctx))[0]
        guids = body[6:]
        self.assertEqual(guids[0:16], _GUID_A.bytes_le)   # +0x24
        self.assertEqual(guids[16:32], _GUID_B.bytes_le)  # +0x14
        self.assertEqual(guids[32:48], _GUID_A.bytes_le)  # +0x04

    def test_absent_guids_are_omitted_entirely(self):
        _tag, body = _split_records(encode_context(Context(guid_14=_GUID_B)))[0]
        self.assertEqual(len(body), 2 + 4 + 16)

    def test_context_with_no_guids_is_just_flags_and_value(self):
        _tag, body = _split_records(encode_context(Context()))[0]
        self.assertEqual(body, struct.pack("<H", 0) + struct.pack("<I", 0))


class TestCmdCompleted(unittest.TestCase):
    def test_layout(self):
        tag, body = _split_records(encode_cmd_completed(11, 22))[0]
        self.assertEqual(tag, TAG_CMD_COMPLETED)
        self.assertEqual(body, struct.pack("<II", 11, 22))


class TestResultStream(unittest.TestCase):
    _COLUMNS = [
        PropInfo(_GUID_A, "heading", PROP_TYPE_STRING),
        PropInfo(_GUID_B, "rank", PROP_TYPE_DWORD),
    ]

    def test_contexts_precede_every_row_one_record_each(self):
        # Contexts are appended as their records arrive, so they all have to
        # land before the first row or row->vt[0x34] indexes nothing.
        stream = encode_result_stream(
            self._COLUMNS,
            [ResultRow(0, 5, ["a", 5]), ResultRow(1, 3, ["b", 3])],
            contexts=[Context(guid_04=_GUID_A), Context(guid_04=_GUID_B)],
        )
        tags = [tag for tag, _b in _split_records(stream)]
        self.assertEqual(
            tags,
            [
                TAG_PROP_INFOS,
                TAG_SORT_INFOS,
                TAG_CONTEXT_INFO,
                TAG_CONTEXT_INFO,
                TAG_RESULT_ROW,
                TAG_RESULT_ROW,
                TAG_CMD_COMPLETED,
            ],
        )

    def test_no_contexts_record_when_there_are_none(self):
        tags = [tag for tag, _b in _split_records(encode_result_stream(self._COLUMNS, []))]
        self.assertNotIn(TAG_CONTEXT_INFO, tags)

    def test_schema_precedes_every_row(self):
        # A row resolves its column types through the schema, so PropInfos has
        # to land first.
        stream = encode_result_stream(
            self._COLUMNS, [ResultRow(1, 5, ["a", 5]), ResultRow(2, 3, ["b", 3])]
        )
        tags = [tag for tag, _body in _split_records(stream)]
        self.assertEqual(
            tags,
            [TAG_PROP_INFOS, TAG_SORT_INFOS, TAG_RESULT_ROW, TAG_RESULT_ROW, TAG_CMD_COMPLETED],
        )

    def test_stream_walks_cleanly_to_its_end(self):
        stream = encode_result_stream(self._COLUMNS, [ResultRow(1, 5, ["a", 5])])
        self.assertEqual(len(_split_records(stream)), 4)

    def test_empty_result_set_still_ends_with_completed(self):
        tags = [tag for tag, _body in _split_records(encode_result_stream(self._COLUMNS, []))]
        self.assertEqual(tags, [TAG_PROP_INFOS, TAG_SORT_INFOS, TAG_CMD_COMPLETED])

    def test_sort_keys_are_carried(self):
        stream = encode_result_stream(self._COLUMNS, [], sort_keys=[SortInfo(_GUID_A, 1)])
        _tag, body = _split_records(stream)[1]
        self.assertEqual(body, struct.pack("<I", 1) + _GUID_A.bytes_le + struct.pack("<H", 1))


if __name__ == "__main__":
    unittest.main()
