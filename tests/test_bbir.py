"""BBIRService: the Blackbird search channel."""

import datetime
import pathlib
import struct
import unittest
import uuid
from unittest.mock import patch

from server.blackbird.irindex import Document
from server.blackbird.irresults import (
    TAG_CONTEXT_INFO,
    TAG_PROP_INFOS,
    TAG_RESULT_ROW,
    TAG_SORT_INFOS,
    decode_bbir_time,
)
from server.config import (
    BBIR_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.mpc import (
    parse_host_block,
)
from server.services import SERVICE_HANDLERS
from server.services.bbir import (
    BBIR_SELECTOR_GET_SEARCH_OBJECTS,
    BBIR_SELECTOR_GET_SOURCES,
    BBIR_SELECTOR_QUERY,
    BbirHandler,
)
from server.session import Session
from server.transport import parse_packet


class TestBBIRService(unittest.TestCase):
    """BBIRService — Blackbird's Find back end (IRCS.DLL).

    Pins the negotiation IRCS.DLL:0x10005fda performs and the record framing
    IRUT.DLL:0x1000bcdd/0x1000bdda reads back out of the reply stream.
    """

    def test_single_interface_guid(self):
        # IRCS.DLL:0x10009008, passed to CMPCConnection with the version dword
        # at 0x10009000. One caller, so one IID.
        self.assertEqual(len(BBIR_INTERFACE_GUIDS), 1)
        guid, msg_class = BBIR_INTERFACE_GUIDS[0]
        self.assertEqual(guid, uuid.UUID("27916FC1-7F7F-11CE-A366-00AA0051EA9C").bytes_le)
        self.assertEqual(msg_class, 0x01)

    def test_service_name_resolves_handler(self):
        # The pipe-open carries "BBIRService"; the registry keys on casefold().
        self.assertIs(SERVICE_HANDLERS["BBIRService".casefold()], BbirHandler)

    def test_discovery_packet_is_well_formed(self):
        handler = BbirHandler(1, "BBIRService", Session())
        pkts = handler.build_discovery_packet(3, 3)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)

    def _get_sources_reply_payloads(self):
        """The two host-block payloads a GetSrcs call answers with."""
        handler = BbirHandler(1, "BBIRService", Session())
        pkts = handler.handle_request(
            0x01, BBIR_SELECTOR_GET_SOURCES, 7, b"\x03\x00\x00\x00\x00", 5, 5
        )
        self.assertEqual(len(pkts), 2)

        payloads = []
        for pkt in pkts:
            parsed = parse_packet(pkt[:-1])
            self.assertTrue(parsed.crc_ok)
            # Frame layout: header byte, u16 content length, u16 routing, host block.
            self.assertEqual(struct.unpack_from("<H", parsed.payload, 3)[0], 1)
            host_block = parse_host_block(parsed.payload[5:])
            self.assertEqual(host_block.selector, BBIR_SELECTOR_GET_SOURCES)
            self.assertEqual(host_block.request_id, 7)
            payloads.append(host_block.payload)
        return payloads

    def test_get_sources_reply_is_dynamic_stream_then_complete(self):
        # The command object derives from CMPCDynReadDataSource (IRCS
        # 0x10003c8b), so the reply is a dynamic stream: 0x87 0x88 + bytes,
        # then a bare 0x86 to release the waiter.
        payloads = self._get_sources_reply_payloads()
        self.assertEqual(payloads[0][:2], bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))
        self.assertEqual(payloads[1], bytes([TAG_DYNAMIC_COMPLETE_SIGNAL]))

    def test_stream_holds_one_cmd_completed_record(self):
        # CIRClientRcvInfo::PeekHeader (IRUT.DLL:0x1000bcdd) reads WORD tag,
        # DWORD body length, and requires the whole body to be present.
        # CSrvrMsgQryCompleted::Serialize (0x100191d9) writes two dwords.
        stream = self._get_sources_reply_payloads()[0][2:]
        tag, cb_body = struct.unpack_from("<HI", stream)
        self.assertEqual(tag, 0x23)  # ISrvrMsgCmdCompleted
        self.assertEqual(cb_body, 8)
        self.assertEqual(len(stream), 6 + cb_body)
        self.assertEqual(struct.unpack_from("<II", stream, 6), (0, 0))

    def test_every_known_selector_answers(self):
        # Leaving one unanswered reproduces the hang the handler exists to fix.
        for selector in (
            BBIR_SELECTOR_GET_SOURCES,
            BBIR_SELECTOR_GET_SEARCH_OBJECTS,
            BBIR_SELECTOR_QUERY,
        ):
            with self.subTest(selector=selector):
                handler = BbirHandler(1, "BBIRService", Session())
                pkts = handler.handle_request(0x01, selector, 1, b"", 5, 5)
                self.assertEqual(len(pkts), 2)

    def test_unknown_selector_returns_none(self):
        handler = BbirHandler(1, "BBIRService", Session())
        self.assertIsNone(handler.handle_request(0x01, 0x09, 1, b"", 5, 5))

    def test_query_head_waits_for_its_chunked_spec(self):
        # Observed head, 2026-08-13: u32, chunked ref (stream 1, 0x21d bytes),
        # u32, 0x85. The IQuerySpec is not inline, so answering on the head
        # completes the request while the client is still streaming.
        handler = BbirHandler(7, "BBIRService", Session())
        head = bytes.fromhex("030000000005011d020000030000000085")
        self.assertIsNone(handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5))

        # 0xE6 carries more, 0xE7 closes. Only the close produces the reply.
        self.assertIsNone(handler.handle_request(0xE6, 0x01, 0, b"\xc0\x00", 5, 5))
        pkts = handler.handle_request(0xE7, 0x01, 0, b"\x02\x00", 5, 5)
        self.assertEqual(len(pkts), 2)

    def test_continuation_frames_reassemble_in_order(self):
        handler = BbirHandler(7, "BBIRService", Session())
        head = bytes.fromhex("030000000005010600000085")
        handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5)
        with patch.object(handler, "_capture") as capture:
            handler.handle_request(0xE6, 0x01, 0, b"\xaa\xbb", 5, 5)
            handler.handle_request(0xE6, 0x01, 0, b"\xcc\xdd", 5, 5)
            handler.handle_request(0xE7, 0x01, 0, b"\xee\xff", 5, 5)
        capture.assert_called_once_with("stream1", b"\xaa\xbb\xcc\xdd\xee\xff")

    def test_unclaimed_stream_is_not_answered(self):
        # No head quoted stream 3, so closing it must not fabricate a reply
        # against a request id nobody is waiting on.
        handler = BbirHandler(7, "BBIRService", Session())
        with patch.object(handler, "_capture"):
            self.assertIsNone(handler.handle_request(0xE7, 0x03, 0, b"\x00", 5, 5))

    def test_captured_query_is_decoded_into_the_log(self):
        # The whole path: the observed head, then the real 541-byte spec.
        blob = (
            pathlib.Path(__file__).resolve().parent / "assets" / "bbir_queryspec.bin"
        ).read_bytes()
        head = (
            b"\x03\x00\x00\x00\x00\x05\x01"
            + struct.pack("<I", len(blob))
            + b"\x03\x00\x00\x00\x00\x85"
        )
        handler = BbirHandler(7, "BBIRService", Session())
        with patch.object(handler, "_capture"):
            self.assertIsNone(handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5))
            with self.assertLogs("server.services.bbir", level="INFO") as logs:
                pkts = handler.handle_request(0xE7, 0x01, 0, blob, 5, 5)

        self.assertEqual(len(pkts), 2)
        decoded = [line for line in logs.output if "bbir_queryspec " in line]
        self.assertEqual(len(decoded), 1)
        self.assertIn("terms='search','term!'", decoded[0])
        self.assertIn("max_results=100", decoded[0])
        self.assertIn("d439ef41-51f5-11f1-b405-000c875355c8", decoded[0])

    def test_matching_query_returns_a_row(self):
        # Retarget the captured spec at text the fixture documents contain.
        # Same lengths keep every downstream offset in the blob valid.
        blob = bytearray(
            (pathlib.Path(__file__).resolve().parent / "assets" / "bbir_queryspec.bin").read_bytes()
        )
        for old_term, new_term in ((b"search", b"ackbir"), (b"term!", b"yadda")):
            at = blob.find(old_term + b"\0")
            blob[at : at + len(old_term)] = new_term
        blob = bytes(blob)

        docs = [
            Document(
                guid=b"\0" * 16,
                storage_path="8/4",
                title="x2qrj4anuhas42kd2117sgjalgs",
                text="Blackbird title\nStory text yadda yadda yadda",
            )
        ]
        handler = BbirHandler(7, "BBIRService", Session())
        head = (
            b"\x03\x00\x00\x00\x00\x05\x01"
            + struct.pack("<I", len(blob))
            + b"\x03\x00\x00\x00\x00\x85"
        )
        with (
            patch.object(handler, "_capture"),
            patch("server.blackbird.irindex.load_documents", return_value=docs),
        ):
            handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5)
            pkts = handler.handle_request(0xE7, 0x01, 0, blob, 5, 5)

        body = b"".join(
            parse_host_block(parse_packet(pkt[:-1]).payload[5:]).payload for pkt in pkts
        )
        self.assertEqual(body[:2], bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))
        self.assertEqual(body[-1], TAG_DYNAMIC_COMPLETE_SIGNAL)

        stream = body[2:-1]
        records = []
        pos = 0
        while pos < len(stream):
            tag, length = struct.unpack_from("<HI", stream, pos)
            records.append((tag, stream[pos + 6 : pos + 6 + length]))
            pos += 6 + length
        self.assertEqual(pos, len(stream), "records must consume the stream exactly")

        # Schema, sort keys, one context, one row, completion. Tag 4 carries a
        # single CContext with no count prefix — a body the client's Load does
        # not consume byte-for-byte desyncs the stream and costs every record
        # after it.
        self.assertEqual(
            [tag for tag, _b in records],
            [TAG_PROP_INFOS, TAG_SORT_INFOS, TAG_CONTEXT_INFO, TAG_RESULT_ROW, 0x23],
        )
        context = records[2][1]
        flags = struct.unpack_from("<H", context)[0]
        self.assertEqual(flags, 0x7)
        self.assertEqual(len(context), 2 + 4 + 3 * 16)
        # The row indexes the contexts in arrival order; CContexts::GetAt
        # bounds-checks it, and a miss costs the source column and the open.
        self.assertLess(struct.unpack_from("<I", records[3][1])[0], 1)
        # The schema declares one column per property the query asked for.
        self.assertEqual(struct.unpack_from("<I", records[0][1])[0], 4)

        row = records[3][1]
        doc_id, rank, array_len = struct.unpack_from("<III", row)
        self.assertEqual(doc_id, 0)
        self.assertEqual(rank, 4)  # "ackbir" once, "yadda" three times
        array = row[12:]
        self.assertEqual(len(array), array_len)

        def column(index):
            offset = struct.unpack_from("<I", array, index * 4)[0]
            return array[offset : array.index(b"\0", offset)]

        # The result list hardwires which column each subitem reads
        # (IRFIND.DLL:0x1000e2b0): subitem 0 takes column 2, subitem 1 falls
        # back to column 1, subitem 2 takes column 3. Column 0 is never shown.
        self.assertEqual(column(0), b"")
        self.assertEqual(column(1), b"x2qrj4anuhas42kd2117sgjalgs")
        self.assertEqual(column(2), b"Blackbird title")

    def test_date_column_is_typed_and_carries_a_real_date(self):
        """Regression for the IRFIND.DLL:0x1000e425 null dereference.

        The Find UI reads the property its own time term filters on with the
        getter that demands type 0x17, ignores the failure, and hands the
        value to CTime. Served as a string the value stays 0, CTime::GetLocalTm
        returns NULL, and IRFIND dereferences it anyway.
        """
        blob = (
            pathlib.Path(__file__).resolve().parent / "assets" / "bbir_queryspec.bin"
        ).read_bytes()
        docs = [
            Document(
                guid=b"\0" * 16,
                storage_path="8/4",
                title="t",
                text="search term!",
                modified=datetime.datetime(2026, 8, 12, 16, 8),
            )
        ]
        handler = BbirHandler(7, "BBIRService", Session())
        head = (
            b"\x03\x00\x00\x00\x00\x05\x01"
            + struct.pack("<I", len(blob))
            + b"\x03\x00\x00\x00\x00\x85"
        )
        with (
            patch.object(handler, "_capture"),
            patch("server.blackbird.irindex.load_documents", return_value=docs),
        ):
            handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5)
            pkts = handler.handle_request(0xE7, 0x01, 0, blob, 5, 5)

        body = b"".join(
            parse_host_block(parse_packet(pkt[:-1]).payload[5:]).payload for pkt in pkts
        )
        stream = body[2:-1]
        records = []
        pos = 0
        while pos < len(stream):
            tag, length = struct.unpack_from("<HI", stream, pos)
            records.append((tag, stream[pos + 6 : pos + 6 + length]))
            pos += 6 + length

        # Column 3 is ec9f69be, the property the query's time term targets.
        schema = records[0][1]
        offset = 4
        types = []
        for _ in range(struct.unpack_from("<I", schema)[0]):
            offset += 16
            name_len = struct.unpack_from("<I", schema, offset)[0]
            offset += 4 + name_len
            types.append(struct.unpack_from("<H", schema, offset)[0])
            offset += 6
        self.assertEqual(types, [0x08, 0x08, 0x08, 0x17])

        row = records[3][1]
        array = row[12:]
        # The slot is an offset; the packed DWORD lives where it points. An
        # inline value gets dereferenced as an offset and aborts the client.
        offset = struct.unpack_from("<4I", array)[3]
        self.assertLessEqual(offset + 4, len(array))
        packed = struct.unpack_from("<I", array, offset)[0]
        self.assertEqual(decode_bbir_time(packed), (2026, 8, 12, 16, 8))

    def test_non_matching_query_returns_no_rows(self):
        blob = (
            pathlib.Path(__file__).resolve().parent / "assets" / "bbir_queryspec.bin"
        ).read_bytes()
        handler = BbirHandler(7, "BBIRService", Session())
        head = (
            b"\x03\x00\x00\x00\x00\x05\x01"
            + struct.pack("<I", len(blob))
            + b"\x03\x00\x00\x00\x00\x85"
        )
        with (
            patch.object(handler, "_capture"),
            patch("server.blackbird.irindex.load_documents", return_value=[]),
        ):
            handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5)
            pkts = handler.handle_request(0xE7, 0x01, 0, blob, 5, 5)

        body = b"".join(
            parse_host_block(parse_packet(pkt[:-1]).payload[5:]).payload for pkt in pkts
        )
        stream = body[2:-1]
        tags = []
        pos = 0
        while pos < len(stream):
            tag, length = struct.unpack_from("<HI", stream, pos)
            tags.append(tag)
            pos += 6 + length
        # Schema still goes out; the client needs it to render an empty list.
        self.assertEqual(tags, [TAG_PROP_INFOS, TAG_SORT_INFOS, 0x23])

    def test_undecodable_query_still_gets_an_answer(self):
        handler = BbirHandler(7, "BBIRService", Session())
        head = b"\x03\x00\x00\x00\x00\x05\x01\x04\x00\x00\x00\x03\x00\x00\x00\x00\x85"
        with patch.object(handler, "_capture"):
            handler.handle_request(0x01, BBIR_SELECTOR_QUERY, 0, head, 5, 5)
            with self.assertLogs("server.services.bbir", level="ERROR") as logs:
                pkts = handler.handle_request(0xE7, 0x01, 0, b"\xff\xff\x00\x00", 5, 5)
        self.assertEqual(len(pkts), 2)
        self.assertTrue(any("bbir_queryspec_unparsed" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
