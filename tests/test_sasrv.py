"""SASRV: the master-list enumerator behind the Security page."""

import struct
import unittest

from server.config import (
    SASRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_END_STATIC,
)
from server.services.sasrv import (
    SA_E_BAD_LIST_KIND,
    SASRV_TOKENS,
    SasrvHandler,
)
from server.session import Session
from server.transport import parse_packet

from .support import (
    signed_in,
)


class TestSASRVServiceMap(unittest.TestCase):
    def test_catalog_matches_saclient_table(self):
        self.assertEqual(len(SASRV_INTERFACE_GUIDS), 29)
        self.assertEqual(
            [selector for _guid, selector in SASRV_INTERFACE_GUIDS],
            list(range(1, 30)),
        )

    def test_produces_discovery_packet(self):
        packets = SasrvHandler(5, "SASRV", Session()).build_discovery_packet(4, 4)
        parsed = parse_packet(packets[0][:-1])
        self.assertTrue(parsed.crc_ok)


class TestSASRVMasterListEnum(unittest.TestCase):
    """Selectors 0x02 / 0x04 — what the Security page's `Fetch(10)` runs.

    The BeginEnum payload below is the one the client sent on 2026-08-01 while
    opening Properties on node 1:270: list kind 10, a zero DWORD, a zero byte,
    and two receive descriptors.
    """

    BEGIN_ENUM_TOKENS = bytes.fromhex("030a000000030000000001008383")

    def setUp(self):
        self.handler = SasrvHandler(6, "SASRV", signed_in())

    @staticmethod
    def _list_page_request(handle, index):
        """Selector 0x05's send side: two DWORD params, then a WORD of 4."""
        return (
            b"\x03"
            + struct.pack("<I", handle)
            + b"\x03"
            + struct.pack("<I", index)
            + b"\x02\x04\x00"
            + b"\x83\x85"
        )

    def test_begin_enum_opens_a_handle_for_the_token_list(self):
        reply = self.handler.begin_enum_reply(self.BEGIN_ENUM_TOKENS)

        status, handle = (
            struct.unpack_from("<I", reply, 1)[0],
            struct.unpack_from("<I", reply, 6)[0],
        )
        self.assertEqual(status, 0)
        self.assertNotEqual(handle, 0)
        self.assertEqual(reply[10], TAG_END_STATIC)

    def test_read_enum_results_reports_the_row_count_then_status(self):
        begin = self.handler.begin_enum_reply(self.BEGIN_ENUM_TOKENS)
        handle = struct.unpack_from("<I", begin, 6)[0]

        reply = self.handler.read_enum_results_reply(
            b"\x03" + struct.pack("<I", handle) + b"\x83\x83"
        )

        count, status = struct.unpack_from("<I", reply, 1)[0], struct.unpack_from("<I", reply, 6)[0]
        self.assertEqual(count, len(SASRV_TOKENS))
        self.assertEqual(status, 0)

    def test_unknown_list_kind_is_refused(self):
        reply = self.handler.begin_enum_reply(
            b"\x03" + struct.pack("<I", 7) + b"\x03\x00\x00\x00\x00\x01\x00\x83\x83"
        )

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], SA_E_BAD_LIST_KIND)

    def test_unknown_handle_is_refused(self):
        reply = self.handler.read_enum_results_reply(b"\x03" + struct.pack("<I", 999) + b"\x83\x83")

        self.assertEqual(struct.unpack_from("<I", reply, 6)[0], SA_E_BAD_LIST_KIND)

    def test_list_page_packs_id_and_asciiz_name_per_row(self):
        """Captured request: handle 1, index 0, WORD 4, then `83 85`.

        The record layout is pinned by the consumer, SACLIENT 0x7F343973:
        `[u32 token_id][ASCIIZ name]`, stride 4 + strlen + 1.
        """
        begin = self.handler.begin_enum_reply(self.BEGIN_ENUM_TOKENS)
        self.assertEqual(struct.unpack_from("<I", begin, 6)[0], 1)

        reply = self.handler.get_list_page_reply(bytes.fromhex("030100000003000000000204008385"))

        self.assertEqual(reply[0], 0x83)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertEqual(reply[5], TAG_END_STATIC)
        self.assertEqual(reply[6], TAG_DYNAMIC_COMPLETE_SIGNAL)

        blob, pos = reply[7:], 0
        for token_id, name in SASRV_TOKENS:
            self.assertEqual(struct.unpack_from("<I", blob, pos)[0], token_id)
            end = blob.index(b"\x00", pos + 4)
            self.assertEqual(blob[pos + 4 : end].decode("ascii"), name)
            pos = end + 1
        self.assertEqual(pos, len(blob))

    def test_list_page_reads_the_index_from_the_second_dword(self):
        """The first DWORD is the handle, not the index.

        With a page size of 20 and 3 rows, index 0 and index 2 both resolve to
        page 0; an index past the end resolves to an empty page instead of
        reusing the handle as an offset.
        """
        self.handler.begin_enum_reply(self.BEGIN_ENUM_TOKENS)

        in_page = self.handler.get_list_page_reply(self._list_page_request(handle=1, index=2))
        past_end = self.handler.get_list_page_reply(self._list_page_request(handle=1, index=40))

        self.assertGreater(len(in_page), 7)
        self.assertEqual(len(past_end), 7)

    def test_end_enum_releases_the_handle(self):
        begin = self.handler.begin_enum_reply(self.BEGIN_ENUM_TOKENS)
        handle = struct.unpack_from("<I", begin, 6)[0]

        reply = self.handler.end_enum_reply(b"\x03" + struct.pack("<I", handle) + b"\x83")

        self.assertEqual(reply, b"\x83\x00\x00\x00\x00" + bytes([TAG_END_STATIC]))
        # A released handle no longer answers a row count.
        after = self.handler.read_enum_results_reply(
            b"\x03" + struct.pack("<I", handle) + b"\x83\x83"
        )
        self.assertEqual(struct.unpack_from("<I", after, 6)[0], SA_E_BAD_LIST_KIND)

    def test_both_selectors_route_through_handle_request(self):
        packets = self.handler.handle_request(
            msg_class=0x01,
            selector=0x02,
            request_id=0,
            payload=self.BEGIN_ENUM_TOKENS,
            server_seq=0,
            client_ack=0,
        )

        parsed = parse_packet(packets[0][:-1])
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(struct.unpack_from("<I", parsed.payload, 9)[0], 0)


if __name__ == "__main__":
    unittest.main()
