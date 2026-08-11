"""Tests for the FindSvc service handler (Find > MSN Service).

The wire contract is documented in docs/MOSFIND.md. The query grammar here is
a re-implementation of what `CQueryLexer_EmitToken` @ MOSFIND 0x7E9B37F8 emits
and what the "of type" combo ships out of STRINGTABLE 0x4EAC, so the fixtures
below are written as the client would send them, not as they are convenient to
parse.
"""

import struct
import unittest

from server.config import FINDSVC_INTERFACE_GUIDS
from server.mpc import decode_dirsrv_request
from server.services.conference import _room_for
from server.services.conference import _rooms as conference_rooms
from server.services.dirsrv import _size_value, build_get_properties_reply_payload
from server.services.findquery import QueryError, parse_query
from server.services.findsvc import (
    FINDSVC_CLASS_SEARCH,
    FINDSVC_SEARCH,
    FindSvcHandler,
    build_search_reply_blocks,
)
from server.store import app_store
from server.transport import parse_packet

# STRINGTABLE 0x4EAC, verbatim — the seven scope fragments the combo can ship.
SCOPE_ALL_MSN = "APPID <> 2 or BBS_FOLDER_FLAGS <> 0"
SCOPE_FOLDERS = "APPID = 1"
SCOPE_BBS = "APPID = 2 AND BBS_FOLDER_FLAGS = 1"
SCOPE_CHAT = "APPID = 4"
SCOPE_TITLES = "APPID in (6,11,12)"
SCOPE_KIOSKS = "APPID = 7"
SCOPE_NEWSGROUPS = "APPID = 2 AND BBS_FOLDER_FLAGS = 0"


def _request(query, arg=0):
    """A method-1 request as `CFindConnection::HrSearch` builds it."""
    text = query.encode("cp1252") + b"\x00"
    return (
        b"\x04"
        + (
            bytes([0x80 | len(text)])
            if len(text) < 0x80
            else bytes([(len(text) >> 8) & 0x7F, len(text) & 0xFF])
        )
        + text
        + b"\x03"
        + struct.pack("<I", arg)
        + b"\x83\x83\x85"
    )


def _split_reply(blocks):
    """Split the two reply blocks into (status, count, mnids).

    Block 0 is `0x83 [status] 0x83 [count] 0x87 0x88 [mnids]`, block 1 the bare
    `0x86` that ends the request.
    """
    data, complete = blocks
    assert complete == b"\x86", complete.hex()
    assert data[0] == 0x83, data[:4].hex()
    status = struct.unpack_from("<I", data, 1)[0]
    assert data[5] == 0x83, data[:8].hex()
    count = struct.unpack_from("<I", data, 6)[0]
    assert data[10] == 0x87, data[:12].hex()
    assert data[11] == 0x88, data[:12].hex()
    body = data[12:]
    assert len(body) % 8 == 0, len(body)
    return status, count, [body[i : i + 8] for i in range(0, len(body), 8)]


def _search(query):
    return _split_reply(build_search_reply_blocks(_request(query)))


def _names(mnids):
    """Resolve reply mnids back to node names through the directory store."""
    by_mnid = {node.mnid_a: node.content.name for node in app_store.content.all_nodes()}
    return [by_mnid[m] for m in mnids]


class TestFindSvcDiscovery(unittest.TestCase):
    def test_advertises_the_run_the_client_opens_on(self):
        # HrSearch hands slot 0x24 the array based at 0x7E9B45E8, whose first
        # entry is 00028BB0. Without it the channel is E_NOINTERFACE and the
        # dialog fails before any request reaches the wire.
        guid, selector = FINDSVC_INTERFACE_GUIDS[0]
        self.assertEqual(guid[:4], struct.pack("<I", 0x00028BB0))
        self.assertEqual(guid[4:], bytes.fromhex("00000000c000000000000046"))
        self.assertEqual(selector, FINDSVC_CLASS_SEARCH)

    def test_run_stops_before_logsrv_claims_00028bb6(self):
        tails = [struct.unpack_from("<I", guid)[0] for guid, _ in FINDSVC_INTERFACE_GUIDS]
        self.assertEqual(tails, list(range(0x00028BB0, 0x00028BB6)))

    def test_discovery_packet_carries_the_iid(self):
        handler = FindSvcHandler(pipe_idx=2, svc_name="FindSvc")
        packets = handler.build_discovery_packet(server_seq=1, client_ack=1)
        payload = b"".join(parse_packet(p).payload for p in packets)
        self.assertIn(struct.pack("<I", 0x00028BB0), payload)


class TestSearchFraming(unittest.TestCase):
    def test_reply_is_status_count_then_a_flat_mnid_array(self):
        status, count, mnids = _search(f"({SCOPE_FOLDERS})")
        self.assertEqual(status, 0)
        self.assertTrue(count)
        self.assertEqual(count, len(mnids))

    def test_ids_ride_0x88_and_a_bare_0x86_ends_the_request(self):
        # The mnids must arrive under 0x88 — 0x86 never reaches the iterator, so
        # PullMnidChunk would read an empty buffer. But 0x88 alone never sets
        # request+0x18, so WaitIncremental keeps answering 0x0B0B000C and the
        # dialog sits on "Retrieving results" with every row already resolved.
        data, complete = build_search_reply_blocks(_request(f"({SCOPE_FOLDERS})"))
        self.assertEqual(data[11], 0x88)
        self.assertEqual(complete, b"\x86")

    def test_completion_block_is_sent_even_with_no_hits(self):
        _data, complete = build_search_reply_blocks(_request("(NAME contains 'nosuchthing')"))
        self.assertEqual(complete, b"\x86")

    def test_handler_emits_both_blocks_as_separate_host_blocks(self):
        handler = FindSvcHandler(pipe_idx=2, svc_name="FindSvc")
        packets = handler.handle_request(
            FINDSVC_CLASS_SEARCH,
            FINDSVC_SEARCH,
            3,
            _request(f"({SCOPE_FOLDERS})"),
            server_seq=1,
            client_ack=1,
        )
        self.assertEqual(len(packets), 2)
        # The completion block rides the same (class, selector, req_id) triple.
        tail = parse_packet(packets[-1]).payload
        self.assertIn(bytes([FINDSVC_CLASS_SEARCH, FINDSVC_SEARCH, 3, 0x86]), tail, tail.hex())

    def test_handler_answers_class_1_method_1(self):
        handler = FindSvcHandler(pipe_idx=2, svc_name="FindSvc")
        packets = handler.handle_request(
            FINDSVC_CLASS_SEARCH,
            FINDSVC_SEARCH,
            7,
            _request(f"({SCOPE_FOLDERS})"),
            server_seq=1,
            client_ack=1,
        )
        self.assertTrue(packets)

    def test_unknown_selector_is_not_answered(self):
        handler = FindSvcHandler(pipe_idx=2, svc_name="FindSvc")
        self.assertIsNone(
            handler.handle_request(FINDSVC_CLASS_SEARCH, 0x02, 7, b"", server_seq=1, client_ack=1)
        )


class TestQueryEvaluation(unittest.TestCase):
    def test_single_term_matches_a_substring_of_the_name(self):
        # `movies` typed into the Containing box with only the Name box ticked.
        _status, _count, mnids = _search("(NAME contains 'movies')")
        self.assertIn("Movies", _names(mnids))

    def test_matching_is_case_insensitive(self):
        upper = _search("(NAME contains 'MOVIES')")[2]
        lower = _search("(NAME contains 'movies')")[2]
        self.assertEqual(upper, lower)

    def test_two_words_are_anded(self):
        # `arts entertainment` compiles to `'arts' & 'entertainment'`.
        hits = _names(_search("(NAME contains 'arts' & 'entertainment')")[2])
        self.assertIn("Arts and Entertainment", hits)
        self.assertNotIn("Movies", hits)

    def test_or_widens(self):
        hits = _names(_search("(NAME contains 'movies' | 'theater')")[2])
        self.assertIn("Movies", hits)
        self.assertIn("Theater and Performance", hits)

    def test_not_excludes(self):
        hits = _names(_search("(NAME contains 'and' & ~'entertainment')")[2])
        self.assertIn("Home and Family", hits)
        self.assertNotIn("Arts and Entertainment", hits)

    def test_star_wildcard_arrives_as_percent(self):
        # `mov*` -> `'mov%'`.
        self.assertIn("Movies", _names(_search("(NAME contains 'mov%')")[2]))

    def test_question_wildcard_arrives_as_underscore(self):
        self.assertIn("Movies", _names(_search("(NAME contains 'mo_ies')")[2]))

    def test_escaped_wildcard_is_literal(self):
        # A user's own `%` ships backslash-escaped and must not match anything
        # that merely has characters where the `%` is.
        self.assertEqual(_search(r"(NAME contains 'mov\%es')")[1], 0)

    def test_combined_field_searches_every_part(self):
        # SEARCH_PROPS is the mask-7 column: name, subject and description.
        self.assertIn("Movies", _names(_search("(SEARCH_PROPS contains 'movies')")[2]))

    def test_unmatched_query_answers_zero_hits_not_an_error(self):
        status, count, mnids = _search("(NAME contains 'nosuchthing')")
        self.assertEqual(status, 0)
        self.assertEqual(count, 0)
        self.assertEqual(mnids, [])


class TestIndexScope(unittest.TestCase):
    """Find lists services, not the content inside them."""

    def _bbs_nodes(self, container):
        return [
            node
            for node in app_store.content.all_nodes()
            if node.content.bbs is not None and node.is_container is container
        ]

    def test_bbs_messages_and_attachments_are_not_indexed(self):
        # They ride the same content store as the directory but are not DIRSRV
        # rows, and the "of type" combo has no entry for them. Left in, they
        # showed up as results with a blank Type column.
        messages = self._bbs_nodes(container=False)
        self.assertTrue(messages, "fixture has no BBS message nodes to exclude")
        indexed = set(_search("(NAME contains '%')")[2])
        for node in messages:
            self.assertNotIn(node.mnid_a, indexed, node.content.name)

    def test_the_board_itself_stays_indexed(self):
        boards = self._bbs_nodes(container=True)
        self.assertTrue(boards, "fixture has no BBS board to index")
        indexed = set(_search(f"(NAME contains '%') AND ({SCOPE_BBS})")[2])
        for node in boards:
            self.assertIn(node.mnid_a, indexed, node.content.name)

    def test_a_board_reports_its_message_count_as_p(self):
        # MSNFIND's Size-cell formatter @ 0x7F37318B renders `p` as
        # "%d messages" when c == 2, so a board counts articles, not bytes.
        # Counted live: a post has to move the number.
        board = self._bbs_nodes(container=True)[0]
        messages = app_store.content.count_children(board.node_id)
        self.assertTrue(messages)
        self.assertEqual(_size_value(board), messages)

    def test_attachments_do_not_inflate_the_message_count(self):
        # Attachment nodes are registered by mnid but deliberately kept off the
        # board's child list — they are files, not articles. The count follows
        # the child list, so it stays the article count.
        board = self._bbs_nodes(container=True)[0]
        children = app_store.content.get_children(board.node_id)
        self.assertGreater(
            len(self._bbs_nodes(container=False)),
            len(children),
            "fixture has no off-list attachment nodes to distinguish",
        )
        self.assertEqual(_size_value(board), len(children))

    def test_a_non_bbs_node_still_reports_bytes(self):
        # c == 7 goes through HrSzForByteCount; the DnR leaf keeps its payload
        # length.
        dnr = next(node for node in app_store.content.all_nodes() if node.app_id == 7)
        self.assertEqual(_size_value(dnr), dnr.content.size_bytes)


class TestChatRoomOccupancy(unittest.TestCase):
    """`p` on a chat node is its roster size — MSNFIND renders it "%d people"."""

    def setUp(self):
        self.node = next(node for node in app_store.content.all_nodes() if node.app_id == 4)
        self.room_id = struct.unpack_from("<I", self.node.mnid_a)[0]
        conference_rooms.clear()
        self.addCleanup(conference_rooms.clear)

    def test_a_room_nobody_joined_reports_zero(self):
        # 0 leaves the Size cell empty, which is what an idle room should look
        # like.
        self.assertEqual(_size_value(self.node), 0)

    def test_reading_p_does_not_register_the_room(self):
        # A search over every chat node must not create a _Room per result.
        _size_value(self.node)
        self.assertEqual(conference_rooms, {})

    def test_occupancy_is_counted_live(self):
        room = _room_for(self.room_id)
        room.members.extend([object(), object(), object()])
        self.assertEqual(_size_value(self.node), 3)
        room.members.pop()
        self.assertEqual(_size_value(self.node), 2)

    def test_every_indexed_node_carries_a_date(self):
        # CFindNav_FillResultRow has no blank branch for `w`; a node with no
        # timestamp renders as the 1601 epoch in the Date Modified column.
        for mnid in _search("(NAME contains '%')")[2]:
            node = next(n for n in app_store.content.all_nodes() if n.mnid_a == mnid)
            self.assertTrue(node.content.modified_filetime, f"{node.node_id} {node.content.name!r}")


class TestScopeFragments(unittest.TestCase):
    def _app_ids(self, query):
        by_mnid = {node.mnid_a: node.app_id for node in app_store.content.all_nodes()}
        return {by_mnid[m] for m in _search(query)[2]}

    def test_folders_scope_keeps_only_app_1(self):
        self.assertEqual(self._app_ids(f"({SCOPE_FOLDERS})"), {1})

    def test_titles_scope_accepts_the_in_list(self):
        self.assertLessEqual(self._app_ids(f"({SCOPE_TITLES})"), {6, 11, 12})

    def test_chat_scope_keeps_only_app_4(self):
        self.assertEqual(self._app_ids(f"({SCOPE_CHAT})"), {4})

    def test_all_msn_scope_admits_bulletin_boards(self):
        # `APPID <> 2 or BBS_FOLDER_FLAGS <> 0` excludes only Internet
        # newsgroups, so an App #2 board (flags 1) stays in.
        self.assertIn(2, self._app_ids(f"({SCOPE_ALL_MSN})"))

    def test_newsgroup_scope_excludes_msn_boards(self):
        self.assertEqual(self._app_ids(f"({SCOPE_NEWSGROUPS})"), set())

    def test_scope_and_text_are_anded(self):
        hits = _names(_search(f"(NAME contains 'movies') AND ({SCOPE_CHAT})")[2])
        self.assertEqual(hits, [])


class TestLocaleFragment(unittest.TestCase):
    def test_show_all_languages_off_scopes_to_one_lcid(self):
        # ShowAllLanguages=FALSE appends `LOCALES contains '<LCID:%08X>'`.
        hits = _names(_search("(NAME contains 'a') AND (LOCALES contains '00000416')")[2])
        self.assertIn("Artes e Entretenimento", hits)
        self.assertNotIn("Arts and Entertainment", hits)


class TestQueryErrors(unittest.TestCase):
    def test_unknown_field_is_rejected(self):
        with self.assertRaises(QueryError):
            parse_query("(NOSUCHFIELD contains 'x')")

    def test_unbalanced_parenthesis_is_rejected(self):
        with self.assertRaises(QueryError):
            parse_query("(NAME contains 'x'")

    def test_rejected_query_answers_zero_hits(self):
        status, count, mnids = _search("(NAME contains)")
        self.assertEqual(status, 0)
        self.assertEqual(count, 0)
        self.assertEqual(mnids, [])


class TestResultRowResolution(unittest.TestCase):
    """The second half: DIRSRV GetProperties over a batch of found mnids."""

    ROW_PROPS = ["f", "c", "a", "tp", "w", "p"]

    def _batch_request(self, node_ids):
        content = app_store.content
        mnids = b"".join(content.get_node(i).mnid_a for i in node_ids)
        props = "\x00".join(self.ROW_PROPS).encode("ascii") + b"\x00"
        return (
            b"\x04"
            + bytes([(len(mnids) >> 8) & 0x7F, len(mnids) & 0xFF])
            + mnids
            + b"\x03"
            + struct.pack("<I", len(node_ids))
            + b"\x03"
            + struct.pack("<I", len(self.ROW_PROPS))
            + b"\x04"
            + bytes([(len(props) >> 8) & 0x7F, len(props) & 0xFF])
            + props
            + b"\x04\x84"
            + b"\x00\x00\x00\x00"
            + b"\x83\x83\x85"
        )

    def _records(self, node_ids):
        request = decode_dirsrv_request(self._batch_request(node_ids))
        self.assertEqual(request.node_ids, node_ids)
        payload = build_get_properties_reply_payload(request)
        count = struct.unpack_from("<I", payload, 6)[0]
        return count, _walk_records(payload[12:])

    def test_one_record_per_requested_mnid(self):
        # CFindResultSet_GetNextRow resolves 20 hits per call and pulls each one
        # out with GetNthNode; a single-record reply fails every row after the
        # first with 0x8B0B0080.
        node_ids = [f"1:{0x100 + i}" for i in range(5)]
        count, records = self._records(node_ids)
        self.assertEqual(count, len(node_ids))
        self.assertEqual(len(records), len(node_ids))

    def test_records_come_back_in_request_order(self):
        node_ids = ["1:257", "1:256", "1:16"]
        _count, records = self._records(node_ids)
        content = app_store.content
        self.assertEqual(
            [record["a"][1] for record in records],
            [content.get_node(i).mnid_a for i in node_ids],
        )

    def test_single_node_callers_still_get_exactly_one_record(self):
        count, records = self._records(["1:16"])
        self.assertEqual(count, 1)
        self.assertEqual(len(records), 1)

    def test_row_shape_sends_utf16_name_ansi_type_and_filetime(self):
        # CFindNav_FillResultRow narrows `f` itself (WideCharToMultiByte), takes
        # `tp` with lstrcpynA, and hands `w` to FileTimeToLocalFileTime.
        _count, (record,) = self._records(["1:256"])
        self.assertEqual(record["f"][0], 0x0B)
        self.assertEqual(record["tp"][0], 0x0A)
        self.assertEqual(record["w"][0], 0x0C)
        self.assertEqual(record["c"][0], 0x03)
        self.assertEqual(record["p"][0], 0x03)

    def test_every_row_carries_all_four_required_tags(self):
        # Missing 'c', 'a', 'f' or 'w' fails the row with 0x8B0B0080 and the
        # result never reaches the list.
        _count, records = self._records([f"1:{0x100 + i}" for i in range(5)])
        for record in records:
            self.assertLessEqual({"c", "a", "f", "w"}, set(record))

    def test_undated_node_sends_an_eight_byte_filetime(self):
        # The details view sends an empty string for a node with no timestamp;
        # MOSFIND would read that as eight bytes of date.
        _count, (record,) = self._records(["1:256"])
        self.assertEqual(len(record["w"][1]), 8)


def _walk_records(body):
    """Decode the dynamic section the way FDecompressPropClnt does.

    `[u32 size][u16 count]` then `[u8 type][asciiz name][value]` per property.
    Only the types the Find row asks for are decoded.
    """
    records = []
    pos = 0
    while pos < len(body):
        size, count = struct.unpack_from("<IH", body, pos)
        end = pos + size
        cursor = pos + 6
        props = {}
        for _ in range(count):
            ptype = body[cursor]
            cursor += 1
            name_end = body.index(b"\x00", cursor)
            name = body[cursor:name_end].decode("ascii")
            cursor = name_end + 1
            if ptype == 0x03:
                value = body[cursor : cursor + 4]
                cursor += 4
            elif ptype == 0x0C:
                value = body[cursor : cursor + 8]
                cursor += 8
            elif ptype == 0x0E:
                length = struct.unpack_from("<I", body, cursor)[0]
                value = body[cursor + 4 : cursor + 4 + length]
                cursor += 4 + length
            elif ptype in (0x0A, 0x0B):
                string_end = body.index(b"\x00", cursor + 1)
                value = body[cursor + 1 : string_end]
                cursor = string_end + 1
            else:
                raise AssertionError(f"unexpected wire type 0x{ptype:02x} for {name!r}")
            props[name] = (ptype, value)
        assert cursor == end, (cursor, end)
        records.append(props)
        pos = end
    return records
