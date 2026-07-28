"""Tests for the BBS service handler (read channel) and sample board fixture.

The BBS read channel rides the generic MOS tree (TREENVCL) exactly like DIRSRV,
so reply framing is shared (build_tree_reply_wire); only the per-node tag
vocabulary differs. See docs/bbs-service-contract.md.
"""

import dataclasses
import struct
import unittest

from server.models import DirsrvRequest
from server.mos_apps import APP_BBS_SERVICE
from server.services import dirsrv
from server.services.bbs import (
    BBS_CLASS_MESSAGE,
    BBS_CLASS_TREE,
    BBSHandler,
    build_bbs_article,
    build_bbs_article_reply_payload,
    build_bbs_get_children_reply_payload,
    build_bbs_get_properties_reply_payload,
    encode_body,
)
from server.services.dirsrv import DIRSRVHandler
from server.store import app_store
from server.transport import parse_packet

# Sample-board node ids, decimal wire form `field_8:field_c` = message id : board
# id. The board itself carries message id 0 — GetParent (0x7F5F12CE) reaches it by
# zeroing field_8, and GetThreadParent (0x7F5F1C3E) reaches a parent post by
# swapping `_P` into field_8.
_BOARD = "0:1"  # Climbing BBS
_YOSEMITE = "256:1"  # msg 0x100 on board 1
_RE_YOSEMITE = "512:1"  # msg 0x200, _P = 0x100
_SPORTS_CATEGORY = "1:266"  # DIRSRV "Sports, Health and Fitness" (f8 0x10A)

# Class-0x0B method-0 request as the reader sends it: the 8-byte mnid it copied
# into its context at +0xA8, one 0x83 status DWORD to receive, and 0x85 marking
# the request as streaming.
_ARTICLE_REQUEST = b"\x04" + bytes([0x80 | 8]) + struct.pack("<II", 0x100, 1) + b"\x83\x85"

# The Yosemite body as the fixture authors it — plain text, whatever format the
# node later asks the wire layer to encode it as.
_YOSEMITE_TEXT = app_store.content.get_node(_YOSEMITE).content.bbs.body


def _node_with_format(body_format):
    """The Yosemite node with its `body_format` swapped, body untouched."""
    node = app_store.content.get_node(_YOSEMITE)
    bbs = dataclasses.replace(node.content.bbs, body_format=body_format)
    return dataclasses.replace(node, content=dataclasses.replace(node.content, bbs=bbs))


def _walk_records(payload):
    """Parse a tree reply (build_tree_reply_wire output) into per-record dicts.

    Reply: 0x83 status, 0x83 node_count, 0x87, 0x88, then node_count SVCPROP
    records `[u32 size][u16 count]{[u8 type][asciiz name][value]}`. Returns each
    record as {name: value} — strings decoded, DWORD/WORD as int, `a` as bytes.
    """
    p = 0
    assert payload[p] == 0x83
    p += 1
    p += 4  # status DWORD
    assert payload[p] == 0x83
    p += 1
    node_count = struct.unpack_from("<I", payload, p)[0]
    p += 4
    assert payload[p] == 0x87
    p += 1
    assert payload[p] == 0x88
    p += 1
    records = []
    for _ in range(node_count):
        rec_start = p
        total_size = struct.unpack_from("<I", payload, p)[0]
        p += 4
        prop_count = struct.unpack_from("<H", payload, p)[0]
        p += 2
        props = {}
        for _ in range(prop_count):
            ptype = payload[p]
            p += 1
            name_end = payload.index(b"\x00", p)
            name = payload[p:name_end].decode("ascii")
            p = name_end + 1
            if ptype == 0x01:
                props[name] = payload[p]
                p += 1
            elif ptype == 0x02:
                props[name] = struct.unpack_from("<H", payload, p)[0]
                p += 2
            elif ptype == 0x03:
                props[name] = struct.unpack_from("<I", payload, p)[0]
                p += 4
            elif ptype in (0x04, 0x0C):
                props[name] = struct.unpack_from("<Q", payload, p)[0]
                p += 8
            elif ptype == 0x0E:
                blob_len = struct.unpack_from("<I", payload, p)[0]
                p += 4
                props[name] = payload[p : p + blob_len]
                p += blob_len
            elif ptype == 0x10:
                # dword array: [count][count*4]
                count = struct.unpack_from("<I", payload, p)[0]
                p += 4
                props[name] = [
                    struct.unpack_from("<I", payload, p + i * 4)[0] for i in range(count)
                ]
                p += count * 4
            elif ptype in (0x0A, 0x0B):
                flag = payload[p]
                p += 1
                if flag & 0x02:
                    props[name] = ""
                elif flag & 0x01:
                    end = payload.index(b"\x00", p)
                    props[name] = payload[p:end].decode("ascii", errors="replace")
                    p = end + 1
                else:
                    end = p
                    while end + 1 < len(payload) and not (
                        payload[end] == 0 and payload[end + 1] == 0
                    ):
                        end += 2
                    props[name] = payload[p:end].decode("utf-16le", errors="replace")
                    p = end + 2
            else:
                raise AssertionError(f"unknown ptype 0x{ptype:02x} for {name!r}")
        assert p - rec_start == total_size, (
            f"record size mismatch: walked {p - rec_start} vs declared {total_size}"
        )
        records.append(props)
    return records


class TestBBSDiscovery(unittest.TestCase):
    def test_discovery_adds_the_message_channel_iid(self):
        # BBS resolves the same generic TREENVCL tree IIDs as DSNAV/DIRSRV plus
        # one more: 00028B2F, which the reader negotiates on a second
        # CreateTnc("BBS", 3) when a message is opened (BBSNAV FUN_7F5FCD1A).
        # Without it that negotiation returns E_NOINTERFACE and the reader
        # reports "Cannot open message" before any request reaches the wire.
        bbs_pkts = BBSHandler(1, "BBS").build_discovery_packet(3, 3)
        dirsrv_pkts = DIRSRVHandler(1, "DIRSRV").build_discovery_packet(3, 3)
        self.assertIsInstance(bbs_pkts, list)
        parsed = parse_packet(bbs_pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        self.assertNotEqual(bbs_pkts, dirsrv_pkts)
        self.assertGreater(len(bbs_pkts[0]), len(dirsrv_pkts[0]))

    def test_interface_table_is_dirsrv_plus_00028b2f(self):
        import uuid

        from server.config import BBS_INTERFACE_GUIDS, DIRSRV_INTERFACE_GUIDS

        self.assertEqual(BBS_INTERFACE_GUIDS[: len(DIRSRV_INTERFACE_GUIDS)], DIRSRV_INTERFACE_GUIDS)
        self.assertEqual(
            BBS_INTERFACE_GUIDS[len(DIRSRV_INTERFACE_GUIDS) :],
            [(uuid.UUID("00028B2F-0000-0000-C000-000000000046").bytes_le, 0x0B)],
        )


class TestBBSGetProperties(unittest.TestCase):
    def test_board_self_record_carries_subject_and_app_id(self):
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00c\x00e\x00_F")
        payload = build_bbs_get_properties_reply_payload(request)
        records = _walk_records(payload)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["e"], "Climbing BBS")
        self.assertEqual(records[0]["c"], APP_BBS_SERVICE)
        # Board has children → _F bit 0x1000 CLEAR. OkToGetChildren @ 0x7F5F1427
        # forces the child count to 0 when the bit is SET, so setting it on a
        # board would collapse the thread list.
        self.assertEqual(records[0]["_F"] & 0x1000, 0)


class TestBBSGetChildren(unittest.TestCase):
    def test_board_lists_every_message_including_replies(self):
        # The tree under a board is flat — the reader enumerates the board once
        # and never asks a message for children, so a reply nested under its
        # parent would never reach the list. Order puts a reply after the
        # message it answers.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00_a")
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        self.assertEqual(
            [r["e"] for r in records],
            ["Yosemite", "RE: Yosemite", "British Climbers"],
        )
        # Authors per reference/screenshots/bbs.png.
        self.assertEqual(records[0]["_a"], "Chris Hahn")
        self.assertEqual(records[2]["_a"], "KEITH SUTTON")

    def test_every_message_carries_an_author_and_a_date(self):
        # A real post always has both. A missing `_D` used to be skipped
        # entirely, which truncated the record; a missing date now still ships
        # as 0, but the fixtures should not rely on that.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00_a\x00_D")
        for record in _walk_records(build_bbs_get_children_reply_payload(request)):
            self.assertTrue(record["_a"], record["e"])
            self.assertGreater(record["_D"], 0, record["e"])

    def test_reply_record_carries_parent_subid(self):
        # RE: Yosemite is a SIBLING of Yosemite whose _P holds Yosemite's f8
        # (0x100). GetThreadParent copies the reply's own mnid and overwrites
        # field_8 with _P, so the two must differ in nothing else.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00_P")
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        by_name = {r["e"]: r for r in records}
        self.assertEqual(by_name["RE: Yosemite"]["_P"], 0x100)
        self.assertEqual(by_name["Yosemite"]["_P"], 0)
        # Same field_c (board), different field_8 — the only difference _P can
        # express.
        parent_a = struct.unpack("<II", by_name["Yosemite"]["a"])
        reply_a = struct.unpack("<II", by_name["RE: Yosemite"]["a"])
        self.assertEqual(parent_a[1], reply_a[1])
        self.assertEqual(parent_a[0], by_name["RE: Yosemite"]["_P"])

    def test_no_message_reports_children(self):
        # Messages are leaves: the reader must never fetch a thread list from
        # one, and an unlisted node would answer with the fallback sentinel.
        for node_id in (_YOSEMITE, _RE_YOSEMITE, "257:1"):
            request = DirsrvRequest(node_id=node_id, prop_group="a\x00e")
            payload = build_bbs_get_children_reply_payload(request)
            self.assertEqual(_walk_records(payload), [], node_id)

    def test_dispatch_via_handler_returns_packet(self):
        # Full read path: wire request (board mnid = message id 0, board id 1 +
        # propList "a,e") → decode → GetChildren reply → framed packet.
        handler = BBSHandler(1, "BBS")
        wire = (
            b"\x04"
            + bytes([0x80 | 8])
            + struct.pack("<II", 0, 1)
            + b"\x04"
            + bytes([0x80 | 4])
            + b"a\x00e\x00"
            + b"\x83\x83\x85"
        )
        pkts = handler.handle_request(BBS_CLASS_TREE, 0x02, 0, wire, 5, 5)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        self.assertIn(b"Yosemite", pkts[0])


class TestBBSBoardWiredIntoCategory(unittest.TestCase):
    def test_sports_category_lists_climbing_bbs_with_bbs_app_id(self):
        # "Sports, Health and Fitness" (1:266) lists the board over DIRSRV; the
        # board's c=2 (APP_BBS_SERVICE) is what routes the client into bbsnav.
        request = DirsrvRequest(node_id=_SPORTS_CATEGORY, prop_group="a\x00c\x00b\x00e")
        payload = dirsrv.build_get_children_reply_payload(request)
        records = _walk_records(payload)
        board = next((r for r in records if r["e"] == "Climbing BBS"), None)
        self.assertIsNotNone(board, "Climbing BBS missing from Sports category listing")
        self.assertEqual(board["c"], APP_BBS_SERVICE)

    def test_board_row_carries_the_delegate_tag_set(self):
        # HrSetupDelegate (MOSSHELL 0x7F3FC14F) needs all four: 'b' bit 0x04 to
        # engage, then 'c' (cap 4) + 'l' (cap 8) + 'i' (cap 2) to build the
        # inner mnid {field_0=2, field_8/field_c=(2,1), field_10=0}. 'l' must be
        # 8 inline bytes (wire type 0x0C) — a 0x0E blob caches a heap pointer
        # and the cap-8 read would copy the pointer, not the mnid.
        request = DirsrvRequest(node_id=_SPORTS_CATEGORY, prop_group="a\x00c\x00b\x00e\x00l\x00i")
        records = _walk_records(dirsrv.build_get_children_reply_payload(request))
        board = next(r for r in records if r["e"] == "Climbing BBS")
        self.assertEqual(board["b"] & 0x04, 0x04)
        self.assertEqual(board["c"], APP_BBS_SERVICE)
        self.assertEqual(board["l"], struct.unpack("<Q", board["a"])[0])
        self.assertEqual(board["i"], 0)

    def test_plain_category_row_has_no_delegate_tags(self):
        # Only the board delegates. A normal category keeps 'b' bit 0x04 clear,
        # otherwise every folder would try to load a navigator.
        request = DirsrvRequest(node_id=_SPORTS_CATEGORY, prop_group="a\x00c\x00b\x00e\x00l\x00i")
        records = _walk_records(dirsrv.build_get_children_reply_payload(request))
        for record in (r for r in records if r["e"] != "Climbing BBS"):
            self.assertEqual(record["b"] & 0x04, 0)


class TestEveryRequestedTagIsReturned(unittest.TestCase):
    """A record must carry one entry per requested tag — no exceptions.

    CServiceProperties::FSet @ 0x7F6418FF only advances the record's property
    count on success, and its first guard rejects any index past that count. So
    a single missing property drops every property after it as well. The client
    then caches the missing ones as present-but-unreceived (RememberProperty
    @ 0x7F3FC8F8 via the FGet-miss branch @ 0x7F3FC8A2), and FindProperty
    @ 0x7F3FCE12 never re-fetches a present element — every later read returns
    0x8B0B0041 "Cannot open service".
    """

    BBS_TAGS = "a\x00c\x00h\x00b\x00e\x00g\x00x\x00_a\x00_D\x00_P\x00_f\x00_t\x00p\x00_F\x00_I"
    DIRSRV_TAGS = "a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i"

    def test_board_is_container_messages_are_not(self):
        # `b` bit 0x01 is bbsnav's conversation test: FUN_7F5F1CAD sets bit 0
        # of the ingest flag when (b & 1) == 0, and FUN_7F5F5DE4 counts a
        # conversation only when that bit is clear. So the board must be a
        # container (0x00) and every message a leaf (0x01) — including a
        # conversation head that has replies.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00b\x00e")
        board = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        self.assertEqual(board["b"] & 0x01, 0x00)

        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00b\x00e\x00_F")
        for record in _walk_records(build_bbs_get_children_reply_payload(request)):
            self.assertEqual(record["b"] & 0x01, 0x01, record["e"])
            # And every message is a leaf in the tree too — replies hang off
            # `_P`, not off the message. OkToGetChildren (0x7F5F1427) forces
            # the child count to 0 when _F bit 0x1000 is set.
            self.assertEqual(record["_F"] & 0x1000, 0x1000, record["e"])

    def test_bbs_board_record_has_no_gaps(self):
        # The board has no author, topic or date — every one of those must
        # still ship a value.
        request = DirsrvRequest(node_id=_BOARD, prop_group=self.BBS_TAGS)
        records = _walk_records(build_bbs_get_properties_reply_payload(request))
        self.assertEqual(len(records), 1)
        self.assertEqual(set(records[0]), set(self.BBS_TAGS.split("\x00")))

    def test_bbs_undated_message_record_has_no_gaps(self):
        # "British Climbers" carries an author but no date.
        request = DirsrvRequest(node_id=_BOARD, prop_group=self.BBS_TAGS)
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        self.assertTrue(records)
        for record in records:
            self.assertEqual(set(record), set(self.BBS_TAGS.split("\x00")))

    def test_dirsrv_board_row_has_no_gaps(self):
        # The delegate row has an empty `tp` and no `w`; both must still ship,
        # or `l`/`i` get stripped and HrSetupDelegate cannot build the mnid.
        request = DirsrvRequest(node_id=_SPORTS_CATEGORY, prop_group=self.DIRSRV_TAGS)
        records = _walk_records(dirsrv.build_get_children_reply_payload(request))
        self.assertTrue(records)
        for record in records:
            self.assertEqual(set(record), set(self.DIRSRV_TAGS.split("\x00")))

    def test_dirsrv_category_rows_have_no_gaps(self):
        request = DirsrvRequest(node_id="1:16", prop_group=self.DIRSRV_TAGS)
        records = _walk_records(dirsrv.build_get_children_reply_payload(request))
        self.assertGreater(len(records), 1)
        for record in records:
            self.assertEqual(set(record), set(self.DIRSRV_TAGS.split("\x00")))


class TestBBSMnidLayout(unittest.TestCase):
    """`field_8` = message id, `field_c` = board id.

    Two bbsnav functions depend on it: GetParent (0x7F5F12CE) zeroes field_8 to
    reach the board, and GetThreadParent (0x7F5F1C3E) swaps `_P` into field_8 to
    reach the parent post. Inverting the pair makes GetParent resolve a message
    to itself, and opening it fails with "Cannot open message" before any wire
    traffic.
    """

    @staticmethod
    def _mnid(record):
        return struct.unpack("<II", record["a"])  # (field_8, field_c)

    def test_board_carries_message_id_zero(self):
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        field_8, field_c = self._mnid(record)
        self.assertEqual(field_8, 0)
        self.assertNotEqual(field_c, 0)

    def test_messages_share_the_board_id_and_zeroing_field_8_reaches_the_board(self):
        board = _walk_records(
            build_bbs_get_properties_reply_payload(
                DirsrvRequest(node_id=_BOARD, prop_group="a\x00e")
            )
        )[0]
        _, board_id = self._mnid(board)

        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e")
        for record in _walk_records(build_bbs_get_children_reply_payload(request)):
            field_8, field_c = self._mnid(record)
            self.assertNotEqual(field_8, 0, record["e"])
            self.assertEqual(field_c, board_id, record["e"])
            # GetParent zeroes field_8; the result must be the board's key.
            self.assertEqual(f"{0}:{field_c}", _BOARD, record["e"])

    def test_reply_parent_id_names_a_sibling_message(self):
        # `_P` goes into field_8, so it must equal the parent's message id while
        # the board id stays put.
        yosemite = _walk_records(
            build_bbs_get_properties_reply_payload(
                DirsrvRequest(node_id=_YOSEMITE, prop_group="a\x00e")
            )
        )[0]
        parent_msg_id, board_id = self._mnid(yosemite)

        reply = _walk_records(
            build_bbs_get_properties_reply_payload(
                DirsrvRequest(node_id=_RE_YOSEMITE, prop_group="a\x00e\x00_P")
            )
        )[0]
        self.assertEqual(reply["_P"], parent_msg_id)
        self.assertEqual(self._mnid(reply)[1], board_id)
        self.assertEqual(f"{reply['_P']}:{board_id}", _YOSEMITE)


class TestBBSPropertiesDialogTags(unittest.TestCase):
    """Shared MOS tree tags requested by the Properties dialog.

    The dialog fetches them one at a time as `{name, 'g'}` groups — observed
    live as `q,g` then `v,g` on node 0:256. build_bbs_props delegates anything
    outside the BBS vocabulary to DIRSRV's serialiser so each tag keeps its
    established wire type.
    """

    def test_language_is_the_dword_array_form_so_the_dialog_names_it(self):
        # `q` must be type 0x10 [count][lcid]. MOSSHELL's formatter @ 0x7F3FBC12
        # case 0x10 calls GetLocaleInfoA and prints a language name; case
        # 0x04/0x08 falls to wsprintfA("%u:%u", …) — the "Language: 0:0" bug.
        # The LCID sits at +4 either way, so MCM's browse-language read is safe.
        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="q\x00g")
        payload = build_bbs_get_properties_reply_payload(request)
        self.assertIn(b"\x10q\x00", payload)
        self.assertNotIn(b"\x04q\x00", payload)
        self.assertNotIn(b"\x03q\x00", payload)
        self.assertEqual(_walk_records(payload)[0]["q"], [0x0409])

    def test_created_and_modified_carry_the_post_date(self):
        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="v\x00w\x00g")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        self.assertEqual(record["v"], "May 16, 1995 10:12 AM")
        self.assertEqual(record["w"], "May 16, 1995 10:12 AM")

    def test_dialog_date_string_agrees_with_what_the_client_renders(self):
        # `_D` is a time_t the client renders through its own timezone, while
        # `v`/`w` pass through verbatim. They must describe the same wall clock.
        # Model the client, not this host: Windows 95 has no historical timezone
        # database, so it applies its CURRENT offset even to a 1995 timestamp.
        # Comparing against datetime.fromtimestamp() would instead use the 1995
        # rule and drift wherever the two differ (Europe/Lisbon: +0200 in 1995,
        # +0100 today).
        import datetime

        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="v\x00_D")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
        as_client_shows_it = (
            datetime.datetime.fromtimestamp(record["_D"], datetime.UTC).replace(tzinfo=None)
            + offset
        )
        from_string = datetime.datetime.strptime(record["v"], "%B %d, %Y %I:%M %p")
        self.assertEqual(as_client_shows_it, from_string)

    def test_dialog_tags_are_never_answered_with_a_dword_stand_in(self):
        # Every string-shaped dialog tag must arrive as 0x0B, not DWORD 0.
        tags = ["j", "k", "ca", "r", "s", "t", "u", "n", "on", "v", "w"]
        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="\x00".join(tags))
        payload = build_bbs_get_properties_reply_payload(request)
        for tag in tags:
            self.assertIn(bytes([0x0B]) + tag.encode() + b"\x00", payload, tag)


class TestBBSClassDispatch(unittest.TestCase):
    def test_method_zero_routes_by_class_not_by_selector(self):
        # `msg_class` is the interface (its discovery selector); `selector` is the
        # method within it. Method 0 exists on both: class 0x03 is GetProperties
        # on the tree channel, class 0x0B is the article fetch on the
        # message-content channel (IID 00028B2F). Dispatching on `selector`
        # alone routed the article fetch into the tree serialiser, which
        # answered with a record the reader cannot use — and the client ACKed it.
        handler = BBSHandler(1, "BBS")
        wire = _ARTICLE_REQUEST
        article = handler.handle_request(BBS_CLASS_MESSAGE, 0x00, 0, wire, 5, 5)
        tree = handler.handle_request(BBS_CLASS_TREE, 0x00, 0, wire, 5, 5)
        self.assertIsNotNone(article)
        self.assertIsNotNone(tree)
        self.assertNotEqual(article, tree)

    def test_unknown_method_on_the_message_class_stays_unanswered(self):
        handler = BBSHandler(1, "BBS")
        with self.assertLogs("server.services.bbs", level="WARNING"):
            self.assertIsNone(
                handler.handle_request(BBS_CLASS_MESSAGE, 0x01, 0, _ARTICLE_REQUEST, 5, 5)
            )


class TestBBSArticle(unittest.TestCase):
    """Class 0x0B method 0 — the message body the Read Message window streams."""

    def _article(self, msg_id=0x100, board_id=1):
        wire = b"\x04" + bytes([0x80 | 8]) + struct.pack("<II", msg_id, board_id) + b"\x83\x85"
        return build_bbs_article_reply_payload(wire)

    def test_reply_is_a_zero_status_then_a_dynamic_complete_section(self):
        # `0x83 [status] 0x87 0x86 [bytes]`. The 0x86 tag matters: MPCCL
        # ProcessTaggedServiceReply (0x04604F26) calls SignalRequestCompletion
        # for 0x86, which sets request +0x18, and the reader's fetch thread
        # (FUN_7F5FB15F) only leaves its WaitIncremental loop when +0x18 makes
        # the wait return 0x0B0B000B. A 0x88 stream-end leaves +0x18 clear, the
        # wait returns 0x0B0B000C forever, and the reader hangs blank.
        payload = self._article()
        self.assertEqual(payload[0], 0x83)
        self.assertEqual(struct.unpack_from("<I", payload, 1)[0], 0)
        self.assertEqual(payload[5], 0x87)
        self.assertEqual(payload[6], 0x86)

    def test_headers_end_at_a_bare_blank_line(self):
        # FUN_7F5FB15F splits the stream at the first two adjacent '\n' bytes.
        # CRLF headers never produce that pair, so the split never fires and the
        # whole article is swallowed as headers.
        article = self._article()[7:]
        head, sep, body = article.partition(b"\n\n")
        self.assertEqual(sep, b"\n\n")
        self.assertNotIn(b"\r", head)
        self.assertTrue(body.startswith(b"{\\rtf1"))

    def test_every_header_matches_the_tabled_name_exactly(self):
        # BBSNAV strncmps each line against a tabled name that includes its
        # trailing space, so `Name: value` with exactly one space is required.
        head = self._article()[7:].partition(b"\n\n")[0].decode()
        for line in head.split("\n"):
            name, sep, value = line.partition(": ")
            self.assertEqual(sep, ": ", line)
            self.assertFalse(value.startswith(" "), line)

    def test_format_header_selects_the_rich_text_stream(self):
        # FUN_7F5FC56F reads MAPI 0x6801001E and strcmps it. Absent, the
        # property reads back PT_ERROR and the render aborts with 0x8B0B0049.
        # SF_TEXT leaves the control on its default font (Courier New); the
        # reference screenshot is proportional, so the font must ride the RTF.
        head = self._article()[7:].partition(b"\n\n")[0]
        self.assertIn(b"X-MOS-Format: RTF\n", head)

    def test_format_header_and_body_come_from_the_node(self):
        # The format is per message, not a server-wide constant. The header the
        # reader dispatches on and the encoder that produced the bytes must be
        # the same choice, both taken from BbsFields.body_format.
        as_text = build_bbs_article(_node_with_format("TEXT"))
        self.assertIn(b"X-MOS-Format: TEXT\n", as_text)
        self.assertTrue(as_text.partition(b"\n\n")[2].startswith(b"In case anyone"))

        as_rtf = build_bbs_article(_node_with_format("RTF"))
        self.assertIn(b"X-MOS-Format: RTF\n", as_rtf)
        self.assertTrue(as_rtf.partition(b"\n\n")[2].startswith(b"{\\rtf1"))

    def test_unsupported_format_fails_here_not_on_the_wire(self):
        # The client's own rejection is a bare 0x8B0B0049 that names no
        # message, so an unencodable fixture must not reach it.
        with self.assertRaises(ValueError) as cap:
            encode_body("body", "RTFCOMP")
        self.assertIn("RTFCOMP", str(cap.exception))

    def test_size_header_does_not_move_with_the_format(self):
        # X-MOS-Size shares MAPI tag 0x68030003 with the tree's `p`, so it stays
        # the plain-text length whatever the body was encoded as — even though
        # the two encodings differ in length.
        text_body = encode_body(_YOSEMITE_TEXT, "TEXT")
        rtf_body = encode_body(_YOSEMITE_TEXT, "RTF")
        self.assertNotEqual(len(text_body), len(rtf_body))
        expected = f"X-MOS-Size: {len(_YOSEMITE_TEXT)}\n".encode()
        self.assertIn(expected, build_bbs_article(_node_with_format("TEXT")))
        self.assertIn(expected, build_bbs_article(_node_with_format("RTF")))

    def test_headers_carry_the_node_identity(self):
        head = self._article()[7:].partition(b"\n\n")[0]
        self.assertIn(b"From: Chris Hahn\n", head)
        self.assertIn(b"Subject: Yosemite\n", head)
        # Newsgroups is the board — the same mnid with the message id zeroed,
        # which is how CBbsNavTreeNode::GetParent reaches it.
        self.assertIn(b"Newsgroups: Climbing BBS\n", head)
        self.assertIn(b"Message-ID: <256.1@bbs.msn.com>\n", head)

    def test_body_is_a_self_contained_rtf_document(self):
        body = self._article()[7:].partition(b"\n\n")[2].decode()
        self.assertTrue(body.startswith("{\\rtf1\\ansi"))
        self.assertTrue(body.endswith("}"))
        self.assertEqual(body.count("{"), body.count("}"))
        # The font has to come from the stream — that is the whole point of
        # choosing SF_RTF over SF_TEXT.
        self.assertIn("\\fonttbl", body)
        self.assertIn("MS Sans Serif;", body)
        self.assertIn("\\f0\\fs16 ", body)

    def test_rtf_body_is_pure_ascii(self):
        # `\\ansi` plus `\\'hh` escapes; a raw high byte in the stream would be
        # read through whatever code page the control happens to be on.
        body = self._article()[7:].partition(b"\n\n")[2]
        self.assertTrue(all(b < 0x80 for b in body))

    def test_blank_lines_survive_as_empty_paragraphs(self):
        # The fixture separates paragraphs with a blank line. One \\par per
        # source line keeps that shape instead of running the text together.
        body = self._article()[7:].partition(b"\n\n")[2].decode()
        self.assertIn("\\par\n\\par\n", body)
        # Three paragraphs and two blank lines between them.
        self.assertEqual(body.count("\\par\n"), 5)

    def test_rtf_escapes_the_control_characters(self):
        from server.services.bbs import build_body_rtf

        doc = build_body_rtf("a\\b{c}d\te")
        self.assertIn(b"a\\\\b\\{c\\}d\\tab e", doc)

    def test_size_header_matches_the_tree_size_property(self):
        # Both land on MAPI tag 0x68030003, so the header and the list pane's
        # Size column must not disagree.
        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="p")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        head = self._article()[7:].partition(b"\n\n")[0]
        self.assertIn(f"X-MOS-Size: {record['p']}\n".encode(), head)

    def test_date_header_shows_the_same_wall_clock_as_the_date_column(self):
        # Windows 95 applies its current timezone rule to every timestamp, so
        # `_D` and this line must agree under the CURRENT offset, not the 1995
        # one. Europe/Lisbon ran +0200 in 1995 and +0100 today.
        import datetime

        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="_D")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
        as_client_shows_it = (
            datetime.datetime.fromtimestamp(record["_D"], datetime.UTC).replace(tzinfo=None)
            + offset
        )
        head = self._article()[7:].partition(b"\n\n")[0].decode()
        line = next(x for x in head.split("\n") if x.startswith("Date: "))
        from_header = datetime.datetime.strptime(line[6:], "%a, %d %b %Y %H:%M:%S %z")
        self.assertEqual(as_client_shows_it, from_header.replace(tzinfo=None))

    def test_unknown_mnid_still_ships_a_well_formed_article(self):
        # An unresolvable node falls back to the store's placeholder. The reply
        # must still split cleanly — an empty or malformed article parks the
        # fetch thread just as a missing reply does.
        article = self._article(msg_id=0xDEAD, board_id=0xBEEF)[7:]
        head, sep, body = article.partition(b"\n\n")
        self.assertEqual(sep, b"\n\n")
        self.assertIn(b"X-MOS-Format: RTF\n", head)
        self.assertTrue(body.startswith(b"{\\rtf1"))
        self.assertTrue(body.endswith(b"}"))


class TestBBSWriteSelectorDeferred(unittest.TestCase):
    def test_get_ticket_selector_is_unhandled(self):
        # Compose first sends GetTicket (sel 12) on the TREEEDCL edit channel.
        # The write path is deferred, so it must be logged unhandled, not
        # answered or misrouted into a read selector.
        handler = BBSHandler(1, "BBS")
        with self.assertLogs("server.services.bbs", level="WARNING") as cap:
            result = handler.handle_request(
                msg_class=0x01,
                selector=0x0C,
                request_id=0,
                payload=b"",
                server_seq=0,
                client_ack=0,
            )
        self.assertIsNone(result)
        self.assertTrue(any("unhandled" in m for m in cap.output))


if __name__ == "__main__":
    unittest.main()
