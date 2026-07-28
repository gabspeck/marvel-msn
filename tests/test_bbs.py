"""Tests for the BBS service handler (read channel) and sample board fixture.

The BBS read channel rides the generic MOS tree (TREENVCL) exactly like DIRSRV,
so reply framing is shared (build_tree_reply_wire); only the per-node tag
vocabulary differs. See docs/bbs-service-contract.md.
"""

import struct
import unittest

from server.models import DirsrvRequest
from server.mos_apps import APP_BBS_SERVICE
from server.services import dirsrv
from server.services.bbs import (
    BBSHandler,
    build_bbs_get_children_reply_payload,
    build_bbs_get_properties_reply_payload,
)
from server.services.dirsrv import DIRSRVHandler
from server.transport import parse_packet

# Sample-board node ids (decimal wire form `f0:f8`). The board keeps f0=2 so it
# draws as a folder; conversations and messages use f0=0 so the client's mnid
# field_8 is 0 and bbsnav's `h` override hands back its own glyph (0x59D).
_BOARD = "2:1"  # Climbing BBS
_YOSEMITE = "0:256"  # _mnid_key(0, 0x100)
_RE_YOSEMITE = "0:512"  # _mnid_key(0, 0x200)
_SPORTS_CATEGORY = "1:266"  # DIRSRV "Sports, Health and Fitness" (f8 0x10A)


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
    def test_discovery_matches_dirsrv_tree_table(self):
        # BBS resolves the same generic TREENVCL tree IIDs as DSNAV/DIRSRV, so
        # its discovery packet is byte-identical for the same pipe/seq/ack.
        bbs_pkts = BBSHandler(1, "BBS").build_discovery_packet(3, 3)
        dirsrv_pkts = DIRSRVHandler(1, "DIRSRV").build_discovery_packet(3, 3)
        self.assertIsInstance(bbs_pkts, list)
        parsed = parse_packet(bbs_pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(bbs_pkts, dirsrv_pkts)


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
    def test_board_children_are_two_conversations_with_author(self):
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00_a")
        payload = build_bbs_get_children_reply_payload(request)
        records = _walk_records(payload)
        # Authors per reference/screenshots/bbs.png.
        self.assertEqual([r["e"] for r in records], ["Yosemite", "British Climbers"])
        self.assertEqual(records[0]["_a"], "Chris Hahn")
        self.assertEqual(records[1]["_a"], "KEITH SUTTON")

    def test_every_message_carries_an_author_and_a_date(self):
        # A real post always has both. A missing `_D` used to be skipped
        # entirely, which truncated the record; a missing date now still ships
        # as 0, but the fixtures should not rely on that.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00_a\x00_D")
        for record in _walk_records(build_bbs_get_children_reply_payload(request)):
            self.assertTrue(record["_a"], record["e"])
            self.assertGreater(record["_D"], 0, record["e"])

    def test_reply_record_carries_parent_subid(self):
        # Yosemite (2:256) → RE: Yosemite, whose _P points back at Yosemite's
        # f8 (0x100) for CBbsNavTreeNode_GetThreadParent / HrGetPMtn.
        request = DirsrvRequest(node_id=_YOSEMITE, prop_group="a\x00e\x00_a\x00_P")
        payload = build_bbs_get_children_reply_payload(request)
        records = _walk_records(payload)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["e"], "RE: Yosemite")
        self.assertEqual(records[0]["_P"], 0x100)

    def test_terminal_message_has_no_children(self):
        # RE: Yosemite (2:512) is a leaf reply — empty thread list, no fallback
        # sentinel leaking into the listview.
        request = DirsrvRequest(node_id=_RE_YOSEMITE, prop_group="a\x00e")
        payload = build_bbs_get_children_reply_payload(request)
        self.assertEqual(_walk_records(payload), [])

    def test_dispatch_via_handler_returns_packet(self):
        # Full read path: wire request (node_id (2,1) + propList "a,e") →
        # decode → GetChildren reply → framed packet.
        handler = BBSHandler(1, "BBS")
        wire = (
            b"\x04" + bytes([0x80 | 8]) + struct.pack("<II", 2, 1)
            + b"\x04" + bytes([0x80 | 4]) + b"a\x00e\x00"
            + b"\x83\x83\x85"
        )
        pkts = handler.handle_request(0x01, 0x02, 0, wire, 5, 5)
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
        request = DirsrvRequest(
            node_id=_SPORTS_CATEGORY, prop_group="a\x00c\x00b\x00e\x00l\x00i"
        )
        records = _walk_records(dirsrv.build_get_children_reply_payload(request))
        board = next(r for r in records if r["e"] == "Climbing BBS")
        self.assertEqual(board["b"] & 0x04, 0x04)
        self.assertEqual(board["c"], APP_BBS_SERVICE)
        self.assertEqual(board["l"], struct.unpack("<Q", board["a"])[0])
        self.assertEqual(board["i"], 0)

    def test_plain_category_row_has_no_delegate_tags(self):
        # Only the board delegates. A normal category keeps 'b' bit 0x04 clear,
        # otherwise every folder would try to load a navigator.
        request = DirsrvRequest(
            node_id=_SPORTS_CATEGORY, prop_group="a\x00c\x00b\x00e\x00l\x00i"
        )
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
        # Yosemite is a leaf `b` but still expandable: _F bit 0x1000 clear.
        yosemite = next(
            r for r in _walk_records(build_bbs_get_children_reply_payload(request))
            if r["e"] == "Yosemite"
        )
        self.assertEqual(yosemite["_F"] & 0x1000, 0)

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
