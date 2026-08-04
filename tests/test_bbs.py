"""Tests for the BBS service handler (read channel) and sample board fixture.

The BBS read channel rides the generic MOS tree (TREENVCL) exactly like DIRSRV,
so reply framing is shared (build_tree_reply_wire); only the per-node tag
vocabulary differs. See docs/bbs-service-contract.md.
"""

import dataclasses
import pathlib
import struct
import tempfile
import unittest

from server.models import DirsrvRequest
from server.mos_apps import APP_BBS_SERVICE
from server.mpc import parse_host_block, parse_request_params
from server.services import bbs, dirsrv
from server.services.bbs import (
    BBS_CLASS_MESSAGE,
    BBS_CLASS_TREE,
    BBS_SELECTOR_POST_ABORT,
    BBS_SELECTOR_POST_APPEND,
    BBS_SELECTOR_POST_COMMIT,
    BBS_SELECTOR_POST_START,
    BBSHandler,
    build_bbs_article,
    build_bbs_article_reply_payload,
    build_bbs_get_children_reply_payload,
    build_bbs_get_properties_reply_payload,
    decode_post_chunk_request,
    decode_post_start_request,
    encode_body,
    parse_article_headers,
)
from server.services.dirsrv import DIRSRVHandler
from server.store import app_store, reset_app_store
from server.transport import parse_packet

from .support import SUBSCRIBER, seed_user, signed_in

# Sample-board node ids, decimal wire form `field_8:field_c` = message id : board
# id. The board itself carries message id 0 — GetParent (0x7F5F12CE) reaches it by
# zeroing field_8, and GetThreadParent (0x7F5F1C3E) reaches a parent post by
# swapping `_P` into field_8.
_BOARD = "0:1"  # Climbing BBS
_YOSEMITE = "256:1"  # msg 0x100 on board 1
_RE_YOSEMITE = "512:1"  # msg 0x200, _P = 0x100
_SPORTS_CATEGORY = "1:266"  # DIRSRV "Sports, Health and Fitness" (f8 0x10A)
_ATTACHMENT_POST = "513:1"  # msg 0x201, one MOSAF object in its body
_ATTACHMENT_FILE = "514:1"  # that object's mnid — message id + 1
_PRICED_ATTACHMENT_POST = "515:1"  # msg 0x203
_PRICED_ATTACHMENT_FILE = "516:1"  # priced MOSAF object at message id + 1


def _mapi_crc(data):
    """MS-OXRTFCP CRC-32: poly 0xEDB88320, init 0, no final complement."""
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    value = 0
    for byte in data:
        value = table[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value

# Class-0x0B method-0 request as the reader sends it: the 8-byte mnid it copied
# into its context at +0xA8, one 0x83 status DWORD to receive, and 0x85 marking
# the request as streaming.
_ARTICLE_REQUEST = b"\x04" + bytes([0x80 | 8]) + struct.pack("<II", 0x100, 1) + b"\x83\x85"

# The Yosemite body as the fixture authors it — plain text, whatever format the
# node later asks the wire layer to encode it as.
_YOSEMITE_TEXT = app_store.content.get_node(_YOSEMITE).content.bbs.body


# A post's header block, in the order FUN_7F5FBD4E @ 0x7F5FBD4E appends it,
# with the bare-LF line terminator it uses (the separator at 0x7F610C0C is one
# 0x0A). `References` appears only on a reply, which this is — to `RE: Yosemite`
# (message 0x200) on the Climbing BBS.
_POST_HEAD = (
    b"X-MOS-To: Climbing BBS\n"
    b"X-MOS-Parent: 512\n"
    b"Subject: RE: RE: Yosemite\n"
    b"References: <512.1@bbs.msn.com>\n"
    b"X-MOS-Icon: 0\n"
    b"X-MOS-Format: TEXT\n"
    b"X-MOS-Attach: 0\n"
    b"X-MOS-Size: 11\n"
    b"X-MOS-CP: 1252\n"
    b"\n"
)
_POST_BODY = b"Nice trip!\n"


def _var(data):
    """A send-side variable parameter (tag 0x04) as the client encodes it."""
    if len(data) < 0x80:
        return b"\x04" + bytes([0x80 | len(data)]) + data
    return b"\x04" + bytes([len(data) >> 8, len(data) & 0xFF]) + data


def _reply_payload(packets):
    """The host-block payload out of a one-packet service reply.

    Frame is `header byte | u16 content length | u16 pipe routing | host block`.
    """
    frame = parse_packet(packets[0][:-1]).payload
    return parse_host_block(frame[5:]).payload


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

    def test_every_node_is_a_native_msn_rich_text_board(self):
        # `_F` bits 0..2 are the message format. CBbs_FIsMsnBbs @ 0x7F600D21
        # returns `(_F & 7) == 0` and OnInitMenuPopup @ 0x7F5FF42C greys Font,
        # Paragraph, Insert File, Insert Object, Paste Special and the
        # formatting toolbar whenever it does, with status text STRINGTABLE 1741
        # "This command is not available in Internet Newsgroups." Format 1 is
        # "Rich text (MSN formatted text)" per dialog 124 radio 0x67.
        for node_id in (_BOARD, _YOSEMITE, _RE_YOSEMITE):
            request = DirsrvRequest(node_id=node_id, prop_group="a\x00e\x00_F")
            record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
            flags = record["_F"]
            self.assertEqual(flags & 0x0007, 0x0001, record["e"])
            # Radio 0x69 "This is an MSN bulletin board".
            self.assertEqual(flags & 0x0800, 0x0800, record["e"])
            # 0x2000 gates New Message (1101) and Reply (1303) via FUN_7F600D56.
            self.assertEqual(flags & 0x2000, 0, record["e"])
            # 0x4000 "No messages with attachments are allowed" via FUN_7F600D84.
            self.assertEqual(flags & 0x4000, 0, record["e"])


class TestBBSAttachmentFixture(unittest.TestCase):
    """The sample message carrying one attachment (`resources/bbs/`).

    Its body is the Compose window's own upload, captured verbatim: MAPI
    compressed RTF holding an embedded MOSAF object (CLSID
    {00028B50-0000-0000-C000-000000000046}). Re-encoding it is not possible —
    nothing here builds the object's compound-file storage — so the bytes must
    reach the reader untouched.
    """

    def setUp(self):
        self.node = app_store.content.get_node(_ATTACHMENT_POST)

    def test_body_reaches_the_reader_byte_for_byte(self):
        article = build_bbs_article(self.node)
        self.assertEqual(article.partition(b"\n\n")[2], self.node.content.bbs.body_raw)

    def test_body_is_compressed_rtf_that_passes_its_own_crc(self):
        # The stream states its own compressed and raw sizes and carries the
        # CRC MS-OXRTFCP defines over the compressed bytes. Losing so much as
        # one byte in transport shows up here.
        body = self.node.content.bbs.body_raw
        comp_size, raw_size, magic, want = struct.unpack_from("<IIII", body, 0)
        self.assertEqual(magic, 0x75465A4C, "LZFu")
        self.assertEqual(comp_size + 4, len(body))
        self.assertEqual(raw_size, 6717)
        self.assertEqual(_mapi_crc(body[16 : comp_size + 4]), want)

    def test_format_header_tells_the_reader_to_decompress(self):
        # FUN_7F5FC56F strcmp's this value: RTFCOMP takes EM_STREAMIN SF_RTF
        # behind WrapCompressedRTFStream. Any other value renders garbage.
        self.assertIn(b"X-MOS-Format: RTFCOMP\n", build_bbs_article(self.node))

    def test_article_declares_one_attachment(self):
        self.assertIn(b"X-MOS-Attach: 1\n", build_bbs_article(self.node))

    def test_tree_record_marks_the_message_for_attached_files_view(self):
        request = DirsrvRequest(node_id=_BOARD, prop_group="e\x00_t")
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        counts = {record["e"]: record["_t"] for record in records}
        self.assertEqual(
            counts,
            {
                "Yosemite": 0,
                "RE: Yosemite": 0,
                "British Climbers": 0,
                "Attachment test": 1,
                "Priced attachment test": 1,
            },
        )

    def test_the_object_mnid_resolves_on_the_tree(self):
        # FUN_7F5FC919 addresses the single MOSAF object as message id + 1 and
        # reads `z` and `_r` off it.
        request = DirsrvRequest(node_id=_ATTACHMENT_FILE, prop_group="z\x00_r")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        self.assertEqual((record["z"], record["_r"]), (0, 0))

    def test_the_object_mnid_exposes_its_download_count(self):
        self.addCleanup(reset_app_store)
        attachment = app_store.content.get_node(_ATTACHMENT_FILE)
        attachment_bbs = dataclasses.replace(attachment.content.bbs, download_count=7)
        app_store.content.add_node(
            dataclasses.replace(
                attachment,
                content=dataclasses.replace(attachment.content, bbs=attachment_bbs),
            )
        )

        request = DirsrvRequest(node_id=_ATTACHMENT_FILE, prop_group="z\x00_r")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        self.assertEqual((record["z"], record["_r"]), (0, 7))

    def test_priced_attachment_has_a_nonzero_price(self):
        message = app_store.content.get_node(_PRICED_ATTACHMENT_POST)
        self.assertEqual(message.content.bbs.attachment_count, 1)

        request = DirsrvRequest(node_id=_PRICED_ATTACHMENT_FILE, prop_group="z\x00_r")
        record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
        self.assertEqual((record["z"], record["_r"]), ((250 << 8) | 3, 0))

    def test_the_uploaded_file_is_kept_off_the_body(self):
        # The file rode its own upload segment as a MOS2 container (the client
        # compresses it through MCM HrMos2CompFile), and the reader never sees
        # those bytes — it downloads them through FTM when the icon is opened.
        data = self.node.content.bbs.attachment_data
        self.assertEqual(data[:4], b"MOS2")
        self.assertEqual(len(data), 175)
        self.assertNotIn(data, self.node.content.bbs.body_raw)


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
            [
                "Yosemite",
                "RE: Yosemite",
                "British Climbers",
                "Attachment test",
                "Priced attachment test",
            ],
        )
        # Authors per reference/screenshots/bbs.png.
        self.assertEqual(records[0]["_a"], "Chris Hahn")
        self.assertEqual(records[2]["_a"], "KEITH SUTTON")

    def test_with_self_flag_leads_the_reply_with_the_board(self):
        # QueryOutOfDate sends flags=1, consumes one record before its loop and
        # compares that record's `g` against the board's own cached `g`. Leading
        # with a child would line the board up against its first message.
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00g", flags=1)
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        self.assertEqual(
            [r["e"] for r in records],
            [
                "Climbing BBS",
                "Yosemite",
                "RE: Yosemite",
                "British Climbers",
                "Attachment test",
                "Priced attachment test",
            ],
        )

    def test_change_stamp_moves_when_a_message_is_deleted(self):
        # The stamp the client caches on the fill, and the one it reads back
        # after a delete, must differ or the row survives the refresh.
        self.addCleanup(reset_app_store)
        request = DirsrvRequest(node_id=_BOARD, prop_group="a\x00e\x00g", flags=1)
        before = _walk_records(build_bbs_get_children_reply_payload(request))[0]["g"]

        app_store.content.remove_node(_YOSEMITE)

        after = _walk_records(build_bbs_get_children_reply_payload(request))[0]["g"]
        self.assertNotEqual(after, before)

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


class TestBBSEditChannel(unittest.TestCase):
    """Class 0x04 — the TREEEDCL write channel BBSNAV binds to `g_BbsEcig`.

    New BBS Folder calls AddNode (selector 2). `CMosTreeNode::Delete` @
    MOSSHELL 0x7F3FFFA4 fetches a ticket (selector 12) and then calls DeleteNode
    (selector 3).
    """

    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    @staticmethod
    def _reply_payload(packets):
        return parse_packet(packets[0][:-1]).payload[8:]

    def _request(self, node_id):
        msg_id, _sep, board_id = node_id.partition(":")
        mnid = struct.pack("<II", int(msg_id), int(board_id))
        return (
            b"\x04\x82\x02\x00"
            + b"\x04" + bytes([0x80 | len(mnid)]) + mnid
            + b"\x83\x83"
        )

    @staticmethod
    def _add_folder_request():
        properties = dirsrv.build_property_record(
            [
                (0x02, "_F", struct.pack("<H", 0x0801)),
                (0x03, "m", struct.pack("<I", 0)),
                (0x10, "q", struct.pack("<II", 1, 0x0409)),
            ]
        )
        request = (
            b"\x04\x82\x02\x00"
            + b"\x04\x88"
            + struct.pack("<II", 0, 1)
            + b"\x04"
            + bytes([0x80 | len(properties)])
            + properties
            + b"\x83\x83\x84"
        )
        # Match the bounded log's complete 32-byte prefix and payload length.
        assert len(request) == 49
        assert request.hex().startswith(
            "0482020004880000000001000000049e1e0000000300025f46000108036d0000"
        )
        return request

    @staticmethod
    def _set_folder_name_request():
        # Captured after clicking Apply in the new BBS folder's Properties
        # dialog. The inner MNID is 0:2 and the single record is f="New BBS".
        request = bytes.fromhex(
            "048202000488000000000200000004921200000001000b6600014e657720424253008383"
        )
        assert len(request) == 36
        return request

    def test_get_ticket_is_answered_on_the_bbs_pipe(self):
        handler = BBSHandler(1, "BBS", signed_in())
        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x0C,
            request_id=0,
            payload=b"\x83\x85",
            server_seq=0,
            client_ack=0,
        )

        self.assertEqual(
            self._reply_payload(packets), dirsrv.build_get_ticket_reply_payload()
        )

    def test_add_node_creates_a_bbs_folder_and_returns_its_mnid(self):
        handler = BBSHandler(1, "BBS", signed_in())
        before = {node.node_id for node in app_store.content.get_children(_BOARD)}

        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x02,
            request_id=1,
            payload=self._add_folder_request(),
            server_seq=0,
            client_ack=0,
        )

        after = {node.node_id for node in app_store.content.get_children(_BOARD)}
        (new_id,) = after - before
        node = app_store.content.get_node(new_id)
        self.assertEqual(node.content.name, "New BBS Folder")
        self.assertEqual(node.app_id, APP_BBS_SERVICE)
        self.assertTrue(node.is_container)
        self.assertIsNotNone(node.content.bbs)
        self.assertTrue(node.content.bbs.has_children)
        message_id, board_id = struct.unpack("<II", node.mnid_a)
        # CBbsNavTreeNode_AddPropPages @ 0x7F5F17AE selects the BBS Folder
        # and Expiration pages only when the inner MNID's message id is zero.
        self.assertEqual(message_id, 0)
        self.assertNotEqual(board_id, 1)
        self.assertEqual(
            self._reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87\x84\x88" + node.mnid_a,
        )

    def test_apply_updates_the_bbs_folder_and_completes(self):
        handler = BBSHandler(1, "BBS", signed_in())
        handler.handle_request(
            msg_class=0x04,
            selector=0x02,
            request_id=1,
            payload=self._add_folder_request(),
            server_seq=0,
            client_ack=0,
        )
        self.assertEqual(app_store.content.get_node("0:2").content.name, "New BBS Folder")

        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x04,
            request_id=2,
            payload=self._set_folder_name_request(),
            server_seq=0,
            client_ack=0,
        )

        self.assertEqual(
            self._reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )
        self.assertEqual(app_store.content.get_node("0:2").content.name, "New BBS")

    def test_delete_node_drops_the_message_from_the_board(self):
        handler = BBSHandler(1, "BBS", signed_in())
        before = [n.node_id for n in app_store.content.get_children(_BOARD)]
        self.assertIn(_RE_YOSEMITE, before)

        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x03,
            request_id=1,
            payload=self._request(_RE_YOSEMITE),
            server_seq=0,
            client_ack=0,
        )

        # status 0 + operation id 0, no variable field — the client polls
        # GetStatus while the status DWORD reads 1.
        self.assertEqual(
            self._reply_payload(packets), b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87"
        )
        self.assertNotIn(
            _RE_YOSEMITE,
            [n.node_id for n in app_store.content.get_children(_BOARD)],
        )

    def test_unmapped_edit_selector_stays_unanswered(self):
        # Lock/Unlock/LinkNode and the rest of the edit table are not served.
        handler = BBSHandler(1, "BBS")
        with self.assertLogs("server.services.bbs", level="WARNING") as cap:
            result = handler.handle_request(
                msg_class=0x04,
                selector=0x05,
                request_id=0,
                payload=b"",
                server_seq=0,
                client_ack=0,
            )
        self.assertIsNone(result)
        self.assertTrue(any("unhandled" in m for m in cap.output))


class PostChannelTestCase(unittest.TestCase):
    """Base for the post tests — commits mutate the shared store, so undo them."""

    def setUp(self):
        reset_app_store()
        # A post is stamped with the account the connection signed in as.
        self.session = signed_in()
        self.handler = BBSHandler(5, "BBS", self.session)
        # A commit writes the upload to disk; keep the test run out of the repo.
        self._captures = tempfile.TemporaryDirectory()
        self._capture_dir = bbs._CAPTURE_DIR
        bbs._CAPTURE_DIR = pathlib.Path(self._captures.name)

    def tearDown(self):
        bbs._CAPTURE_DIR = self._capture_dir
        self._captures.cleanup()
        reset_app_store()

    def start(self, head, *, parent=0x200, board=1, total=None, attachments=b"", attach_count=0):
        """Method-2 request, in the parameter order FUN_7F5FB7CA builds."""
        return (
            b"\x03"
            + struct.pack("<I", len(head) if total is None else total)
            + b"\x04"
            + bytes([0x80 | 8])
            + struct.pack("<II", parent, board)
            + b"\x02\x01\x00"
            + _var(attachments)
            + b"\x02"
            + struct.pack("<H", attach_count)
            + _var(head)
            + b"\x03"
            + struct.pack("<I", len(head))
            + b"\x81"
        )

    def chunk(self, handle, data):
        """Method-3/4 request: handle byte, chunk, chunk length, receive byte."""
        return bytes([0x01, handle]) + _var(data) + b"\x03" + struct.pack("<I", len(data)) + b"\x81"

    def send(self, selector, payload):
        packets = self.handler.handle_request(BBS_CLASS_MESSAGE, selector, 1, payload, 5, 5)
        self.assertIsNotNone(packets, f"selector 0x{selector:02x} left the client waiting")
        return _reply_payload(packets)

    def post(self, head, body, **kwargs):
        """A whole two-segment post; returns the committed node.

        `total` counts the header block plus the body — the dword FUN_7F5FBD4E
        computes before any attachment segment is added.
        """
        kwargs.setdefault("total", len(head) + len(body))
        handle = self.send(BBS_SELECTOR_POST_START, self.start(head, **kwargs))[1]
        self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, body))
        return app_store.content.get_children(_BOARD)[-1]


class TestBBSPostFraming(PostChannelTestCase):
    """Class 0x0B methods 2/3/4/7 — the Compose window's chunked upload."""

    def test_start_answers_with_a_nonzero_handle(self):
        # Every post method receives exactly one byte (request vtable +0x20) and
        # FUN_7F5FB7CA bails with 0x8B0B0001 when it reads back zero. Leaving
        # the method unanswered instead parked the Compose window forever.
        reply = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD))
        self.assertEqual(reply[0], 0x81)
        self.assertNotEqual(reply[1], 0)
        self.assertEqual(reply[2], 0x87)
        self.assertEqual(len(reply), 3)

    def test_commit_quotes_the_handle_start_issued(self):
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD))[1]
        reply = self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, _POST_BODY))
        self.assertNotEqual(reply[1], 0)

    def test_unknown_handle_fails_the_post_instead_of_stalling_it(self):
        with self.assertLogs("server.services.bbs", level="ERROR"):
            reply = self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(0x7F, _POST_BODY))
        self.assertEqual(reply, bytes([0x81, 0x00, 0x87]))

    def test_concurrent_uploads_get_distinct_handles(self):
        first = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD))[1]
        second = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD))[1]
        self.assertNotEqual(first, second)

    def test_append_carries_a_middle_chunk(self):
        # FUN_7F5FC2D8 emits method 3 for any chunk that is neither the first
        # nor the one emptying the last segment — attachments, or a segment over
        # 1 MB. The article must reassemble in send order.
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD, total=999))[1]
        self.send(BBS_SELECTOR_POST_APPEND, self.chunk(handle, b"first half. "))
        self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, b"second half."))
        node = app_store.content.get_children(_BOARD)[-1]
        self.assertEqual(node.content.bbs.body_raw, b"first half. second half.")

    def test_abort_drops_the_upload_and_sends_no_receive_byte(self):
        # Method 7 carries the handle alone and FUN_7F5FB7CA releases it without
        # waiting, so the reply is a bare end-of-static.
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD))[1]
        self.assertEqual(self.send(BBS_SELECTOR_POST_ABORT, bytes([0x01, handle])), b"\x87")
        with self.assertLogs("server.services.bbs", level="ERROR"):
            reply = self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, _POST_BODY))
        self.assertEqual(reply[1], 0)

    def test_dispatch_routes_every_post_method_on_the_message_class(self):
        for selector in (
            BBS_SELECTOR_POST_START,
            BBS_SELECTOR_POST_APPEND,
            BBS_SELECTOR_POST_COMMIT,
            BBS_SELECTOR_POST_ABORT,
        ):
            with self.subTest(selector=selector):
                payload = (
                    self.start(_POST_HEAD)
                    if selector == BBS_SELECTOR_POST_START
                    else self.chunk(1, _POST_BODY)
                )
                self.assertIsNotNone(
                    self.handler.handle_request(BBS_CLASS_MESSAGE, selector, 1, payload, 5, 5)
                )


class TestBBSChunkedFieldUpload(PostChannelTestCase):
    """A field too big for the request body rides class 0xE6/0xE7 frames.

    `MPCCL!AppendTaggedRequestField @ 0x046067E2` swaps the field for a 6-byte
    `[0x05][stream_id][u32 length]` reference and queues the bytes through
    `AppendChunkedRequestField @ 0x04606CB2`, which stamps each frame
    `[0xE6|0xE7][stream_id]` and memcpy's the payload after it. 0xE7 is the last
    frame. Rich text and attachments always take this path — the body alone
    runs past the 1024-byte packet the client can receive.
    """

    def ref_chunk(self, handle, stream_id, total_length):
        """Method-3/4 request whose chunk is a reference, not inline bytes."""
        return (
            bytes([0x01, handle, 0x05, stream_id])
            + struct.pack("<I", total_length)
            + b"\x03"
            + struct.pack("<I", total_length)
            + b"\x81"
        )

    def feed(self, stream_id, data, *, last):
        msg_class = 0xE7 if last else 0xE6
        frame = bytes([msg_class, stream_id]) + data
        block = parse_host_block(frame)
        self.assertEqual(block.msg_class, msg_class)
        self.assertEqual(block.selector, stream_id)
        self.assertEqual(block.request_id, 0)
        self.assertEqual(block.payload, data, "continuation payload must not lose bytes")
        return self.handler.handle_request(
            block.msg_class, block.selector, block.request_id, block.payload, 5, 5
        )

    def test_continuation_frames_are_never_acked(self):
        # They are one-way. An ack on the stream would be a reply the client has
        # no request waiting for.
        self.assertIsNone(self.feed(1, b"abc", last=True))

    def test_referenced_field_reassembles_in_arrival_order(self):
        body = b"".join(bytes([0x41 + i]) * 200 for i in range(6)) + b"tail"
        total = len(_POST_HEAD) + len(body)
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD, total=total))[1]
        body, tail = body[:-4], body[-4:]
        self.send(BBS_SELECTOR_POST_APPEND, self.ref_chunk(handle, 4, len(body)))
        for offset in range(0, len(body), 460):
            frame = body[offset : offset + 460]
            self.feed(4, frame, last=offset + 460 >= len(body))
        self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, tail))
        node = app_store.content.get_children(_BOARD)[-1]
        self.assertEqual(node.content.bbs.body_raw, body + tail)

    def test_commit_waits_for_a_stream_that_has_not_closed(self):
        # The client does not drain the frames before it sends method 4, so the
        # commit lands first. Storing then would truncate the article.
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD, total=999))[1]
        before = len(app_store.content.get_children(_BOARD))
        self.send(BBS_SELECTOR_POST_COMMIT, self.ref_chunk(handle, 9, 12))
        self.feed(9, b"first ", last=False)
        self.assertEqual(len(app_store.content.get_children(_BOARD)), before)
        self.feed(9, b"half", last=True)
        children = app_store.content.get_children(_BOARD)
        self.assertEqual(len(children), before + 1)
        self.assertEqual(children[-1].content.bbs.body_raw, b"first half")

    def test_deferred_commit_still_acks_immediately(self):
        # FUN_7F5FB7CA reads the byte back and fails the post on zero, so the
        # ack cannot wait for the stream.
        handle = self.send(BBS_SELECTOR_POST_START, self.start(_POST_HEAD, total=999))[1]
        reply = self.send(BBS_SELECTOR_POST_COMMIT, self.ref_chunk(handle, 3, 4))
        self.assertEqual(reply, bytes([0x81, 0x01, 0x87]))


class TestChunkedReferenceDecoding(unittest.TestCase):
    def test_reference_is_six_bytes_and_carries_no_inline_data(self):
        # Parsing it as a variable field reads the stream id as a length byte
        # and swallows the rest of the request — that is what reduced a real
        # 1722-byte post to 207 bytes on the wire.
        payload = bytes([0x01, 0x2A, 0x05, 0x02]) + struct.pack("<I", 1534) + b"\x81"
        send_params, recv = parse_request_params(payload)
        self.assertEqual(recv, [0x81])
        self.assertEqual(len(send_params), 2)
        self.assertEqual(send_params[0].value, 0x2A)
        self.assertEqual(send_params[1].stream_id, 0x02)
        self.assertEqual(send_params[1].total_length, 1534)

    def test_copy_tag_0x45_decodes_the_same_way(self):
        # 0x45 is 0x05 with the caller's 0x40 bit carried over from tag 0x44.
        send_params, _ = parse_request_params(bytes([0x45, 0x07]) + struct.pack("<I", 9))
        self.assertEqual(send_params[0].tag, 0x45)
        self.assertEqual(send_params[0].stream_id, 0x07)
        self.assertEqual(send_params[0].total_length, 9)

    def test_variable_field_tag_0x04_is_untouched(self):
        send_params, _ = parse_request_params(b"\x04" + bytes([0x80 | 3]) + b"abc")
        self.assertEqual(send_params[0].data, b"abc")


class TestBBSPostRequestDecoding(PostChannelTestCase):
    def test_target_is_the_parent_message_and_its_board(self):
        # The 8-byte parameter comes from FUN_7F5FB7CA's context at +0xA8:
        # MAPI 0x68140003 (X-MOS-Parent) then the high dword of 0x68160014.
        # It packs like every other BBS mnid, so a reply to 0x200 on board 1
        # arrives as (0x200, 1).
        request = decode_post_start_request(self.start(_POST_HEAD, parent=0x200, board=1))
        self.assertEqual((request.parent_msg_id, request.board_id), (0x200, 1))

    def test_start_reads_the_total_size_and_the_first_chunk(self):
        request = decode_post_start_request(self.start(_POST_HEAD, total=1234))
        self.assertEqual(request.total_bytes, 1234)
        self.assertEqual(request.chunk, _POST_HEAD)

    def test_attachment_count_comes_from_the_second_word(self):
        request = decode_post_start_request(
            self.start(_POST_HEAD, attachments=struct.pack("<II", 7, 9), attach_count=2)
        )
        self.assertEqual(request.attachment_count, 2)

    def test_empty_attachment_array_is_the_common_shape(self):
        # A post with no attachments still sends the array parameter, as a
        # zero-length blob (`04 80`). Treating that as a missing parameter
        # would misalign every parameter after it.
        request = decode_post_start_request(self.start(_POST_HEAD))
        self.assertEqual(request.attachment_count, 0)
        self.assertEqual(request.chunk, _POST_HEAD)

    def test_abort_request_carries_a_handle_and_no_chunk(self):
        request = decode_post_chunk_request(bytes([0x01, 0x2A]))
        self.assertEqual(request.handle, 0x2A)
        self.assertEqual(request.chunk, b"")


class TestBBSPostedArticleParsing(PostChannelTestCase):
    def test_headers_end_at_the_first_blank_line(self):
        # FUN_7F5FBD4E terminates each line with the separator at 0x7F610C0C,
        # a single 0x0A, and closes the block with a second one. Splitting on
        # CRLF would swallow the whole article as headers.
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertEqual(node.content.name, "RE: RE: Yosemite")
        self.assertEqual(node.content.bbs.body_raw, _POST_BODY)

    def test_every_header_the_compose_window_writes_is_recognised(self):
        headers = parse_article_headers(_POST_HEAD)
        self.assertEqual(
            sorted(headers),
            [
                "References",
                "Subject",
                "X-MOS-Attach",
                "X-MOS-CP",
                "X-MOS-Format",
                "X-MOS-Icon",
                "X-MOS-Parent",
                "X-MOS-Size",
                "X-MOS-To",
            ],
        )

    def test_a_body_containing_a_blank_line_keeps_it(self):
        node = self.post(_POST_HEAD, b"one\n\ntwo")
        self.assertEqual(node.content.bbs.body_raw, b"one\n\ntwo")


class TestBBSPostCommit(PostChannelTestCase):
    def test_commit_puts_the_message_on_the_board(self):
        before = len(app_store.content.get_children(_BOARD))
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertEqual(len(app_store.content.get_children(_BOARD)), before + 1)
        self.assertEqual(node.content.name, "RE: RE: Yosemite")

    def test_new_message_takes_a_free_id_on_the_same_board(self):
        # Message ids are the field_8 half of the mnid; `_P` threading and the
        # article fetch both key on them, so a collision would alias two posts.
        existing = {n.node_id for n in app_store.content.get_children(_BOARD)}
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertNotIn(node.node_id, existing)
        self.assertTrue(node.node_id.endswith(":1"))

    def test_thread_parent_comes_from_the_header(self):
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertEqual(node.content.bbs.parent_subid, 0x200)

    def test_post_is_a_message_not_a_container_and_reports_no_children(self):
        # `b` bit 0x01 SET is bbsnav's conversation test, and `_F` bit 0x1000
        # stops OkToGetChildren asking a message for children it has none of.
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertFalse(node.is_container)
        self.assertFalse(node.content.bbs.has_children)

    def test_committed_post_survives_a_board_enumeration(self):
        node = self.post(_POST_HEAD, _POST_BODY)
        request = DirsrvRequest(node_id=_BOARD, prop_group="e\x00_P\x00_D")
        records = _walk_records(build_bbs_get_children_reply_payload(request))
        self.assertIn(node.content.name, [r["e"] for r in records])

    def test_a_post_with_no_subject_still_names_its_row(self):
        # The Compose window writes the Subject line even when the property read
        # back PT_ERROR, leaving it empty. An empty `e` gives a nameless row.
        head = _POST_HEAD.replace(b"Subject: RE: RE: Yosemite\n", b"Subject: \n")
        self.assertTrue(self.post(head, _POST_BODY).content.name)

    def test_the_author_is_the_account_the_connection_signed_in_as(self):
        # The uploaded article carries no From header, so the identity can only
        # come from the session. It goes out as `_a` and as the article's From,
        # which is also the key the Member Properties sheet resolves on.
        node = self.post(_POST_HEAD, _POST_BODY)
        display_name = seed_user().display_name

        self.assertEqual(node.content.bbs.author, display_name)
        self.assertIn(f"From: {display_name}\n".encode(), bbs.build_bbs_article(node))
        self.assertEqual(
            app_store.member.get_member(display_name).display_name, display_name
        )

    def test_a_different_account_signs_its_own_posts(self):
        self.handler = BBSHandler(5, "BBS", signed_in(SUBSCRIBER))
        node = self.post(_POST_HEAD, _POST_BODY)
        self.assertEqual(node.content.bbs.author, seed_user(SUBSCRIBER).display_name)


class TestBBSPostedAttachments(PostChannelTestCase):
    """A post carrying files — one upload segment per attachment past the body.

    `FUN_7F5FC1D4` @ 0x7F5FC1D4 appends one segment per attachment after the
    body, and the method-2 `total_bytes` dword counts the header block plus the
    body alone. The file bytes therefore start at exactly that offset and never
    belong to the article the reader streams into its RichEdit.
    """

    def post_with_file(self, file_bytes, *, count=1, body=None):
        head = _POST_HEAD.replace(b"X-MOS-Attach: 0\n", f"X-MOS-Attach: {count}\n".encode())
        body = _POST_BODY if body is None else body
        handle = self.send(
            BBS_SELECTOR_POST_START,
            self.start(head, total=len(head) + len(body), attach_count=count),
        )[1]
        self.send(BBS_SELECTOR_POST_APPEND, self.chunk(handle, body))
        self.send(BBS_SELECTOR_POST_COMMIT, self.chunk(handle, file_bytes))
        return app_store.content.get_children(_BOARD)[-1]

    def test_file_bytes_stay_out_of_the_body(self):
        node = self.post_with_file(b"\x00\x01\x02PK-ish file bytes")
        self.assertEqual(node.content.bbs.body_raw, _POST_BODY)
        self.assertEqual(node.content.bbs.attachment_data, b"\x00\x01\x02PK-ish file bytes")

    def test_article_declares_the_attachment_count(self):
        node = self.post_with_file(b"file", count=2)
        self.assertIn(b"X-MOS-Attach: 2\n", build_bbs_article(node))

    def test_each_attachment_resolves_at_message_id_plus_k(self):
        # FUN_7F5FC919 @ 0x7F5FC919 addresses the k-th MOSAF object in the body
        # as (message id + k, board id) and reads `z` and `_r` off it. An mnid
        # that does not resolve leaves the object without its properties.
        node = self.post_with_file(b"file", count=2)
        msg_id, _sep, board_id = node.node_id.partition(":")
        for k in (1, 2):
            with self.subTest(attachment=k):
                key = f"{int(msg_id) + k}:{board_id}"
                request = DirsrvRequest(node_id=key, prop_group="z\x00_r")
                record = _walk_records(build_bbs_get_properties_reply_payload(request))[0]
                self.assertEqual(record["z"], 0)
                self.assertEqual(record["_r"], 0)

    def test_attachments_are_not_listed_on_the_board(self):
        # They are files, not messages. A row per attachment would show up in
        # the reader's list pane.
        node = self.post_with_file(b"file")
        children = {child.node_id for child in app_store.content.get_children(_BOARD)}
        msg_id, _sep, board_id = node.node_id.partition(":")
        self.assertNotIn(f"{int(msg_id) + 1}:{board_id}", children)

    def test_the_next_post_starts_past_the_attachment_ids(self):
        # A message with attachments owns message id + 1 … + N as well. Handing
        # the next post one of those aliases two nodes onto one mnid.
        first = self.post_with_file(b"file", count=2)
        second = self.post(_POST_HEAD, _POST_BODY)
        first_id = int(first.node_id.partition(":")[0])
        self.assertEqual(int(second.node_id.partition(":")[0]), first_id + 3)


class TestBBSPostedBodyRoundTrip(PostChannelTestCase):
    def test_uploaded_body_goes_back_out_untouched(self):
        # The Compose window encodes before it uploads — RTFCOMP (MAPI
        # compressed RTF) or TEXT, per the X-MOS-Format it wrote. Re-encoding
        # would corrupt a compressed body, which no encoder here produces.
        compressed = bytes(range(0x20, 0x60))
        head = _POST_HEAD.replace(b"X-MOS-Format: TEXT\n", b"X-MOS-Format: RTFCOMP\n")
        node = self.post(head, compressed)
        article = build_bbs_article(node)
        self.assertEqual(article.partition(b"\n\n")[2], compressed)

    def test_format_header_is_echoed_so_the_reader_picks_the_same_stream(self):
        head = _POST_HEAD.replace(b"X-MOS-Format: TEXT\n", b"X-MOS-Format: RTFCOMP\n")
        node = self.post(head, b"x")
        self.assertIn(b"X-MOS-Format: RTFCOMP\n", build_bbs_article(node))

    def test_size_column_reports_the_length_the_client_declared(self):
        # X-MOS-Size is the plain-text length, which an encoded body no longer
        # has. Both the `p` property and the header must carry the declared one.
        head = _POST_HEAD.replace(b"X-MOS-Size: 11\n", b"X-MOS-Size: 4096\n")
        node = self.post(head, _POST_BODY)
        self.assertEqual(node.content.size_bytes, 4096)
        self.assertIn(b"X-MOS-Size: 4096\n", build_bbs_article(node))

    def test_a_posted_reply_is_readable_over_the_article_channel(self):
        node = self.post(_POST_HEAD, _POST_BODY)
        msg_id, _sep, board_id = node.node_id.partition(":")
        wire = (
            b"\x04"
            + bytes([0x80 | 8])
            + struct.pack("<II", int(msg_id), int(board_id))
            + b"\x83\x85"
        )
        article = build_bbs_article_reply_payload(wire)[7:]
        head, sep, body = article.partition(b"\n\n")
        self.assertEqual(sep, b"\n\n")
        self.assertIn(b"Subject: RE: RE: Yosemite\n", head)
        self.assertEqual(body, _POST_BODY)


if __name__ == "__main__":
    unittest.main()
