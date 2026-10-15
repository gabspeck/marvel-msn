"""DIRSRV and TREEEDCL: tree reads, property records and node editing."""

import pathlib
import shutil
import struct
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from server.config import (
    MPC_CLASS_CONTINUATION_LAST,
    MPC_CLASS_CONTINUATION_MORE,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.models import DirsrvRequest
from server.mpc import (
    build_host_block,
    build_service_packet,
    decode_dirsrv_request,
    parse_host_block,
)
from server.services.dirsrv import (
    DIRSRV_CLASS_TREE,
    DS_E_NOT_FOUND,
    ENUM_SHN_KEY_ICONS,
    SUPPORTED_BROWSE_LCIDS,
    DirsrvHandler,
    add_node_reply,
    build_property_record,
    build_props,
    delete_node_reply,
    enum_shn_reply,
    get_children_reply,
    get_datasets_reply,
    get_deid_from_go_word_reply,
    get_parents_reply,
    get_properties_reply,
    get_ticket_reply,
    set_properties_reply,
)
from server.session import Session
from server.store import (
    RIGHTS_AUTHORING,
    app_store,
    blackbird_state,
    default_seed,
    reset_app_store,
)
from server.transport import parse_packet

from .support import (
    ADMIN,
    SUBSCRIBER,
    AddNodeContentStore,
    reply_payload,
    signed_in,
)


def _walk_get_children_records(payload):
    """Parse a DIRSRV GetChildren reply into a list of {prop_name: parsed_value}.

    Per `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` §"Per-record on-wire format":
        +0  u32 total_size
        +4  u16 prop_count
        +6  for prop in prop_count: u8 type, asciiz name, value-by-type

    Returns parsed values: 'a' as raw 8-byte mnid blob; 'e' as decoded ASCII.
    Other props are kept in raw form by their type byte. Used by structural
    record-vs-identity assertions.
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
                value = payload[p : p + 1]
                p += 1
            elif ptype == 0x03:
                value = payload[p : p + 4]
                p += 4
            elif ptype == 0x04 or ptype == 0x0C:
                value = payload[p : p + 8]
                p += 8
            elif ptype == 0x0E:
                blob_len = struct.unpack_from("<I", payload, p)[0]
                p += 4
                value = payload[p : p + blob_len]
                p += blob_len
            elif ptype in (0x0A, 0x0B):
                flag = payload[p]
                p += 1
                if flag & 0x02:
                    value = ""
                elif flag & 0x01:
                    end = payload.index(b"\x00", p)
                    value = payload[p:end].decode("ascii", errors="replace")
                    p = end + 1
                else:
                    end = p
                    while end + 1 < len(payload) and not (
                        payload[end] == 0 and payload[end + 1] == 0
                    ):
                        end += 2
                    value = payload[p:end].decode("utf-16le", errors="replace")
                    p = end + 2
            else:
                raise AssertionError(f"unknown ptype 0x{ptype:02x} for prop {name!r}")
            props[name] = value
        assert p - rec_start == total_size, (
            f"record size mismatch: walked {p - rec_start} vs declared {total_size}"
        )
        records.append(props)
    return records


class TestDIRSRVReply(unittest.TestCase):
    def test_self_properties(self):
        request = DirsrvRequest(
            dword_0=0,
            dword_1=1,
            prop_group="q",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        # Should start with two 0x83 dwords
        self.assertEqual(payload[0], 0x83)
        status = struct.unpack("<I", payload[1:5])[0]
        self.assertEqual(status, 0)
        self.assertEqual(payload[5], 0x83)
        # Then 0x87 end, then 0x88 dynamic
        self.assertIn(0x87, payload)
        self.assertIn(0x88, payload)

    def test_children_of_default_root_return_localized_wrappers(self):
        # DirsrvRequest() defaults to node_id="0:0" — GetSpecialMnid(0), the
        # Worldwide Categories hub. Its children are the localized Categories
        # wrappers.
        request = DirsrvRequest(
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Categories (US)", payload)
        self.assertIn(b"Categorias (BR)", payload)

    def test_with_self_flag_leads_the_reply_with_the_requested_node(self):
        # `CMosTreeNode::QueryOutOfDate` @ 0x7F3FDB3F asks for {g, a} with
        # flags=1 and reads the reply as [self][children…]. The lazy loader
        # `OkToGetChildren` sends flags=0 and must keep getting children alone.
        prop_group = "g\x00a"
        plain = _walk_get_children_records(
            get_children_reply(DirsrvRequest(node_ids=["1:16"], prop_group=prop_group))
        )
        with_self = _walk_get_children_records(
            get_children_reply(DirsrvRequest(node_ids=["1:16"], prop_group=prop_group, flags=1))
        )

        self.assertEqual(len(with_self), len(plain) + 1)
        self.assertEqual(
            with_self[0]["a"],
            app_store.content.get_node("1:16").mnid_a,
        )
        self.assertEqual(with_self[1:], plain)

    def test_all_children_grant_authoring_rights(self):
        request = DirsrvRequest(
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e\x00x",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request, RIGHTS_AUTHORING)
        records = _walk_get_children_records(payload)

        self.assertGreater(len(records), 0)
        for record in records:
            self.assertEqual(record["x"], struct.pack("<I", 0x70))
        self.assertIn(b"\x03x\x00\x70\x00\x00\x00", payload)
        self.assertNotIn(b"\x0ex\x00", payload)

    def test_parent_and_child_counts_follow_the_directory_graph(self):
        request = DirsrvRequest(
            node_ids=["1:256"],
            node_id_raw=struct.pack("<II", 1, 256),
            prop_group="np\x00nc",
            recv_descriptors=[0x83, 0x83, 0x85],
        )

        [record] = _walk_get_children_records(get_properties_reply(request))

        self.assertEqual(record["np"], struct.pack("<I", 1))
        self.assertEqual(record["nc"], struct.pack("<I", 13))

    def test_parent_count_increases_when_a_node_is_listed_twice(self):
        self.addCleanup(reset_app_store)
        node = app_store.content.get_node("4:0")
        app_store.content.add_child("0:0", node)
        request = DirsrvRequest(
            node_ids=[node.node_id],
            node_id_raw=node.mnid_a,
            prop_group="np\x00nc",
            recv_descriptors=[0x83, 0x83, 0x85],
        )

        [record] = _walk_get_children_records(get_properties_reply(request))

        self.assertEqual(record["np"], struct.pack("<I", 2))
        self.assertEqual(record["nc"], struct.pack("<I", 0))

    def test_get_properties_returns_self_record_only(self):
        # GetProperties (selector 0x00) is always a single-record query for
        # the requested node's own props. SetPropertyGroupFromPsp on the
        # client feeds the FIRST received record into the requesting node;
        # delegating to children corrupts wrappers (Cats US ends up named
        # "Arts and Entertainment", its first child).
        request = DirsrvRequest(
            node_ids=[f"1:{0x10}"],
            node_id_raw=struct.pack("<II", 1, 0x10),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        self.assertIn(b"Categories (US)", payload)
        # First child A&E must NOT appear — that was the corruption signal.
        self.assertNotIn(b"Arts and Entertainment", payload)
        # Self-mnid must be present.
        self.assertIn(struct.pack("<II", 1, 0x10), payload)

    def test_worldwide_categories_hub_self_properties(self):
        # Wire "0:0" is GetSpecialMnid(0) — the Worldwide Categories hub.
        # mnid_a = (0, 0), its own (field_8, field_c).
        #
        # The `e` we send here never reaches the UI: RememberProperty @
        # MOSSHELL 0x7F3FBA69 matches the mnid against GetSpecialMnid(0)/(1)
        # and substitutes STRINGTABLE 0x8E / 0x8F. We still send the matching
        # text so server logs read the same as the client.
        request = DirsrvRequest(
            node_ids=["0:0"],
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        self.assertIn(b"Worldwide Categories", payload)

    def test_special_msn_today_node_returns_title(self):
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        self.assertIn(b"MSN Today", payload)

    def test_explicit_leaves_skip_the_fallback_sentinel(self):
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_special_msn_today_leaf_children_emit_self_nav_record(self):
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(struct.pack("<II", 4, 0), payload)
        self.assertIn(b"MSN Today", payload)
        # 4:0 is a leaf: b=0x01 (LEAF), so HOMEBASE click goes through
        # ExecuteCommand's Exec branch (not Browse).
        self.assertIn(b"\x01b\x00\x01", payload)
        # c=6 (APP_MEDIA_VIEWER / MOSVIEW.EXE). Both click (via
        # ExecuteCommand 0x3000 leaf path) and the "Show MSN Today on
        # startup" auto-Exec (via CMosShellFolder::ParseDisplayName 'T'
        # branch with NO 'b' gate — docs/MOSSHELL.md §7.4) land in
        # CMosTreeNode::Exec, which on c!=7 falls through to the sync
        # HRMOSExec(6, …) path: MCM formats `mosview.exe -MOS:6:<shn>:w`
        # and CreateProcessA's it (docs/MOSVIEW.md §3.1).
        self.assertIn(b"\x03c\x00" + struct.pack("<I", 6), payload)
        self.assertNotIn(b"\x03c\x00" + struct.pack("<I", 7), payload)
        self.assertNotIn(b"\x03c\x00" + struct.pack("<I", 1), payload)
        # No `fn` on a MOSVIEW leaf — the launcher reads the mnid off
        # the wire cmdline, not a DnR temp filename.
        self.assertNotIn(b"fn\x00\x01MSNTODAY.HTM", payload)

    def test_worldwide_categories_hub_holds_only_categories_wrappers(self):
        # Wire "0:0" = GetSpecialMnid(0) = the Worldwide Categories hub, and the
        # HOMEBASE Categories LJUMP 1:0:0:0 target. It carries exactly the
        # localized Categories wrappers: browsing the hub lists them all, and
        # GetLocalizedNode takes the first to survive the locale filter, so
        # Cats (US) must lead for the Categories button to land there.
        #
        # Regression guard: the Member Assistance wrappers belong to the OTHER
        # hub ("1:0"), and neither hub may list itself. Serving them here put
        # four extra rows — including a self-reference — in the Worldwide
        # Categories view.
        request = DirsrvRequest(
            node_ids=["0:0"],
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(struct.pack("<II", 1, 0x10), payload)  # Categories (US) 'a'
        self.assertIn(struct.pack("<II", 1, 0x13), payload)  # Categorias (BR) 'a'
        self.assertIn(b"Categories (US)", payload)
        self.assertIn(b"Categorias (BR)", payload)
        self.assertNotIn(struct.pack("<II", 1, 0x11), payload)  # no MA (US)
        self.assertNotIn(struct.pack("<II", 1, 0x14), payload)  # no MA (BR)
        self.assertNotIn(struct.pack("<II", 1, 0), payload)  # no WW MA hub
        self.assertNotIn(b"Member Assistance", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)  # no MSN Today
        self.assertNotIn(struct.pack("<II", 3, 1), payload)  # no Favorite Places

    def test_worldwide_member_assistance_hub_holds_only_ma_wrappers(self):
        # Twin of the above on wire "1:0" = GetSpecialMnid(1), the LJUMP
        # 1:1:0:0 target. This hub was already correct; the assertion pins it
        # so the two hubs stay symmetric.
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(struct.pack("<II", 1, 0x11), payload)  # Member Assistance (US)
        self.assertIn(struct.pack("<II", 1, 0x14), payload)  # Assistencia (BR)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertNotIn(struct.pack("<II", 1, 0x10), payload)  # no Cats (US)
        self.assertNotIn(struct.pack("<II", 1, 0x13), payload)  # no Cats (BR)
        self.assertNotIn(b"Categories (US)", payload)

    def test_narrow_root_children_request_returns_localized_wrappers(self):
        request = DirsrvRequest(
            node_ids=["0:0"],
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(struct.pack("<II", 1, 0x10), payload)
        self.assertIn(b"Categories (US)", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)

        # Server "1:0" is the LJUMP 1:1:0:0 target (client's MSN Central /
        # Worldwide Member Assistance hub). Its children are MA US + MA BR.
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(struct.pack("<II", 1, 0x11), payload)
        self.assertIn(b"Member Assistance (US)", payload)

        # Unknown / terminal-leaf nodes must not leak the fallback sentinel
        # (FFFFFFFF:FFFFFFFF) into the listview.
        for node_id, raw in (
            ("3:1", struct.pack("<II", 3, 1)),
            (f"1:{0x100}", struct.pack("<II", 1, 0x100)),  # Arts and Entertainment
        ):
            request = DirsrvRequest(
                node_ids=[node_id],
                node_id_raw=raw,
                dword_0=1,
                dword_1=14,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = get_children_reply(request)
            self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_startup_browse_walk_for_hubs_omits_menu_aliases(self):
        # MSN Today (4:0) and Favorite Places (3:1) are client-side HOMEBASE
        # aliases. Neither hub may enumerate them.
        for node_id, f8, localized in (
            ("0:0", 0, 0x10),  # WW Categories → Categories (US)
            ("1:0", 1, 0x11),  # WW Member Assistance → Member Assistance (US)
        ):
            request = DirsrvRequest(
                node_ids=[node_id],
                node_id_raw=struct.pack("<II", f8, 0),
                dword_0=1,
                dword_1=14,
                prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = get_children_reply(request)
            self.assertNotIn(struct.pack("<II", 4, 0), payload)
            self.assertNotIn(struct.pack("<II", 3, 1), payload)
            # The hub's own localized wrapper — the GetLocalizedNode target
            # for that HOMEBASE button — must be present.
            self.assertIn(struct.pack("<II", 1, localized), payload)

    def test_worldwide_member_assistance_hub_self_identity(self):
        # Server wire "1:0" = client's MSN Central, overloaded as Worldwide
        # Member Assistance. Self-query returns the WMA name.
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        self.assertIn(b"Worldwide Member Assistance", payload)

    def test_worldwide_member_assistance_lists_locales(self):
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)

    def test_member_assistance_us_lists_nine_with_msn_today(self):
        # 1:17 = Member Assistance (US). Its children include the live 4:0
        # MSN Today leaf so clicking the in-MA entry launches MOSVIEW exactly
        # as the HOMEBASE MSN Today button does.
        request = DirsrvRequest(
            node_ids=[f"1:{0x11}"],
            node_id_raw=struct.pack("<II", 1, 0x11),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"The MSN Member Lobby", payload)
        self.assertIn(b"MSN Beta Center", payload)
        self.assertIn(b"MSN Today", payload)
        self.assertIn(b"Member Agreement", payload)
        self.assertIn(struct.pack("<II", 4, 0), payload)  # live MOSVIEW leaf

    def test_categories_us_children_emit_fourteen_categories(self):
        request = DirsrvRequest(
            node_ids=[f"1:{0x10}"],
            node_id_raw=struct.pack("<II", 1, 0x10),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e\x00tp",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Arts and Entertainment", payload)
        self.assertIn(b"The Microsoft Network Beta", payload)
        # "Folder"-tagged entries still surface as distinct listview rows.
        self.assertIn(b"Interest, Leisure and Hobbies", payload)

    def test_arts_and_entertainment_children_emit_subleaves(self):
        request = DirsrvRequest(
            node_ids=[f"1:{0x100}"],
            node_id_raw=struct.pack("<II", 1, 0x100),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Books and Writing", payload)
        self.assertIn(b"Coming Attractions", payload)
        self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_filter_on_scopes_worldwide_children_to_lcid(self):
        # filter_on=1, lcid=pt-BR → WW MA's children (server "1:0") drop
        # MA (US) and keep only MA (BR).
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=struct.pack("<II", 1, 0x0416),
            locale_lcid=0x0416,
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)
        self.assertNotIn(b"Member Assistance (US)", payload)

        # filter_on=0 — the 4-byte form — keeps everything.
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=b"\x00\x00\x00\x00",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)

    def test_filter_on_picks_localized_categories(self):
        # LJUMP 1:0:0:0 (HOMEBASE Categories) targets MSN root and the client
        # calls GetLocalizedNode with filter_on=1. The first locale-matching
        # child must be Categorias (BR) under pt-BR — without the localized
        # wrapper as a direct child of MSN root the filter would skip past
        # both Cats(US) and MA(US) and surface Worldwide Categories instead.
        request = DirsrvRequest(
            node_ids=["0:0"],
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=struct.pack("<II", 1, 0x0416),
            locale_lcid=0x0416,
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        records = _walk_get_children_records(payload)
        self.assertGreater(len(records), 0)
        self.assertEqual(records[0].get("e"), "Categorias (BR)")
        self.assertEqual(struct.unpack("<II", records[0]["a"]), (1, 0x13))
        names = [r.get("e") for r in records]
        self.assertNotIn("Categories (US)", names)
        self.assertNotIn("Member Assistance (US)", names)

    def test_records_match_node_identity(self):
        # Structural per-record walk: every GetChildren record's `a` (mnid blob)
        # must match the `e` (display name) at that index. Catches record
        # mislabel / ordering bugs that substring asserts cannot.
        cases = [
            (
                "0:0",
                struct.pack("<II", 0, 0),
                [
                    ((1, 0x10), "Categories (US)"),
                    ((1, 0x13), "Categorias (BR)"),
                ],
            ),
            (
                "1:0",
                struct.pack("<II", 1, 0),
                [
                    ((1, 0x11), "Member Assistance (US)"),
                    ((1, 0x14), "Assistencia ao Associado (BR)"),
                ],
            ),
            (
                f"1:{0x10}",
                struct.pack("<II", 1, 0x10),
                [
                    ((1, 0x100), "Arts and Entertainment"),
                    ((1, 0x101), "Business and Finance"),
                    ((1, 0x102), "Computers and Software"),
                    ((1, 0x103), "Education and Reference"),
                    ((1, 0x104), "Home and Family"),
                    ((1, 0x105), "Interest, Leisure and Hobbies"),
                    ((1, 0x106), "People and Communities"),
                    ((1, 0x107), "Public Affairs"),
                    ((1, 0x108), "Science and Technology"),
                    ((1, 0x109), "Special Events"),
                    ((1, 0x10A), "Sports, Health and Fitness"),
                    ((1, 0x10B), "The Internet Center"),
                    ((1, 0x10C), "The MSN Member Lobby"),
                    ((1, 0x10D), "The Microsoft Network Beta"),
                    ((1, 0x10E), "Media View samples"),
                    ((1, 0x10F), "MSN Chat"),
                ],
            ),
            (
                f"1:{0x11}",
                struct.pack("<II", 1, 0x11),
                [
                    ((1, 0x300), "The MSN Member Lobby"),
                    ((1, 0x301), "MSN Beta Center"),
                    ((4, 0), "MSN Today"),
                    ((1, 0x303), "Member Assistance Kiosk - July 19"),
                    ((1, 0x304), "First-Time-User Experience"),
                    ((1, 0x305), "Member Guidelines"),
                    ((1, 0x306), "MSN Beta News Flash - July 19"),
                    ((1, 0x307), "Member Guidelines"),
                    ((1, 0x308), "Member Agreement"),
                ],
            ),
            (
                f"1:{0x10E}",
                struct.pack("<II", 1, 0x10E),
                [
                    ((0x1000, 0), "Employee Handbook Example"),
                    ((0x1001, 0), "France Magazine"),
                    ((0x1002, 0), "MediaView Online Documentation"),
                    ((1, 0x400), "Blackbird Publish Target"),
                    ((1, 0x111), "DnR Transfer Test"),
                    ((1, 0x112), "DnR Compressed Test"),
                    ((1, 0x113), "DnR Compressed Test B"),
                    ((1, 0x114), "DnR Server-Compressed"),
                ],
            ),
        ]
        for node_id, raw, expected in cases:
            request = DirsrvRequest(
                node_ids=[node_id],
                node_id_raw=raw,
                dword_0=1,
                dword_1=14,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = get_children_reply(request)
            records = _walk_get_children_records(payload)
            self.assertEqual(
                len(records),
                len(expected),
                f"node={node_id} record count {len(records)} != expected {len(expected)}",
            )
            for idx, (props, (exp_a, exp_e)) in enumerate(zip(records, expected, strict=True)):
                a_blob = props.get("a")
                self.assertIsNotNone(a_blob, f"node={node_id} idx={idx} missing 'a'")
                self.assertEqual(
                    struct.unpack("<II", a_blob),
                    exp_a,
                    f"node={node_id} idx={idx}: a={struct.unpack('<II', a_blob)} != {exp_a}",
                )
                self.assertEqual(
                    props.get("e"),
                    exp_e,
                    f"node={node_id} idx={idx}: e={props.get('e')!r} != {exp_e!r}",
                )

    def test_dsnav_details_column_tags_use_documented_type_bytes(self):
        # DSNAV.md §12/§14.2 pins the wire types for the details-view columns:
        # tp=0x0A ASCIIZ, p=0x03 DWORD (size), w=0x0C FILETIME (8-byte).
        # `l` is advertised but unread — DWORD 0 is the safe default (§12).
        request = DirsrvRequest(
            node_ids=["1:0"],
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        # Containers emit type_str="Directory" via _container_content default.
        # ASCII string bodies use the shared flag-byte wire body: \x01 + asciiz.
        self.assertIn(b"\x0atp\x00\x01Directory\x00", payload)
        # Category containers have size_bytes=0 → inline 0x03 DWORD 0.
        self.assertIn(b"\x03p\x00\x00\x00\x00\x00", payload)
        # Every seeded container carries the content-drop date, so `w` ships as
        # a 0x0C FILETIME.
        self.assertIn(b"\x0cw\x00", payload)
        for type_byte in (0x03, 0x0A, 0x0E, 0x0B):
            self.assertNotIn(bytes([type_byte]) + b"w\x00", payload)
        # `l` still emits as DWORD 0 (§12 safe default for unresolved tags).
        self.assertIn(b"\x03l\x00\x00\x00\x00\x00", payload)
        # Regression guard: the old 0x0E blob emit must be gone for these tags.
        self.assertNotIn(b"\x0etp\x00", payload)
        self.assertNotIn(b"\x0ep\x00", payload)
        self.assertNotIn(b"\x0el\x00", payload)

    def test_undated_node_still_ships_w_as_an_empty_string(self):
        # A node with no timestamp must still emit `w`, as an EMPTY 0x0A string
        # (flag byte 0x01, zero-length). The column formatter @ 0x7F3FBC12 case
        # 0x0A copies the ASCIIZ through, so the cell renders blank and the
        # cache element is marked received. Omitting the tag instead poisons it
        # permanently — see build_props' PROP_LAST_CHANGED comment. No seeded
        # node takes this path any more, so build the undated node here.
        node = replace(
            app_store.content.get_node("1:256"),
            content=replace(
                app_store.content.get_node("1:256").content,
                modified="",
                modified_filetime=0,
            ),
        )
        props = build_props(["w"], node, is_children=True)
        self.assertEqual(props, [(0x0A, "w", b"\x01\x00")])

    def test_msn_today_leaf_emits_nonzero_size_dword(self):
        # The MSN Today fixture carries size_bytes=5*1024*1024; `p` must land
        # as an inline 0x03 DWORD so MOSSHELL's FormatSizeString formats it,
        # not the low-4 of a heap pointer.
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"\x03p\x00" + struct.pack("<I", 5 * 1024 * 1024), payload)
        # tp carries the MSN Today fixture's type_str "News & Features".
        self.assertIn(b"\x0atp\x00\x01News & Features\x00", payload)
        # `w` ships as 0x0C + 8-byte FILETIME (100-ns since 1601-01-01 UTC).
        # Fixture date "April 15, 2026" → FILETIME. Recompute here to stay in
        # sync with `_date_string_to_wire_filetime` in store/fixtures.py.
        from server.store.fixtures import _date_string_to_wire_filetime

        ft = _date_string_to_wire_filetime("April 15, 2026")
        self.assertGreater(ft, 0)
        self.assertIn(b"\x0cw\x00" + struct.pack("<Q", ft), payload)
        # Regression guards: `w` must not land as DWORD or as blob.
        self.assertNotIn(b"\x03w\x00", payload)
        self.assertNotIn(b"\x0ew\x00", payload)

    def test_msn_today_mixed_content_request_returns_fixture_values(self):
        """Client can mix nav and content props on is_children=True and get real values."""
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="e\x00j\x00k\x00ca\x00tp\x00z\x00o\x00g",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_children_reply(request)
        self.assertIn(b"\x0ae\x00\x01MSN Today\x00", payload)
        self.assertIn(b"\x0bj\x00\x01Your daily window to MSN.\x00", payload)
        self.assertIn(b"\x0bk\x00\x01today\x00", payload)
        self.assertIn(b"\x0bca\x00\x01News\x00", payload)
        self.assertIn(b"\x0atp\x00\x01News & Features\x00", payload)
        # z, o are DWORD 0 in the fixture — but emitted as 0x03 (not the old
        # else-branch DWORD 0 that masked whether the builder knew the prop).
        self.assertIn(b"\x03z\x00" + struct.pack("<I", 0), payload)
        self.assertIn(b"\x03o\x00" + struct.pack("<I", 0), payload)
        # g still DWORD 0 (purpose unresolved).
        self.assertIn(b"\x03g\x00" + struct.pack("<I", 0), payload)

    def test_msn_today_dialog_uses_dialog_wire_types(self):
        """Properties dialog (is_children=False) gets 0x0B tp and 0x0B w string."""
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="e\x00tp\x00w\x00j",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        self.assertIn(b"\x0ae\x00\x01MSN Today\x00", payload)
        self.assertIn(b"\x0btp\x00\x01News & Features\x00", payload)
        self.assertIn(b"\x0bw\x00\x01April 15, 2026\x00", payload)
        self.assertIn(b"\x0bj\x00\x01Your daily window to MSN.\x00", payload)

    def test_language_prop_ships_as_counted_lcid_array(self):
        # Per-node `q` lookup (not the 0:0 language-list short-circuit):
        # MSN Today's language travels on the wire as type 0x04 qword
        # so the client's `*(u32*)(value + 4)` read lands on the LCID
        # instead of adjacent heap. Packing as type 0x03 DWORD would
        # put the LCID at offset 0 and the +4 read would fall off the
        # 4-byte buffer — root cause of the garbage combobox.
        request = DirsrvRequest(
            node_ids=["4:0"],
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="q",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = get_properties_reply(request)
        # DSNED stores q as SVCPROP type 0x10, whose size invariant is
        # `length == count * 4 + 4`. One LCID therefore starts with count 1.
        self.assertIn(b"\x04q\x00" + struct.pack("<II", 1, 1033), payload)
        # Regression guard: the old 4-byte DWORD emit must be gone.
        self.assertNotIn(b"\x03q\x00" + struct.pack("<I", 1033), payload)

    def test_language_list_has_one_record_per_locale(self):
        # The MCM browse-language worker opens a DIRSRV pipe with
        # ver_param="U" and asks for `q` on node 0:0 with a 4-byte zero
        # locale. Observed on the wire as selector 0x02 (dword_0=0,
        # is_children=False) — NOT the GetChildren selector the static
        # RE suggested. Gate on propList=["q"] so we short-circuit to a
        # per-locale reply regardless of is_children.
        for dword_0 in (0, 1):
            request = DirsrvRequest(
                node_ids=["0:0"],
                node_id_raw=struct.pack("<II", 0, 0),
                dword_0=dword_0,
                dword_1=1,
                prop_group="q",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = get_children_reply(request)
            for lcid in SUPPORTED_BROWSE_LCIDS:
                self.assertIn(
                    b"\x04q\x00" + struct.pack("<II", 1, lcid),
                    payload,
                    f"LCID 0x{lcid:04x} missing when dword_0={dword_0}",
                )
        # Address-bar enumeration (different propList) still resolves
        # through the regular content tree — no language leakage.
        addrbar_request = DirsrvRequest(
            node_ids=["0:0"],
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        addrbar_payload = get_children_reply(addrbar_request)
        # Regular GetChildren on MSN root returns the localized wrappers
        # (the address-bar entries); the language-list short-circuit is
        # scoped to propList=["q"] only, so this reply carries nav data.
        self.assertIn(b"Categories (US)", addrbar_payload)
        for lcid in SUPPORTED_BROWSE_LCIDS:
            self.assertNotIn(b"\x04q\x00" + struct.pack("<II", 1, lcid), addrbar_payload)


class TestDIRSRVGetParents(unittest.TestCase):
    """Selector 0x01 used when MSNFIND activates a result row."""

    REQUEST = bytes.fromhex(
        "04880400000000000000010003000000000302000000048463006100048400000000838385"
    )

    def test_msn_today_parent_is_member_assistance(self):
        request = decode_dirsrv_request(self.REQUEST)
        self.assertEqual(request.node_id, "4:0")
        self.assertEqual(request.prop_group, "c\x00a")
        self.assertEqual(request.dword_0, 0)
        self.assertEqual(request.dword_1, 2)

        records = _walk_get_children_records(get_parents_reply(request))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["c"], struct.pack("<I", 1))
        self.assertEqual(records[0]["a"], struct.pack("<II", 1, 0x11))

    def test_handler_routes_observed_tree_class_and_selector(self):
        handler = DirsrvHandler(pipe_idx=5, svc_name="DIRSRV", session=Session())

        packets = handler.handle_request(
            msg_class=DIRSRV_CLASS_TREE,
            selector=0x01,
            request_id=0,
            payload=self.REQUEST,
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        self.assertEqual(
            reply_payload(packets),
            get_parents_reply(decode_dirsrv_request(self.REQUEST)),
        )


class TestDIRSRVUnhandledSelector(unittest.TestCase):
    """DIRSRV must warn (not silently fall through to GetProperties) on
    selectors that have no registered handler — keeps unmapped client
    paths visible in the wire log.
    """

    def test_unknown_selector_warns_and_returns_none(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        # Selector 0x07 has no TREENVCL method and must surface as an
        # `unhandled` warning, not a self-record reply.
        payload = b""
        with self.assertLogs("server.services.dirsrv", level="WARNING") as cap:
            result = handler.handle_request(
                msg_class=DIRSRV_CLASS_TREE,
                selector=0x07,
                request_id=0,
                payload=payload,
                server_seq=0,
                client_ack=0,
            )
        self.assertIsNone(result)
        self.assertTrue(any("unhandled" in m for m in cap.output))


class TestDIRSRVEnumShn(unittest.TestCase):
    """Selector 0x05 — the Change Icon picker's list source.

    Wire request captured from MOSSHELL's ChangeIconDlgProc WM_INITDIALOG:
    `01 00 83 82 85`.
    """

    REQUEST = b"\x01\x00\x83\x82\x85"

    def test_reply_carries_status_count_and_dword_stream(self):
        from server.services import shabby as shabby_mod

        ids = shabby_mod.enum_pickable_shabby_ids()
        self.assertEqual(
            enum_shn_reply(self.REQUEST),
            b"\x83\x00\x00\x00\x00"
            + b"\x82"
            + struct.pack("<H", len(ids))
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + b"".join(struct.pack("<I", i) for i in ids),
        )

    def test_dynamic_tag_is_complete_signal_not_stream_end(self):
        """0x86, not 0x88 — the opposite of GetChildren.

        Only 0x86 runs MPCCL SignalRequestCompletion, which sets request
        +0x18 and stops WaitForMessage from calling ResetEvent.
        ShnIterator_GetAtIndex waits before reading its buffer, so under
        0x88 the wait CTreeNavClient::EnumShn already performed leaves
        nothing to wake it and the Change Icon click hangs.
        """
        # 0x83 + dword, then 0x82 + word = 8 bytes of static section.
        payload = enum_shn_reply(self.REQUEST)
        self.assertEqual(payload[8], TAG_END_STATIC)
        self.assertEqual(payload[9], TAG_DYNAMIC_COMPLETE_SIGNAL)
        self.assertNotIn(TAG_DYNAMIC_STREAM_END, payload[8:10])

    def test_whole_stream_ships_in_one_block(self):
        """Every index must satisfy `index*4 <= size` on the first pass.

        A short buffer drops ShnIterator_GetAtIndex into
        `while (iVar1 != 0xB0B000B)` comparing the data-iface return, not
        the wait's — an infinite spin.
        """
        from server.services import shabby as shabby_mod

        ids = shabby_mod.enum_pickable_shabby_ids()
        body = enum_shn_reply(self.REQUEST)[10:]
        self.assertEqual(len(body), 4 * len(ids))
        for index in range(len(ids)):
            self.assertLessEqual(index * 4, len(body))

    def test_stream_is_ascending_and_inside_the_picker_window(self):
        from server.services import shabby as shabby_mod

        ids = shabby_mod.enum_pickable_shabby_ids()
        # The client breaks on the first id above the window, so order matters.
        self.assertEqual(ids, sorted(ids))
        self.assertTrue(ids)
        for shabby_id in ids:
            self.assertGreater(shabby_id, 0x0598)
            self.assertLessEqual(shabby_id, 0x0A48)

    def test_every_enumerated_id_resolves_to_icon_bytes(self):
        from server.services import shabby as shabby_mod

        for shabby_id in shabby_mod.enum_pickable_shabby_ids():
            blob = shabby_mod.load_shabby_bytes(shabby_id)
            self.assertIsNotNone(blob, f"no blob for 0x{shabby_id:04x}")
            # ExtractIconExA needs a real ICO/EXE/DLL — reserved word then
            # RES_ICON in the ICONDIR header.
            self.assertEqual(blob[:4], b"\x00\x00\x01\x00")

    def test_default_h_value_is_in_the_enumerated_list(self):
        from server.services import shabby as shabby_mod

        self.assertIn(
            shabby_mod.DEFAULT_NODE_ICON_ID,
            shabby_mod.enum_pickable_shabby_ids(),
        )

    def test_unknown_key_enumerates_empty_without_hanging(self):
        payload = enum_shn_reply(b"\x01\x07\x83\x82\x85")
        self.assertEqual(
            payload,
            b"\x83\x00\x00\x00\x00\x82\x00\x00"
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]),
        )

    def test_selector_dispatches_to_a_reply_packet(self):
        handler = DirsrvHandler(pipe_idx=4, svc_name="DIRSRV", session=Session())
        packets = handler.handle_request(
            msg_class=0x03,
            selector=0x05,
            request_id=12,
            payload=self.REQUEST,
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        self.assertEqual(reply_payload(packets), enum_shn_reply(self.REQUEST))

    def test_key_constant_matches_the_observed_request(self):
        self.assertEqual(self.REQUEST[1], ENUM_SHN_KEY_ICONS)


class TestDIRSRVAddShabby(unittest.TestCase):
    """Class 0x04 selector 0x07 — icon and banner upload."""

    TRACE_HEAD = bytes.fromhex("04 82 02 00 01 00 05 01 36 04 00 00 03 36 04 00 00 83 83 83")

    def setUp(self):
        from server.services import shabby as shabby_mod

        self._pickable_icons = dict(shabby_mod.PICKABLE_ICONS)
        self._icon_registry = dict(shabby_mod.SHABBY_REGISTRY)

    def tearDown(self):
        from server.services import shabby as shabby_mod

        shabby_mod.PICKABLE_ICONS.clear()
        shabby_mod.PICKABLE_ICONS.update(self._pickable_icons)
        shabby_mod.SHABBY_REGISTRY.clear()
        shabby_mod.SHABBY_REGISTRY.update(self._icon_registry)

    @staticmethod
    def _reply_host_block(packets):
        from server.pipe import parse_pipe_frames

        parsed = parse_packet(packets[0][:-1])
        frames = parse_pipe_frames(parsed.payload)
        return parse_host_block(frames[0].content[2:])

    def test_chunked_icon_upload_replies_after_last_frame(self):
        from server.services import shabby as shabby_mod

        blob = shabby_mod.load_shabby_bytes(0x059A)
        self.assertEqual(len(blob), 1078)
        expected_id = max(shabby_mod.PICKABLE_ICONS) + 1
        handler = DirsrvHandler(4, "DIRSRV", signed_in(ADMIN))

        self.assertIsNone(handler.handle_request(0x04, 0x07, 4, self.TRACE_HEAD, 0, 0))
        self.assertIsNone(
            handler.handle_request(MPC_CLASS_CONTINUATION_MORE, 1, 0, blob[:463], 0, 0)
        )
        self.assertIsNone(
            handler.handle_request(MPC_CLASS_CONTINUATION_MORE, 1, 0, blob[463:926], 0, 0)
        )
        packets = handler.handle_request(MPC_CLASS_CONTINUATION_LAST, 1, 0, blob[926:], 0, 0)

        host_block = self._reply_host_block(packets)
        self.assertEqual(host_block.msg_class, 0x04)
        self.assertEqual(host_block.selector, 0x07)
        self.assertEqual(host_block.request_id, 4)
        self.assertEqual(
            host_block.payload,
            b"\x83\x00\x00\x00\x00"
            + b"\x83\x00\x00\x00\x00"
            + b"\x83"
            + struct.pack("<I", expected_id)
            + b"\x87",
        )
        self.assertIn(expected_id, shabby_mod.enum_pickable_shabby_ids())
        self.assertEqual(shabby_mod.load_shabby_bytes(expected_id), blob)

    def test_small_inline_icon_upload_completes_in_the_call_reply(self):
        from server.services import shabby as shabby_mod

        blob = b"\x00\x00\x01\x00inline-ico"
        request = (
            b"\x04\x82\x02\x00"
            + b"\x01\x00"
            + b"\x04"
            + bytes([0x80 | len(blob)])
            + blob
            + b"\x03"
            + struct.pack("<I", len(blob))
            + b"\x83\x83\x83"
        )
        handler = DirsrvHandler(4, "DIRSRV", signed_in(ADMIN))

        packets = handler.handle_request(0x04, 0x07, 9, request, 0, 0)

        host_block = self._reply_host_block(packets)
        shabby_id = struct.unpack_from("<I", host_block.payload, 11)[0]
        self.assertEqual(shabby_mod.load_shabby_bytes(shabby_id), blob)

    def test_non_author_refused_before_upload_starts(self):
        handler = DirsrvHandler(4, "DIRSRV", signed_in(SUBSCRIBER))

        packets = handler.handle_request(0x04, 0x07, 4, self.TRACE_HEAD, 0, 0)

        host_block = self._reply_host_block(packets)
        self.assertEqual(struct.unpack_from("<I", host_block.payload, 1)[0], 0x101)
        self.assertEqual(handler._shabby_uploads, {})

    def test_short_closing_stream_is_refused_and_not_registered(self):
        from server.services import shabby as shabby_mod

        before = shabby_mod.enum_pickable_shabby_ids()
        handler = DirsrvHandler(4, "DIRSRV", signed_in(ADMIN))
        handler.handle_request(0x04, 0x07, 4, self.TRACE_HEAD, 0, 0)

        packets = handler.handle_request(MPC_CLASS_CONTINUATION_LAST, 1, 0, b"short", 0, 0)

        host_block = self._reply_host_block(packets)
        self.assertEqual(struct.unpack_from("<I", host_block.payload, 1)[0], 0x101)
        self.assertEqual(shabby_mod.enum_pickable_shabby_ids(), before)

    def test_download_and_run_payload_uploads_under_format_0x85(self):
        """DSNED 0x7F5723BE uploads the compressed DnR file, not an image."""
        from server.services import shabby as shabby_mod

        blob = bytes(range(256)) * 8
        head = (
            b"\x04\x82\x02\x00"
            + bytes([0x01, shabby_mod.FORMAT_MOS_COMPRESSED])
            + b"\x05\x01"
            + struct.pack("<I", len(blob))
            + b"\x03"
            + struct.pack("<I", len(blob))
            + b"\x83\x83\x83"
        )
        handler = DirsrvHandler(4, "DIRSRV", signed_in(ADMIN))

        self.assertIsNone(handler.handle_request(0x04, 0x07, 7, head, 0, 0))
        self.assertIsNone(
            handler.handle_request(MPC_CLASS_CONTINUATION_MORE, 1, 0, blob[:900], 0, 0)
        )
        packets = handler.handle_request(MPC_CLASS_CONTINUATION_LAST, 1, 0, blob[900:], 0, 0)

        host_block = self._reply_host_block(packets)
        self.assertEqual(struct.unpack_from("<I", host_block.payload, 1)[0], 0)
        shabby_id = struct.unpack_from("<I", host_block.payload, 11)[0]
        self.assertEqual(
            shabby_mod.unpack_shabby_id(shabby_id)[0],
            shabby_mod.FORMAT_MOS_COMPRESSED,
        )
        self.assertEqual(shabby_mod.load_shabby_bytes(shabby_id), blob)
        # The payload must stay out of the Change Icon picker.
        self.assertNotIn(shabby_id, shabby_mod.enum_pickable_shabby_ids())


class TestDIRSRVGetTicket(unittest.TestCase):
    def test_minimal_ticket_reply_shape(self):
        self.assertEqual(
            get_ticket_reply(signed_in(ADMIN)),
            b"\x83\x00\x00\x00\x00\x87\x86\x02\x00",
        )

    def test_edit_channel_selector_returns_ticket_packet(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x0C,
            request_id=0,
            payload=b"\x83\x85",
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        # header + size prefix + routing + class + selector + one-byte VLI
        self.assertEqual(reply_payload(packets), get_ticket_reply(handler.session))


class TestDIRSRVGetDataSets(unittest.TestCase):
    def test_empty_dataset_reply_contains_complete_property_record(self):
        self.assertEqual(
            get_datasets_reply(),
            b"\x83\x00\x00\x00\x00\x87\x86\x06\x00\x00\x00\x00\x00",
        )

    def test_edit_channel_selector_returns_dataset_packet(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x0B,
            request_id=1,
            payload=bytes.fromhex("04 82 02 00 04 84 42 42 53 00 03 04 00 00 00 83 85"),
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        # header + size prefix + routing + class + selector + one-byte VLI
        self.assertEqual(reply_payload(packets), get_datasets_reply())


class TestDIRSRVAddNode(unittest.TestCase):
    @staticmethod
    def _tagged_var(value):
        return b"\x04" + bytes([0x80 | len(value)]) + value

    def test_creates_child_and_returns_completed_operation(self):
        properties = build_property_record(
            [
                (0x0F, "h", struct.pack("<I", 0x059B)),
                (0x03, "c", struct.pack("<I", 1)),
                (0x03, "g", struct.pack("<I", 1)),
                (0x01, "b", b"\x00"),
                (0x03, "m", struct.pack("<I", 0)),
                (0x0A, "ca", b"\x01\x00"),
                (0x03, "o", struct.pack("<I", 0)),
                (0x10, "q", struct.pack("<II", 1, 0x0409)),
                (0x0A, "tp", b"\x01Folder\x00"),
                (0x0B, "f", b"\x01New Folder\x00"),
            ]
        )
        request = (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", 1, 16))
            + self._tagged_var(properties)
            + b"\x83\x83\x84"
        )
        self.assertEqual(len(request), 108)
        store = AddNodeContentStore()

        reply = add_node_reply(request, signed_in(ADMIN), store)

        new_mnid = struct.pack("<II", 1, 17)
        self.assertEqual(
            reply,
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87\x84\x88" + new_mnid,
        )
        node = store.get_node("1:17")
        self.assertEqual(store.children["1:16"], ["1:17"])
        self.assertEqual(node.content.name, "New Folder")
        self.assertEqual(node.content.type_str, "Folder")
        self.assertEqual(node.content.language, 0x0409)
        self.assertTrue(node.is_container)
        self.assertEqual(node.host_usernames, ())
        self.assertEqual(node.secondary_icon_shabby_id, 0x059B)

    def test_a_deleted_childs_mnid_is_not_handed_to_the_next_node(self):
        # Create an Encarta node (c=11), delete it, then create a
        # Download-and-Run node (c=7). Reissuing the mnid leaves MOSSHELL
        # holding the Encarta 'c' for the new node, and DSNED's GETPMTE
        # switches on 'c' — the sheet loses its Download and Run page.
        store = AddNodeContentStore()

        def create(app_id, type_str, name):
            properties = build_property_record(
                [
                    (0x03, "c", struct.pack("<I", app_id)),
                    (0x03, "g", struct.pack("<I", 1)),
                    (0x01, "b", b"\x00"),
                    (0x03, "m", struct.pack("<I", 0)),
                    (0x0A, "ca", b"\x01\x00"),
                    (0x03, "o", struct.pack("<I", 0)),
                    (0x10, "q", struct.pack("<II", 1, 0x0409)),
                    (0x0A, "tp", b"\x01" + type_str.encode() + b"\x00"),
                    (0x0B, "f", b"\x01" + name.encode() + b"\x00"),
                ]
            )
            request = (
                self._tagged_var(b"\x02\x00")
                + self._tagged_var(struct.pack("<II", 1, 16))
                + self._tagged_var(properties)
                + b"\x83\x83\x84"
            )
            reply = add_node_reply(request, signed_in(ADMIN), store)
            return f"{struct.unpack('<I', reply[-8:-4])[0]}:{struct.unpack('<I', reply[-4:])[0]}"

        encarta = create(11, "Microsoft Encarta Viewer", "New Microsoft Encarta Viewer")
        self.assertEqual(store.get_node(encarta).app_id, 11)

        store.retired.add(encarta)
        del store.nodes[encarta]
        store.children["1:16"].remove(encarta)

        dnr = create(7, "Download-and-Run File", "New Download-and-Run File")

        self.assertNotEqual(dnr, encarta)
        self.assertEqual(store.get_node(dnr).app_id, 7)

    def test_created_chat_adds_its_creator_to_the_host_list(self):
        properties = build_property_record(
            [
                (0x03, "c", struct.pack("<I", 4)),
                (0x01, "b", b"\x01"),
                (0x0A, "tp", b"\x01Chat Room\x00"),
                (0x0B, "f", b"\x01New Chat\x00"),
            ]
        )
        request = (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", 1, 16))
            + self._tagged_var(properties)
            + b"\x83\x83\x84"
        )
        store = AddNodeContentStore()
        built_in = next(node for node in default_seed().directory_nodes if node.app_id == 4)
        store.add_child("1:16", built_in)

        reply = add_node_reply(request, signed_in(ADMIN), store)

        new_mnid = reply[-8:]
        instance_id, field_8 = struct.unpack("<II", new_mnid)
        node = store.get_node(f"{instance_id}:{field_8}")
        self.assertEqual(instance_id, 2)
        self.assertEqual(node.host_usernames, (ADMIN,))
        self.assertIs(store.find_app_instance(4, instance_id), node)

    def test_rejects_the_read_side_receive_shape(self):
        store = AddNodeContentStore()
        reply = add_node_reply(b"\x83\x85", signed_in(ADMIN), store)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertEqual(store.children["1:16"], [])

    def test_preserves_the_inner_mnid_of_a_delegate(self):
        inner_mnid = struct.pack("<II", 0, 2)
        properties = build_property_record(
            [
                (0x03, "c", struct.pack("<I", 2)),
                (0x01, "b", b"\x04"),
                (0x0C, "l", inner_mnid),
                (0x02, "i", b"\x00\x00"),
                (0x0A, "tp", b"\x01Bulletin Board Folder\x00"),
            ]
        )
        request = (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", 1, 16))
            + self._tagged_var(properties)
            + b"\x83\x83\x84"
        )
        store = AddNodeContentStore()

        add_node_reply(request, signed_in(ADMIN), store)

        node = store.get_node("1:17")
        self.assertTrue(node.delegate)
        self.assertEqual(node.delegate_mnid_a, inner_mnid)
        properties = {
            name: value for _ptype, name, value in build_props(["a", "l"], node, is_children=False)
        }
        self.assertEqual(properties["a"], struct.pack("<I", 8) + node.mnid_a)
        self.assertEqual(properties["l"], inner_mnid)

    def test_edit_selector_2_is_add_node_not_get_children(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        with patch(
            "server.services.dirsrv.add_node_reply",
            return_value=b"\x83\x00\x00\x00\x00",
        ) as build_reply:
            packets = handler.handle_request(
                msg_class=0x04,
                selector=0x02,
                request_id=2,
                payload=b"add-node",
                server_seq=0,
                client_ack=0,
            )

        build_reply.assert_called_once_with(b"add-node", handler.session, app_store.content)
        self.assertEqual(reply_payload(packets), b"\x83\x00\x00\x00\x00")


class _SetPropertiesContentStore:
    """Holds one real category node — the shape DSNED's Folder editor edits."""

    NODE_ID = "1:256"  # "Arts and Entertainment", app_id 1 (tp "Category")

    def __init__(self):
        node = next(node for node in default_seed().directory_nodes if node.node_id == self.NODE_ID)
        self.nodes = {node.node_id: node}

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    find_node = get_node

    def add_node(self, node):
        self.nodes[node.node_id] = node


class TestDIRSRVSetProperties(unittest.TestCase):
    """Class 0x04 selector 0x04 — the Properties sheet's write path.

    Each page applies one control per call, so these records carry the whole
    page at once only to keep the tests short; the handler treats the record as
    a set either way.
    """

    OK = b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87"

    def setUp(self):
        # A bbix write persists to disk. Point it somewhere disposable so the
        # suite does not publish a title into the server's real state.
        self._state_dir = tempfile.mkdtemp()
        self._saved_state_dir = blackbird_state.STATE_DIR
        blackbird_state.STATE_DIR = pathlib.Path(self._state_dir)

    def tearDown(self):
        blackbird_state.STATE_DIR = self._saved_state_dir
        shutil.rmtree(self._state_dir, ignore_errors=True)

    @staticmethod
    def _tagged_var(value):
        return b"\x04" + bytes([0x80 | len(value)]) + value

    @staticmethod
    def _ascii(text):
        return b"\x01" + text.encode("ascii") + b"\x00"

    @staticmethod
    def _wide(text):
        return b"\x00" + text.encode("utf-16-le") + b"\x00\x00"

    def _request(self, properties, *, node_id=_SetPropertiesContentStore.NODE_ID):
        field_0, field_8 = (int(part) for part in node_id.split(":"))
        return (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", field_0, field_8))
            + self._tagged_var(build_property_record(properties))
            + b"\x83\x83"
        )

    def test_general_page_fields_reach_the_node(self):
        store = _SetPropertiesContentStore()
        request = self._request(
            [
                (0x0B, "f", self._wide("Arts & Leisure")),
                (0x0A, "k", self._ascii("artsgo")),
                (0x0A, "j", self._ascii("Everything cultural.")),
                (0x0A, "ca", self._ascii("Entertainment")),
                (0x03, "o", struct.pack("<I", 2)),
                # (amount 250) << 8 | currency index 3
                (0x0D, "z", struct.pack("<I", (250 << 8) | 3)),
            ]
        )

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        content = store.get_node(store.NODE_ID).content
        self.assertEqual(content.name, "Arts & Leisure")
        self.assertEqual(content.go_word, "artsgo")
        self.assertEqual(content.description, "Everything cultural.")
        self.assertEqual(content.category, "Entertainment")
        self.assertEqual(content.rating_dword, 2)
        self.assertEqual(content.price_dword, (250 << 8) | 3)

    def test_context_page_fields_reach_the_node(self):
        store = _SetPropertiesContentStore()
        request = self._request(
            [
                (0x10, "q", struct.pack("<II", 1, 0x0416)),
                (0x0A, "r", self._ascii("Books, Movies")),
                (0x0A, "s", self._ascii("Critics")),
                (0x0A, "t", self._ascii("Redmond, WA")),
                (0x0A, "n", self._ascii("MSN Editorial")),
                (0x0A, "on", self._ascii("Jane Doe")),
                (0x11, "y", struct.pack("<I", 4242)),
            ]
        )

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        content = store.get_node(store.NODE_ID).content
        self.assertEqual(content.language, 0x0416)
        self.assertEqual(content.topics, "Books, Movies")
        self.assertEqual(content.people, "Critics")
        self.assertEqual(content.place, "Redmond, WA")
        self.assertEqual(content.forum_mgr, "MSN Editorial")
        self.assertEqual(content.owner, "Jane Doe")
        self.assertEqual(content.vendor_id, 4242)

    def test_change_icon_shabby_id_survives_the_next_property_read(self):
        store = _SetPropertiesContentStore()
        selected_id = 0x059B
        request = self._request([(0x0F, "h", struct.pack("<I", selected_id))])

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        node = store.get_node(store.NODE_ID)
        self.assertEqual(node.secondary_icon_shabby_id, selected_id)
        self.assertEqual(
            build_props(["h"], node, is_children=False),
            [(0x03, "h", struct.pack("<I", selected_id))],
        )

    def test_blackbird_site_record_survives_the_next_property_read(self):
        """The `bbix` record Blackbird's Release Wizard writes, byte for byte.

        Captured from a live publish (server log 2026-08-12): 84 opaque bytes
        carrying the title's root object GUID, publish FILETIME, `bbview.exe`
        and the title name. The wizard reads this back before its next publish
        to tell a first publish from a re-publish, so the round trip has to be
        exact — see docs/BLACKBIRD.md §6.1.
        """
        store = _SetPropertiesContentStore()
        site = bytes.fromhex(
            "0100000041ef39d4f551f111b405000c875355c880ca7b4be029dd0100000000"
            "6262766965772e65786500000000000000783271726a34616e7568617334326b"
            "643231313773676a616c6773000500a0b90101a0"
        )
        self.assertEqual(len(site), 0x54)
        request = self._request([(0x0E, "bbix", struct.pack("<I", len(site)) + site)])

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        node = store.get_node(store.NODE_ID)
        self.assertEqual(node.content.blackbird_site, site)
        self.assertEqual(
            build_props(["bbix"], node, is_children=False),
            [(0x0E, "bbix", struct.pack("<I", len(site)) + site)],
        )

    def test_unpublished_node_reports_an_empty_blackbird_site(self):
        """Nothing published answers a zero-length 0x0E blob.

        NODEEXEC.EXE reads the length FGet reports: 0x54 launches the viewer,
        any other non-zero length is its return 5 ("The version of this
        Blackbird title is incorrect"), and only 0 is return 10 ("This
        Blackbird node has not yet been initialized"). A 4-byte DWORD would
        make an unpublished node look like a corrupt record.
        """
        store = _SetPropertiesContentStore()
        node = store.get_node(store.NODE_ID)
        self.assertEqual(
            build_props(["bbix"], node, is_children=False),
            [(0x0E, "bbix", struct.pack("<I", 0))],
        )

    def test_dnr_page_writes_survive_the_next_read(self):
        """The four writes DSNED 0x7F5723BE makes after AddShabby returns."""
        store = _SetPropertiesContentStore()
        shabby_id = 0x85000001
        request = self._request(
            [
                (0x0F, "fi", struct.pack("<I", shabby_id)),
                (0x03, "zc", struct.pack("<I", 3)),
                (0x0A, "fn", self._ascii("SETUP.EXE")),
                (0x03, "p", struct.pack("<I", 51700)),
            ]
        )

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        node = store.get_node(store.NODE_ID)
        self.assertEqual(node.content.dnr_shabby_id, shabby_id)
        self.assertEqual(node.content.dnr_compression, 3)
        self.assertEqual(node.content.dnr_file_name, "SETUP.EXE")
        self.assertEqual(node.content.size_bytes, 51700)
        self.assertEqual(
            build_props(["fi", "zc", "fn", "p"], node, is_children=False),
            [
                (0x03, "fi", struct.pack("<I", shabby_id)),
                (0x03, "zc", struct.pack("<I", 3)),
                (0x0A, "fn", b"\x01SETUP.EXE\x00"),
                (0x03, "p", struct.pack("<I", 51700)),
            ],
        )

    def test_untouched_fields_survive_a_partial_write(self):
        store = _SetPropertiesContentStore()
        before = store.get_node(store.NODE_ID)

        set_properties_reply(
            self._request([(0x0A, "k", self._ascii("artsgo"))]), signed_in(ADMIN), store
        )

        after = store.get_node(store.NODE_ID)
        self.assertEqual(after.content.name, before.content.name)
        self.assertEqual(after.content.language, before.content.language)
        self.assertEqual(after.app_id, before.app_id)
        self.assertEqual(after.mnid_a, before.mnid_a)
        self.assertEqual(after.is_container, before.is_container)

    def test_cleared_control_arrives_as_type_zero_with_no_value(self):
        """An empty edit box writes type 0x00 and zero value bytes.

        `CMosTreeEdit::SetProperty` @ MOSSHELL 0x7F403522 forces the type byte
        to 0 when the control's text length is 0, and SVCPROP's own decoder
        consumes nothing for it. Clicking OK on the General page with an empty
        Go word must clear the field, not fail the record.
        """
        store = _SetPropertiesContentStore()
        request = self._request([(0x00, "k", b"")])

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        self.assertEqual(store.get_node(store.NODE_ID).content.go_word, "")

    def test_unstored_tag_is_ignored_without_failing_the_record(self):
        store = _SetPropertiesContentStore()
        request = self._request(
            [
                (0x0F, "mf", struct.pack("<I", 0x0501)),
                (0x0A, "ca", self._ascii("Entertainment")),
            ]
        )

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(reply, self.OK)
        self.assertEqual(store.get_node(store.NODE_ID).content.category, "Entertainment")

    def test_rejects_the_add_node_receive_shape(self):
        store = _SetPropertiesContentStore()
        before = store.get_node(store.NODE_ID)
        request = (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", 1, 256))
            + self._tagged_var(build_property_record([]))
            + b"\x83\x83\x84"
        )

        reply = set_properties_reply(request, signed_in(ADMIN), store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertIs(store.get_node(store.NODE_ID), before)

    def test_rejects_an_unknown_node(self):
        store = _SetPropertiesContentStore()

        reply = set_properties_reply(
            self._request([(0x0A, "k", self._ascii("nope"))], node_id="9:99"),
            signed_in(ADMIN),
            store,
        )

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)

    def test_edit_selector_4_is_set_props_not_get_shabby(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        with patch(
            "server.services.dirsrv.set_properties_reply",
            return_value=b"\x83\x00\x00\x00\x00",
        ) as build_reply:
            packets = handler.handle_request(
                msg_class=0x04,
                selector=0x04,
                request_id=3,
                payload=b"set-properties",
                server_seq=0,
                client_ack=0,
            )

        build_reply.assert_called_once_with(b"set-properties", handler.session, app_store.content)
        self.assertEqual(reply_payload(packets), b"\x83\x00\x00\x00\x00")


class _DeleteNodeContentStore:
    """The sample BBS board plus the messages listed under it."""

    BOARD_ID = "0:1"

    def __init__(self):
        seed = default_seed()
        self.children = {self.BOARD_ID: list(seed.directory_children[self.BOARD_ID])}
        wanted = {self.BOARD_ID, *self.children[self.BOARD_ID]}
        self.nodes = {n.node_id: n for n in seed.directory_nodes if n.node_id in wanted}

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    find_node = get_node

    def remove_node(self, node_id):
        if node_id not in self.nodes:
            return False
        del self.nodes[node_id]
        for ids in self.children.values():
            ids[:] = [i for i in ids if i != node_id]
        return True


class TestDIRSRVDeleteNode(unittest.TestCase):
    """Class 0x04 selector 0x03 — the shell's Delete verb.

    `CTreeEditClient::PrivateDeleteNode` @ TREEEDCL 0x7F2C1BE3 sends the ticket
    and the 8-byte MNID and asks for two DWORDs back.
    """

    @staticmethod
    def _tagged_var(value):
        return b"\x04" + bytes([0x80 | len(value)]) + value

    def _request(self, node_id):
        msg_id, _sep, board_id = node_id.partition(":")
        return (
            self._tagged_var(b"\x02\x00")
            + self._tagged_var(struct.pack("<II", int(msg_id), int(board_id)))
            + b"\x83\x83"
        )

    def test_edit_class_selector_three_dispatches_to_delete(self):
        handler = DirsrvHandler(4, "DIRSRV", signed_in(ADMIN))
        request = self._request("1:271")
        with patch(
            "server.services.dirsrv.delete_node_reply",
            return_value=b"\x87",
        ) as delete:
            packets = handler.handle_request(0x04, 0x03, 3, request, 5, 5)

        self.assertIsNotNone(packets)
        delete.assert_called_once_with(request, handler.session, app_store.content)

    def test_removes_the_node_and_reports_a_completed_operation(self):
        store = _DeleteNodeContentStore()
        doomed = store.children[store.BOARD_ID][0]

        reply = delete_node_reply(self._request(doomed), signed_in(ADMIN), store)

        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")
        self.assertNotIn(doomed, store.nodes)
        self.assertNotIn(doomed, store.children[store.BOARD_ID])

    def test_unknown_node_fails_without_touching_the_board(self):
        store = _DeleteNodeContentStore()
        before = list(store.children[store.BOARD_ID])

        reply = delete_node_reply(self._request("9000:1"), signed_in(ADMIN), store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertEqual(store.children[store.BOARD_ID], before)

    def test_rejects_the_add_node_receive_shape(self):
        # AddNode asks for a variable field back as well. Answering a request
        # shaped for three receives would leave the client short a field.
        store = _DeleteNodeContentStore()
        doomed = store.children[store.BOARD_ID][0]
        request = self._request(doomed)[:-2] + b"\x83\x83\x84"

        reply = delete_node_reply(request, signed_in(ADMIN), store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertIn(doomed, store.nodes)

    def test_rejects_a_ticket_that_does_not_carry_its_own_length(self):
        store = _DeleteNodeContentStore()
        doomed = store.children[store.BOARD_ID][0]
        msg_id, _sep, board_id = doomed.partition(":")
        request = (
            self._tagged_var(b"\x09\x00")
            + self._tagged_var(struct.pack("<II", int(msg_id), int(board_id)))
            + b"\x83\x83"
        )

        reply = delete_node_reply(request, signed_in(ADMIN), store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertIn(doomed, store.nodes)


class TestDIRSRVGetDeidFromGoWord(unittest.TestCase):
    """Selector 0x03 reply mirrors LOGSRV bootstrap's post-static var pattern:
    `0x83 [status] 0x87 0x84 [len=8] [deid:8]`. Status DWORD 0 = success.
    """

    @staticmethod
    def _build_request(go_word):
        wide = go_word.encode("utf-16-le") + b"\x00\x00"
        # Length byte uses inline form (bit 7 set, low 7 bits = length).
        # All fixtures keep go-words short enough for the inline form.
        assert len(wide) < 0x80
        return (
            b"\x04"
            + bytes([0x80 | len(wide)])
            + wide
            + b"\x04\x84\x00\x00\x00\x00"  # locale: count=0
            + b"\x83\x84"  # recv descriptors
        )

    def test_known_go_word_returns_matching_deid(self):
        # MSN Today fixture: node_id "4:0", go_word "today" (case fold).
        payload = get_deid_from_go_word_reply(self._build_request("Today"))
        expected = (
            b"\x83\x00\x00\x00\x00"  # status=0
            + bytes([TAG_END_STATIC])  # 0x87
            + b"\x84\x88"  # 0x84 var, len=8 inline
            + struct.pack("<II", 4, 0)  # deid (4, 0)
        )
        self.assertEqual(payload, expected)

    def test_unknown_go_word_returns_zero_deid_with_error(self):
        payload = get_deid_from_go_word_reply(self._build_request("nonexistent"))
        expected = (
            b"\x83"
            + struct.pack("<I", DS_E_NOT_FOUND)
            + bytes([TAG_END_STATIC])
            + b"\x84\x88"
            + b"\x00" * 8
        )
        self.assertEqual(payload, expected)

    def test_dispatch_via_handler(self):
        handler = DirsrvHandler(pipe_idx=1, svc_name="DIRSRV", session=Session())
        result = handler.handle_request(
            msg_class=0x01,
            selector=0x03,
            request_id=0,
            payload=self._build_request("today"),
            server_seq=0,
            client_ack=0,
        )
        self.assertIsNotNone(result)


class TestPropertyRecord(unittest.TestCase):
    def test_format(self):
        props = [(0x03, "q", struct.pack("<I", 1))]
        record = build_property_record(props)
        # total_size (4) + prop_count (2) + type(1) + "q\0"(2) + value(4) = 13
        total_size = struct.unpack("<I", record[:4])[0]
        self.assertEqual(total_size, 13)
        prop_count = struct.unpack("<H", record[4:6])[0]
        self.assertEqual(prop_count, 1)
        # Type byte
        self.assertEqual(record[6], 0x03)
        # Name
        self.assertEqual(record[7:9], b"q\x00")
        # Value
        self.assertEqual(struct.unpack("<I", record[9:13])[0], 1)

    def test_multiple_properties(self):
        props = [
            (0x03, "a", struct.pack("<I", 0)),
            (0x0E, "p", struct.pack("<I", 5) + b"Hello"),
        ]
        record = build_property_record(props)
        prop_count = struct.unpack("<H", record[4:6])[0]
        self.assertEqual(prop_count, 2)

    def test_empty_record(self):
        record = build_property_record([])
        total_size = struct.unpack("<I", record[:4])[0]
        self.assertEqual(total_size, 6)  # just header
        prop_count = struct.unpack("<H", record[4:6])[0]
        self.assertEqual(prop_count, 0)


class TestGetShabbyReplyFragmentation(unittest.TestCase):
    """End-to-end test for the DIRSRV GetShabby reply carrying default.ico.

    Guards the specific regression described in Phase-1 diagnosis:
    default.ico (1078 bytes, 25 stuffable bytes) produced a first frame
    of 1029 wire bytes — over the MOSCP PacketSize=1024 limit — which
    MOSCP silently dropped, causing ExtractIconEx to miss the file and
    every node to render the forbidden glyph.
    """

    def _build_get_shabby_reply_packets(self, shabby_id):
        from server.config import TAG_DYNAMIC_COMPLETE_SIGNAL, TAG_END_STATIC
        from server.mpc import build_tagged_reply_dword
        from server.services import shabby as shabby_mod

        blob = shabby_mod.load_shabby_bytes(shabby_id) or b""
        reply_payload = (
            build_tagged_reply_dword(0)
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + blob
        )
        host_block = build_host_block(0x06, 0x04, 7, reply_payload)
        return blob, host_block, build_service_packet(4, host_block, 5, 5)

    def test_default_ico_reply_packets_fit_packet_size(self):
        from server.services import shabby as shabby_mod

        shabby_id = shabby_mod.pack_shabby_id(shabby_mod.FORMAT_ICO, 2)
        blob, _, pkts = self._build_get_shabby_reply_packets(shabby_id)
        self.assertEqual(len(blob), 1078)  # the file we're guarding
        self.assertGreaterEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertLessEqual(len(pkt), 1024)

    def test_default_ico_reply_reassembles_to_original_blob(self):
        from server.services import shabby as shabby_mod

        shabby_id = shabby_mod.pack_shabby_id(shabby_mod.FORMAT_ICO, 1)
        blob, host_block, pkts = self._build_get_shabby_reply_packets(shabby_id)

        # Strip per-frame header/prefix and reassemble pipe_data.
        parsed = [parse_packet(p[:-1]) for p in pkts]
        if len(parsed) == 1:
            chunk = parsed[0].payload[3:]  # hdr + size_prefix
        else:
            chunks = [parsed[0].payload[3:]] + [p.payload[1:] for p in parsed[1:]]
            chunk = b"".join(chunks)

        routing = struct.unpack("<H", chunk[:2])[0]
        self.assertEqual(routing, 4)
        self.assertEqual(chunk[2:], host_block)
        # And the blob body is literally default.ico.
        self.assertTrue(host_block.endswith(blob))


if __name__ == "__main__":
    unittest.main()
