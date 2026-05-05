"""Tests for LOGSRV and DIRSRV service payload builders."""

import struct
import unittest
from pathlib import Path
from unittest import mock

from server.blackbird.m14_parse import parse_payload
from server.blackbird.m14_payload import build_m14_payload_for_deid
from server.blackbird.m14_synth import build_source_model
from server.config import (
    DIRSRV_INTERFACE_GUIDS,
    LOGSRV_INTERFACE_GUIDS,
    MEDVIEW_INTERFACE_GUIDS,
    MEDVIEW_SELECTOR_HANDSHAKE,
    MEDVIEW_SELECTOR_HFS_OPEN,
    MEDVIEW_SELECTOR_HFS_READ,
    MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC,
    MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
    MEDVIEW_SELECTOR_TITLE_GET_INFO,
    MEDVIEW_SELECTOR_TITLE_OPEN,
    MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
    MEDVIEW_SELECTOR_VA_CONVERT_HASH,
    MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
    MEDVIEW_SELECTOR_VA_RESOLVE,
    OLREGSRV_INTERFACE_GUIDS,
    PIPE_ALWAYS_SET,
    PIPE_CONTINUATION,
    PIPE_LAST_DATA,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.models import DirsrvRequest, DwordParam, EndMarker, VarParam
from server.mpc import (
    _build_continuation_frame,
    build_host_block,
    build_service_packet,
    build_tagged_reply_var,
    parse_tagged_params,
)
from server.services.dirsrv import (
    DS_E_NOT_FOUND,
    SUPPORTED_BROWSE_LCIDS,
    DIRSRVHandler,
    build_dirsrv_service_map_payload,
    build_get_children_reply_payload,
    build_get_deid_from_go_word_reply_payload,
    build_get_properties_reply_payload,
    build_property_record,
)
from server.services.ftm import (
    FTM_CLIENT_FILE_ID_SIZE,
    FTM_COUNTER_OFFSET,
    FTM_FALLBACK_FILENAME,
    FTMHandler,
    _build_bill_client_reply,
    _build_request_download_reply,
    _resolve_ftm_target,
)
from server.services.logsrv import (
    LOGSRVHandler,
    build_logsrv_bootstrap_payload,
    build_logsrv_service_map_payload,
)
from server.services.medview import MEDVIEWHandler
from server.services.olregsrv import (
    OLREGSRVHandler,
    build_olregsrv_service_map_payload,
)
from server.transport import parse_packet
from server.wire import decode_header_byte


class TestLOGSRVBootstrap(unittest.TestCase):
    def test_structure(self):
        payload = build_logsrv_bootstrap_payload()
        # Should contain 7 dword tags (0x83), then 0x87, then 0x84 variable
        pos = 0
        dword_count = 0
        while pos < len(payload) and payload[pos] == 0x83:
            dword_count += 1
            pos += 5  # tag + 4-byte value
        self.assertEqual(dword_count, 7)
        self.assertEqual(payload[pos], 0x87)  # end of static section
        pos += 1
        self.assertEqual(payload[pos], 0x84)  # variable tag
        pos += 1
        # Next byte is length (0x90 = inline 16)
        self.assertEqual(payload[pos], 0x90)
        pos += 1
        # 16 bytes of data
        self.assertEqual(len(payload) - pos, 16)

    def test_first_dword_is_zero(self):
        # Field 0 = login result code, should be 0 (success)
        payload = build_logsrv_bootstrap_payload()
        result_code = struct.unpack("<I", payload[1:5])[0]
        self.assertEqual(result_code, 0)

    def test_parseable(self):
        payload = build_logsrv_bootstrap_payload()
        params = parse_tagged_params(payload)
        self.assertIsNotNone(params)
        self.assertGreater(len(params), 0)
        # First 7 params should be dwords
        for p in params[:7]:
            self.assertIsInstance(p, DwordParam)
        # Then an EndMarker
        self.assertIsInstance(params[7], EndMarker)
        # Then a variable param
        self.assertIsInstance(params[8], VarParam)


class TestLOGSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        # 10 GUIDs * 17 bytes each = 170 bytes
        payload = build_logsrv_service_map_payload()
        self.assertEqual(len(payload), len(LOGSRV_INTERFACE_GUIDS) * 17)

    def test_guid_format(self):
        payload = build_logsrv_service_map_payload()
        # Each record is 16-byte GUID + 1-byte selector
        for i, (guid_bytes, selector) in enumerate(LOGSRV_INTERFACE_GUIDS):
            record = payload[i * 17 : (i + 1) * 17]
            self.assertEqual(record[:16], guid_bytes)
            self.assertEqual(record[16], selector)

    def test_produces_packet(self):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.build_discovery_packet(3, 3)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)

    def test_known_wire_bytes(self):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.build_discovery_packet(3, 3)
        expected_start = bytes.fromhex("83 83 e3 af 00 03 00 00 00 00")
        self.assertEqual(pkts[0][:10], expected_start)


class TestLOGSRVReply(unittest.TestCase):
    def test_login_reply_returns_packet(self):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x00, 0, b"", 4, 4)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_password_change_reply(self):
        # Selector 0x01 = password change
        pw_payload = bytes.fromhex(
            "04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19"
            "3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00"
            "00 54 2b 10 04 b8 83"
        )
        handler = LOGSRVHandler(8, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x01, 0, pw_payload, 37, 36)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_post_transfer_returns_packet(self):
        """Selector 0x02 is called on a fresh LOGSRV pipe after the FTM
        phone-book transfer finishes; client hangs at "Starting transfer..."
        if the server returns None.  Minimum viable reply is an empty 0x84
        variable satisfying the single recv descriptor.
        """
        payload = bytes.fromhex("03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84")
        handler = LOGSRVHandler(6, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x02, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_query_returns_packet(self):
        """Selector 0x07 (SIGNUP's 'product details' query) must reply.

        The client sends a single recv descriptor (0x85) and hangs when
        the server returns None; the minimum viable reply is an empty
        0x84 variable.
        """
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x07, 1, b"\x85", 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_post_signup_query_returns_packet(self):
        """Selector 0x0d fires on a fresh LOGSRV pipe right after the
        OLREGSRV commit reply.  Returning None makes the client disconnect
        before the Internet-access prompt and Congrats dialog can appear.
        """
        payload = bytes.fromhex("03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84")
        handler = LOGSRVHandler(6, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x0D, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_existing_member_phonebook_query_returns_packet(self):
        """Opcode 0x0e fires on a fresh LOGSRV pipe from SIGNUP's
        "I'm already a member → Update local phone numbers → Connect"
        path.  Caller checks recv_dword == 0 for success.
        """
        payload = bytes.fromhex("03 08 00 00 00 83")
        handler = LOGSRVHandler(4, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x0E, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkt = handler.handle_request(0x06, 0xFF, 0, b"", 5, 5)
        self.assertIsNone(pkt)

    def test_known_login_reply_wire_bytes(self):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x00, 0, b"", 4, 4)
        expected = bytes.fromhex(
            "84 84 e3 3b 00 03 00 06 00 00 83 00 00 00 00 83"
            "00 00 00 00 83 00 00 00 00 83 00 00 00 00 83 00"
            "00 00 00 83 00 00 00 00 83 00 00 00 00 87 84 1b"
            "35 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 2b 11 96 ab 0d"
        )
        self.assertEqual(pkts[0], expected)


class TestDIRSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        payload = build_dirsrv_service_map_payload()
        self.assertEqual(len(payload), len(DIRSRV_INTERFACE_GUIDS) * 17)

    def test_guid_records_match_catalog(self):
        payload = build_dirsrv_service_map_payload()
        for i, (guid_bytes, selector) in enumerate(DIRSRV_INTERFACE_GUIDS):
            record = payload[i * 17 : (i + 1) * 17]
            self.assertEqual(record[:16], guid_bytes)
            self.assertEqual(record[16], selector)


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
        payload = build_get_properties_reply_payload(request)
        # Should start with two 0x83 dwords
        self.assertEqual(payload[0], 0x83)
        status = struct.unpack("<I", payload[1:5])[0]
        self.assertEqual(status, 0)
        self.assertEqual(payload[5], 0x83)
        # Then 0x87 end, then 0x88 dynamic
        self.assertIn(0x87, payload)
        self.assertIn(0x88, payload)

    def test_children_of_default_root_return_localized_wrappers(self):
        # DirsrvRequest() defaults to node_id="0:0". MSN root is server wire
        # "0:0" (GetSpecialMnid(0) → field_8=0, field_c=0). Its children list
        # is the address-bar dropdown: Cats US / MA US / WW Cat / WW MA.
        request = DirsrvRequest(
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Categories (US)", payload)
        self.assertIn(b"Worldwide Member Assistance", payload)

    def test_get_properties_returns_self_record_only(self):
        # GetProperties (selector 0x00) is always a single-record query for
        # the requested node's own props. SetPropertyGroupFromPsp on the
        # client feeds the FIRST received record into the requesting node;
        # delegating to children corrupts wrappers (Cats US ends up named
        # "Arts and Entertainment", its first child).
        request = DirsrvRequest(
            node_id=f"1:{0x10}",
            node_id_raw=struct.pack("<II", 1, 0x10),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"Categories (US)", payload)
        # First child A&E must NOT appear — that was the corruption signal.
        self.assertNotIn(b"Arts and Entertainment", payload)
        # Self-mnid must be present.
        self.assertIn(struct.pack("<II", 1, 0x10), payload)

    def test_msn_root_self_properties_return_correct_name(self):
        # Client's MSN root wire = "0:0". Self-query returns "The Microsoft
        # Network" with mnid_a = (0, 0) — its own (field_8, field_c).
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"The Microsoft Network", payload)

    def test_special_msn_today_node_returns_title(self):
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"MSN Today", payload)

    def test_explicit_leaf_children_do_not_fall_back_to_unknown_sentinel(self):
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_special_msn_today_leaf_children_emit_self_nav_record(self):
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
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

    def test_msn_root_children_emit_localized_wrappers(self):
        # Server "0:0" is the HOMEBASE Categories LJUMP target (LJUMP 1:0:0:0
        # resolves to the client's MSN root which has wire key "0:0" on the
        # server). GetLocalizedNode on this node takes the first child, so
        # Cats US must lead the list for the Categories button to land there.
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(struct.pack("<II", 1, 0x10), payload)  # Categories (US) 'a'
        self.assertIn(struct.pack("<II", 1, 0x11), payload)  # Member Assistance (US) 'a'
        self.assertIn(struct.pack("<II", 1, 0x12), payload)  # Worldwide Categories 'a'
        self.assertIn(struct.pack("<II", 1, 0), payload)     # WW MA (aliased to wire "1:0")
        self.assertIn(b"Categories (US)", payload)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertIn(b"Worldwide Categories", payload)
        self.assertIn(b"Worldwide Member Assistance", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)  # no MSN Today
        self.assertNotIn(struct.pack("<II", 3, 1), payload)  # no Favorite Places

    def test_narrow_root_children_request_returns_localized_wrappers(self):
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(struct.pack("<II", 1, 0x10), payload)
        self.assertIn(b"Categories (US)", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)

        # Server "1:0" is the LJUMP 1:1:0:0 target (client's MSN Central /
        # Worldwide Member Assistance hub). Its children are MA US + MA BR.
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(struct.pack("<II", 1, 0x11), payload)
        self.assertIn(b"Member Assistance (US)", payload)

        # Unknown / terminal-leaf nodes must not leak the fallback sentinel
        # (FFFFFFFF:FFFFFFFF) into the listview.
        for node_id, raw in (
            ("3:1", struct.pack("<II", 3, 1)),
            (f"1:{0x100}", struct.pack("<II", 1, 0x100)),  # Arts and Entertainment
        ):
            request = DirsrvRequest(
                node_id=node_id,
                node_id_raw=raw,
                dword_0=1,
                dword_1=14,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_get_children_reply_payload(request)
            self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_startup_browse_walk_for_msn_root_omits_menu_aliases(self):
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        # MSN Today and Favorite Places are client-side HOMEBASE aliases; they
        # must not appear in the server-enumerated root listing.
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)
        # The localized wrappers must be present — these are the
        # GetLocalizedNode targets for the Categories / MA buttons.
        self.assertIn(struct.pack("<II", 1, 0x10), payload)
        self.assertIn(struct.pack("<II", 1, 0x11), payload)

    def test_worldwide_member_assistance_hub_self_identity(self):
        # Server wire "1:0" = client's MSN Central, overloaded as Worldwide
        # Member Assistance. Self-query returns the WMA name.
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"Worldwide Member Assistance", payload)

    def test_worldwide_member_assistance_children_return_locale_wrappers(self):
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)

    def test_member_assistance_us_children_emit_nine_entries_with_msn_today_link(self):
        # 1:17 = Member Assistance (US). Its children include the live 4:0
        # MSN Today leaf so clicking the in-MA entry launches MOSVIEW exactly
        # as the HOMEBASE MSN Today button does.
        request = DirsrvRequest(
            node_id=f"1:{0x11}",
            node_id_raw=struct.pack("<II", 1, 0x11),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"The MSN Member Lobby", payload)
        self.assertIn(b"MSN Beta Center", payload)
        self.assertIn(b"MSN Today", payload)
        self.assertIn(b"Member Agreement", payload)
        self.assertIn(struct.pack("<II", 4, 0), payload)  # live MOSVIEW leaf

    def test_categories_us_children_emit_fourteen_categories(self):
        request = DirsrvRequest(
            node_id=f"1:{0x10}",
            node_id_raw=struct.pack("<II", 1, 0x10),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00b\x00e\x00tp",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Arts and Entertainment", payload)
        self.assertIn(b"The Microsoft Network Beta", payload)
        # "Folder"-tagged entries still surface as distinct listview rows.
        self.assertIn(b"Interest, Leisure and Hobbies", payload)

    def test_arts_and_entertainment_children_emit_subleaves(self):
        request = DirsrvRequest(
            node_id=f"1:{0x100}",
            node_id_raw=struct.pack("<II", 1, 0x100),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Books and Writing", payload)
        self.assertIn(b"Coming Attractions", payload)
        self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_filter_on_locale_scopes_worldwide_children_to_matching_lcid(self):
        # filter_on=1, lcid=pt-BR → WW MA's children (server "1:0") drop
        # MA (US) and keep only MA (BR).
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=struct.pack("<II", 1, 0x0416),
            locale_lcid=0x0416,
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)
        self.assertNotIn(b"Member Assistance (US)", payload)

        # filter_on=0 — the 4-byte form — keeps everything.
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=b"\x00\x00\x00\x00",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertIn(b"Assistencia ao Associado (BR)", payload)

    def test_filter_on_locale_picks_localized_categories_under_msn_root(self):
        # LJUMP 1:0:0:0 (HOMEBASE Categories) targets MSN root and the client
        # calls GetLocalizedNode with filter_on=1. The first locale-matching
        # child must be Categorias (BR) under pt-BR — without the localized
        # wrapper as a direct child of MSN root the filter would skip past
        # both Cats(US) and MA(US) and surface Worldwide Categories instead.
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            locale_raw=struct.pack("<II", 1, 0x0416),
            locale_lcid=0x0416,
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
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
                    ((1, 0x11), "Member Assistance (US)"),
                    ((1, 0x14), "Assistencia ao Associado (BR)"),
                    ((1, 0x12), "Worldwide Categories"),
                    ((1, 0), "Worldwide Member Assistance"),
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
                f"1:{0x12}",
                struct.pack("<II", 1, 0x12),
                [
                    ((1, 0x10), "Categories (US)"),
                    ((1, 0x13), "Categorias (BR)"),
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
        ]
        for node_id, raw, expected in cases:
            request = DirsrvRequest(
                node_id=node_id,
                node_id_raw=raw,
                dword_0=1,
                dword_1=14,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_get_children_reply_payload(request)
            records = _walk_get_children_records(payload)
            self.assertEqual(
                len(records), len(expected),
                f"node={node_id} record count {len(records)} != expected {len(expected)}",
            )
            for idx, (props, (exp_a, exp_e)) in enumerate(zip(records, expected, strict=True)):
                a_blob = props.get("a")
                self.assertIsNotNone(a_blob, f"node={node_id} idx={idx} missing 'a'")
                self.assertEqual(
                    struct.unpack("<II", a_blob), exp_a,
                    f"node={node_id} idx={idx}: a={struct.unpack('<II', a_blob)} != {exp_a}",
                )
                self.assertEqual(
                    props.get("e"), exp_e,
                    f"node={node_id} idx={idx}: e={props.get('e')!r} != {exp_e!r}",
                )

    def test_dsnav_details_column_tags_use_documented_type_bytes(self):
        # DSNAV.md §12/§14.2 pins the wire types for the details-view columns:
        # tp=0x0A ASCIIZ, p=0x03 DWORD (size), w=0x0C FILETIME (8-byte).
        # `l` is advertised but unread — DWORD 0 is the safe default (§12).
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        # Containers emit type_str="Directory" via _container_content default.
        # ASCII string bodies use the shared flag-byte wire body: \x01 + asciiz.
        self.assertIn(b"\x0atp\x00\x01Directory\x00", payload)
        # Category containers have size_bytes=0 → inline 0x03 DWORD 0.
        self.assertIn(b"\x03p\x00\x00\x00\x00\x00", payload)
        # Category containers have empty modified → `w` is skipped entirely so
        # the listview cell renders blank instead of a bogus 1601 date.
        # Check every plausible wire-type + name combination is absent.
        for type_byte in (0x03, 0x0C, 0x0E, 0x0B, 0x0A):
            self.assertNotIn(bytes([type_byte]) + b"w\x00", payload)
        # `l` still emits as DWORD 0 (§12 safe default for unresolved tags).
        self.assertIn(b"\x03l\x00\x00\x00\x00\x00", payload)
        # Regression guard: the old 0x0E blob emit must be gone for these tags.
        self.assertNotIn(b"\x0etp\x00", payload)
        self.assertNotIn(b"\x0ep\x00", payload)
        self.assertNotIn(b"\x0el\x00", payload)

    def test_msn_today_leaf_emits_nonzero_size_dword(self):
        # The MSN Today fixture carries size_bytes=5*1024*1024; `p` must land
        # as an inline 0x03 DWORD so MOSSHELL's FormatSizeString formats it,
        # not the low-4 of a heap pointer.
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
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
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=1,
            dword_1=14,
            prop_group="e\x00j\x00k\x00ca\x00tp\x00z\x00o\x00g",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
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

    def test_msn_today_properties_dialog_request_uses_dialog_wire_types(self):
        """Properties dialog (is_children=False) gets 0x0B tp and 0x0B w string."""
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="e\x00tp\x00w\x00j",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"\x0ae\x00\x01MSN Today\x00", payload)
        self.assertIn(b"\x0btp\x00\x01News & Features\x00", payload)
        self.assertIn(b"\x0bw\x00\x01April 15, 2026\x00", payload)
        self.assertIn(b"\x0bj\x00\x01Your daily window to MSN.\x00", payload)

    def test_language_prop_ships_as_qword_with_lcid_at_offset_four(self):
        # Per-node `q` lookup (not the 0:0 language-list short-circuit):
        # MSN Today's language travels on the wire as type 0x04 qword
        # so the client's `*(u32*)(value + 4)` read lands on the LCID
        # instead of adjacent heap. Packing as type 0x03 DWORD would
        # put the LCID at offset 0 and the +4 read would fall off the
        # 4-byte buffer — root cause of the garbage combobox.
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="q",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        # Wire: type 0x04, name "q\0", 8-byte qword = [header_u32][lcid_u32].
        self.assertIn(b"\x04q\x00" + struct.pack("<II", 0, 1033), payload)
        # Regression guard: the old 4-byte DWORD emit must be gone.
        self.assertNotIn(b"\x03q\x00" + struct.pack("<I", 1033), payload)

    def test_language_list_request_returns_one_record_per_supported_locale(self):
        # The MCM browse-language worker opens a DIRSRV pipe with
        # ver_param="U" and asks for `q` on node 0:0 with a 4-byte zero
        # locale. Observed on the wire as selector 0x02 (dword_0=0,
        # is_children=False) — NOT the GetChildren selector the static
        # RE suggested. Gate on propList=["q"] so we short-circuit to a
        # per-locale reply regardless of is_children.
        for dword_0 in (0, 1):
            request = DirsrvRequest(
                node_id="0:0",
                node_id_raw=struct.pack("<II", 0, 0),
                dword_0=dword_0,
                dword_1=1,
                prop_group="q",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_get_children_reply_payload(request)
            for lcid in SUPPORTED_BROWSE_LCIDS:
                self.assertIn(
                    b"\x04q\x00" + struct.pack("<II", 0, lcid),
                    payload,
                    f"LCID 0x{lcid:04x} missing when dword_0={dword_0}",
                )
        # Address-bar enumeration (different propList) still resolves
        # through the regular content tree — no language leakage.
        addrbar_request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        addrbar_payload = build_get_children_reply_payload(addrbar_request)
        # Regular GetChildren on MSN root returns the localized wrappers
        # (the address-bar entries); the language-list short-circuit is
        # scoped to propList=["q"] only, so this reply carries nav data.
        self.assertIn(b"Categories (US)", addrbar_payload)
        for lcid in SUPPORTED_BROWSE_LCIDS:
            self.assertNotIn(
                b"\x04q\x00" + struct.pack("<II", 0, lcid), addrbar_payload
            )


class TestDIRSRVUnhandledSelector(unittest.TestCase):
    """DIRSRV must warn (not silently fall through to GetProperties) on
    selectors that have no registered handler — keeps unmapped client
    paths visible in the wire log.
    """

    def test_unknown_selector_warns_and_returns_none(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        # Selector 0x01 (GetParents) — no handler today, must surface as
        # an `unhandled` warning, not a self-record reply.
        payload = b""
        with self.assertLogs("server.services.dirsrv", level="WARNING") as cap:
            result = handler.handle_request(
                msg_class=0x01,
                selector=0x01,
                request_id=0,
                payload=payload,
                server_seq=0,
                client_ack=0,
            )
        self.assertIsNone(result)
        self.assertTrue(any("unhandled" in m for m in cap.output))


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
            b"\x04" + bytes([0x80 | len(wide)]) + wide
            + b"\x04\x84\x00\x00\x00\x00"  # locale: count=0
            + b"\x83\x84"                    # recv descriptors
        )

    def test_known_go_word_returns_matching_deid(self):
        # MSN Today fixture: node_id "4:0", go_word "today" (case fold).
        payload = build_get_deid_from_go_word_reply_payload(
            self._build_request("Today")
        )
        expected = (
            b"\x83\x00\x00\x00\x00"               # status=0
            + bytes([TAG_END_STATIC])             # 0x87
            + b"\x84\x88"                         # 0x84 var, len=8 inline
            + struct.pack("<II", 4, 0)            # deid (4, 0)
        )
        self.assertEqual(payload, expected)

    def test_unknown_go_word_returns_zero_deid_with_error(self):
        payload = build_get_deid_from_go_word_reply_payload(
            self._build_request("nonexistent")
        )
        expected = (
            b"\x83" + struct.pack("<I", DS_E_NOT_FOUND)
            + bytes([TAG_END_STATIC])
            + b"\x84\x88"
            + b"\x00" * 8
        )
        self.assertEqual(payload, expected)

    def test_dispatch_via_handler(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        result = handler.handle_request(
            msg_class=0x01,
            selector=0x03,
            request_id=0,
            payload=self._build_request("today"),
            server_seq=0,
            client_ack=0,
        )
        self.assertIsNotNone(result)


class TestOLREGSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        payload = build_olregsrv_service_map_payload()
        self.assertEqual(len(payload), len(OLREGSRV_INTERFACE_GUIDS) * 17)

    def test_guid_format(self):
        payload = build_olregsrv_service_map_payload()
        for i, (guid_bytes, selector) in enumerate(OLREGSRV_INTERFACE_GUIDS):
            record = payload[i * 17 : (i + 1) * 17]
            self.assertEqual(record[:16], guid_bytes)
            self.assertEqual(record[16], selector)

    def test_produces_packet(self):
        handler = OLREGSRVHandler(4, "OLREGSRV")
        pkts = handler.build_discovery_packet(6, 6)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)


class TestOLREGSRVReply(unittest.TestCase):
    def test_class01_acked_with_hresult_zero(self):
        """The class=0x01 head of the commit gets an HRESULT=0 reply body."""
        handler = OLREGSRVHandler(4, "OLREGSRV")
        pkts = handler.handle_request(0x01, 0x01, 0, b"", 5, 5)
        self.assertIsNotNone(pkts)
        self.assertEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # Payload must contain tag 0x83 followed by four zero bytes.
        self.assertIn(b"\x83\x00\x00\x00\x00", parsed.payload)

    def test_one_way_records_get_no_reply(self):
        """class=0xe6/0xe7 continuation frames are fire-and-forget."""
        handler = OLREGSRVHandler(4, "OLREGSRV")
        self.assertIsNone(handler.handle_request(0xE7, 0x01, 0, b"", 5, 5))
        self.assertIsNone(handler.handle_request(0xE6, 0x02, 0, b"", 5, 5))
        self.assertIsNone(handler.handle_request(0xE7, 0x02, 0, b"", 5, 5))

    def test_sel02_probe_left_unanswered(self):
        """sel=0x02 pre-check must stay silent — any reply aborts signup."""
        handler = OLREGSRVHandler(4, "OLREGSRV")
        self.assertIsNone(handler.handle_request(0x01, 0x02, 0, b"\x83", 5, 5))


class TestFTMHandler(unittest.TestCase):
    def test_request_download_reply_returns_packet(self):
        payload = bytes.fromhex(
            "04 bc 70 6c 61 6e 73 2e 74 78 74 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00"
        )
        handler = FTMHandler(1, "FTM")
        pkts = handler.handle_request(0x01, 0x00, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_bill_client_reply_returns_packet(self):
        handler = FTMHandler(1, "FTM")
        pkts = handler.handle_request(0x01, 0x03, 0, b"", 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = FTMHandler(1, "FTM")
        self.assertIsNone(handler.handle_request(0x01, 0x02, 0, b"", 5, 5))

    def test_resolve_ftm_target_returns_name_for_expected_var_layout(self):
        payload = (
            b"\x04"
            + bytes([0x80 | 60])
            + b"ms_Ynt.hlp\x00"
            + b"\x00" * (60 - len("ms_Ynt.hlp") - 1)
        )
        filename, _ = _resolve_ftm_target(payload)
        self.assertEqual(filename, "ms_Ynt.hlp")

    def test_resolve_ftm_target_falls_back_for_unexpected_var_size(self):
        payload = b"\x04" + bytes([0x80 | 32]) + b"plans.txt\x00" + b"\x00" * 22
        filename, _ = _resolve_ftm_target(payload)
        self.assertEqual(filename, FTM_FALLBACK_FILENAME)

    def test_request_download_reply_echoes_filename(self):
        payload = _build_request_download_reply("ms_Ynt.hlp", 0)
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b"ms_Ynt.hlp\x00", payload)

    def test_request_download_reply_handles_non_ascii_filename(self):
        payload = _build_request_download_reply("pláns.txt", 0)
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b"plns.txt\x00", payload)

    def test_request_download_reply_size_matches_content_len(self):
        payload = _build_request_download_reply("prodinfo.rtf", 42)
        # After 2-byte 0x84 length prefix, size1 at offset 0x08 and
        # size2 at offset 0x0C must both equal content_len.
        body = payload[2:]
        self.assertEqual(struct.unpack("<I", body[0x08:0x0C])[0], 42)
        self.assertEqual(struct.unpack("<I", body[0x0C:0x10])[0], 42)

    def test_bill_client_reply_has_zero_chunk_length(self):
        payload = _build_bill_client_reply()
        self.assertEqual(payload[0], 0x84)
        self.assertEqual(struct.unpack("<H", payload[0x11:0x13])[0], 0)

    def test_bill_client_reply_carries_content(self):
        content = b"{\\rtf1 hi}"
        payload = _build_bill_client_reply(content)
        body = payload[2:]  # strip 0x84 + length prefix
        self.assertEqual(struct.unpack("<H", body[0x10:0x12])[0], len(content))
        self.assertEqual(body[0x12 : 0x12 + len(content)], content)


def _make_logsrv_request(counter, selector=0x00):
    """Synthesize a signup-path FTM request with LOGSRV+counter CFI."""
    cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
    cfi[:6] = b"LOGSRV"
    struct.pack_into("<I", cfi, FTM_COUNTER_OFFSET, counter)
    return build_tagged_reply_var(0x04, bytes(cfi)) + b"\x84"


class TestFTMSignupLogsrvMapping(unittest.TestCase):
    def test_counter_0_maps_to_plans_txt(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(0))
        self.assertEqual(filename, "plans.txt")
        self.assertIn(b"[Countries]", content)
        self.assertIn(b"[PaymentOptions]", content)
        self.assertIn(b"PaymentOption1=CHARGE", content)

    def test_counter_1_maps_to_prodinfo(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(1))
        self.assertEqual(filename, "prodinfo.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_2_maps_to_legalagr(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(2))
        self.assertEqual(filename, "legalagr.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_3_maps_to_newtips(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(3))
        self.assertEqual(filename, "newtips.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_out_of_range_falls_through(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(99))
        # Unknown counter leaves the source name intact — no content served.
        self.assertEqual(filename, "LOGSRV")
        self.assertEqual(content, b"")

    def test_direct_filename_is_served_from_disk(self):
        # Billing path: client sends "plans.txt" directly — resolved
        # against server/data/signup/plans.txt dynamically.
        cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
        cfi[: len(b"plans.txt")] = b"plans.txt"
        payload = build_tagged_reply_var(0x04, bytes(cfi))
        filename, content = _resolve_ftm_target(payload)
        self.assertEqual(filename, "plans.txt")
        self.assertIn(b"[PaymentOptions]", content)

    def test_unknown_direct_filename_returns_empty(self):
        cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
        cfi[: len(b"missing.bin")] = b"missing.bin"
        payload = build_tagged_reply_var(0x04, bytes(cfi))
        filename, content = _resolve_ftm_target(payload)
        self.assertEqual(filename, "missing.bin")
        self.assertEqual(content, b"")

    def test_request_download_reply_encodes_mapped_filename(self):
        handler = FTMHandler(5, "FTM")
        pkts = handler.handle_request(
            0x01,
            0x00,
            0,
            _make_logsrv_request(1),
            10,
            10,
        )
        self.assertIsNotNone(pkts)
        # The mapped filename must appear in the on-wire reply.
        joined = b"".join(pkts)
        self.assertIn(b"prodinfo.rtf\x00", joined)

    def test_bill_client_reply_emits_rtf_for_counter_1(self):
        handler = FTMHandler(5, "FTM")
        pkts = handler.handle_request(
            0x01,
            0x03,
            1,
            _make_logsrv_request(1, selector=0x03),
            10,
            10,
        )
        self.assertIsNotNone(pkts)
        joined = b"".join(pkts)
        _, expected = _resolve_ftm_target(_make_logsrv_request(1))
        self.assertIn(expected, joined)


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


class TestServicePacketFragmentation(unittest.TestCase):
    """Tests for multi-frame pipe fragmentation in build_service_packet."""

    def test_small_payload_single_packet(self):
        host_block = build_host_block(0x06, 0x00, 0, b"\x00" * 50)
        pkts = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts), 1)
        self.assertLessEqual(len(pkts[0]), 1024)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_large_payload_two_packets(self):
        # 1052-byte payload mimics the billing reply
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        self.assertEqual(len(pkts), 2)

    def test_both_packets_within_limit(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        for i, pkt in enumerate(pkts):
            self.assertLessEqual(len(pkt), 1024, f"Packet {i + 1} exceeds 1024 bytes")

    def test_both_packets_valid_crc(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        for i, pkt in enumerate(pkts):
            parsed = parse_packet(pkt[:-1])
            self.assertIsNotNone(parsed, f"Packet {i + 1} unparseable")
            self.assertTrue(parsed.crc_ok, f"Packet {i + 1} CRC fail")

    def test_first_frame_no_last_data(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[0][:-1])
        # First byte of payload is the pipe frame header
        hdr = decode_header_byte(parsed.payload[0])
        self.assertTrue(hdr & PIPE_CONTINUATION, "Frame 1 missing CONTINUATION")
        self.assertFalse(hdr & PIPE_LAST_DATA, "Frame 1 should NOT have LAST_DATA")

    def test_second_frame_has_last_data(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[1][:-1])
        hdr = decode_header_byte(parsed.payload[0])
        self.assertTrue(hdr & PIPE_CONTINUATION, "Frame 2 missing CONTINUATION")
        self.assertTrue(hdr & PIPE_LAST_DATA, "Frame 2 missing LAST_DATA")

    def test_first_frame_has_size_prefix(self):
        """Frame 1 content starts with uint16_le(total_pipe_data_len)."""
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[0][:-1])
        # After frame header byte, next 2 bytes = pipe_data size prefix
        size_prefix = struct.unpack("<H", parsed.payload[1:3])[0]
        expected_pipe_data_len = 2 + len(host_block)  # routing_prefix + host_block
        self.assertEqual(size_prefix, expected_pipe_data_len)

    def test_second_frame_no_size_prefix(self):
        """Frame 2 content is raw continuation data (no 2-byte prefix)."""
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        # Reconstruct: frame1 content after header = size_prefix(2) + chunk1
        # frame2 content after header = chunk2
        chunk1 = p1.payload[3:]  # skip header(1) + size_prefix(2)
        chunk2 = p2.payload[1:]  # skip header(1) only
        pipe_data = chunk1 + chunk2
        # First 2 bytes of pipe_data = routing prefix (pipe_idx as uint16_le)
        routing = struct.unpack("<H", pipe_data[:2])[0]
        self.assertEqual(routing, 8)  # pipe_idx we passed
        # Remaining = host_block
        self.assertEqual(pipe_data[2:], host_block)

    def test_seq_increments_across_packets(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        self.assertEqual(p1.seq, 10)
        self.assertEqual(p2.seq, 11)

    def test_seq_wraps_at_127(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 127, 5)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        self.assertEqual(p1.seq, 127)
        self.assertEqual(p2.seq, 0)

    def test_billing_reply_fragments(self):
        """The actual billing handler produces correctly fragmented packets."""
        handler = LOGSRVHandler(8, "LOGSRV")
        pkts = handler.handle_request(0x06, 0x0A, 0, b"", 10, 10)
        self.assertEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertLessEqual(len(pkt), 1024)
            parsed = parse_packet(pkt[:-1])
            self.assertTrue(parsed.crc_ok)

    def test_custom_max_wire_bytes(self):
        """Fragmentation threshold is configurable."""
        host_block = build_host_block(0x06, 0x00, 0, b"\x00" * 200)
        # With default 1024 limit, this fits in one packet
        pkts_default = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts_default), 1)
        # With a tight limit, it fragments. Every packet must stay under
        # the limit — no "first two frames + overflow on the last" bug.
        pkts_tight = build_service_packet(3, host_block, 5, 5, max_wire_bytes=100)
        self.assertGreaterEqual(len(pkts_tight), 2)
        for p in pkts_tight:
            self.assertLessEqual(len(p), 100)


class TestContinuationFrame(unittest.TestCase):
    def test_flags_with_last(self):
        frame = _build_continuation_frame(3, b"\x01\x02\x03", last=True)
        hdr = decode_header_byte(frame[0])
        self.assertTrue(hdr & PIPE_ALWAYS_SET)
        self.assertTrue(hdr & PIPE_CONTINUATION)
        self.assertTrue(hdr & PIPE_LAST_DATA)
        self.assertEqual(hdr & 0x0F, 3)

    def test_flags_without_last(self):
        frame = _build_continuation_frame(3, b"\x01\x02\x03", last=False)
        hdr = decode_header_byte(frame[0])
        self.assertTrue(hdr & PIPE_ALWAYS_SET)
        self.assertTrue(hdr & PIPE_CONTINUATION)
        self.assertFalse(hdr & PIPE_LAST_DATA)

    def test_content_follows_header_directly(self):
        data = b"\xaa\xbb\xcc"
        frame = _build_continuation_frame(3, data, last=True)
        # Frame = header(1) + raw content (no length prefix)
        self.assertEqual(len(frame), 1 + len(data))
        self.assertEqual(frame[1:], data)


class TestLOGSRVCommitTagType(unittest.TestCase):
    """LOGSRV billing-commit replies (selectors 0x0B/0x0C) MUST use 0x84
    (var) rather than 0x83 (dword).  BILLADD's
    BillingDlg_ProcessCommitReply unblocks on either, but its tag-type
    check rejects 0x83 — leaving the OK button stuck."""

    def _commit_reply(self, selector):
        handler = LOGSRVHandler(3, "LOGSRV")
        pkts = handler.handle_request(0x06, selector, 0, b"", 5, 5)
        parsed = parse_packet(pkts[0][:-1])
        # Skip pipe header(1) + length prefix(2) + routing prefix(2)
        host_block = parsed.payload[5:]
        # host_block layout: msg_class | selector | VLI req_id | reply
        # Our request_id=0 fits in 1 VLI byte → reply starts at offset 3.
        return host_block[3:]

    def test_pm_commit_uses_var_tag(self):
        reply = self._commit_reply(0x0B)
        self.assertEqual(reply[0], 0x84, "PM commit reply must use 0x84 var tag, not 0x83 dword")

    def test_billing_commit_uses_var_tag(self):
        reply = self._commit_reply(0x0C)
        self.assertEqual(
            reply[0], 0x84, "Billing commit reply must use 0x84 var tag, not 0x83 dword"
        )

    def test_var_payload_is_status_dword(self):
        # Inline length byte (bit 7 set) for a 4-byte status dword = 0x84.
        reply = self._commit_reply(0x0C)
        self.assertEqual(reply[1], 0x84)  # 0x80 | 4
        self.assertEqual(len(reply), 2 + 4)
        status = struct.unpack("<I", reply[2:6])[0]
        self.assertEqual(status, 0)


class TestServicePacketBoundaries(unittest.TestCase):
    """Exact-boundary cases for build_service_packet fragmentation."""

    def _largest_unfragmented_payload_len(self):
        # Binary search for the largest host-block payload that still
        # fits in a single wire packet under the default 1024 limit.
        lo, hi = 0, 2048
        while lo < hi:
            mid = (lo + hi + 1) // 2
            host_block = build_host_block(0x06, 0x00, 0, b"\x00" * mid)
            pkts = build_service_packet(3, host_block, 5, 5)
            if len(pkts) == 1 and len(pkts[0]) <= 1024:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def test_no_fragmentation_at_exact_cutoff(self):
        n = self._largest_unfragmented_payload_len()
        host_block = build_host_block(0x06, 0x00, 0, b"\x00" * n)
        pkts = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts), 1)
        self.assertLessEqual(len(pkts[0]), 1024)

    def test_fragmentation_one_byte_past_cutoff(self):
        n = self._largest_unfragmented_payload_len()
        host_block = build_host_block(0x06, 0x00, 0, b"\x00" * (n + 1))
        pkts = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts), 2)

    def test_seq_wrap_chunk2_zero(self):
        # seq=0x7F + 1 wraps to 0x00 in chunk 2 (mask 0x7F).
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 0x7F, 5)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        self.assertEqual(p1.seq, 0x7F)
        self.assertEqual(p2.seq, 0x00)

    def test_chunks_reassemble_to_original_pipe_data(self):
        # Round-trip: chunk1 + chunk2 (after stripping per-frame overhead)
        # must equal routing_prefix + host_block.
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        self.assertEqual(len(pkts), 2)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        chunk1 = p1.payload[3:]  # skip header(1) + size_prefix(2)
        chunk2 = p2.payload[1:]  # skip header(1) only
        expected = struct.pack("<H", 8) + host_block
        self.assertEqual(chunk1 + chunk2, expected)

    def test_stuffing_margin_absorbs_small_burst(self):
        # A modest sprinkling of stuffed bytes (0x1b, 0x0d) inside an
        # otherwise normal payload must not push any wire packet past
        # the max_wire_bytes limit.  Content-aware splitting (not a
        # fixed margin) keeps packets in range.
        body = (b"\x00" * 1037) + (b"\x1b" * 15)
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, body))
        pkts = build_service_packet(8, host_block, 10, 10)
        self.assertEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertLessEqual(len(pkt), 1024)
            parsed = parse_packet(pkt[:-1])
            self.assertTrue(parsed.crc_ok)

    def test_dense_stuffing_still_fits(self):
        # A payload with enough stuffable bytes to blow past the old
        # fixed 20-byte margin must still produce all-in-range packets.
        # default.ico had 25 stuffable bytes and used to emit a 1029-byte
        # first frame — exactly the bug this file now prevents.
        body = (b"\x00" * 1000) + (b"\x1b" * 50)
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, body))
        pkts = build_service_packet(8, host_block, 10, 10)
        self.assertGreaterEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertLessEqual(len(pkt), 1024)


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


class TestMEDVIEWServiceMap(unittest.TestCase):
    def test_guid_count(self):
        # docs/MEDVIEW.md §2.1 — 42 IIDs sourced from MVTTL14C.DLL:0x7E84C1B0.
        self.assertEqual(len(MEDVIEW_INTERFACE_GUIDS), 42)

    def test_selectors_are_1_based_contiguous(self):
        # Client indexes the array at call time; selectors must match
        # position + 1 so the hard-coded 0x1F (handshake) resolves to
        # IID 00028BB8 at position 30.
        for i, (_guid, sel) in enumerate(MEDVIEW_INTERFACE_GUIDS):
            self.assertEqual(sel, i + 1)

    def test_handshake_selector_is_0x1F(self):
        self.assertEqual(MEDVIEW_SELECTOR_HANDSHAKE, 0x1F)

    def test_title_open_selector_is_0x01(self):
        self.assertEqual(MEDVIEW_SELECTOR_TITLE_OPEN, 0x01)

    def test_discovery_payload_size(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.build_discovery_packet(3, 3)
        self.assertIsInstance(pkts, list)
        self.assertGreaterEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)


class TestMEDVIEWHandshake(unittest.TestCase):
    def test_handshake_reply_is_nonzero_dword(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 0x01 (byte=1), 0x04 with 12 zero bytes, 0x83 recv.
        req_payload = bytes.fromhex("01 01 04 8c 00 00 20 00 06 40 00 00 09 04 00 00 83")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_HANDSHAKE, 0, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # Extract the host block payload from the pipe frame.
        # Layout: header byte + size_prefix (2B) + routing (2B) + host_block
        # host_block: class + selector + VLI req_id + reply_payload
        body = parsed.payload
        # Skip: header(1) + size(2) + routing(2) + class(1) + selector(1) + vli(1)
        reply_payload = body[8:]
        self.assertEqual(reply_payload[0], 0x83)  # dword tag
        validation = struct.unpack("<I", reply_payload[1:5])[0]
        self.assertNotEqual(validation, 0)
        self.assertEqual(reply_payload[5], TAG_END_STATIC)

    def test_handshake_unknown_selector_returns_none(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkt = handler.handle_request(0x01, 0x99, 0, b"", 5, 5)
        self.assertIsNone(pkt)


class TestMEDVIEWTitleOpen(unittest.TestCase):
    # TitleOpen spec format is `:%d[%s]%d` (docs/MOSVIEW.md §5.3); on the
    # HRMOSExec(c=6) path MSN Today lands as `:2[4]0` — svcid=2, deid=4,
    # serial=0. `_title_name_from_spec` extracts "4". The live handler now
    # serves a synthetic title branch, but the old Blackbird-backed
    # builder remains covered separately below.
    _MSN_TODAY_REQ = (
        b"\x04\x87:2[4]0\x00"        # tag=0x04 var, len|0x80=0x87, 7-byte ASCIIZ
        b"\x03\x00\x00\x00\x00"      # cached checksum 1 = 0
        b"\x03\x00\x00\x00\x00"      # cached checksum 2 = 0
        b"\x81\x81\x83\x83\x83\x83\x83"
    )

    def _decode_reply(self, req_payload):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_TITLE_OPEN, 1, req_payload, 5, 5,
        )
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # Frame layout: header(1) + size(2) + routing(2) + class(1)
        # + selector(1) + vli(1) — reply tagged stream starts at +8.
        return parsed.payload[8:]

    def _split_body(self, reply):
        # Static prefix: 2×2 (tagged bytes) + 5×5 (tagged dwords) + 1 (0x87)
        # + 1 (0x86) = 31 bytes before the dynamic payload.
        return reply[31:]

    def _open_handler(self, req_payload=None):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_OPEN,
            1,
            req_payload or self._MSN_TODAY_REQ,
            5,
            5,
        )
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        return handler, parsed.payload[8:]

    def test_title_open_reply_has_static_plus_dynamic(self):
        reply = self._decode_reply(self._MSN_TODAY_REQ)
        # Must start with 0x81 (title_id byte), nonzero value.
        self.assertEqual(reply[0], 0x81)
        self.assertNotEqual(reply[1], 0)  # title_id must be nonzero!
        # Second byte: 0x81 service_byte
        self.assertEqual(reply[2], 0x81)
        self.assertEqual(reply[3], 0x01)  # nonzero fileSystemMode selects remote HFS
        # Then 5×0x83 dwords
        pos = 4
        for _ in range(5):
            self.assertEqual(reply[pos], 0x83)
            pos += 5
        # End-static
        self.assertEqual(reply[pos], TAG_END_STATIC)
        pos += 1
        # Dynamic-complete
        self.assertEqual(reply[pos], TAG_DYNAMIC_COMPLETE_SIGNAL)

    def test_title_open_handler_caches_test_title_topics(self):
        # OpenTitle on deid="4" now resolves to the simple inline-section
        # `Test Title` fixture (`resources/titles/4.ttl`). It has zero
        # content proxies — only an embedded Caption control inside the
        # Page's CVForm, which is invisible to the wire — so `topics` is
        # empty after OpenTitle. Wire-byte content pins for the rich
        # `msn_today.ttl` fixture live in
        # `test_blackbird_payload_builder_preserved`.
        handler, _reply = self._open_handler()
        self.assertEqual(handler.title_caption, "Test Title")
        self.assertEqual(handler.topics, ())

    def test_blackbird_payload_builder_preserved(self):
        # `resources/titles/msn_today.ttl` is the reference Blackbird
        # `msn today.ttl` (sha256 4a6e884f…). The preserved Blackbird-
        # backed builder lowers it to: 3 supported top-level topic-source
        # entries (2 text + 1 image) → 3 topics, 1 real sec06 scaffold
        # record, empty sec07/sec08. CStringTable (sec04) carries 9
        # strings (title/section/form/frame/stylesheet/resource_folder +
        # 3 proxy names). Asserting against the body-builder output
        # directly (the wire path fragments at the 1024-byte boundary).
        result = build_m14_payload_for_deid("msn_today")
        self.assertEqual(result.caption, "MSN Today")
        parsed = parse_payload(result.payload)
        # Section-0 is now a multi-face / multi-descriptor blob lowered
        # from `model["stylesheet"]` per
        # `docs/mosview-authored-text-and-font-re.md`. The reference TTL
        # has 7 fonts (keys 0–6) and 54 styles (CSTYLE_NAME_DICTIONARY
        # indices 0..0x35), so the layout is:
        #   header     0x12
        #   face table 7 * 0x20 = 0xE0
        #   descriptor 54 * 0x2A = 0x8DC
        #   overrides  0
        #   pointer    7 * 0x04 = 0x1C   (one entry per face slot —
        #                                  `MVCL14N!FUN_7e896661` indexes
        #                                  by face_slot_index and AVs on
        #                                  out-of-bounds reads)
        #   total      0x9EA = 2538 bytes
        self.assertEqual(parsed.font_blob.length, 0x9EA)
        # Header: descriptor_count=54 (no clamp needed — every authored
        # style_id has a real descriptor), face_off=0x12,
        # descriptor_off=0xF2, override_count=0, override_off=0x9CE,
        # header_word_0c=0, pointer_table_off=0x9CE
        self.assertEqual(
            struct.unpack_from("<HHHHHH", parsed.font_blob.data, 0x02),
            (54, 0x12, 0xF2, 0, 0x9CE, 0),
        )
        self.assertEqual(
            struct.unpack_from("<H", parsed.font_blob.data, 0x10)[0],
            0x9CE,
        )
        # Face slot 0 is the "inherit"/empty slot reserved by font key 0;
        # slot 1 = Times New Roman, slot 2 = Arial, slot 3 = Courier New
        # (used by Preformatted/Code/Fixed Width per CSTYLE_DEFAULT_PROPS).
        self.assertEqual(parsed.font_blob.data[0x12:0x32], b"\x00" * 0x20)
        self.assertEqual(
            parsed.font_blob.data[0x32:0x52].rstrip(b"\x00"),
            b"Times New Roman",
        )
        self.assertEqual(
            parsed.font_blob.data[0x52:0x72].rstrip(b"\x00"),
            b"Arial",
        )
        self.assertEqual(
            parsed.font_blob.data[0x72:0x92].rstrip(b"\x00"),
            b"Courier New",
        )
        # Descriptor[0] = Normal: face_slot=1 (Times New Roman), lfHeight
        # -14 (= -MulDiv(11pt, 96, 72) = -11 * 4 // 3), lfWeight 400,
        # text_color black, back_color white — pinned in
        # CSTYLE_DEFAULT_PROPS[0]. lfHeight uses standard Win32 pt-to-px
        # at 96 DPI; consumed unmodified by `CreateFontIndirectA` in
        # MOSVIEW's MM_TEXT DC.
        desc0_off = 0xF2
        self.assertEqual(
            struct.unpack_from("<H", parsed.font_blob.data, desc0_off)[0],
            1,
        )
        self.assertEqual(
            parsed.font_blob.data[desc0_off + 0x06:desc0_off + 0x09],
            b"\x00\x00\x00",
        )
        self.assertEqual(
            parsed.font_blob.data[desc0_off + 0x09:desc0_off + 0x0C],
            b"\xFF\xFF\xFF",
        )
        self.assertEqual(
            struct.unpack_from("<i", parsed.font_blob.data, desc0_off + 0x0C)[0],
            -14,
        )
        self.assertEqual(
            struct.unpack_from("<i", parsed.font_blob.data, desc0_off + 0x1C)[0],
            400,
        )
        # Descriptor[1] = Heading 1: face_slot=2 (Arial), lfHeight -29
        # (= -MulDiv(22pt, 96, 72)), lfWeight 700 (bold), text_color
        # authored = 0x80 (dark red).
        desc1_off = desc0_off + 0x2A
        self.assertEqual(
            struct.unpack_from("<H", parsed.font_blob.data, desc1_off)[0],
            2,
        )
        self.assertEqual(
            parsed.font_blob.data[desc1_off + 0x06:desc1_off + 0x09],
            b"\x80\x00\x00",
        )
        self.assertEqual(
            struct.unpack_from("<i", parsed.font_blob.data, desc1_off + 0x0C)[0],
            -29,
        )
        self.assertEqual(
            struct.unpack_from("<i", parsed.font_blob.data, desc1_off + 0x1C)[0],
            700,
        )
        # Descriptor[0x1e] = Hyperlink: face=1, text_color=blue,
        # lfUnderline=1.
        desc_hyper = desc0_off + 0x1E * 0x2A
        self.assertEqual(
            parsed.font_blob.data[desc_hyper + 0x06:desc_hyper + 0x09],
            b"\x00\x00\xFF",
        )
        self.assertEqual(parsed.font_blob.data[desc_hyper + 0x21], 1)
        # Descriptor[0x22] = Strikethrough: lfStrikeOut=1 (name-tagged
        # special-case; flags_word matches Hyperlink/Underline so
        # lfUnderline is also set).
        desc_strike = desc0_off + 0x22 * 0x2A
        self.assertEqual(parsed.font_blob.data[desc_strike + 0x22], 1)
        self.assertEqual(parsed.font_blob.data[desc_strike + 0x21], 1)
        # Descriptor[0x23] = Preformatted: face_slot=3 (Courier).
        desc_pre = desc0_off + 0x23 * 0x2A
        self.assertEqual(
            struct.unpack_from("<H", parsed.font_blob.data, desc_pre)[0],
            3,
        )
        # sec07/sec08 records are dropped at wire boundary (BB-magic +
        # child-pane/popup source not recovered for the supported subset.
        self.assertEqual(parsed.sec07.record_count, 0)
        self.assertEqual(parsed.sec08.record_count, 0)
        # sec06 carries one window scaffold record lowered from
        # `model["frame"]` + `model["form"]` per
        # `docs/cbframe-cbform-sec06-mapping.md`:
        #   caption (+0x15) ← CBFrame.caption = "MSN Today"
        #   flags  (+0x48) = 0x08 (outer rect absolute pixels)
        #   outer rect (+0x49..+0x58) ← CBFrame.rect_left/top/right/bottom
        #     = (0, 0, 640, 480)
        #   all three COLORREFs (+0x5B / +0x78 / +0x7C) ←
        #     CBForm.background_color = 0x009098A8 (light tan;
        #     RGB(168,152,144); BBDESIGN Page Background color picker
        #     value confirmed via showcase TTL where setting picker
        #     to yellow produced 0x0000FFFF in this same slot).
        #   top-band rect (+0x80..+0x8F) = -1 sentinels → use full
        #     client area
        self.assertEqual(parsed.sec06.record_count, 1)
        self.assertEqual(
            parsed.sec06.data[0x15:0x15 + len(b"MSN Today\x00")],
            b"MSN Today\x00",
        )
        self.assertEqual(parsed.sec06.data[0x48], 0x08)
        self.assertEqual(
            struct.unpack_from("<iiii", parsed.sec06.data, 0x49),
            (0, 0, 640, 480),
        )
        self.assertEqual(
            struct.unpack_from("<I", parsed.sec06.data, 0x5B)[0],
            0x009098A8,
        )
        self.assertEqual(
            struct.unpack_from("<II", parsed.sec06.data, 0x78),
            (0x009098A8, 0x009098A8),
        )
        self.assertEqual(
            struct.unpack_from("<iiii", parsed.sec06.data, 0x80),
            (-1, -1, -1, -1),
        )
        self.assertEqual(parsed.sec04.count, 9)
        self.assertEqual(parsed.sec13.count, 2)
        self.assertEqual(parsed.sec01.data, b"MSN Today\x00")
        # sec02 is "Copyright information" (MOSVIEW message 0x406); empty
        # because no TTL we synthesize today carries a copyright property.
        self.assertEqual(parsed.sec02.data, b"")
        # sec6a carries the bare deid (Marvel HRMOSExec path, not a
        # Windows path — see `m14_payload` module docstring).
        self.assertEqual(parsed.sec6a.data, b"msn_today\x00")
        self.assertEqual(parsed.trailing, b"")
        # Real metadata threaded through: 3 topic-source entries
        # → topic_count=3,
        # va_get_contents=0x1000 (synthesizer's first_address), CRC32 cache
        # headers non-zero.
        self.assertEqual(result.metadata.topic_count, 3)
        self.assertEqual(result.metadata.va_get_contents, 0x1000)
        self.assertEqual(result.metadata.addr_get_contents, 0x1000)
        self.assertNotEqual(result.metadata.cache_header0, 0)
        self.assertNotEqual(result.metadata.cache_header1, 0)
        # Per-topic mapping: 3 entries (2 text + 1 image) with the
        # synthesizer's address/topic_number/context_hash assignments.
        # Homepage.bdf TextRuns has 2 `'#'`-separated paragraphs;
        # heuristic style assignment puts the first as Heading 1 and
        # the rest as Normal. Calendar of Events.bdf's TextRuns is
        # `00 00` (empty body, 0 paragraphs); image entries don't
        # contribute paragraphs either. Topic numbers are 1-based per
        # `m14_synth.build_topic_source_metadata`.
        self.assertEqual(len(result.topics), 3)
        topic1 = result.topic_by_number(1)
        self.assertIsNotNone(topic1)
        self.assertEqual(topic1.address, 0x1000)
        self.assertEqual(topic1.kind, "text")
        self.assertEqual(len(topic1.paragraphs), 2)
        self.assertEqual(topic1.paragraphs[0].style_id, 1)  # Heading 1
        self.assertTrue(topic1.paragraphs[0].text.startswith("This is an example"))
        self.assertEqual(topic1.paragraphs[1].style_id, 0)  # Normal
        self.assertTrue(topic1.paragraphs[1].text.startswith("Ordered list"))
        topic2 = result.topic_by_number(2)
        self.assertIsNotNone(topic2)
        self.assertEqual(topic2.address, 0x1100)
        self.assertEqual(topic2.kind, "text")
        self.assertEqual(topic2.paragraphs, ())  # empty TextRuns → no paragraphs
        topic3 = result.topic_by_number(3)
        self.assertIsNotNone(topic3)
        self.assertEqual(topic3.kind, "image")

    def test_title_open_body_allows_more_topic_sources_without_more_window_records(self):
        ttl_path = Path(__file__).resolve().parents[1] / "resources" / "titles" / "msn_today.ttl"
        model = build_source_model(ttl_path)
        extra_entry = dict(model["topic_source_entries"][0])
        extra_entry["entry_index"] = len(model["topic_source_entries"])
        extra_entry["proxy_name"] = "Homepage Copy"
        model["topic_source_entries"].append(extra_entry)
        model["section"]["contents"].append(model["section"]["contents"][0])
        with mock.patch("server.blackbird.m14_payload.build_source_model", return_value=model):
            result = build_m14_payload_for_deid("msn_today")
        parsed = parse_payload(result.payload)
        self.assertEqual(result.metadata.topic_count, 4)
        self.assertEqual(len(result.topics), 4)
        topic4 = result.topic_by_number(4)
        self.assertIsNotNone(topic4)
        self.assertEqual(topic4.address, 0x1300)
        self.assertEqual(parsed.sec07.record_count, 0)
        self.assertEqual(parsed.sec08.record_count, 0)
        self.assertEqual(parsed.sec06.record_count, 1)

    def test_title_open_body_falls_back_to_deid_for_unknown(self):
        # deid "42" has no .ttl fixture — the handler emits an empty
        # payload with caption "Title 42\0" in sec01/sec6a so the viewer
        # still shows something informative.
        result = build_m14_payload_for_deid("42")
        self.assertEqual(result.caption, "Title 42")
        parsed = parse_payload(result.payload)
        # Empty fallback ships the same minimal section-0 (96 B) as the
        # real-content path — keeps the engine on a fully-validated branch
        # even when no text items reference a style.
        self.assertEqual(parsed.font_blob.length, 0x60)
        self.assertEqual(parsed.sec07.record_count, 0)
        self.assertEqual(parsed.sec08.record_count, 0)
        self.assertEqual(parsed.sec06.record_count, 0)
        self.assertEqual(parsed.sec01.data, b"Title 42\x00")
        self.assertEqual(parsed.sec02.length, 0)
        self.assertEqual(parsed.sec6a.data, b"Title 42\x00")
        self.assertEqual(parsed.sec13.count, 0)
        self.assertEqual(parsed.sec04.count, 0)
        self.assertEqual(parsed.trailing, b"")
        # Empty fallback metadata: zero dwords + only header0 non-zero
        # (CRC32 of the empty payload). topics tuple is empty.
        self.assertEqual(result.metadata.topic_count, 0)
        self.assertEqual(result.metadata.va_get_contents, 0)
        self.assertEqual(result.metadata.addr_get_contents, 0)
        self.assertNotEqual(result.metadata.cache_header0, 0)
        self.assertEqual(result.metadata.cache_header1, 0)
        self.assertEqual(result.topics, ())


class TestMEDVIEWTitleGetInfo(unittest.TestCase):
    def test_get_info_reply_size_zero(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 <title_byte>, 3× 0x03 dword, 0x83 recv.
        req_payload = bytes.fromhex(
            "01 01"
            "03 07 00 00 00"    # info_kind=7 (0x2B records)
            "03 00 00 2b 00"    # bufsize=0x002b, index=0
            "03 00 00 00 00"    # buffer_ptr=0
            "83"
        )
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_GET_INFO, 2, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        body = parsed.payload
        reply = body[8:]
        # 0x83 <dword=0>
        self.assertEqual(reply[0], 0x83)
        size = struct.unpack("<I", reply[1:5])[0]
        self.assertEqual(size, 0)
        # 0x87 end-static
        self.assertEqual(reply[5], TAG_END_STATIC)
        # 0x86 dynamic-complete-signal
        self.assertEqual(reply[6], TAG_DYNAMIC_COMPLETE_SIGNAL)


class TestMEDVIEWCacheMissRpcs(unittest.TestCase):
    # Open the rich `msn_today.ttl` fixture (3 topics) so the cache-push
    # tests have a topic mapping to look up against. The TitleOpen spec
    # is `:%d[%s]%d` per `docs/MOSVIEW.md` §5.3 — svcid=2, deid=msn_today,
    # serial=0; ASCIIZ string length 15 → length-prefix byte 0x8F.
    _OPEN_TITLE_REQ = (
        b"\x04\x8f:2[msn_today]0\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x81\x81\x83\x83\x83\x83\x83"
    )

    def _open_title(self, handler):
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_TITLE_OPEN, 1, self._OPEN_TITLE_REQ, 5, 5,
        )
        self.assertIsNotNone(pkts)
        return pkts

    def _subscribe(self, handler, notification_type, request_id):
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            request_id,
            bytes([0x01, notification_type, 0x85]),
            5,
            5,
        )
        self.assertIsNotNone(pkts)
        return pkts

    def test_async_cache_miss_selectors_ack_then_push(self):
        # Selectors 0x06 (ConvertHashToVa) / 0x07 (ConvertTopicToVa) /
        # 0x15 (FetchNearbyTopic) share the ack-only synchronous reply
        # contract per `docs/medview-service-contract.md`. The real
        # answer arrives later through the matching subscription's
        # async push (type-3 op-4 frame for 0x06/0x07; type-0 0xBF
        # chunk for 0x15) — but only when a subscription has been
        # opened. With no subscription state on a fresh handler, the
        # synchronous reply is bare `0x87`.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        for selector in (
            MEDVIEW_SELECTOR_VA_CONVERT_HASH,
            MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
            MEDVIEW_SELECTOR_VA_RESOLVE,
        ):
            pkts = handler.handle_request(0x01, selector, 9, req_payload, 5, 5)
            self.assertIsNotNone(pkts, f"selector 0x{selector:02x} returned None")
            parsed = parse_packet(pkts[0][:-1])
            self.assertTrue(parsed.crc_ok)
            reply = parsed.payload[8:]
            self.assertEqual(reply, bytes([TAG_END_STATIC]),
                             f"selector 0x{selector:02x} ack mismatch")

    def test_async_cache_pushes_match_blackbird_topic_mappings(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._open_title(handler)
        self._subscribe(handler, 3, 2)
        self._subscribe(handler, 0, 3)

        topic1 = next(topic for topic in handler.topics if topic.topic_number == 1)

        hash_req = b"\x01\x01\x03" + struct.pack("<I", topic1.context_hash)
        hash_pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_VA_CONVERT_HASH, 9, hash_req, 5, 5,
        )
        self.assertIsNotNone(hash_pkts)
        self.assertGreaterEqual(len(hash_pkts), 2)
        hash_push = parse_packet(hash_pkts[1][:-1]).payload[8:]
        self.assertEqual(hash_push[0], 0x85)
        self.assertEqual(
            struct.unpack("<HHBBIII", hash_push[1:19]),
            (4, 18, 0x01, 1, topic1.context_hash, 0x1000, 0x1000),
        )

        topic_req = b"\x01\x01\x03" + struct.pack("<I", topic1.topic_number)
        topic_pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_VA_CONVERT_TOPIC, 10, topic_req, 5, 5,
        )
        self.assertIsNotNone(topic_pkts)
        self.assertGreaterEqual(len(topic_pkts), 2)
        topic_push = parse_packet(topic_pkts[1][:-1]).payload[8:]
        self.assertEqual(topic_push[0], 0x85)
        self.assertEqual(
            struct.unpack("<HHBBIII", topic_push[1:19]),
            (4, 18, 0x01, 0, topic1.topic_number, 0x1000, 0x1000),
        )

        # Selector 0x15 (VA_RESOLVE) now pushes a case-1 0xBF text chunk
        # carrying the topic's first authored paragraph + chosen style.
        # See `_PUSH_DISPATCH` in `services/medview.py` — `MEDVIEW_FETCH_NEARBY_TOPIC`
        # bound to `_push_case1_text`. Synthetic title has one paragraph
        # (style_id 0); 4.ttl topics use heuristic style assignment.
        text_req = b"\x01\x01\x03" + struct.pack("<I", topic1.address)
        text_pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_VA_RESOLVE, 11, text_req, 5, 5,
        )
        self.assertIsNotNone(text_pkts)
        self.assertGreaterEqual(len(text_pkts), 2)
        text_push = parse_packet(text_pkts[1][:-1]).payload[8:]
        self.assertEqual(text_push[0], 0x85)
        self.assertEqual(text_push[1], 0xBF)
        self.assertEqual(text_push[2], 0x01)
        self.assertEqual(struct.unpack("<I", text_push[13:17])[0], topic1.address)
        # case-1 dispatch byte at name_buf[0x26] = chunk[0x2A] = push[0x2B]
        self.assertEqual(text_push[1 + 4 + 0x26], 0x01)

    def test_fetch_adjacent_topic_acks_then_pushes_a5_status(self):
        # Spec §0x16 (post-update): selector 0x16 is async-refresh —
        # synchronous reply is just an ack, the actual content arrives
        # via notification type 0. We push a 0xA5 HfcStatusRecord
        # keyed by (title_slot, current_token) so the engine's 30 s
        # wait loop short-circuits via cache match.
        from server.config import (
            MEDVIEW_FETCH_ADJACENT_TOPIC,
            MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
        )
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Open a type-0 subscription so the push has a destination.
        handler.handle_request(
            0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 1, bytes.fromhex("01 00 85"), 5, 5,
        )
        # FetchAdjacentTopic request: title_slot=1, current_token=0,
        # direction=0.
        req_payload = bytes.fromhex("01 01 03 00 00 00 00 01 00")
        pkts = handler.handle_request(
            0x01, MEDVIEW_FETCH_ADJACENT_TOPIC, 11, req_payload, 5, 5,
        )
        self.assertIsNotNone(pkts)
        # Two packets: ack reply + async push frame.
        self.assertGreaterEqual(len(pkts), 2)
        # First packet: bare ack.
        sync_reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(sync_reply, bytes([TAG_END_STATIC]))
        # Second packet: type-0 push carrying 0x85 + 0xA5 record.
        push_payload = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(push_payload[0], 0x85)  # MPCCL chunk tag
        # 0xA5 HfcStatusRecord layout: u8 0xA5, u8 title_byte, u16 status, u32 contents_token
        self.assertEqual(push_payload[1], 0xA5)
        self.assertEqual(push_payload[2], 0x01)  # title_byte = title_slot
        self.assertEqual(struct.unpack("<H", push_payload[3:5])[0], 0)         # status
        self.assertEqual(struct.unpack("<I", push_payload[5:9])[0], 0)         # contents_token

    def test_load_topic_highlights_returns_empty_dynbytes(self):
        # Selector 0x10 (LoadTopicHighlights) returns synchronous
        # `dynbytes` per spec — NOT ack-only like the async-cache trio
        # above. Empty result = 8-byte opaque header + zero highlight
        # count = 12 bytes total. Static section: bare `0x87 0x86`
        # (no leading scalar) so the recv loop knows the dynamic body
        # follows.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC, 9, req_payload, 5, 5,
        )
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        reply = parsed.payload[8:]
        # `0x87 0x86 <12 zero bytes>`
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], TAG_DYNAMIC_COMPLETE_SIGNAL)
        self.assertEqual(reply[2:14], b"\x00" * 12)


class TestMEDVIEWTitlePreNotify(unittest.TestCase):
    def test_pre_notify_reply_ships_status_dword(self):
        # Spec §0x1E (post-update): `PreNotifyTitle` returns
        # `status:i32` = 0 for queued+acked. Wire bytes:
        # 0x83 <dword=0> 0x87.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 0x00, 0x02 0x0a 0x00 (opcode=10), 0x04 with 6 bytes.
        req_payload = bytes.fromhex("01 00 02 0a 00 04 86 00 00 00 00 00 00")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY, 3, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        reply = parsed.payload[8:]
        self.assertEqual(reply[0], 0x83)
        self.assertEqual(struct.unpack("<I", reply[1:5])[0], 0)
        self.assertEqual(reply[5], TAG_END_STATIC)

    def test_opcode_8_heartbeat_returns_status_zero(self):
        # Opcode 0x08 SendClientStatus per spec is the keepalive pulse
        # MVTTL14C fires every >5s while async wait loops are active.
        # Same i32 status reply as any other wire-bound opcode.
        # (Use a small req_id so the VLI-encoded request_id fits in 1
        # byte — the `[8:]` slice assumes that.)
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 0x01, 0x02 0x08 0x00 (opcode=8), 0x04 0x81 0x91 (1-byte heartbeat).
        req_payload = bytes.fromhex("01 01 02 08 00 04 81 91")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY, 7, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply[0], 0x83)
        self.assertEqual(struct.unpack("<I", reply[1:5])[0], 0)
        self.assertEqual(reply[5], TAG_END_STATIC)


class TestMEDVIEWSubscribeNotification(unittest.TestCase):
    def test_subscribe_reply_per_notification_type(self):
        # Wire-observed request: `01 <type> 85` (0x85 = dynamic-recv).
        # All 5 types reply `0x87 0x88` (iterator stream-end).  0x88
        # creates the dynamicReplyState in MPCCL!ProcessTaggedServiceReply,
        # making m_pMoreDatRef non-NULL — the master-flag check at
        # MVTTL14C 0x7E844FA7 (`MOV [ESI+0x44], 0x1` gated on
        # `*[ESI+0x28] != 0` AND HRESULT >= 0) passes for every slot.
        # Using 0x86 instead would fire SignalRequestCompletion which
        # sets request +0x18=1, suppressing ResetEvent in WaitForMessage
        # and causing a ~30%-CPU MsgWaitForSingleObject spin per request.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        for notification_type in range(5):
            req_payload = bytes([0x01, notification_type, 0x85])
            pkts = handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
                notification_type,
                req_payload,
                5,
                5,
            )
            self.assertIsNotNone(pkts)
            parsed = parse_packet(pkts[0][:-1])
            self.assertTrue(parsed.crc_ok)
            reply = parsed.payload[8:]
            self.assertEqual(reply, bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))


class TestMEDVIEWOneway(unittest.TestCase):
    def test_oneway_continuation_returns_none(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # class=0xE6 → one-way continuation, no reply expected.
        pkt = handler.handle_request(0xE6, 0x01, 0, b"\x00" * 16, 5, 5)
        self.assertIsNone(pkt)


class TestMEDVIEWTitleService(unittest.TestCase):
    """Spec class TitleService — selectors 0x00, 0x02, 0x04 (excludes
    0x01 OpenTitle and 0x03 GetTitleInfoRemote, which have dedicated
    test classes above)."""

    def _open_title(self, handler):
        # Drives the handler through a successful OpenTitle so the slot
        # is registered for ValidateTitle / CloseTitle assertions. Use
        # the rich `msn_today` fixture so the handler caches non-empty
        # topics — `test_close_title_drops_per_title_state` checks that
        # CloseTitle then clears them.
        req = (
            b"\x04\x8f:2[msn_today]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        from server.config import MEDVIEW_OPEN_TITLE
        handler.handle_request(0x01, MEDVIEW_OPEN_TITLE, 1, req, 5, 5)

    def test_validate_title_returns_zero_when_no_title_open(self):
        from server.config import MEDVIEW_VALIDATE_TITLE
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 81")
        pkts = handler.handle_request(0x01, MEDVIEW_VALIDATE_TITLE, 1, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x81 <byte=0> 0x87
        self.assertEqual(reply, bytes([0x81, 0x00, TAG_END_STATIC]))

    def test_validate_title_returns_nonzero_after_open(self):
        from server.config import MEDVIEW_VALIDATE_TITLE
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._open_title(handler)
        req_payload = bytes.fromhex("01 01 81")
        pkts = handler.handle_request(0x01, MEDVIEW_VALIDATE_TITLE, 2, req_payload, 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x01)  # is_valid != 0
        self.assertEqual(reply[2], TAG_END_STATIC)

    def test_close_title_acks(self):
        from server.config import MEDVIEW_CLOSE_TITLE
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._open_title(handler)
        req_payload = bytes.fromhex("01 01")
        pkts = handler.handle_request(0x01, MEDVIEW_CLOSE_TITLE, 3, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_close_title_drops_per_title_state(self):
        from server.config import MEDVIEW_CLOSE_TITLE
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._open_title(handler)
        self.assertGreater(len(handler.topics), 0)
        req_payload = bytes.fromhex("01 01")
        handler.handle_request(0x01, MEDVIEW_CLOSE_TITLE, 3, req_payload, 5, 5)
        self.assertEqual(handler.topics, ())
        self.assertEqual(handler.title_caption, "")

    def test_query_topics_returns_empty_session(self):
        from server.config import MEDVIEW_QUERY_TOPICS
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Minimal request: titleSlot, queryClass, primaryText, queryFlags=0,
        # queryMode. We only care that the handler survives and emits the
        # documented static fields.
        req_payload = bytes.fromhex("01 01") + bytes.fromhex("02 00 00") + b"\x04\x82query\x00" + bytes.fromhex("01 00") + bytes.fromhex("02 00 00")
        pkts = handler.handle_request(0x01, MEDVIEW_QUERY_TOPICS, 4, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x81 <highlightContext=0> 0x83 <logicalCount=0> 0x83 <secondary=0> 0x87 0x86
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], 0x83)
        self.assertEqual(struct.unpack("<I", reply[3:7])[0], 0)
        self.assertEqual(reply[7], 0x83)
        self.assertEqual(struct.unpack("<I", reply[8:12])[0], 0)
        self.assertEqual(reply[12], TAG_END_STATIC)
        self.assertEqual(reply[13], TAG_DYNAMIC_COMPLETE_SIGNAL)


class TestMEDVIEWWordWheelService(unittest.TestCase):
    """Spec class WordWheelService — selectors 0x08–0x0F. No word wheel
    is synthesized today; replies are empty/zero-result shapes that
    let the wrapper's recv loop decode cleanly."""

    def test_open_word_wheel_empty_session(self):
        from server.config import MEDVIEW_OPEN_WORD_WHEEL
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01") + b"\x04\x82wheel\x00" + bytes.fromhex("81 83")
        pkts = handler.handle_request(0x01, MEDVIEW_OPEN_WORD_WHEEL, 1, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x81 <wheel_id=0> 0x83 <count=0> 0x87
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], 0x83)
        self.assertEqual(struct.unpack("<I", reply[3:7])[0], 0)
        self.assertEqual(reply[7], TAG_END_STATIC)

    def test_query_word_wheel_zero_status(self):
        from server.config import MEDVIEW_QUERY_WORD_WHEEL
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 02 00 00") + b"\x04\x81q\x00" + bytes.fromhex("82")
        pkts = handler.handle_request(0x01, MEDVIEW_QUERY_WORD_WHEEL, 1, req_payload, 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x82 <word=0> 0x87
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)
        self.assertEqual(reply[3], TAG_END_STATIC)

    def test_close_word_wheel_acks(self):
        from server.config import MEDVIEW_CLOSE_WORD_WHEEL
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, MEDVIEW_CLOSE_WORD_WHEEL, 1, bytes.fromhex("01 00"), 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_count_key_matches_zero(self):
        from server.config import MEDVIEW_COUNT_KEY_MATCHES
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 00") + b"\x04\x81k\x00" + bytes.fromhex("82")
        pkts = handler.handle_request(0x01, MEDVIEW_COUNT_KEY_MATCHES, 1, req_payload, 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)


class TestMEDVIEWAddressHighlightService(unittest.TestCase):
    """Spec class AddressHighlightService — selectors 0x05, 0x11, 0x12,
    0x13 (excludes 0x06/0x07 cache-miss async + 0x10 highlight blob,
    covered above)."""

    def test_convert_address_to_va_acks_then_pushes(self):
        from server.config import MEDVIEW_CONVERT_ADDRESS_TO_VA
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        pkts = handler.handle_request(0x01, MEDVIEW_CONVERT_ADDRESS_TO_VA, 1, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_find_highlight_address_zero(self):
        from server.config import MEDVIEW_FIND_HIGHLIGHT_ADDRESS
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 00 03 11 11 11 11 03 22 22 22 22")
        pkts = handler.handle_request(0x01, MEDVIEW_FIND_HIGHLIGHT_ADDRESS, 1, req_payload, 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply[0], 0x83)
        self.assertEqual(struct.unpack("<I", reply[1:5])[0], 0)
        self.assertEqual(reply[5], TAG_END_STATIC)

    def test_release_highlight_context_acks(self):
        from server.config import MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT, 1, bytes.fromhex("01 01"), 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_refresh_highlight_address_acks(self):
        from server.config import MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 03 01 00 00 00")
        pkts = handler.handle_request(0x01, MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS, 1, req_payload, 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))


class TestMEDVIEWSessionService(unittest.TestCase):
    """Spec class SessionService — selectors 0x17, 0x18, 0x1F. The
    existing TestMEDVIEWHandshake / TestMEDVIEWSubscribeNotification
    cover 0x1F and 0x17; this class covers the new 0x18."""

    def test_unsubscribe_acks_and_drops_state(self):
        from server.config import (
            MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
            MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS,
        )
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # First subscribe to type 0 so there's state to drop.
        sub_payload = bytes.fromhex("01 00 85")
        handler.handle_request(0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 1, sub_payload, 5, 5)
        self.assertIn(0, handler._subscriptions)
        # Then unsubscribe.
        unsub_payload = bytes.fromhex("01 00")
        pkts = handler.handle_request(0x01, MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS, 2, unsub_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))
        self.assertNotIn(0, handler._subscriptions)


class TestMEDVIEWRemoteFsError(unittest.TestCase):
    """Spec selector 0x1D GetRemoteFsError — synchronous u16."""

    def test_get_remote_fs_error_returns_zero(self):
        from server.config import MEDVIEW_GET_REMOTE_FS_ERROR
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, MEDVIEW_GET_REMOTE_FS_ERROR, 1, bytes.fromhex("82"), 5, 5)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x82 <word=0> 0x87
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)
        self.assertEqual(reply[3], TAG_END_STATIC)


class TestMEDVIEWBaggageBm0(unittest.TestCase):
    """bm0 baggage delivery — small kind=5 raster for the bitmap probe.

    See `docs/MEDVIEW.md` §10 for the paint-loop trace and §6c for the
    baggage selector wire layout. The container is now a 64×64 24bpp
    raster (12331 B total) with an empty trailer — produced by
    `src.server.blackbird.wire.build_baggage_container` over a
    `build_kind5_raster` body. These tests pin the open-size
    declaration and the structural shape (preamble, kind byte, pixel
    data dimensions) without freezing the entire payload byte sequence.
    """

    _BM0_PREAMBLE_LEN = 8        # container header
    _BM0_KIND5_HEADER_LEN = 28
    _BM0_PIXEL_BYTES = 12288     # 64×64 24bpp packed
    _BM0_TRAILER_LEN = 7         # empty trailer = 1B reserved + 2B count + 4B size
    _BM0_CONTAINER_LEN = (
        _BM0_PREAMBLE_LEN + _BM0_KIND5_HEADER_LEN
        + _BM0_PIXEL_BYTES + _BM0_TRAILER_LEN
    )
    _OPEN_REQ = bytes.fromhex("01 01 04 84 62 6d 30 00 01 02 81 83")  # bm0 retry form

    def _decode_reply(self, selector, req_id, payload):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, selector, req_id, payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # header(1) + size(2) + routing(2) + class(1) + selector(1) + vli(1) = 8
        return parsed.payload[8:]

    def test_hfs_open_bm0_declares_container_size(self):
        # 0x87 end-static, 0x81 <handle=0x42>, 0x83 <size=12331>
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_OPEN, 11, self._OPEN_REQ)
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], 0x81)
        self.assertEqual(reply[2], 0x42)
        self.assertEqual(reply[3], 0x83)
        size = struct.unpack("<I", reply[4:8])[0]
        self.assertEqual(size, self._BM0_CONTAINER_LEN)

    def test_hfs_read_bm0_kind_byte_passes_parser_gate(self):
        # Read first 64 bytes — covers preamble + kind5 header. Bitmap
        # starts at offset 8; first byte must be 5 to clear
        # FUN_7e887a40's `kind < 5` gate.
        read_req = bytes.fromhex("01 42 03 40 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 12, read_req)
        # 0x81 <status=0> 0x87 0x86 <chunk>
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], TAG_END_STATIC)
        self.assertEqual(reply[3], TAG_DYNAMIC_COMPLETE_SIGNAL)
        chunk = reply[4 : 4 + 64]
        self.assertEqual(chunk[8], 0x05)  # kind byte at bitmap-header offset 0

    def test_hfs_read_bm0_preamble_and_header_byte_sequence(self):
        # Pin the preamble + 30-byte kind=5 header so the layout encoder
        # in `blackbird.wire` can't drift unchecked. Pixel content (900KB)
        # not byte-pinned — covered structurally by the kind5_raster
        # tests in `test_blackbird_wire.TestKind5Raster`.
        read_req = bytes.fromhex("01 42 03 24 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 12, read_req)
        chunk = reply[4 : 4 + 36]
        expected_header = bytes.fromhex(
            "00 00"                  # container reserved
            "01 00"                  # bitmap count = 1
            "08 00 00 00"            # offset to bitmap[0]
            "05 00"                  # kind=5, compression=raw
            "00 00 00 00"            # 2x skip-int (narrow form)
            "02 30"                  # byte-narrow varints: planes=1, bpp=24
            "80 00 80 00"            # ushort-narrow: width=64, height=64
            "00 00 00 00"            # palette_count=0, reserved=0
            "0060"                    # ushort-narrow pixel_byte_count = 12288
            "0e 00"                  # ushort-narrow trailer_size = 7
            "1c 00 00 00"            # pixel_data_offset = 28
            "1c 30 00 00"            # trailer_offset = 28 + 12288 = 12316
        )
        self.assertEqual(chunk, expected_header)

    def test_hfs_read_bm0_pixel_data_is_solid_white(self):
        # Read 27 bytes from offset 36 (start of pixel data). Bm0 ships
        # a solid-white 24bpp raster as the neutral backdrop until
        # authored CBFrame bitmap lowering exists.
        read_req = bytes.fromhex("01 42 03 1b 00 00 00 03 24 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 13, read_req)
        chunk = reply[4 : 4 + 27]
        self.assertEqual(chunk, b"\xFF" * 27)

    def test_hfs_read_bm0_full_request_is_pipe_safe(self):
        read_req = (
            b"\x01\x42"
            + b"\x03" + struct.pack("<I", self._BM0_CONTAINER_LEN)
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x85"
        )
        handler = MEDVIEWHandler(5, "MEDVIEW")
        reply = handler._handle_read_remote_hfs_file(12, read_req)
        self.assertEqual(reply[:4], bytes([0x81, 0x00, TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]))
        self.assertEqual(len(reply) - 4, self._BM0_CONTAINER_LEN)

        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_HFS_READ, 12, read_req, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertGreater(len(pkts), 1)
        self.assertTrue(all(len(pkt) <= 1024 for pkt in pkts))

    def test_hfs_read_bm0_trailer_is_empty(self):
        # Trailer at container offset 8 + 28 + 12288 = 12324. Read 7 B.
        # Layout: 1B reserved=0, 2B count=0, 4B tail_size=0.
        read_req = bytes.fromhex("01 42 03 07 00 00 00 03 24 30 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 14, read_req)
        chunk = reply[4 : 4 + 7]
        self.assertEqual(chunk, b"\x00" * 7)


if __name__ == "__main__":
    unittest.main()
