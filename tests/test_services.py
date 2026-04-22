"""Tests for LOGSRV and DIRSRV service payload builders."""

import struct
import unittest

from server.config import (
    DIRSRV_INTERFACE_GUIDS,
    LOGSRV_INTERFACE_GUIDS,
    MEDVIEW_INTERFACE_GUIDS,
    MEDVIEW_SELECTOR_HANDSHAKE,
    MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
    MEDVIEW_SELECTOR_TITLE_GET_INFO,
    MEDVIEW_SELECTOR_TITLE_OPEN,
    MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
    OLREGSRV_INTERFACE_GUIDS,
    PIPE_ALWAYS_SET,
    PIPE_CONTINUATION,
    PIPE_LAST_DATA,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
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
    SUPPORTED_BROWSE_LCIDS,
    build_dirsrv_reply_payload,
    build_dirsrv_service_map_payload,
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


class TestDIRSRVReply(unittest.TestCase):
    def test_self_properties(self):
        request = DirsrvRequest(
            dword_0=0,
            dword_1=1,
            prop_group="q",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        # Should start with two 0x83 dwords
        self.assertEqual(payload[0], 0x83)
        status = struct.unpack("<I", payload[1:5])[0]
        self.assertEqual(status, 0)
        self.assertEqual(payload[5], 0x83)
        # Then 0x87 end, then 0x88 dynamic
        self.assertIn(0x87, payload)
        self.assertIn(0x88, payload)

    def test_children_contains_msn_root(self):
        request = DirsrvRequest(
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(b"The Microsoft Network", payload)
        self.assertIn(struct.pack("<II", 1, 0), payload)

    def test_root_properties_alias_to_special_msn_root(self):
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(b"The Microsoft Network", payload)
        self.assertIn(struct.pack("<II", 1, 0), payload)

    def test_special_msn_today_node_returns_title(self):
        request = DirsrvRequest(
            node_id="4:0",
            node_id_raw=struct.pack("<II", 4, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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

    def test_msn_root_children_emit_category_nodes(self):
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(struct.pack("<II", 0x44000E, 0), payload)
        self.assertIn(struct.pack("<II", 0x44000F, 0), payload)
        self.assertIn(b"The News", payload)
        self.assertIn(b"Entertainment", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)
        self.assertNotIn(struct.pack("<II", 1, 1), payload)

    def test_narrow_root_children_request_returns_category_nodes(self):
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(struct.pack("<II", 0x44000E, 0), payload)
        self.assertIn(b"The News", payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)
        self.assertNotIn(struct.pack("<II", 1, 1), payload)

        request = DirsrvRequest(
            node_id="1:1",
            node_id_raw=struct.pack("<II", 1, 1),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(struct.pack("<II", 0x44000E, 0), payload)
        self.assertIn(b"The News", payload)

        for node_id, raw in (
            ("3:1", struct.pack("<II", 3, 1)),
            ("4456462:0", struct.pack("<II", 0x44000E, 0)),
        ):
            request = DirsrvRequest(
                node_id=node_id,
                node_id_raw=raw,
                dword_0=1,
                dword_1=14,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_dirsrv_reply_payload(request)
            if node_id == "3:1":
                self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)
            else:
                self.assertNotIn(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF), payload)

    def test_startup_browse_walk_for_msn_root_omits_menu_aliases(self):
        request = DirsrvRequest(
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertNotIn(struct.pack("<II", 1, 0), payload)
        self.assertNotIn(struct.pack("<II", 4, 0), payload)
        self.assertNotIn(struct.pack("<II", 3, 1), payload)
        self.assertNotIn(struct.pack("<II", 1, 1), payload)
        self.assertIn(struct.pack("<II", 0x44000E, 0), payload)
        self.assertIn(struct.pack("<II", 0x44000F, 0), payload)

    def test_special_menu_mnid_aliases_resolve_to_named_nodes(self):
        for node_id, raw, expected_name in (
            ("1:1", struct.pack("<II", 1, 1), b"Member Assistance"),
        ):
            request = DirsrvRequest(
                node_id=node_id,
                node_id_raw=raw,
                dword_0=0,
                dword_1=1,
                prop_group="a\x00e",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_dirsrv_reply_payload(request)
            self.assertIn(expected_name, payload)

    def test_member_assistance_children_return_category_nodes(self):
        request = DirsrvRequest(
            node_id="1:1",
            node_id_raw=struct.pack("<II", 1, 1),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(b"The News", payload)
        self.assertIn(b"Entertainment", payload)

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
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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
        payload = build_dirsrv_reply_payload(request)
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
            payload = build_dirsrv_reply_payload(request)
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
        addrbar_payload = build_dirsrv_reply_payload(addrbar_request)
        self.assertIn(b"The Microsoft Network", addrbar_payload)
        for lcid in SUPPORTED_BROWSE_LCIDS:
            self.assertNotIn(
                b"\x04q\x00" + struct.pack("<II", 0, lcid), addrbar_payload
            )


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

        shabby_id = shabby_mod.pack_shabby_id(shabby_mod.FORMAT_ICO, 1)
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
    # serial=0.  `_title_name_from_spec` extracts "4", the handler then
    # reads `resources/titles/4.ttl` and pulls CTitle.name ("MSN Today")
    # via the TTL parser (see src/server/services/ttl.py and docs/BLACKBIRD.md §3).
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

    def test_title_open_reply_has_static_plus_dynamic(self):
        reply = self._decode_reply(self._MSN_TODAY_REQ)
        # Must start with 0x81 (title_id byte), nonzero value.
        self.assertEqual(reply[0], 0x81)
        self.assertNotEqual(reply[1], 0)  # title_id must be nonzero!
        # Second byte: 0x81 service_byte
        self.assertEqual(reply[2], 0x81)
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

    def test_title_open_body_is_nine_section_with_msn_today_label(self):
        # After 2×0x81 + 5×0x83 static + 0x87 + 0x86 the dynamic body runs
        # to end-of-frame.  For MSN Today (deid="4") the synthesized body
        # places "MSN Today\0" in section 4 (the raw-blob the title-name
        # query at MOSVIEW!0x7F3C6575 actually reads via info_kind=1).
        reply = self._decode_reply(self._MSN_TODAY_REQ)
        # Static prefix: 2×2 (tagged bytes) + 5×5 (tagged dwords) + 1 (0x87)
        # + 1 (0x86) = 31 bytes before the dynamic payload.
        body = reply[31:]
        self.assertEqual(body[:8], b"\x00\x00" * 4)      # Sections 0-3 empty
        self.assertEqual(body[8:10], b"\x0a\x00")        # Section 4 size=10
        self.assertEqual(body[10:20], b"MSN Today\x00")  # Section 4 data
        self.assertEqual(body[20:26], b"\x00\x00" * 3)   # Sections 5-7 empty
        self.assertEqual(body[26:28], b"\x00\x00")       # Section 8 count=0
        self.assertEqual(len(body), 28)

    def test_title_open_body_falls_back_to_deid_for_unknown(self):
        # deid "42" isn't in _TITLE_NAMES — the handler synthesizes
        # "Title 42\0" so the viewer still shows something informative
        # instead of "Unknown Title Name".
        req = (
            b"\x04\x88:2[42]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        reply = self._decode_reply(req)
        body = reply[31:]
        self.assertEqual(body[:8], b"\x00\x00" * 4)
        self.assertEqual(body[8:10], b"\x09\x00")        # "Title 42\0" = 9 bytes
        self.assertEqual(body[10:19], b"Title 42\x00")
        self.assertEqual(body[19:25], b"\x00\x00" * 3)
        self.assertEqual(body[25:27], b"\x00\x00")


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


class TestMEDVIEWTitlePreNotify(unittest.TestCase):
    def test_pre_notify_reply_is_end_static_only(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 0x00, 0x02 0x0a 0x00 (opcode=10), 0x04 with 6 bytes.
        req_payload = bytes.fromhex("01 00 02 0a 00 04 86 00 00 00 00 00 00")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY, 3, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        body = parsed.payload
        reply = body[8:]
        # Single 0x87 end-static, nothing else.
        self.assertEqual(reply, bytes([TAG_END_STATIC]))


class TestMEDVIEWSubscribeNotification(unittest.TestCase):
    def test_subscribe_reply_is_end_static_only(self):
        # Each of the 5 subscribers hrAttachToService allocates calls
        # selector 0x17 with `01 <type> 88`: tagged byte (the
        # notification-type index) + one recv descriptor for the async
        # handle.  Server declines with static-only so slot 0x48 on the
        # client reads *ppvVar1 == NULL and the subscribe is skipped.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        for notification_type in range(5):
            req_payload = bytes([0x01, notification_type, 0x88])
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
            self.assertEqual(reply, bytes([TAG_END_STATIC]))


class TestMEDVIEWOneway(unittest.TestCase):
    def test_oneway_continuation_returns_none(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # class=0xE6 → one-way continuation, no reply expected.
        pkt = handler.handle_request(0xE6, 0x01, 0, b"\x00" * 16, 5, 5)
        self.assertIsNone(pkt)


if __name__ == "__main__":
    unittest.main()
