"""Tests for LOGSRV and DIRSRV service payload builders."""

import struct
import unittest
from dataclasses import replace
from unittest.mock import patch

from server.config import (
    CONFLOC_INTERFACE_GUIDS,
    CONFSRV_INTERFACE_GUIDS,
    DIRSRV_INTERFACE_GUIDS,
    LOGSRV_INTERFACE_GUIDS,
    MEDVIEW_DATA_EDIT_ADD,
    MEDVIEW_DATA_EDIT_CLASS,
    MEDVIEW_DATA_EDIT_DELETE,
    MEDVIEW_DATA_EDIT_GET_TICKET,
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
    SASRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_PARTIAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.models import DirsrvRequest, DwordParam, EndMarker, VarParam
from server.mpc import (
    _build_continuation_frame,
    build_host_block,
    build_service_packet,
    build_tagged_reply_var,
    parse_host_block,
    parse_tagged_params,
)
from server.services.conference import (
    CONFLOC_DATA_EDIT_ADD,
    CONFLOC_DATA_EDIT_CLASS,
    CONFLOC_DATA_EDIT_DELETE,
    CONFLOC_DATA_EDIT_GET_PROPERTIES,
    CONFLOC_DATA_EDIT_GET_TICKET,
    CONFLOC_DATA_EDIT_SET_PROPERTIES,
    CONFLOC_RESULT_FOUND,
    CONFLOC_RESULT_NOT_FOUND,
    CONFSRV_EVENT_PARTICIPANTS,
    CONFSRV_EVENT_TEXT,
    CONFSRV_JOINED,
    CONFSRV_ROLE_HOST,
    CONFSRV_ROLE_PARTICIPANT,
    CONFSRV_ROLE_SPECTATOR,
    CONFSRV_ROOM_FULL,
    CONFSRV_SELECTOR_JOIN,
    CONFSRV_SELECTOR_SEND,
    CONFLOCHandler,
    CONFSRVHandler,
)
from server.services.dirsrv import (
    DS_E_NOT_FOUND,
    ENUM_SHN_KEY_ICONS,
    SUPPORTED_BROWSE_LCIDS,
    DIRSRVHandler,
    build_add_node_reply_payload,
    build_delete_node_reply_payload,
    build_dirsrv_service_map_payload,
    build_enum_shn_reply_payload,
    build_get_children_reply_payload,
    build_get_datasets_reply_payload,
    build_get_deid_from_go_word_reply_payload,
    build_get_properties_reply_payload,
    build_get_ticket_reply_payload,
    build_property_record,
    build_props,
    build_set_properties_reply_payload,
)
from server.services.ftm import (
    FTM_BBS_SOURCE,
    FTM_BBS_UNPACK_METHOD,
    FTM_CLIENT_FILE_ID_SIZE,
    FTM_COUNTER_OFFSET,
    FTM_FALLBACK_FILENAME,
    FTMHandler,
    _build_bill_client_reply,
    _build_request_download_reply,
    _resolve_ftm_target,
)
from server.services.logsrv import (
    LOGIN_BLOB_LEN,
    LOGIN_BLOB_MEMBER_ID_OFFSET,
    LOGIN_BLOB_PASSWORD_OFFSET,
    LOGIN_RESULT_BAD_MEMBER_ID,
    LOGIN_RESULT_BAD_PASSWORD,
    LOGSRVHandler,
    _handle_billing_query,
    _handle_login,
    _handle_password_change,
    build_logsrv_bootstrap_payload,
    build_logsrv_service_map_payload,
)
from server.services.medview import MEDVIEWHandler
from server.services.medview.payload import BM0_BAGGAGE
from server.services.olregsrv import (
    OLREGSRVHandler,
    build_olregsrv_service_map_payload,
)
from server.services.sasrv import (
    SA_E_BAD_LIST_KIND,
    SASRV_TOKENS,
    SASRVHandler,
    build_sasrv_service_map_payload,
)
from server.session import Session
from server.store import (
    RIGHTS_AUTHORING,
    ConferenceFields,
    app_store,
    default_seed,
    reset_app_store,
)
from server.transport import parse_packet
from server.wire import decode_header_byte

from .support import (
    ADMIN,
    ADMIN_PASSWORD,
    SUBSCRIBER,
    SUBSCRIBER_PASSWORD,
    signed_in,
)


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


def _login_blob(member_id, password):
    """The credential blob GUIDE.EXE!VerifyAccountViaLogSrv @ 0x04304024 builds."""
    blob = bytearray(LOGIN_BLOB_LEN)
    blob[LOGIN_BLOB_MEMBER_ID_OFFSET : LOGIN_BLOB_MEMBER_ID_OFFSET + len(member_id)] = (
        member_id.encode("ascii")
    )
    blob[LOGIN_BLOB_PASSWORD_OFFSET : LOGIN_BLOB_PASSWORD_OFFSET + len(password)] = password.encode(
        "ascii"
    )
    return bytes(blob)


def _login_request(member_id=ADMIN, password=ADMIN_PASSWORD):
    """A whole selector 0x00 request: version dword, blob, recv descriptors."""
    return (
        b"\x03"
        + struct.pack("<I", 0x001643)
        + build_tagged_reply_var(0x04, _login_blob(member_id, password))
        + b"\x83" * 7
        + b"\x84"
    )


# Every result `VerifyAccountViaLogSrv` @ GUIDE.EXE 0x04304024 gives its own
# dialog. Anything outside this set falls to the catch-all, string 0x2F5
# "Password not valid.", which is why the bad-password reply must stay unmapped.
_LOGIN_RESULTS_THE_CLIENT_MAPS = frozenset(
    {0x00, 0x0C, 0x01, 0x02, 0x0A, 0x0D, 0x16, 0x22, 0x23, 0x24}
)


class TestLOGSRVLogin(unittest.TestCase):
    """Selector 0x00 checks the blob against the store and signs the session in."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def _login(self, session, member_id, password):
        reply = _handle_login(_login_request(member_id, password), session)
        return struct.unpack_from("<I", reply, 1)[0]

    def test_matching_credentials_sign_the_connection_in(self):
        session = Session()
        self.assertEqual(self._login(session, ADMIN, ADMIN_PASSWORD), 0)
        self.assertTrue(session.is_authenticated)
        self.assertEqual(session.user.display_name, "Bill Gates")

    def test_a_wrong_password_names_the_password(self):
        # An unmapped result is the client's catch-all, which is string 0x2F5
        # "Password not valid. Please type it again."
        session = Session()
        self.assertEqual(
            self._login(session, ADMIN, SUBSCRIBER_PASSWORD), LOGIN_RESULT_BAD_PASSWORD
        )
        self.assertNotIn(LOGIN_RESULT_BAD_PASSWORD, _LOGIN_RESULTS_THE_CLIENT_MAPS)
        self.assertFalse(session.is_authenticated)

    def test_an_unknown_member_id_names_the_member_id(self):
        # 2 is string 0x2FC "This member ID is not valid."
        session = Session()
        self.assertEqual(self._login(session, "nobody", ADMIN_PASSWORD), LOGIN_RESULT_BAD_MEMBER_ID)
        self.assertFalse(session.is_authenticated)

    def test_a_known_member_id_is_not_reported_as_unknown(self):
        # The two failures are distinguishable, so a typo'd password must not
        # tell the member their id is wrong.
        session = Session()
        self.assertNotEqual(
            self._login(session, ADMIN, SUBSCRIBER_PASSWORD), LOGIN_RESULT_BAD_MEMBER_ID
        )

    def test_a_request_without_the_blob_is_rejected(self):
        session = Session()
        result = struct.unpack_from("<I", _handle_login(b"", session), 1)[0]
        self.assertEqual(result, LOGIN_RESULT_BAD_MEMBER_ID)
        self.assertFalse(session.is_authenticated)

    def test_the_reply_shape_is_the_same_whether_accepted_or_rejected(self):
        # The client unmarshals seven dwords and a 16-byte variable either way;
        # only the first dword differs.
        accepted = _handle_login(_login_request(), Session())
        rejected = _handle_login(b"", Session())
        self.assertEqual(len(accepted), len(rejected))
        self.assertEqual(accepted[5:], rejected[5:])


class TestLOGSRVPasswordChange(unittest.TestCase):
    """Selector 0x01 commits only against the account that signed in."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    @staticmethod
    def _request(old, new):
        return (
            build_tagged_reply_var(0x04, old.encode() + b"\x00" * (17 - len(old)))
            + build_tagged_reply_var(0x04, new.encode() + b"\x00" * (17 - len(new)))
            + b"\x83"
        )

    def test_the_right_current_password_commits_the_new_one(self):
        session = signed_in()
        reply = _handle_password_change(self._request(ADMIN_PASSWORD, "newpass"), session)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, "newpass"))
        self.assertEqual(session.user.password, "newpass")

    def test_a_wrong_current_password_changes_nothing(self):
        reply = _handle_password_change(self._request("guess", "newpass"), signed_in())
        self.assertNotEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))

    def test_an_anonymous_connection_cannot_change_a_password(self):
        reply = _handle_password_change(self._request(ADMIN_PASSWORD, "newpass"), Session())
        self.assertNotEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))


class TestLOGSRVBillingQuery(unittest.TestCase):
    """Selector 0x0A describes the account the connection signed in as."""

    def _buffer(self, session):
        payload = _handle_billing_query(session)
        return parse_tagged_params(payload)[0].data

    def test_each_account_gets_its_own_address_and_card(self):
        admin = self._buffer(signed_in(ADMIN))
        subscriber = self._buffer(signed_in(SUBSCRIBER))

        self.assertIn(b"Gates\x00", admin)
        self.assertIn(b"Redmond\x00", admin)
        self.assertNotIn(b"Gates\x00", subscriber)
        self.assertIn(b"Jobs\x00", subscriber)
        self.assertIn(b"Cupertino\x00", subscriber)

    def test_the_buffer_is_always_the_full_0x41c_bytes(self):
        for session in (signed_in(ADMIN), Session()):
            with self.subTest(user=session.user.username or "anonymous"):
                self.assertEqual(len(self._buffer(session)), 0x41C)


class TestLOGSRVReply(unittest.TestCase):
    def test_login_reply_returns_packet(self):
        handler = LOGSRVHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x00, 0, _login_request(), 4, 4)
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
        handler = LOGSRVHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x00, 0, _login_request(), 4, 4)
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


class TestConferenceStartup(unittest.TestCase):
    def test_discovery_catalogs_match_confapi_tables(self):
        self.assertEqual(
            [guid[0] for guid, _selector in CONFLOC_INTERFACE_GUIDS],
            [
                0x52,
                0x53,
                0x54,
                0x55,
                0x56,
                0x57,
                0x58,
                0x60,
                0x61,
                0x70,
                0x71,
                0x72,
                0x73,
                0x74,
                0x78,
                0x79,
                0x81,
            ],
        )
        self.assertEqual(
            [guid[0] for guid, _selector in CONFSRV_INTERFACE_GUIDS],
            [0xC8, 0xC9, 0xCA],
        )
        self.assertEqual(
            [selector for _guid, selector in CONFLOC_INTERFACE_GUIDS],
            list(range(1, 18)),
        )

    def test_locator_resolves_a_created_chat_node(self):
        store = _AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="1:275",
            is_container=True,
            app_id=4,
            mnid_a=struct.pack("<II", 1, 275),
            content=parent.content,
        )
        store.add_child("1:16", chat)
        handler = CONFLOCHandler(10, "CONFLOC", content_store=store)

        reply = handler.build_locate_reply_payload(b"\x03" + struct.pack("<I", 1) + b"\x82\x82")

        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 1)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_FOUND)
        self.assertEqual(reply[6], TAG_END_STATIC)

    def test_locator_resolves_the_default_chat_room(self):
        reset_app_store()
        room = app_store.content.get_node("1:271")
        self.assertEqual(room.content.name, "MSN Chat")
        self.assertEqual(room.app_id, 4)
        self.assertEqual(room.content.conference.room_capacity, 10)
        self.assertEqual(room.content.conference.message_length, 1000)
        self.assertTrue(room.content.conference.join_as_participants)
        self.assertEqual(room.host_usernames, ("billg",))
        self.assertIn(
            room,
            app_store.content.get_children("1:16", struct.pack("<II", 1, 0x0409)),
        )

        handler = CONFLOCHandler(10, "CONFLOC")
        reply = handler.build_locate_reply_payload(
            b"\x03" + struct.pack("<I", 1) + b"\x82\x82"
        )

        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 1)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_FOUND)

    def test_data_edit_get_ticket_returns_the_capability_blob(self):
        handler = CONFLOCHandler(10, "CONFLOC", signed_in())
        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_GET_TICKET,
            0,
            b"\x83\x85",
            0,
            0,
        )
        parsed = parse_packet(packets[0][:-1])
        self.assertEqual(parsed.payload[8:], build_get_ticket_reply_payload(handler.session))

    def test_data_edit_add_completes_the_chat_record(self):
        handler = CONFLOCHandler(10, "CONFLOC", signed_in())
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = struct.pack("<IH", 6, 0)
        request = (
            b"\x04\x82" + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\xff\xff"
            + b"\x04\x86" + properties
            + b"\x83\x83"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_ADD,
            1,
            request,
            0,
            0,
        )
        parsed = parse_packet(packets[0][:-1])

        self.assertEqual(
            parsed.payload[8:],
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )

    def test_data_edit_delete_completes_after_tree_delete(self):
        record_id = struct.pack("<II", 1, 271)
        request = (
            b"\x04\x82\x02\x00"
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\xff\xff"
            + b"\x83\x83"
        )
        # TREEEDCL removes the directory node before DATAEDCL reaches CONFLOC.
        handler = CONFLOCHandler(
            10,
            "CONFLOC",
            signed_in(),
            content_store=_AddNodeContentStore(),
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_DELETE,
            1,
            request,
            0,
            0,
        )

        parsed = parse_packet(packets[0][:-1])
        self.assertEqual(
            parsed.payload[8:],
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )

    def test_data_edit_get_properties_round_trips_the_authored_record(self):
        handler = CONFLOCHandler(10, "CONFLOC", signed_in())
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = build_property_record(
            [
                (0x03, "ds", struct.pack("<I", 1)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "mm", struct.pack("<I", 100)),
                (0x03, "unrequested", struct.pack("<I", 42)),
            ]
        )
        add_request = (
            b"\x04\x82" + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\xff\xff"
            + b"\x04" + bytes([0x80 | len(properties)]) + properties
            + b"\x83\x83"
        )
        handler.build_data_edit_add_reply_payload(1, add_request)
        get_request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89ds\x00ml\x00mm\x00"
            + b"\x83\x83\x85"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_GET_PROPERTIES,
            2,
            get_request,
            0,
            0,
        )
        parsed = parse_packet(packets[0][:-1])
        selected = build_property_record(
            [
                (0x03, "ds", struct.pack("<I", 1)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "mm", struct.pack("<I", 100)),
            ]
        )

        self.assertEqual(
            parsed.payload[8:],
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_seeded_chat_exposes_its_conference_settings(self):
        reset_app_store()
        handler = CONFLOCHandler(10, "CONFLOC", signed_in())
        record_id = struct.pack("<II", 1, 0x10F)
        request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89mm\x00ml\x00ds\x00"
            + b"\x83\x83\x85"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_GET_PROPERTIES,
            2,
            request,
            0,
            0,
        )
        parsed = parse_packet(packets[0][:-1])
        selected = build_property_record(
            [
                (0x03, "mm", struct.pack("<I", 10)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "ds", struct.pack("<I", 1)),
            ]
        )

        self.assertEqual(
            parsed.payload[8:],
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_data_edit_set_properties_applies_the_conversation_values(self):
        store = _AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="1:275",
            is_container=True,
            app_id=4,
            mnid_a=struct.pack("<II", 1, 275),
            content=parent.content,
        )
        store.add_child("1:16", chat)
        handler = CONFLOCHandler(10, "CONFLOC", signed_in(), content_store=store)
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = build_property_record(
            [
                (0x03, "ml", struct.pack("<I", 500)),
                (0x03, "mm", struct.pack("<I", 200)),
                (0x03, "ds", struct.pack("<I", 0)),
            ]
        )
        request = (
            b"\x04\x82" + ticket
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\x00\x00"
            + b"\x04" + bytes([0x80 | len(properties)]) + properties
            + b"\x83\x83"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_DATA_EDIT_SET_PROPERTIES,
            3,
            request,
            0,
            0,
        )
        parsed = parse_packet(packets[0][:-1])

        self.assertEqual(
            parsed.payload[8:],
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )
        self.assertNotIn(record_id, handler._records)
        conference = store.get_node("1:275").content.conference
        self.assertEqual(conference.room_capacity, 200)
        self.assertEqual(conference.message_length, 500)
        self.assertFalse(conference.join_as_participants)

        join_reply = CONFSRVHandler(
            11,
            "CONFSRV",
            signed_in(SUBSCRIBER),
            content_store=store,
        ).build_join_reply_payload(
            b"\x03" + struct.pack("<I", 1) + b"\x04\x81\x00\x85"
        )
        self.assertEqual(struct.unpack_from("<H", join_reply, 10)[0], CONFSRV_ROLE_SPECTATOR)
        self.assertEqual(struct.unpack_from("<I", join_reply, 12)[0], 500)

        fresh_handler = CONFLOCHandler(
            10, "CONFLOC", signed_in(), content_store=store,
        )
        get_request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88" + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89mm\x00ml\x00ds\x00"
            + b"\x83\x83\x85"
        )
        fresh_reply = fresh_handler.build_data_edit_get_properties_reply_payload(
            4, get_request,
        )
        selected = build_property_record(
            [
                (0x03, "mm", struct.pack("<I", 200)),
                (0x03, "ml", struct.pack("<I", 500)),
                (0x03, "ds", struct.pack("<I", 0)),
            ]
        )
        self.assertEqual(
            fresh_reply,
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_data_edit_add_rejects_anonymous_writes(self):
        handler = CONFLOCHandler(10, "CONFLOC")
        ticket = b"\x02\x00"
        request = (
            b"\x04\x82" + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88" + struct.pack("<II", 1, 275)
            + b"\x02\xff\xff"
            + b"\x04\x86" + struct.pack("<IH", 6, 0)
            + b"\x83\x83"
        )
        reply = handler.build_data_edit_add_reply_payload(1, request)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)

    def test_locator_rejects_an_unknown_room(self):
        handler = CONFLOCHandler(10, "CONFLOC", content_store=_AddNodeContentStore())
        reply = handler.build_locate_reply_payload(b"\x03" + struct.pack("<I", 275) + b"\x82\x82")
        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 0)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_NOT_FOUND)

    def test_join_designates_billg_as_host(self):
        reset_app_store()
        handler = CONFSRVHandler(11, "CONFSRV", signed_in())
        reply = handler.build_join_reply_payload(
            b"\x03" + struct.pack("<I", 1) + b"\x04\x81\x00\x85"
        )

        self.assertEqual(
            reply[:2],
            bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]),
        )
        status, padding, participant, role, message_limit, name_chars = struct.unpack_from(
            "<HHIHII", reply, 2
        )
        self.assertEqual(status, CONFSRV_JOINED)
        self.assertEqual(padding, 0)
        self.assertEqual(participant, 1)
        self.assertEqual(role, CONFSRV_ROLE_HOST)
        self.assertEqual(message_limit, 1000)
        self.assertEqual(name_chars, len("MSN Chat") + 1)
        self.assertEqual(
            reply[20 : 20 + name_chars * 2].decode("utf-16le").rstrip("\x00"),
            "MSN Chat",
        )

    def test_join_pushes_billg_as_the_host_participant(self):
        reset_app_store()
        handler = CONFSRVHandler(11, "CONFSRV", signed_in())
        packets = handler.handle_request(
            0x01,
            CONFSRV_SELECTOR_JOIN,
            7,
            b"\x03" + struct.pack("<I", 1) + b"\x04\x81\x00\x85",
            0,
            0,
        )

        self.assertEqual(len(packets), 2)
        join_payload = parse_packet(packets[0][:-1]).payload[8:]
        participant_push = parse_packet(packets[1][:-1]).payload[8:]
        self.assertEqual(join_payload[:2], bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))
        self.assertEqual(participant_push[0], TAG_DYNAMIC_STREAM_END)

        event_type, padding, sender = struct.unpack_from("<HHI", participant_push, 1)
        participant_id, role, name_len, reserved_1, reserved_2 = struct.unpack_from(
            "<IHIHH", participant_push, 9,
        )
        name = participant_push[23 : 23 + name_len].decode("cp1252")
        self.assertEqual(event_type, CONFSRV_EVENT_PARTICIPANTS)
        self.assertEqual(padding, 0)
        self.assertEqual(sender, 0)
        self.assertEqual(participant_id, 1)
        self.assertEqual(role, CONFSRV_ROLE_HOST)
        self.assertEqual((reserved_1, reserved_2), (0, 0))
        self.assertEqual(name, "Bill Gates")

    def test_join_keeps_other_accounts_as_participants(self):
        reset_app_store()
        handler = CONFSRVHandler(11, "CONFSRV", signed_in(SUBSCRIBER))
        packets = handler.handle_request(
            0x01,
            CONFSRV_SELECTOR_JOIN,
            7,
            b"\x03" + struct.pack("<I", 1) + b"\x04\x81\x00\x85",
            0,
            0,
        )

        join_payload = parse_packet(packets[0][:-1]).payload[8:]
        participant_push = parse_packet(packets[1][:-1]).payload[8:]
        join_role = struct.unpack_from("<H", join_payload, 10)[0]
        participant_role = struct.unpack_from("<H", participant_push, 13)[0]

        self.assertEqual(join_role, CONFSRV_ROLE_PARTICIPANT)
        self.assertEqual(participant_role, CONFSRV_ROLE_PARTICIPANT)

    def test_join_uses_the_room_host_list(self):
        store = _AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="275:1",
            is_container=False,
            app_id=4,
            mnid_a=struct.pack("<II", 275, 1),
            content=replace(
                parent.content,
                conference=ConferenceFields(
                    room_capacity=10,
                    message_length=1000,
                    join_as_participants=False,
                ),
            ),
            host_usernames=(SUBSCRIBER.upper(), ADMIN),
        )
        store.add_child("1:16", chat)
        join_request = b"\x03" + struct.pack("<I", 275) + b"\x04\x81\x00\x85"

        first_host_reply = CONFSRVHandler(
            11,
            "CONFSRV",
            signed_in(SUBSCRIBER),
            content_store=store,
        ).build_join_reply_payload(join_request)
        second_host_reply = CONFSRVHandler(
            11,
            "CONFSRV",
            signed_in(ADMIN),
            content_store=store,
        ).build_join_reply_payload(join_request)
        nonhost_reply = CONFSRVHandler(
            11,
            "CONFSRV",
            Session(),
            content_store=store,
        ).build_join_reply_payload(join_request)

        self.assertEqual(
            struct.unpack_from("<H", first_host_reply, 10)[0],
            CONFSRV_ROLE_HOST,
        )
        self.assertEqual(
            struct.unpack_from("<H", second_host_reply, 10)[0],
            CONFSRV_ROLE_HOST,
        )
        self.assertEqual(
            struct.unpack_from("<H", nonhost_reply, 10)[0],
            CONFSRV_ROLE_SPECTATOR,
        )

    def test_join_refuses_members_past_the_room_capacity(self):
        store = _AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="275:1",
            is_container=False,
            app_id=4,
            mnid_a=struct.pack("<II", 275, 1),
            content=replace(
                parent.content,
                conference=ConferenceFields(
                    room_capacity=2,
                    message_length=1000,
                    join_as_participants=True,
                ),
            ),
        )
        store.add_child("1:16", chat)
        join_request = b"\x03" + struct.pack("<I", 275) + b"\x04\x81\x00\x85"
        first = CONFSRVHandler(11, "CONFSRV", signed_in(ADMIN), content_store=store)
        second = CONFSRVHandler(12, "CONFSRV", signed_in(SUBSCRIBER), content_store=store)
        refused = CONFSRVHandler(13, "CONFSRV", signed_in(ADMIN), content_store=store)

        first_reply = first.build_join_reply_payload(join_request)
        second_reply = second.build_join_reply_payload(join_request)
        refused_packets = refused.handle_request(
            0x01, CONFSRV_SELECTOR_JOIN, 7, join_request, 0, 0,
        )
        refused_reply = parse_packet(refused_packets[0][:-1]).payload[8:]

        self.assertEqual(struct.unpack_from("<H", first_reply, 2)[0], CONFSRV_JOINED)
        self.assertEqual(struct.unpack_from("<H", second_reply, 2)[0], CONFSRV_JOINED)
        self.assertEqual(len(refused_packets), 1)
        self.assertEqual(struct.unpack_from("<H", refused_reply, 2)[0], CONFSRV_ROOM_FULL)

        first.close()
        retry_reply = refused.build_join_reply_payload(join_request)
        self.assertEqual(struct.unpack_from("<H", retry_reply, 2)[0], CONFSRV_JOINED)
        second.close()
        refused.close()

    def test_send_acknowledges_and_echoes_text_on_the_join_iterator(self):
        handler = CONFSRVHandler(11, "CONFSRV", signed_in())
        handler.handle_request(
            0x01,
            CONFSRV_SELECTOR_JOIN,
            7,
            b"\x03" + struct.pack("<I", 1) + b"\x04\x81\x00\x85",
            0,
            0,
        )
        text = "hello".encode("utf-16le") + b"\x00\x00"
        request_record = struct.pack("<HHI", CONFSRV_EVENT_TEXT, 0, 99) + text
        request = b"\x04" + bytes([0x80 | len(request_record)]) + request_record

        packets = handler.handle_request(
            0x01,
            CONFSRV_SELECTOR_SEND,
            8,
            request,
            2,
            0,
        )

        self.assertEqual(len(packets), 2)
        ack = parse_packet(packets[0][:-1]).payload[8:]
        push = parse_packet(packets[1][:-1]).payload[8:]
        self.assertEqual(ack, bytes([TAG_END_STATIC]))
        self.assertEqual(push[0], TAG_DYNAMIC_STREAM_END)
        event_type, padding, participant_id = struct.unpack_from("<HHI", push, 1)
        self.assertEqual((event_type, padding, participant_id), (CONFSRV_EVENT_TEXT, 0, 1))
        self.assertEqual(push[9:].decode("utf-16le").rstrip("\x00"), "hello")


class TestSASRVServiceMap(unittest.TestCase):
    def test_catalog_matches_saclient_table(self):
        self.assertEqual(len(SASRV_INTERFACE_GUIDS), 29)
        self.assertEqual(
            [selector for _guid, selector in SASRV_INTERFACE_GUIDS],
            list(range(1, 30)),
        )

    def test_guid_records_match_catalog(self):
        payload = build_sasrv_service_map_payload()
        for i, (guid_bytes, selector) in enumerate(SASRV_INTERFACE_GUIDS):
            record = payload[i * 17 : (i + 1) * 17]
            self.assertEqual(record, guid_bytes + bytes([selector]))

    def test_produces_discovery_packet(self):
        packets = SASRVHandler(5, "SASRV").build_discovery_packet(4, 4)
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
        self.handler = SASRVHandler(6, "SASRV", signed_in())

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
        reply = self.handler.build_begin_enum_reply_payload(self.BEGIN_ENUM_TOKENS)

        status, handle = (
            struct.unpack_from("<I", reply, 1)[0],
            struct.unpack_from("<I", reply, 6)[0],
        )
        self.assertEqual(status, 0)
        self.assertNotEqual(handle, 0)
        self.assertEqual(reply[10], TAG_END_STATIC)

    def test_read_enum_results_reports_the_row_count_then_status(self):
        begin = self.handler.build_begin_enum_reply_payload(self.BEGIN_ENUM_TOKENS)
        handle = struct.unpack_from("<I", begin, 6)[0]

        reply = self.handler.build_read_enum_results_reply_payload(
            b"\x03" + struct.pack("<I", handle) + b"\x83\x83"
        )

        count, status = struct.unpack_from("<I", reply, 1)[0], struct.unpack_from("<I", reply, 6)[0]
        self.assertEqual(count, len(SASRV_TOKENS))
        self.assertEqual(status, 0)

    def test_unknown_list_kind_is_refused(self):
        reply = self.handler.build_begin_enum_reply_payload(
            b"\x03" + struct.pack("<I", 7) + b"\x03\x00\x00\x00\x00\x01\x00\x83\x83"
        )

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], SA_E_BAD_LIST_KIND)

    def test_unknown_handle_is_refused(self):
        reply = self.handler.build_read_enum_results_reply_payload(
            b"\x03" + struct.pack("<I", 999) + b"\x83\x83"
        )

        self.assertEqual(struct.unpack_from("<I", reply, 6)[0], SA_E_BAD_LIST_KIND)

    def test_list_page_packs_id_and_asciiz_name_per_row(self):
        """Captured request: handle 1, index 0, WORD 4, then `83 85`.

        The record layout is pinned by the consumer, SACLIENT 0x7F343973:
        `[u32 token_id][ASCIIZ name]`, stride 4 + strlen + 1.
        """
        begin = self.handler.build_begin_enum_reply_payload(self.BEGIN_ENUM_TOKENS)
        self.assertEqual(struct.unpack_from("<I", begin, 6)[0], 1)

        reply = self.handler.build_get_list_page_reply_payload(
            bytes.fromhex("030100000003000000000204008385")
        )

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
        self.handler.build_begin_enum_reply_payload(self.BEGIN_ENUM_TOKENS)

        in_page = self.handler.build_get_list_page_reply_payload(
            self._list_page_request(handle=1, index=2)
        )
        past_end = self.handler.build_get_list_page_reply_payload(
            self._list_page_request(handle=1, index=40)
        )

        self.assertGreater(len(in_page), 7)
        self.assertEqual(len(past_end), 7)

    def test_end_enum_releases_the_handle(self):
        begin = self.handler.build_begin_enum_reply_payload(self.BEGIN_ENUM_TOKENS)
        handle = struct.unpack_from("<I", begin, 6)[0]

        reply = self.handler.build_end_enum_reply_payload(
            b"\x03" + struct.pack("<I", handle) + b"\x83"
        )

        self.assertEqual(reply, b"\x83\x00\x00\x00\x00" + bytes([TAG_END_STATIC]))
        # A released handle no longer answers a row count.
        after = self.handler.build_read_enum_results_reply_payload(
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
        # DirsrvRequest() defaults to node_id="0:0" — GetSpecialMnid(0), the
        # Worldwide Categories hub. Its children are the localized Categories
        # wrappers.
        request = DirsrvRequest(
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(b"Categories (US)", payload)
        self.assertIn(b"Categorias (BR)", payload)

    def test_with_self_flag_leads_the_reply_with_the_requested_node(self):
        # `CMosTreeNode::QueryOutOfDate` @ 0x7F3FDB3F asks for {g, a} with
        # flags=1 and reads the reply as [self][children…]. The lazy loader
        # `OkToGetChildren` sends flags=0 and must keep getting children alone.
        prop_group = "g\x00a"
        plain = _walk_get_children_records(
            build_get_children_reply_payload(DirsrvRequest(node_id="1:16", prop_group=prop_group))
        )
        with_self = _walk_get_children_records(
            build_get_children_reply_payload(
                DirsrvRequest(node_id="1:16", prop_group=prop_group, flags=1)
            )
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
        payload = build_get_children_reply_payload(request, RIGHTS_AUTHORING)
        records = _walk_get_children_records(payload)

        self.assertGreater(len(records), 0)
        for record in records:
            self.assertEqual(record["x"], struct.pack("<I", 0x70))
        self.assertIn(b"\x03x\x00\x70\x00\x00\x00", payload)
        self.assertNotIn(b"\x0ex\x00", payload)

    def test_parent_and_child_counts_follow_the_directory_graph(self):
        request = DirsrvRequest(
            node_id="1:256",
            node_id_raw=struct.pack("<II", 1, 256),
            prop_group="np\x00nc",
            recv_descriptors=[0x83, 0x83, 0x85],
        )

        [record] = _walk_get_children_records(build_get_properties_reply_payload(request))

        self.assertEqual(record["np"], struct.pack("<I", 1))
        self.assertEqual(record["nc"], struct.pack("<I", 13))

    def test_parent_count_increases_when_a_node_is_listed_twice(self):
        self.addCleanup(reset_app_store)
        node = app_store.content.get_node("4:0")
        app_store.content.add_child("0:0", node)
        request = DirsrvRequest(
            node_id=node.node_id,
            node_id_raw=node.mnid_a,
            prop_group="np\x00nc",
            recv_descriptors=[0x83, 0x83, 0x85],
        )

        [record] = _walk_get_children_records(build_get_properties_reply_payload(request))

        self.assertEqual(record["np"], struct.pack("<I", 2))
        self.assertEqual(record["nc"], struct.pack("<I", 0))

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

    def test_worldwide_categories_hub_self_properties(self):
        # Wire "0:0" is GetSpecialMnid(0) — the Worldwide Categories hub.
        # mnid_a = (0, 0), its own (field_8, field_c).
        #
        # The `e` we send here never reaches the UI: RememberProperty @
        # MOSSHELL 0x7F3FBA69 matches the mnid against GetSpecialMnid(0)/(1)
        # and substitutes STRINGTABLE 0x8E / 0x8F. We still send the matching
        # text so server logs read the same as the client.
        request = DirsrvRequest(
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=0,
            dword_1=1,
            prop_group="a\x00e",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_properties_reply_payload(request)
        self.assertIn(b"Worldwide Categories", payload)

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
            node_id="0:0",
            node_id_raw=struct.pack("<II", 0, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
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
            node_id="1:0",
            node_id_raw=struct.pack("<II", 1, 0),
            dword_0=1,
            dword_1=14,
            prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_get_children_reply_payload(request)
        self.assertIn(struct.pack("<II", 1, 0x11), payload)  # Member Assistance (US)
        self.assertIn(struct.pack("<II", 1, 0x14), payload)  # Assistencia (BR)
        self.assertIn(b"Member Assistance (US)", payload)
        self.assertNotIn(struct.pack("<II", 1, 0x10), payload)  # no Cats (US)
        self.assertNotIn(struct.pack("<II", 1, 0x13), payload)  # no Cats (BR)
        self.assertNotIn(b"Categories (US)", payload)

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

    def test_startup_browse_walk_for_hubs_omits_menu_aliases(self):
        # MSN Today (4:0) and Favorite Places (3:1) are client-side HOMEBASE
        # aliases. Neither hub may enumerate them.
        for node_id, f8, localized in (
            ("0:0", 0, 0x10),  # WW Categories → Categories (US)
            ("1:0", 1, 0x11),  # WW Member Assistance → Member Assistance (US)
        ):
            request = DirsrvRequest(
                node_id=node_id,
                node_id_raw=struct.pack("<II", f8, 0),
                dword_0=1,
                dword_1=14,
                prop_group="a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i",
                recv_descriptors=[0x83, 0x83, 0x85],
            )
            payload = build_get_children_reply_payload(request)
            self.assertNotIn(struct.pack("<II", 4, 0), payload)
            self.assertNotIn(struct.pack("<II", 3, 1), payload)
            # The hub's own localized wrapper — the GetLocalizedNode target
            # for that HOMEBASE button — must be present.
            self.assertIn(struct.pack("<II", 1, localized), payload)

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
        # Category containers have empty modified → `w` ships as an EMPTY 0x0A
        # string (flag byte 0x02). The column formatter @ 0x7F3FBC12 case 0x0A
        # copies the ASCIIZ through, so the cell renders blank, and the cache
        # element is marked received. Omitting the tag instead would poison it
        # permanently — see build_props' PROP_LAST_CHANGED comment.
        self.assertIn(b"\x0aw\x00\x01\x00", payload)
        for type_byte in (0x03, 0x0C, 0x0E, 0x0B):
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

    def test_language_prop_ships_as_counted_lcid_array(self):
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
        # DSNED stores q as SVCPROP type 0x10, whose size invariant is
        # `length == count * 4 + 4`. One LCID therefore starts with count 1.
        self.assertIn(b"\x04q\x00" + struct.pack("<II", 1, 1033), payload)
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
                    b"\x04q\x00" + struct.pack("<II", 1, lcid),
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
            self.assertNotIn(b"\x04q\x00" + struct.pack("<II", 1, lcid), addrbar_payload)


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
            build_enum_shn_reply_payload(self.REQUEST),
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
        payload = build_enum_shn_reply_payload(self.REQUEST)
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
        body = build_enum_shn_reply_payload(self.REQUEST)[10:]
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
        payload = build_enum_shn_reply_payload(b"\x01\x07\x83\x82\x85")
        self.assertEqual(
            payload,
            b"\x83\x00\x00\x00\x00\x82\x00\x00"
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]),
        )

    def test_selector_dispatches_to_a_reply_packet(self):
        handler = DIRSRVHandler(pipe_idx=4, svc_name="DIRSRV")
        packets = handler.handle_request(
            msg_class=0x03,
            selector=0x05,
            request_id=12,
            payload=self.REQUEST,
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        parsed = parse_packet(packets[0][:-1])
        self.assertTrue(parsed.crc_ok)
        self.assertEqual(parsed.payload[8:], build_enum_shn_reply_payload(self.REQUEST))

    def test_key_constant_matches_the_observed_request(self):
        self.assertEqual(self.REQUEST[1], ENUM_SHN_KEY_ICONS)


class TestDIRSRVGetTicket(unittest.TestCase):
    def test_minimal_ticket_reply_shape(self):
        self.assertEqual(
            build_get_ticket_reply_payload(),
            b"\x83\x00\x00\x00\x00\x87\x86\x02\x00",
        )

    def test_edit_channel_selector_returns_ticket_packet(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x0C,
            request_id=0,
            payload=b"\x83\x85",
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        parsed = parse_packet(packets[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # header + size prefix + routing + class + selector + one-byte VLI
        self.assertEqual(parsed.payload[8:], build_get_ticket_reply_payload(handler.session))


class TestDIRSRVGetDataSets(unittest.TestCase):
    def test_empty_dataset_reply_contains_complete_property_record(self):
        self.assertEqual(
            build_get_datasets_reply_payload(),
            b"\x83\x00\x00\x00\x00\x87\x86\x06\x00\x00\x00\x00\x00",
        )

    def test_edit_channel_selector_returns_dataset_packet(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        packets = handler.handle_request(
            msg_class=0x04,
            selector=0x0B,
            request_id=1,
            payload=bytes.fromhex("04 82 02 00 04 84 42 42 53 00 03 04 00 00 00 83 85"),
            server_seq=0,
            client_ack=0,
        )

        self.assertIsNotNone(packets)
        parsed = parse_packet(packets[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # header + size prefix + routing + class + selector + one-byte VLI
        self.assertEqual(parsed.payload[8:], build_get_datasets_reply_payload())


class _AddNodeContentStore:
    def __init__(self):
        parent = next(node for node in default_seed().directory_nodes if node.node_id == "1:16")
        self.nodes = {parent.node_id: parent}
        self.children = {parent.node_id: []}

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    def get_children(self, node_id):
        return [self.nodes[child_id] for child_id in self.children.get(node_id, [])]

    def find_app_instance(self, app_id, instance_id):
        for node in self.nodes.values():
            if (
                node.app_id == app_id
                and struct.unpack_from("<I", node.mnid_a)[0] == instance_id
            ):
                return node
        return None

    def add_child(self, parent_id, node):
        self.nodes[node.node_id] = node
        self.children.setdefault(node.node_id, [])
        self.children.setdefault(parent_id, []).append(node.node_id)

    def add_node(self, node):
        self.nodes[node.node_id] = node


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
        store = _AddNodeContentStore()

        reply = build_add_node_reply_payload(request, store)

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
        store = _AddNodeContentStore()
        built_in = next(
            node for node in default_seed().directory_nodes if node.app_id == 4
        )
        store.add_child("1:16", built_in)

        reply = build_add_node_reply_payload(request, store, session=signed_in(ADMIN))

        new_mnid = reply[-8:]
        instance_id, field_8 = struct.unpack("<II", new_mnid)
        node = store.get_node(f"{instance_id}:{field_8}")
        self.assertEqual(instance_id, 2)
        self.assertEqual(node.host_usernames, (ADMIN,))
        self.assertIs(store.find_app_instance(4, instance_id), node)

    def test_rejects_the_read_side_receive_shape(self):
        store = _AddNodeContentStore()
        reply = build_add_node_reply_payload(b"\x83\x85", store)
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
        store = _AddNodeContentStore()

        build_add_node_reply_payload(request, store)

        node = store.get_node("1:17")
        self.assertTrue(node.delegate)
        self.assertEqual(node.delegate_mnid_a, inner_mnid)
        properties = {
            name: value
            for _ptype, name, value in build_props(
                ["a", "l"], node, is_children=False
            )
        }
        self.assertEqual(properties["a"], struct.pack("<I", 8) + node.mnid_a)
        self.assertEqual(properties["l"], inner_mnid)

    def test_edit_class_selector_two_does_not_fall_through_to_get_children(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        with patch(
            "server.services.dirsrv.build_add_node_reply_payload",
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

        build_reply.assert_called_once_with(b"add-node", session=handler.session)
        parsed = parse_packet(packets[0][:-1])
        self.assertEqual(parsed.payload[8:], b"\x83\x00\x00\x00\x00")


class _SetPropertiesContentStore:
    """Holds one real category node — the shape DSNED's Folder editor edits."""

    NODE_ID = "1:256"  # "Arts and Entertainment", app_id 1 (tp "Category")

    def __init__(self):
        node = next(node for node in default_seed().directory_nodes if node.node_id == self.NODE_ID)
        self.nodes = {node.node_id: node}

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    def add_node(self, node):
        self.nodes[node.node_id] = node


class TestDIRSRVSetProperties(unittest.TestCase):
    """Class 0x04 selector 0x04 — the Properties sheet's write path.

    Each page applies one control per call, so these records carry the whole
    page at once only to keep the tests short; the handler treats the record as
    a set either way.
    """

    OK = b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87"

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

        reply = build_set_properties_reply_payload(request, store)

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

        reply = build_set_properties_reply_payload(request, store)

        self.assertEqual(reply, self.OK)
        content = store.get_node(store.NODE_ID).content
        self.assertEqual(content.language, 0x0416)
        self.assertEqual(content.topics, "Books, Movies")
        self.assertEqual(content.people, "Critics")
        self.assertEqual(content.place, "Redmond, WA")
        self.assertEqual(content.forum_mgr, "MSN Editorial")
        self.assertEqual(content.owner, "Jane Doe")
        self.assertEqual(content.vendor_id, 4242)

    def test_untouched_fields_survive_a_partial_write(self):
        store = _SetPropertiesContentStore()
        before = store.get_node(store.NODE_ID)

        build_set_properties_reply_payload(
            self._request([(0x0A, "k", self._ascii("artsgo"))]), store
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

        reply = build_set_properties_reply_payload(request, store)

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

        reply = build_set_properties_reply_payload(request, store)

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

        reply = build_set_properties_reply_payload(request, store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertIs(store.get_node(store.NODE_ID), before)

    def test_rejects_an_unknown_node(self):
        store = _SetPropertiesContentStore()

        reply = build_set_properties_reply_payload(
            self._request([(0x0A, "k", self._ascii("nope"))], node_id="9:99"), store
        )

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)

    def test_edit_class_selector_four_does_not_fall_through_to_get_shabby(self):
        handler = DIRSRVHandler(pipe_idx=1, svc_name="DIRSRV")
        with patch(
            "server.services.dirsrv.build_set_properties_reply_payload",
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

        build_reply.assert_called_once_with(b"set-properties", session=handler.session)
        parsed = parse_packet(packets[0][:-1])
        self.assertEqual(parsed.payload[8:], b"\x83\x00\x00\x00\x00")


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
        handler = DIRSRVHandler(4, "DIRSRV", signed_in(ADMIN))
        request = self._request("1:271")
        with patch(
            "server.services.dirsrv.build_delete_node_reply_payload",
            return_value=b"\x87",
        ) as delete:
            packets = handler.handle_request(0x04, 0x03, 3, request, 5, 5)

        self.assertIsNotNone(packets)
        delete.assert_called_once_with(request, session=handler.session)

    def test_removes_the_node_and_reports_a_completed_operation(self):
        store = _DeleteNodeContentStore()
        doomed = store.children[store.BOARD_ID][0]

        reply = build_delete_node_reply_payload(self._request(doomed), store)

        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")
        self.assertNotIn(doomed, store.nodes)
        self.assertNotIn(doomed, store.children[store.BOARD_ID])

    def test_unknown_node_fails_without_touching_the_board(self):
        store = _DeleteNodeContentStore()
        before = list(store.children[store.BOARD_ID])

        reply = build_delete_node_reply_payload(self._request("9000:1"), store)

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)
        self.assertEqual(store.children[store.BOARD_ID], before)

    def test_rejects_the_add_node_receive_shape(self):
        # AddNode asks for a variable field back as well. Answering a request
        # shaped for three receives would leave the client short a field.
        store = _DeleteNodeContentStore()
        doomed = store.children[store.BOARD_ID][0]
        request = self._request(doomed)[:-2] + b"\x83\x83\x84"

        reply = build_delete_node_reply_payload(request, store)

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

        reply = build_delete_node_reply_payload(request, store)

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
        payload = build_get_deid_from_go_word_reply_payload(self._build_request("Today"))
        expected = (
            b"\x83\x00\x00\x00\x00"  # status=0
            + bytes([TAG_END_STATIC])  # 0x87
            + b"\x84\x88"  # 0x84 var, len=8 inline
            + struct.pack("<II", 4, 0)  # deid (4, 0)
        )
        self.assertEqual(payload, expected)

    def test_unknown_go_word_returns_zero_deid_with_error(self):
        payload = build_get_deid_from_go_word_reply_payload(self._build_request("nonexistent"))
        expected = (
            b"\x83"
            + struct.pack("<I", DS_E_NOT_FOUND)
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


def _make_bbs_attachment_request(attachment_id=0x202, board_id=1):
    """Synthesize MOSAF's BBS FRI for one attachment node."""
    cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
    cfi[: len(FTM_BBS_SOURCE)] = FTM_BBS_SOURCE.encode("ascii")
    struct.pack_into("<IIII", cfi, 32, 2, board_id, attachment_id, 0)
    return build_tagged_reply_var(0x04, bytes(cfi)) + b"\x84"


class TestFTMBbsAttachment(unittest.TestCase):
    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def test_bbs_fri_resolves_the_fixture_upload(self):
        filename, content = _resolve_ftm_target(_make_bbs_attachment_request())
        self.assertEqual(filename, FTM_BBS_SOURCE)
        self.assertEqual(len(content), 175)
        self.assertEqual(content[:4], b"MOS2")

    def test_reply_preserves_mosaf_filename_and_selects_mos2_unpack(self):
        payload = _build_request_download_reply(
            FTM_BBS_SOURCE,
            175,
            unpack_method=FTM_BBS_UNPACK_METHOD,
            override_filename=False,
        )
        reply = payload[2:]
        self.assertEqual(struct.unpack_from("<I", reply, 0x08)[0], 175)
        self.assertEqual(struct.unpack_from("<I", reply, 0x0C)[0], 175)
        self.assertEqual(struct.unpack_from("<I", reply, 0x10)[0], 0x03)
        self.assertEqual(
            struct.unpack_from("<I", reply, 0x14)[0],
            FTM_BBS_UNPACK_METHOD,
        )
        self.assertEqual(reply[0x28:], b"\x00" * 32)

    def test_bill_client_carries_the_mos2_container(self):
        handler = FTMHandler(5, "FTM")
        pkts = handler.handle_request(
            0x01,
            0x03,
            1,
            _make_bbs_attachment_request(),
            10,
            10,
        )
        self.assertIn(b"MOS2", b"".join(pkts))

    def test_request_download_does_not_increment_the_download_count(self):
        handler = FTMHandler(5, "FTM")
        handler.handle_request(
            0x01,
            0x00,
            1,
            _make_bbs_attachment_request(),
            10,
            10,
        )
        attachment = app_store.content.get_node("514:1")
        self.assertEqual(attachment.content.bbs.download_count, 0)

    def test_bill_client_increments_the_download_count(self):
        handler = FTMHandler(5, "FTM")
        for expected in (1, 2):
            handler.handle_request(
                0x01,
                0x03,
                expected,
                _make_bbs_attachment_request(),
                10,
                10,
            )
            attachment = app_store.content.get_node("514:1")
            self.assertEqual(attachment.content.bbs.download_count, expected)


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
    # serial=0. The deid selects resources/titles/HANDBOOK.M14.
    _MSN_TODAY_REQ = (
        b"\x04\x87:2[4]0\x00"  # tag=0x04 var, len|0x80=0x87, 7-byte ASCIIZ
        b"\x03\x00\x00\x00\x00"  # cached checksum 1 = 0
        b"\x03\x00\x00\x00\x00"  # cached checksum 2 = 0
        b"\x81\x81\x83\x83\x83\x83\x83"
    )

    def _decode_reply(self, req_payload):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_OPEN,
            1,
            req_payload,
            5,
            5,
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

    def test_title_open_loads_m14_when_deid_has_fixture(self):
        handler, _reply = self._open_handler()
        self.assertIsNotNone(handler.loaded_m14)
        self.assertEqual(handler.loaded_m14.title, "Employee Handbook Example")
        self.assertEqual(handler.loaded_m14.home_display.topic_pos, 0xA7)
        self.assertEqual(handler.title_metadata.contents_va, 0xA7)
        self.assertEqual(handler.title_metadata.addr_base, 0)
        self.assertEqual(handler.title_metadata.topic_count, 22)

    def test_title_open_body_carries_m14_system_strings(self):
        handler, _reply = self._open_handler()
        self.assertIn(b"Employee Handbook Example\x00", handler.title_body)
        self.assertIn(
            "© 1996 Centric Development, Inc.\x00".encode("cp1252"),
            handler.title_body,
        )

    def test_sample_deids_select_the_two_compiled_m14_files(self):
        for deid, archive_name, title_name in (
            ("1000", "HANDBOOK.M14", "Employee Handbook Example"),
            ("1001", "FRANCE.M14", "France"),
            ("1002", "MVDOC.M14", "MediaView Online Documentation"),
        ):
            token = f":2[{deid}]0".encode("ascii") + b"\x00"
            request = (
                b"\x04"
                + bytes([0x80 | len(token)])
                + token
                + b"\x03\x00\x00\x00\x00"
                + b"\x03\x00\x00\x00\x00"
                + b"\x81\x81\x83\x83\x83\x83\x83"
            )
            handler, _reply = self._open_handler(request)
            self.assertIsNotNone(handler.loaded_m14)
            self.assertEqual(handler.loaded_m14.archive_name, archive_name)
            self.assertEqual(handler.loaded_m14.title, title_name)


class TestMEDVIEWTitleGetInfo(unittest.TestCase):
    def test_get_info_reply_size_zero(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Request: 0x01 <title_byte>, 3× 0x03 dword, 0x83 recv.
        req_payload = bytes.fromhex(
            "01 01"
            "03 07 00 00 00"  # info_kind=7 (0x2B records)
            "03 00 00 2b 00"  # bufsize=0x002b, index=0
            "03 00 00 00 00"  # buffer_ptr=0
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


class TestMEDVIEWDataEdit(unittest.TestCase):
    @staticmethod
    def _add_request():
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 271)
        properties = struct.pack("<IH", 6, 0)
        return (
            b"\x04" + bytes([0x80 | len(ticket)]) + ticket
            + b"\x03\x06\x00\x00\x00"
            + b"\x04" + bytes([0x80 | len(record_id)]) + record_id
            + b"\x02\xff\xff"
            + b"\x04" + bytes([0x80 | len(properties)]) + properties
            + b"\x83\x83"
        )

    @staticmethod
    def _delete_request():
        return (
            b"\x04\x82\x02\x00"
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + struct.pack("<II", 4098, 0)
            + b"\x02\xff\xff"
            + b"\x83\x83"
        )

    def test_data_edit_get_ticket_does_not_dispatch_as_viewer_cache_miss(self):
        handler = MEDVIEWHandler(5, "MEDVIEW", signed_in(ADMIN))
        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_DATA_EDIT_GET_TICKET,
            0,
            b"\x83\x85",
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, build_get_ticket_reply_payload(handler.session))
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x87\x86\x02\x00")

    def test_data_edit_add_does_not_dispatch_as_validate_title(self):
        handler = MEDVIEWHandler(5, "MEDVIEW", signed_in(ADMIN))
        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_DATA_EDIT_ADD,
            1,
            self._add_request(),
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")

    def test_data_edit_delete_does_not_dispatch_as_open_title(self):
        handler = MEDVIEWHandler(5, "MEDVIEW", signed_in(ADMIN))

        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_DATA_EDIT_DELETE,
            1,
            self._delete_request(),
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")

    def test_data_edit_delete_refuses_anonymous_writes(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")

        reply = handler._handle_data_edit_delete(1, self._delete_request())

        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)


class TestMEDVIEWCacheMissRpcs(unittest.TestCase):
    """Selectors 0x05 / 0x06 / 0x07 / 0x15 / 0x16 ack synchronously and
    push the resolved entry on the matching notification iterator."""

    @staticmethod
    def _subscribe(handler, notification_type, request_id):
        return handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            request_id,
            bytes([0x01, notification_type, 0x85]),
            5,
            5,
        )

    def test_async_cache_miss_selectors_bare_ack_when_no_subscription(self):
        # Without a matching subscription the handler ships only the
        # synchronous bare ack — the push has no iterator to ride.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        for selector in (
            MEDVIEW_SELECTOR_VA_CONVERT_HASH,
            MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
            MEDVIEW_SELECTOR_VA_RESOLVE,
        ):
            pkts = handler.handle_request(0x01, selector, 9, req_payload, 5, 5)
            self.assertIsNotNone(pkts, f"selector 0x{selector:02x} returned None")
            self.assertEqual(len(pkts), 1)
            reply = parse_packet(pkts[0][:-1]).payload[8:]
            self.assertEqual(
                reply,
                bytes([TAG_END_STATIC]),
                f"selector 0x{selector:02x} ack mismatch",
            )

    def test_unknown_hash_pushes_type3_frame_with_va_zero(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._subscribe(handler, 3, 2)
        key = 0xCAFEBABE
        hash_req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_VA_CONVERT_HASH,
            9,
            hash_req,
            5,
            5,
        )
        self.assertGreaterEqual(len(pkts), 2)
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(push[0], 0x85)
        # type-3 op-code 4 frame: u16 op=4, u16 len=18, u8 title, u8 kind,
        # u32 key, u32 va, u32 addr.
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 1, key, 0, 0),
        )

    def test_empty_context_hash_resolves_to_m14_contents(self):
        for deid, expected_va, expected_addr in (
            ("4", 0xA7, 0),
            ("1001", 0xC930, 0x18699),
        ):
            handler = MEDVIEWHandler(5, "MEDVIEW")
            token = f":2[{deid}]0".encode("ascii") + b"\x00"
            open_req = (
                b"\x04"
                + bytes([0x80 | len(token)])
                + token
                + b"\x03\x00\x00\x00\x00"
                + b"\x03\x00\x00\x00\x00"
                + b"\x81\x81\x83\x83\x83\x83\x83"
            )
            handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_TITLE_OPEN,
                1,
                open_req,
                5,
                5,
            )
            self._subscribe(handler, 3, 2)
            hash_req = b"\x01\x01\x03\x01\x00\x00\x00"
            pkts = handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_VA_CONVERT_HASH,
                9,
                hash_req,
                5,
                5,
            )
            push = parse_packet(pkts[1][:-1]).payload[8:]
            self.assertEqual(
                struct.unpack("<HHBBIII", push[1:19]),
                (4, 18, 0x01, 1, 1, expected_va, expected_addr),
            )

    def test_m14_link_hash_resolves_through_context_btree(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        token = b":2[1001]0\x00"
        open_req = (
            b"\x04"
            + bytes([0x80 | len(token)])
            + token
            + b"\x03\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_OPEN,
            1,
            open_req,
            5,
            5,
        )
        self._subscribe(handler, 3, 2)
        key = 0x6348
        hash_req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_VA_CONVERT_HASH,
            9,
            hash_req,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 1, key, 0x4696, 0x8338),
        )

    def test_convert_topic_pushes_type3_kind_0(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._subscribe(handler, 3, 2)
        key = 0x00000005
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
            10,
            req,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 0, key, 0, 0),
        )

    def test_va_resolve_pushes_empty_case1_bf_chunk(self):
        # Selector 0x15 pushes opcode 0xBF on the type-0 iterator —
        # that's the record HfcCache_InsertOrdered writes into HfcNear's
        # per-title cache at title+4, unblocking the 30-s retry loop.
        # No loaded title with captions → empty case-1 ("skip empty row").
        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._subscribe(handler, 0, 3)
        key = 0x12345678
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_VA_RESOLVE,
            11,
            req,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xBF)
        self.assertEqual(push[2], 0x01)
        self.assertEqual(struct.unpack("<I", push[13:17])[0], key)
        self.assertEqual(push[1 + 0x2A], 0x01)

    def test_va_resolve_pushes_native_m14_control_stream(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        open_req = (
            b"\x04\x87:2[4]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_OPEN, 1, open_req, 5, 5)
        self.assertIsNotNone(handler.loaded_m14)
        self._subscribe(handler, 0, 3)
        key = handler.loaded_m14.home_display.topic_pos
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_VA_RESOLVE,
            11,
            req,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xBF)
        self.assertEqual(push[1 + 0x2A], 0x20)
        self.assertIn(b"MVIMG,MVIMAGE, !homed.SHG\x00", push)

    def test_fetch_adjacent_topic_pushes_type0_a5(self):
        from server.config import MEDVIEW_FETCH_ADJACENT_TOPIC

        handler = MEDVIEWHandler(5, "MEDVIEW")
        self._subscribe(handler, 0, 1)
        req_payload = bytes.fromhex("01 01 03 00 00 00 00 01 00")
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_FETCH_ADJACENT_TOPIC,
            11,
            req_payload,
            5,
            5,
        )
        self.assertGreaterEqual(len(pkts), 2)
        sync = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(sync, bytes([TAG_END_STATIC]))
        push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xA5)

    def test_m14_topic_chunks_carry_pane_bounds_and_adjacent_records(self):
        from server.config import MEDVIEW_FETCH_ADJACENT_TOPIC

        handler = MEDVIEWHandler(5, "MEDVIEW")
        token = b":2[1001]0\x00"
        open_req = (
            b"\x04" + bytes([0x80 | len(token)]) + token + b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(0x01, MEDVIEW_SELECTOR_TITLE_OPEN, 1, open_req, 5, 5)
        self._subscribe(handler, 0, 1)

        req_payload = b"\x01\x01\x03" + struct.pack("<I", 0x4696) + b"\x01\x01"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_FETCH_ADJACENT_TOPIC,
            11,
            req_payload,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        chunk = push[1:]
        name_size = struct.unpack_from("<H", chunk, 2)[0]
        self.assertEqual(chunk[0], 0xBF)
        # 0x4696 opens its topic, so its leading token is the adjacent
        # 0x4695 rather than a shared end-of-content sentinel.
        self.assertEqual(
            struct.unpack_from("<III", chunk, 8),
            (0x4695, 0x4696, 0x46D3),
        )
        self.assertEqual(
            struct.unpack_from("<II", chunk, 4 + name_size + 0x14),
            (0x4696, 0x46D3),
        )

        req_payload = b"\x01\x01\x03" + struct.pack("<I", 0x46D3) + b"\x01\x01"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_FETCH_ADJACENT_TOPIC,
            12,
            req_payload,
            5,
            5,
        )
        push = parse_packet(pkts[1][:-1]).payload[8:]
        chunk = push[1:]
        self.assertEqual(chunk[0], 0xBF)
        self.assertEqual(
            struct.unpack_from("<III", chunk, 8),
            (0x4696, 0x46D3, 0x4968),
        )
        self.assertIn(b"The Cathars were followers", chunk)

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
            0x01,
            MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC,
            9,
            req_payload,
            5,
            5,
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
    @staticmethod
    def _subscribe(handler, notification_type, request_id):
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            request_id,
            bytes([0x01, notification_type, 0x85]),
            5,
            5,
        )

    @staticmethod
    def _subscriber_state_request(notification_type, enabled):
        state_payload = bytes([notification_type]) + struct.pack(
            "<I",
            int(enabled),
        )
        return b"\x01\x00\x02\x07\x00\x04" + bytes([0x80 | len(state_payload)]) + state_payload

    @staticmethod
    def _picture_start_request(
        *,
        transfer_id,
        name="albi.bmp",
        current_size=0,
        mode=0,
        state_flags=0,
    ):
        start_payload = (
            bytes([1, mode])
            + struct.pack("<II", current_size, transfer_id)
            + bytes([state_flags])
            + name.encode("ascii")
            + b"\x00"
        )
        return (
            b"\x01\x01"
            b"\x02\x04\x00"
            b"\x04" + bytes([0x80 | len(start_payload)]) + start_payload + b"\x83"
        )

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

    def test_picture_start_pushes_status_then_file_bytes(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        picture = b"BM" + b"\x00" * 12 + struct.pack("<Iii", 40, 113, 95) + b"\x00" * 12
        handler.baggage_map = {"albi.bmp": picture}
        self._subscribe(handler, 3, 3)
        self._subscribe(handler, 4, 4)

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            5,
            self._picture_start_request(transfer_id=0x12345678),
            10,
            5,
        )
        self.assertEqual(len(pkts), 3)

        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x87")

        status_push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(status_push[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 1, 113, 95, 0, 0, 0x12345678),
        )

        chunk_push = parse_packet(pkts[2][:-1]).payload[8:]
        self.assertEqual(chunk_push[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture), 0x12345678, 0),
        )
        self.assertEqual(chunk_push[13:], picture)

    def test_picture_chunks_wait_for_type4_subscription(self):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        picture = b"BMresume-data"
        handler.baggage_map = {"albi.bmp": picture}
        self._subscribe(handler, 3, 3)

        start_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            5,
            self._picture_start_request(
                transfer_id=7,
                current_size=2,
                mode=1,
            ),
            10,
            5,
        )
        self.assertEqual(len(start_pkts), 2)
        status_push = parse_packet(start_pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 0, 0, 0, 0, 0, 7),
        )

        subscribe_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            4,
            b"\x01\x04\x85",
            20,
            5,
        )
        self.assertEqual(len(subscribe_pkts), 2)
        chunk_push = parse_packet(subscribe_pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture) - 2, 7, 2),
        )
        self.assertEqual(chunk_push[13:], picture[2:])

    def test_reset_mode_start_on_valid_object_sends_status_only(self):
        # The client's transfer-teardown pass: mode 1 (subscriber reset) with
        # stateFlags bit 0 (object already valid). It reports currentSize 0 but
        # already holds the finished bytes, so re-pushing them writes a second
        # copy into a buffer it has finished with. Status record only.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        picture = b"BMalready-delivered"
        handler.baggage_map = {"albi.bmp": picture}
        self._subscribe(handler, 3, 3)
        self._subscribe(handler, 4, 4)

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            5,
            self._picture_start_request(
                transfer_id=7,
                mode=1,
                state_flags=0x01,
            ),
            10,
            5,
        )
        # Reply + one type-3 status push, and no type-4 chunk push.
        self.assertEqual(len(pkts), 2)
        status_push = parse_packet(pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 0, 0, 0, 0, 0, 7),
        )
        self.assertEqual(handler._pending_picture_transfers, {})

    def test_reset_mode_holds_chunks_until_subscriber_reenabled(self):
        # mode 1 on a not-yet-valid object still needs the bytes, but the
        # type-4 subscriber is going down. Hold them until opcode 0x07 reports
        # the stream enabled again.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        picture = b"BMheld-until-enabled"
        handler.baggage_map = {"albi.bmp": picture}
        self._subscribe(handler, 3, 3)
        self._subscribe(handler, 4, 4)

        start_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            5,
            self._picture_start_request(transfer_id=7, mode=1),
            10,
            5,
        )
        self.assertEqual(len(start_pkts), 2)
        self.assertIn(7, handler._pending_picture_transfers)

        # The client's own disable report must not release them either.
        disable_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            6,
            self._subscriber_state_request(4, False),
            20,
            5,
        )
        self.assertEqual(len(disable_pkts), 1)

        enable_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            7,
            self._subscriber_state_request(4, True),
            30,
            5,
        )
        self.assertEqual(len(enable_pkts), 2)
        chunk_push = parse_packet(enable_pkts[1][:-1]).payload[8:]
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture), 7, 0),
        )
        self.assertEqual(chunk_push[13:], picture)
        self.assertEqual(handler._pending_picture_transfers, {})

    def test_online_start_after_disable_report_holds_chunks(self):
        # Once the client reports type 4 disabled, an online-mode start must
        # not push into the dead stream.
        handler = MEDVIEWHandler(5, "MEDVIEW")
        picture = b"BMno-live-stream"
        handler.baggage_map = {"albi.bmp": picture}
        self._subscribe(handler, 3, 3)
        self._subscribe(handler, 4, 4)
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            5,
            self._subscriber_state_request(4, False),
            10,
            5,
        )

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
            6,
            self._picture_start_request(transfer_id=7, mode=0),
            20,
            5,
        )
        self.assertEqual(len(pkts), 2)
        self.assertIn(7, handler._pending_picture_transfers)


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
        # OpenTitle registers the (single) title slot so subsequent
        # ValidateTitle and CloseTitle assertions pass. Title token bytes
        # are ignored — the handler always ships the same hardcoded body.
        req = (
            b"\x04\x84:2[]0\x00\x03\x00\x00\x00\x00\x03\x00\x00\x00\x00\x81\x81\x83\x83\x83\x83\x83"
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

    def test_query_topics_returns_empty_session(self):
        from server.config import MEDVIEW_QUERY_TOPICS

        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Minimal request: titleSlot, queryClass, primaryText, queryFlags=0,
        # queryMode. We only care that the handler survives and emits the
        # documented static fields.
        req_payload = (
            bytes.fromhex("01 01")
            + bytes.fromhex("02 00 00")
            + b"\x04\x82query\x00"
            + bytes.fromhex("01 00")
            + bytes.fromhex("02 00 00")
        )
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
        pkts = handler.handle_request(
            0x01, MEDVIEW_CLOSE_WORD_WHEEL, 1, bytes.fromhex("01 00"), 5, 5
        )
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
        pkts = handler.handle_request(
            0x01, MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT, 1, bytes.fromhex("01 01"), 5, 5
        )
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
        pkts = handler.handle_request(
            0x01, MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS, 2, unsub_payload, 5, 5
        )
        self.assertIsNotNone(pkts)
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply, bytes([TAG_END_STATIC]))
        self.assertNotIn(0, handler._subscriptions)

    def test_iterator_cancel_clears_subscription_state(self):
        """`handle_iterator_cancel(class, sel, req_id)` drops the one
        subscription whose `(class, req_id)` matches and leaves the rest."""
        from server.config import MEDVIEW_SUBSCRIBE_NOTIFICATIONS

        handler = MEDVIEWHandler(5, "MEDVIEW")
        # Subscribe types 0..4 with distinct req_ids 1..5.
        for n_type, req_id in enumerate(range(1, 6)):
            sub_payload = bytes([0x01, n_type, 0x85])
            handler.handle_request(
                0x01,
                MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
                req_id,
                sub_payload,
                5,
                5,
            )
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 2, 3, 4})

        # Cancel the type=2 iterator (req_id=3).
        handler.handle_iterator_cancel(0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 3)
        self.assertNotIn(2, handler._subscriptions)
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 3, 4})

    def test_iterator_cancel_with_no_subscription_is_idempotent(self):
        from server.config import MEDVIEW_SUBSCRIBE_NOTIFICATIONS

        handler = MEDVIEWHandler(5, "MEDVIEW")
        # No state, no exception.
        handler.handle_iterator_cancel(0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 42)
        self.assertEqual(handler._subscriptions, {})


class TestConnectionIteratorCancelDispatch(unittest.TestCase):
    """Connection-layer routing of the MPCCL iterator-cancel frame.

    Drives `ConnectionState._handle_service_data` directly with a fake
    socket so the cancel branch is exercised end-to-end: detect → handler
    hook → wire ack.  See `docs/MEDVIEW.md` §6d.0.
    """

    PIPE_IDX = 4

    class _FakeSocket:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def close(self):
            pass

    def _make_conn(self):
        from server.config import MEDVIEW_SUBSCRIBE_NOTIFICATIONS
        from server.connection import ConnectionState

        sock = self._FakeSocket()
        conn = ConnectionState(sock)
        handler = MEDVIEWHandler(self.PIPE_IDX, "MEDVIEW")
        # Seed 5 subscriptions matching the engine's `MVAsyncNotifyDispatch`
        # slot allocation: types 0..4 with req_ids 1..5.
        for n_type, req_id in enumerate(range(1, 6)):
            sub_payload = bytes([0x01, n_type, 0x85])
            handler.handle_request(
                0x01,
                MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
                req_id,
                sub_payload,
                5,
                5,
            )
        conn.services[self.PIPE_IDX] = handler
        return conn, handler, sock

    def _build_cancel_frame(self, msg_class, selector, req_id):
        """Build the raw host-block bytes the connection layer receives."""
        from server.mpc import build_host_block

        return build_host_block(msg_class, selector, req_id, b"\x0f")

    def _parse_wire(self, raw):
        """Strip the leading ACK packet and return the host-block payload
        of the first DATA packet (without pipe-routing prefix or VLI)."""
        from server.config import PACKET_TERMINATOR
        from server.mpc import parse_host_block
        from server.pipe import parse_pipe_frames

        packets = []
        buf = bytearray()
        for b in raw:
            if b == PACKET_TERMINATOR:
                packets.append(parse_packet(bytes(buf)))
                buf.clear()
            else:
                buf.append(b)
        data_pkts = [p for p in packets if p is not None and p.type == "DATA"]
        self.assertTrue(data_pkts, "no DATA packet produced")
        frames = parse_pipe_frames(data_pkts[0].payload)
        self.assertEqual(len(frames), 1)
        # frame.content = pipe_idx(u16) + host_block
        hb = parse_host_block(frames[0].content[2:])
        self.assertIsNotNone(hb)
        return hb

    def test_cancel_frame_emits_canonical_ack_and_clears_state(self):
        from server.config import MEDVIEW_SUBSCRIBE_NOTIFICATIONS
        from server.mpc import ITERATOR_CANCEL_ACK

        conn, handler, sock = self._make_conn()
        # Cancel the type=2 iterator (req_id=3 from the seed loop).
        frame = self._build_cancel_frame(0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 3)

        with self.assertLogs("server.services.medview.handler", level="INFO") as medview_logs:
            with self.assertLogs("server.connection", level="INFO") as conn_logs:
                conn._handle_service_data(self.PIPE_IDX, frame)

        # (a) Reply payload is the canonical iterator-cancel ack.
        hb = self._parse_wire(bytes(sock.sent))
        self.assertEqual(hb.msg_class, 0x01)
        self.assertEqual(hb.selector, MEDVIEW_SUBSCRIBE_NOTIFICATIONS)
        self.assertEqual(hb.request_id, 3)
        self.assertEqual(hb.payload, ITERATOR_CANCEL_ACK)

        # (b) Matching subscription is gone; others remain.
        self.assertNotIn(2, handler._subscriptions)
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 3, 4})

        # (c) svc_iterator_cancel is logged at the connection layer.
        self.assertTrue(
            any("svc_iterator_cancel" in m for m in conn_logs.output),
            f"missing svc_iterator_cancel log: {conn_logs.output}",
        )

        # (d) subscribe_notifications is NOT logged for the cancel frame —
        # the cancel branch must come before the `handle_request` dispatch.
        cancel_phase = [m for m in medview_logs.output if "subscribe_notifications req_id=3" in m]
        self.assertEqual(
            cancel_phase,
            [],
            "cancel frame leaked into subscribe handler",
        )

    def test_cancel_frame_on_pipe_without_handler_is_ignored(self):
        from server.config import MEDVIEW_SUBSCRIBE_NOTIFICATIONS

        conn, _handler, sock = self._make_conn()
        bare_pipe = self.PIPE_IDX + 1  # not registered
        frame = self._build_cancel_frame(0x01, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, 99)

        with self.assertLogs("server.connection", level="INFO") as conn_logs:
            conn._handle_service_data(bare_pipe, frame)

        self.assertTrue(
            any("no_handler" in m for m in conn_logs.output),
            f"missing no_handler log: {conn_logs.output}",
        )
        self.assertEqual(bytes(sock.sent), b"")


class TestMEDVIEWRemoteFsError(unittest.TestCase):
    """Spec selector 0x1D GetRemoteFsError — synchronous u16."""

    def test_get_remote_fs_error_returns_zero(self):
        from server.config import MEDVIEW_GET_REMOTE_FS_ERROR

        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(
            0x01, MEDVIEW_GET_REMOTE_FS_ERROR, 1, bytes.fromhex("82"), 5, 5
        )
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        # 0x82 <word=0> 0x87
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)
        self.assertEqual(reply[3], TAG_END_STATIC)


class TestMEDVIEWBaggageBm0(unittest.TestCase):
    """bm0 baggage delivery — kind=5 raster sized to the CBFrame.

    Container layout: 8 B preamble + 30 B kind=5 header (wide-form
    pixel_byte_count) + 38400 B all-FF pixels (640×480 1bpp) + 7 B
    empty trailer = 38445 B total. See `docs/MEDVIEW.md` §10."""

    _BM0_PREAMBLE_LEN = 8
    _BM0_KIND5_HEADER_LEN = 30  # wide pixel_byte_count varint
    _BM0_PIXEL_BYTES = 38400  # 640 × 480 / 8 for 1bpp
    _BM0_TRAILER_LEN = 7
    _BM0_CONTAINER_LEN = (
        _BM0_PREAMBLE_LEN + _BM0_KIND5_HEADER_LEN + _BM0_PIXEL_BYTES + _BM0_TRAILER_LEN
    )
    # bm0 retry form: tag=0x04 var "bm0\0" (4 B, length-prefix 0x84).
    _OPEN_REQ_BM0 = bytes.fromhex("01 01 04 84 62 6d 30 00 01 02 81 83")
    # First-probe form: tag=0x04 var "|bm0\0" (5 B, length-prefix 0x85).
    _OPEN_REQ_PIPE_BM0 = bytes.fromhex("01 01 04 85 7c 62 6d 30 00 01 02 81 83")

    def _decode_reply(self, selector, req_id, payload):
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, selector, req_id, payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        return parsed.payload[8:]

    def test_container_size_matches_constant(self):
        self.assertEqual(self._BM0_CONTAINER_LEN, 38445)
        self.assertEqual(len(BM0_BAGGAGE), 38445)

    def test_hfs_open_pipe_bm0_is_rejected(self):
        # MVTTL14C's first probe is `|bm0` (`wsprintfA("|bm%d", idx)`);
        # rejection causes the wrapper to retry with the canonical name.
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_OPEN, 10, self._OPEN_REQ_PIPE_BM0)
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], 0x81)
        self.assertEqual(reply[2], 0x00)  # handle = 0 → reject
        self.assertEqual(reply[3], 0x83)
        self.assertEqual(struct.unpack("<I", reply[4:8])[0], 0)

    def test_hfs_open_bm0_declares_container_size(self):
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_OPEN, 11, self._OPEN_REQ_BM0)
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], 0x81)
        self.assertEqual(reply[2], 0x42)
        self.assertEqual(reply[3], 0x83)
        self.assertEqual(
            struct.unpack("<I", reply[4:8])[0],
            self._BM0_CONTAINER_LEN,
        )

    def test_hfs_read_bm0_kind_byte_passes_parser_gate(self):
        # First read of 64 B starting at offset 0 — covers preamble +
        # kind5 header. Bitmap begins at offset 8; first byte must be 5
        # to clear MVDecodeBitmapBaggage's `kind < 5` gate.
        read_req = bytes.fromhex("01 42 03 40 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 12, read_req)
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], TAG_END_STATIC)
        self.assertEqual(reply[3], TAG_DYNAMIC_COMPLETE_SIGNAL)
        chunk = reply[4 : 4 + 64]
        self.assertEqual(chunk[8], 0x05)

    def test_hfs_read_bm0_preamble_and_header_byte_sequence(self):
        # 38B = 8 preamble + 30 kind=5 header (wide-form pixel_byte_count).
        read_req = bytes.fromhex("01 42 03 26 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 12, read_req)
        chunk = reply[4 : 4 + 38]
        expected_header = bytes.fromhex(
            "00 00"  # container reserved
            "01 00"  # bitmap count = 1
            "08 00 00 00"  # offset to bitmap[0]
            "05 00"  # kind=5, compression=raw
            "00 00 00 00"  # 2x skip-int (narrow form)
            "02 02"  # byte-narrow: planes=1, bpp=1
            "00 05 c0 03"  # ushort-narrow: width=640, height=480
            "00 00 00 00"  # palette_count=0, reserved=0
            "01 2c 01 00"  # u32-wide pixel_byte_count = 38400
            "0e 00"  # ushort-narrow trailer_size = 7
            "1e 00 00 00"  # pixel_data_offset = 30
            "1e 96 00 00"  # trailer_offset = 30 + 38400 = 38430
        )
        self.assertEqual(chunk, expected_header)

    def test_hfs_read_bm0_pixel_data_is_solid_white(self):
        # Pixel data starts at container-offset 38 (= 8 preamble + 30 header).
        read_req = bytes.fromhex("01 42 03 20 00 00 00 03 26 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 13, read_req)
        chunk = reply[4 : 4 + 32]
        self.assertEqual(chunk, b"\xff" * 32)

    def test_hfs_read_bm0_trailer_is_empty(self):
        # Trailer at container-offset 38 + 38400 = 38438. Read 7 B.
        offset = self._BM0_PREAMBLE_LEN + self._BM0_KIND5_HEADER_LEN + self._BM0_PIXEL_BYTES
        read_req = (
            b"\x01\x42"
            + b"\x03\x07\x00\x00\x00"
            + b"\x03"
            + struct.pack("<I", offset)
            + b"\x81\x85"
        )
        reply = self._decode_reply(MEDVIEW_SELECTOR_HFS_READ, 14, read_req)
        chunk = reply[4 : 4 + 7]
        self.assertEqual(chunk, b"\x00" * 7)

    def test_hfs_read_bm0_full_request_is_pipe_safe(self):
        # The full bm0 fits in one host block but requires transport
        # fragmentation. Every transport packet remains within PacketSize.
        read_req = (
            b"\x01\x42"
            + b"\x03"
            + struct.pack("<I", self._BM0_CONTAINER_LEN)
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x85"
        )
        handler = MEDVIEWHandler(5, "MEDVIEW")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_HFS_READ, 12, read_req, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertGreater(len(pkts), 1)
        self.assertTrue(all(len(pkt) <= 1024 for pkt in pkts))


class TestMEDVIEWM14BaggageDispatch(unittest.TestCase):
    @staticmethod
    def _open_handler():
        handler = MEDVIEWHandler(5, "MEDVIEW")
        open_req = (
            b"\x04\x87:2[4]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_TITLE_OPEN,
            1,
            open_req,
            5,
            5,
        )
        return handler

    def test_open_title_exposes_compiled_m14_baggage(self):
        handler = self._open_handler()
        self.assertIn("homed.shg", handler.baggage_map)
        self.assertIn("handbook.m14", handler.baggage_map)
        self.assertNotIn("bm0", handler.baggage_map)

    def test_native_image_reference_opens_and_reads_hfs_baggage(self):
        handler = self._open_handler()
        name = b"!homed.SHG\x00"
        open_req = b"\x01\x01\x04" + bytes([0x80 | len(name)]) + name + b"\x01\x02\x81\x83"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_HFS_OPEN,
            21,
            open_req,
            5,
            5,
        )
        reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(reply[0], TAG_END_STATIC)
        handle = reply[2]
        self.assertNotEqual(handle, 0)
        self.assertEqual(
            struct.unpack_from("<I", reply, 4)[0],
            len(handler.baggage_map["homed.shg"]),
        )

        read_req = (
            b"\x01"
            + bytes([handle])
            + b"\x03\x20\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x85"
        )
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_HFS_READ,
            22,
            read_req,
            5,
            5,
        )
        read_reply = parse_packet(pkts[0][:-1]).payload[8:]
        self.assertEqual(
            read_reply[4:36],
            handler.baggage_map["homed.shg"][:32],
        )

    def test_large_hfs_read_streams_all_bytes_before_completion(self):
        handler = self._open_handler()
        name = b"!homed.SHG\x00"
        open_req = b"\x01\x01\x04" + bytes([0x80 | len(name)]) + name + b"\x01\x02\x81\x83"
        open_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_HFS_OPEN,
            21,
            open_req,
            5,
            5,
        )
        handle = parse_packet(open_pkts[0][:-1]).payload[10]
        baggage = handler.baggage_map["homed.shg"]
        offset = 5
        read_req = (
            b"\x01"
            + bytes([handle])
            + b"\x03"
            + struct.pack("<I", len(baggage) - offset)
            + b"\x03"
            + struct.pack("<I", offset)
            + b"\x81\x85"
        )
        packets = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_HFS_READ,
            22,
            read_req,
            5,
            5,
        )

        dynamic_block_max = 0x4000
        pipe_blocks = []
        current = bytearray()
        expected_size = None
        for packet in packets:
            parsed = parse_packet(packet[:-1])
            self.assertTrue(parsed.crc_ok)
            header = decode_header_byte(parsed.payload[0])
            if expected_size is None:
                expected_size = struct.unpack_from("<H", parsed.payload, 1)[0]
                current.extend(parsed.payload[3:])
            else:
                current.extend(parsed.payload[1:])
            if header & PIPE_LAST_DATA:
                self.assertEqual(len(current), expected_size)
                pipe_blocks.append(bytes(current))
                current = bytearray()
                expected_size = None

        self.assertEqual(
            len(pipe_blocks),
            (len(baggage[offset:]) + dynamic_block_max - 1) // dynamic_block_max,
        )
        replies = []
        for pipe_block in pipe_blocks:
            self.assertEqual(struct.unpack_from("<H", pipe_block)[0], 5)
            host_block = parse_host_block(pipe_block[2:])
            self.assertIsNotNone(host_block)
            self.assertEqual(host_block.request_id, 22)
            replies.append(host_block.payload)

        self.assertEqual(replies[0][:4], b"\x81\x00\x87" + bytes([TAG_DYNAMIC_PARTIAL]))
        for reply in replies[1:-1]:
            self.assertEqual(reply[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(replies[-1][0], TAG_DYNAMIC_COMPLETE_SIGNAL)
        self.assertLessEqual(len(replies[0][4:]), dynamic_block_max)
        self.assertTrue(
            all(len(reply[1:]) <= dynamic_block_max for reply in replies[1:]),
        )
        received = replies[0][4:] + b"".join(reply[1:] for reply in replies[1:])
        self.assertEqual(received, baggage[offset:])
        self.assertTrue(all(len(packet) <= 1024 for packet in packets))


if __name__ == "__main__":
    unittest.main()
